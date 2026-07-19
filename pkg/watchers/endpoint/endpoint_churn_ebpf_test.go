// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build ebpf && linux

// Real-kernel test for the pod-restart attach path. Creates and deletes veths
// and verifies the netlink fast path emits EndpointCreated/EndpointDeleted with
// low (sub-poll-interval) latency. Requires NET_ADMIN; run via `make test-ebpf`
// (sudo) or in a privileged linux container:
//
//	docker run --privileged -v "$PWD":/src -w /src golang:1.26 \
//	  go test -tags=ebpf -run VethChurn ./pkg/watchers/endpoint/
package endpoint

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/retina/pkg/common"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/pubsub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

const (
	churnRounds = 20
	namePool    = 5
	vethPrefix  = "rtnchurn"
	peerPrefix  = "rtnpeer" // deliberately not matching vethPrefix so peers are ignored
)

// cleanupChurnVeths removes any leftover test veths (deleting one end removes the pair).
func cleanupChurnVeths(t *testing.T) {
	t.Helper()
	links, err := netlink.LinkList()
	if err != nil {
		return
	}
	for _, l := range links {
		n := l.Attrs().Name
		if strings.HasPrefix(n, vethPrefix) || strings.HasPrefix(n, peerPrefix) {
			_ = netlink.LinkDel(l)
		}
	}
}

// TestVethChurnLatency simulates pod restarts (delete/recreate of the same veth
// identity) and asserts every create yields an EndpointCreated quickly and every
// delete yields an EndpointDeleted.
func TestVethChurnLatency(t *testing.T) {
	log.SetupZapLogger(log.GetDefaultLogOpts())
	cleanupChurnVeths(t)
	t.Cleanup(func() { cleanupChurnVeths(t) })

	ps := pubsub.New()

	var mu sync.Mutex
	createdAt := map[string]time.Time{}
	deletedAt := map[string]time.Time{}
	cb := pubsub.CallBackFunc(func(msg interface{}) {
		ev, ok := msg.(*EndpointEvent)
		if !ok {
			return
		}
		attrs, ok := ev.Obj.(netlink.LinkAttrs)
		if !ok || !strings.HasPrefix(attrs.Name, vethPrefix) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch ev.Type {
		case EndpointCreated:
			if _, seen := createdAt[attrs.Name]; !seen {
				createdAt[attrs.Name] = time.Now()
			}
		case EndpointDeleted:
			if _, seen := deletedAt[attrs.Name]; !seen {
				deletedAt[attrs.Name] = time.Now()
			}
		}
	})
	id := ps.Subscribe(common.PubSubEndpoints, &cb)
	defer ps.Unsubscribe(common.PubSubEndpoints, id) //nolint:errcheck

	v := &EndpointWatcher{
		enableNetlinkEvents: true,
		l:                   log.Logger().Named("churn-watcher"),
		p:                   ps,
		current:             make(cache),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v.subscribe(ctx)

	var latencies []time.Duration
	for i := 0; i < churnRounds; i++ {
		// Reuse a small name pool so each round is a delete+recreate of the same
		// pod-like identity — the exact path a pod restart exercises.
		name := fmt.Sprintf("%s%d", vethPrefix, i%namePool)
		peer := fmt.Sprintf("%s%d", peerPrefix, i%namePool)

		la := netlink.NewLinkAttrs()
		la.Name = name
		veth := &netlink.Veth{LinkAttrs: la, PeerName: peer}

		start := time.Now()
		require.NoError(t, netlink.LinkAdd(veth), "LinkAdd %s (round %d)", name, i)

		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			_, ok := createdAt[name]
			return ok
		}, 5*time.Second, 2*time.Millisecond, "EndpointCreated for %s (round %d)", name, i)

		mu.Lock()
		latencies = append(latencies, createdAt[name].Sub(start))
		mu.Unlock()

		require.NoError(t, netlink.LinkDel(veth), "LinkDel %s (round %d)", name, i)

		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			_, ok := deletedAt[name]
			return ok
		}, 5*time.Second, 2*time.Millisecond, "EndpointDeleted for %s (round %d)", name, i)

		// Reset so the next reuse of this name is observed afresh.
		mu.Lock()
		delete(createdAt, name)
		delete(deletedAt, name)
		mu.Unlock()
	}

	var maxLat, total time.Duration
	for _, l := range latencies {
		total += l
		if l > maxLat {
			maxLat = l
		}
	}
	avg := total / time.Duration(len(latencies))
	t.Logf("veth create->EndpointCreated latency: avg=%v max=%v over %d rounds", avg, maxLat, len(latencies))

	// The whole point: attach latency is event-driven, not bound to the poll interval.
	assert.Less(t, maxLat, 2*time.Second, "attach event latency should be far below any refresh interval")
}
