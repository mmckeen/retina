// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
// nolint

package apiserver

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/retina/pkg/common"
	kcfg "github.com/microsoft/retina/pkg/config"
	cc "github.com/microsoft/retina/pkg/controllers/cache"
	"github.com/microsoft/retina/pkg/log"
	filtermanagermocks "github.com/microsoft/retina/pkg/managers/filtermanager"
	"github.com/microsoft/retina/pkg/pubsub"
	"github.com/microsoft/retina/pkg/watchers/apiserver/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var errDNS = errors.New("DNS error")

func TestGetWatcher(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	a := Watcher(kcfg.DefaultFilterMapMaxEntries)
	assert.NotNil(t, a)

	aAgain := Watcher(kcfg.DefaultFilterMapMaxEntries)
	assert.Equal(t, a, aAgain, "Expected the same veth watcher instance")
}

func TestAPIServerWatcherStop(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockedFilterManager := filtermanagermocks.NewMockIFilterManager(ctrl)

	// When apiserver is already stopped.
	a := &ApiServerWatcher{
		isRunning:     false,
		l:             log.Logger().Named("apiserver-watcher"),
		filterManager: mockedFilterManager,
		restConfig:    getMockConfig(true),
	}
	err := a.Stop(ctx)
	assert.NoError(t, err, "Expected no error when stopping a stopped apiserver watcher")
	assert.Equal(t, false, a.isRunning, "Expected apiserver watcher to be stopped")

	// Start the watcher.
	err = a.Init(ctx)
	assert.NoError(t, err, "Expected no error when starting a stopped apiserver watcher")

	// Stop the watcher.
	err = a.Stop(ctx)
	assert.NoError(t, err, "Expected no error when stopping a running apiserver watcher")
	assert.Equal(t, false, a.isRunning, "Expected apiserver watcher to be stopped")
}

func TestRefresh(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mockedResolver := mocks.NewMockIHostResolver(ctrl)
	mockedFilterManager := filtermanagermocks.NewMockIFilterManager(ctrl)

	a := &ApiServerWatcher{
		l:             log.Logger().Named("apiserver-watcher"),
		hostResolver:  mockedResolver,
		filterManager: mockedFilterManager,
		client:        getMockKubeClient(),
	}

	// Return 2 random IPs for the host everytime LookupHost is called.
	mockedResolver.EXPECT().LookupHost(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, host string) ([]string, error) {
		return []string{randomIP(), randomIP()}, nil
	}).AnyTimes()

	mockedFilterManager.EXPECT().AddIPs(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockedFilterManager.EXPECT().DeleteIPs(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	a.Refresh(ctx)
	assert.NoError(t, a.Refresh(context.Background()), "Expected no error when refreshing the cache")
}

// TestRefreshSkipsNonIPv4 verifies IPv6 apiserver IPs (e.g. dual-stack) are
// skipped rather than fed to the IPv4-keyed filter map as nils — which the
// level-triggered re-assert would otherwise repeat every refresh.
func TestRefreshSkipsNonIPv4(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockedResolver := mocks.NewMockIHostResolver(ctrl)
	mockedResolver.EXPECT().LookupHost(gomock.Any(), gomock.Any()).Return([]string{"10.9.9.9", "fd00::1"}, nil).AnyTimes()

	var got []net.IP
	mockedFilterManager := filtermanagermocks.NewMockIFilterManager(ctrl)
	mockedFilterManager.EXPECT().AddIPs(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ips []net.IP, _ filtermanagermocks.Requestor, _ filtermanagermocks.RequestMetadata) error {
			got = ips
			return nil
		}).AnyTimes()
	mockedFilterManager.EXPECT().DeleteIPs(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	a := &ApiServerWatcher{
		l:             log.Logger().Named("apiserver-watcher"),
		hostResolver:  mockedResolver,
		filterManager: mockedFilterManager,
		client:        getMockKubeClient(),
	}

	require.NoError(t, a.Refresh(context.Background()))

	// 3 IPv4s from the mock kube client + 1 from the resolver; fd00::1 skipped.
	assert.Len(t, got, 4, "expected only the IPv4 addresses")
	for _, ip := range got {
		assert.NotNil(t, ip, "no nil entries may reach the filter manager")
	}
}

// TestSnapshot verifies the pubsub snapshot source returns the current apiserver
// IP set as a single add event (and nothing when empty), so a late subscriber
// converges to the current state.
func TestSnapshot(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	a := &ApiServerWatcher{
		l:       log.Logger().Named("apiserver-watcher"),
		current: cache{},
	}
	assert.Nil(t, a.snapshot(), "empty current should yield no snapshot events")

	a.current = cache{"10.0.0.1": struct{}{}, "10.0.0.2": struct{}{}, "fd00::1": struct{}{}}
	snap := a.snapshot()
	require.Len(t, snap, 1, "snapshot should be a single add event carrying all current IPs")
	ev, ok := snap[0].(*cc.CacheEvent)
	require.True(t, ok, "snapshot item should be a *cache.CacheEvent")
	assert.Equal(t, cc.EventTypeAddAPIServerIPs, ev.Type, "snapshot event should be an apiserver-IP add")
	obj, ok := ev.Obj.(*common.APIServerObject)
	require.True(t, ok, "snapshot event payload should be an *common.APIServerObject")
	got := make([]string, 0, len(obj.IPs()))
	for _, ip := range obj.IPs() {
		got = append(got, ip.String())
	}
	assert.ElementsMatch(t, []string{"10.0.0.1", "10.0.0.2"}, got,
		"snapshot must carry the IPv4 set and skip IPv6, matching the publish path's filter")

	// All-IPv6 current: nothing publishable, so no snapshot event at all.
	a.current = cache{"fd00::2": struct{}{}}
	assert.Nil(t, a.snapshot(), "an all-IPv6 set should yield no snapshot events")
}

// TestRefreshPublishesDeleteBeforeAdd pins the publish order on an IP change.
// The cache keys every apiserver IP under one endpoint and handles a delete by
// dropping the whole entry, so a delete published after the add re-assert would
// wipe the set just asserted and leave the cache without an apiserver endpoint
// until the next refresh.
func TestRefreshPublishesDeleteBeforeAdd(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockedResolver := mocks.NewMockIHostResolver(ctrl)
	gomock.InOrder(
		mockedResolver.EXPECT().LookupHost(gomock.Any(), gomock.Any()).Return([]string{"10.0.0.1", "10.0.0.2"}, nil).Times(1),
		mockedResolver.EXPECT().LookupHost(gomock.Any(), gomock.Any()).Return([]string{"10.0.0.1"}, nil).Times(1),
	)
	mockedFilterManager := filtermanagermocks.NewMockIFilterManager(ctrl)
	mockedFilterManager.EXPECT().AddIPs(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockedFilterManager.EXPECT().DeleteIPs(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	a := &ApiServerWatcher{
		l:             log.Logger().Named("apiserver-watcher"),
		hostResolver:  mockedResolver,
		filterManager: mockedFilterManager,
		client:        getMockKubeClient(),
		current:       cache{},
	}

	// Record the order of published event types on the apiserver topic.
	var mu sync.Mutex
	type published struct {
		typ cc.EventType
		ips []string
	}
	var events []published
	fn := pubsub.CallBackFunc(func(msg interface{}) {
		ev, ok := msg.(*cc.CacheEvent)
		if !ok {
			return
		}
		obj, ok := ev.Obj.(*common.APIServerObject)
		if !ok || obj.EP == nil {
			return
		}
		ips := []string{}
		for _, ip := range obj.IPs() {
			ips = append(ips, ip.String())
		}
		mu.Lock()
		events = append(events, published{ev.Type, ips})
		mu.Unlock()
	})
	ps := pubsub.New()
	id := ps.Subscribe(common.PubSubAPIServer, &fn)
	defer ps.Unsubscribe(common.PubSubAPIServer, id) //nolint:errcheck // best-effort cleanup in test

	require.NoError(t, a.Refresh(context.Background()))
	require.NoError(t, a.Refresh(context.Background())) // drops 10.0.0.2

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		del := -1
		for i, e := range events {
			if e.typ == cc.EventTypeDeleteAPIServerIPs {
				del = i
				break
			}
		}
		if del < 0 {
			return false
		}
		assert.Equal(t, []string{"10.0.0.2"}, events[del].ips, "the delete must carry the dropped IP")
		// The re-assert of the surviving set must come after the delete, so
		// consumers that drop the whole entry on delete end converged.
		for _, e := range events[del+1:] {
			if e.typ == cc.EventTypeAddAPIServerIPs {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond,
		"expected the delete to be published before the add re-assert")
}

// TestSnapshotConcurrentWithRefresh hammers snapshot() while Refresh commits —
// under -race this pins the mutex protecting a.current, the only thing that
// makes serving snapshots to arbitrary subscriber goroutines safe.
func TestSnapshotConcurrentWithRefresh(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockedResolver := mocks.NewMockIHostResolver(ctrl)
	mockedResolver.EXPECT().LookupHost(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, string) ([]string, error) {
			return []string{randomIP(), randomIP()}, nil
		}).AnyTimes()
	mockedFilterManager := filtermanagermocks.NewMockIFilterManager(ctrl)
	mockedFilterManager.EXPECT().AddIPs(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockedFilterManager.EXPECT().DeleteIPs(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	a := &ApiServerWatcher{
		l:             log.Logger().Named("apiserver-watcher"),
		hostResolver:  mockedResolver,
		filterManager: mockedFilterManager,
		client:        getMockKubeClient(),
		current:       cache{},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			a.snapshot()
		}
	}()
	for range 10 {
		require.NoError(t, a.Refresh(context.Background()))
	}
	<-done
}

func TestDiffCache(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockedResolver := mocks.NewMockIHostResolver(ctrl)

	old := make(map[string]struct{})
	new := make(map[string]struct{})

	old["192.168.1.1"] = struct{}{}
	old["192.168.1.2"] = struct{}{}
	new["192.168.1.2"] = struct{}{}
	new["192.168.1.3"] = struct{}{}

	a := &ApiServerWatcher{
		l:            log.Logger().Named("apiserver-watcher"),
		hostResolver: mockedResolver,
		current:      old,
		new:          new,
	}

	created, deleted := a.diffCache()
	assert.Equal(t, 1, len(created), "Expected 1 created host")
	assert.Equal(t, 1, len(deleted), "Expected 1 deleted host")
}

func TestRefreshLookUpAlwaysFail(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mockedResolver := mocks.NewMockIHostResolver(ctrl)

	a := &ApiServerWatcher{
		l:            log.Logger().Named("apiserver-watcher"),
		hostResolver: mockedResolver,
		client:       getMockKubeClient(),
	}

	mockedResolver.EXPECT().LookupHost(gomock.Any(), gomock.Any()).Return(nil, errors.New("Error")).AnyTimes()

	a.Refresh(ctx)
	require.Error(t, a.Refresh(context.Background()), "Expected error when refreshing the cache")
}

func TestInitWithIncorrectURL(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mockedResolver := mocks.NewMockIHostResolver(ctrl)
	mockedFilterManager := filtermanagermocks.NewMockIFilterManager(ctrl)

	a := &ApiServerWatcher{
		l:             log.Logger().Named("apiserver-watcher"),
		hostResolver:  mockedResolver,
		restConfig:    getMockConfig(false),
		client:        getMockKubeClient(),
		filterManager: mockedFilterManager,
	}

	mockedResolver.EXPECT().LookupHost(gomock.Any(), gomock.Any()).Return([]string{}, nil).AnyTimes()
	require.Error(t, a.Init(ctx), "Expected error during init")
}

func randomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

// Mock function to simulate getting a Kubernetes config
func getMockConfig(isCorrect bool) *rest.Config {
	if isCorrect {
		return &rest.Config{
			Host: "https://kubernetes.default.svc.cluster.local:443",
		}
	}
	return &rest.Config{
		Host: "",
	}
}

func getMockKubeClient() client.Client {
	kubernetesSvc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIPs: []string{"172.0.16.1"},
		},
	}

	slice := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes",
			Namespace: "default",
			Labels: map[string]string{
				discoveryv1.LabelServiceName: "kubernetes",
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"100.64.83.200"}},
			{Addresses: []string{"100.64.83.201"}},
		},
	}
	return fake.NewFakeClient(&slice, &kubernetesSvc)
}

func TestRefreshFailsFirstFourAttemptsSucceedsOnFifth(t *testing.T) {
	_, err := log.SetupZapLogger(log.GetDefaultLogOpts())
	require.NoError(t, err)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mockedResolver := mocks.NewMockIHostResolver(ctrl)
	mockedFilterManager := filtermanagermocks.NewMockIFilterManager(ctrl)

	a := &ApiServerWatcher{
		l:             log.Logger().Named("apiserver-watcher"),
		hostResolver:  mockedResolver,
		filterManager: mockedFilterManager,
		client:        getMockKubeClient(),
	}

	// Simulate LookupHost failing the first four times and succeeding on the fifth.
	gomock.InOrder(
		mockedResolver.EXPECT().LookupHost(gomock.Any(), gomock.Any()).Return(nil, errDNS).Times(4),
		mockedResolver.EXPECT().LookupHost(gomock.Any(), gomock.Any()).Return([]string{"127.0.0.1"}, nil).Times(1),
	)

	mockedFilterManager.EXPECT().AddIPs(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockedFilterManager.EXPECT().DeleteIPs(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	err = a.Refresh(ctx)
	require.NoError(t, err, "Expected no error when refreshing the cache")
}
