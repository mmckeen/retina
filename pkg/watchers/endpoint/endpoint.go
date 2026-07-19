// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package endpoint

import (
	"context"
	"sync"

	"github.com/microsoft/retina/pkg/common"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/pubsub"
	"go.uber.org/zap"
)

type EndpointWatcher struct {
	isRunning           bool
	enableNetlinkEvents bool
	l                   *log.ZapLogger
	current             cache
	new                 cache
	p                   pubsub.PubSubInterface
	mu                  sync.Mutex
	// cancel tears down the goroutines Init started (netlink subscription and
	// refresher). Derived from Init's ctx, so parent cancellation propagates and
	// Stop works for standalone callers too — one signal, not a ctx/stop-channel pair.
	cancel context.CancelFunc
	// deletedIndexes holds interface indexes that netlink reported removed since
	// the last refresh, guarded by delMu (the netlink reader writes it, Refresh
	// drains it). It lets Refresh detect a delete+recreate that reused an index
	// within one reconcile — which diffCache alone cannot see. Empty when netlink
	// events are disabled or on Windows.
	delMu          sync.Mutex
	deletedIndexes map[int]struct{}
	// hooks holds the watcher's OS-facing dependencies (netlink calls on linux),
	// injectable per instance in tests. The type is defined per-OS. A zero value
	// means production defaults (see osHooks on linux).
	hooks hooks //nolint:unused // driven by osHooks on linux; windows has no netlink hooks
}

var e *EndpointWatcher

// NewEndpointWatcher creates a new endpoint watcher.
func Watcher(enableNetlinkEvents bool) *EndpointWatcher {
	if e == nil {
		e = &EndpointWatcher{
			isRunning: false,
			l:         log.Logger().Named("endpoint-watcher"),
			p:         pubsub.New(),
			current:   make(cache),
		}
	}
	e.enableNetlinkEvents = enableNetlinkEvents

	return e
}

func (e *EndpointWatcher) Init(ctx context.Context) error {
	if e.isRunning {
		e.l.Info("endpoint watcher is already running")
		return nil
	}
	ctx, e.cancel = context.WithCancel(ctx)
	// Register the snapshot source before subscribers join so a subscriber that
	// joins after the watcher (e.g. packetparser) replays the current veth set
	// immediately instead of waiting for the next refresh.
	e.p.RegisterSource(common.PubSubEndpoints, e.snapshot)
	e.subscribe(ctx)
	e.isRunning = true
	return nil
}

func (e *EndpointWatcher) Stop(ctx context.Context) error {
	if !e.isRunning {
		e.l.Info("endpoint watcher is not running")
		return nil
	}
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	e.isRunning = false
	return nil
}

// recordDeletedIndex notes an interface index netlink reported removed. Called
// from the netlink reader goroutine; drained by Refresh.
func (e *EndpointWatcher) recordDeletedIndex(index int) {
	e.delMu.Lock()
	if e.deletedIndexes == nil {
		e.deletedIndexes = make(map[int]struct{})
	}
	e.deletedIndexes[index] = struct{}{}
	e.delMu.Unlock()
}

// drainDeletedIndexes returns and clears the indexes netlink reported removed
// since the last call.
func (e *EndpointWatcher) drainDeletedIndexes() map[int]struct{} {
	e.delMu.Lock()
	d := e.deletedIndexes
	e.deletedIndexes = nil
	e.delMu.Unlock()
	return d
}

func (e *EndpointWatcher) Refresh(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Drain netlink-reported deletes BEFORE listing. A delete that lands after
	// the list would pair with the stale pre-delete sample and misread as a
	// reuse (index present in both old and new), publishing a spurious
	// delete+create for an interface that is simply gone. Drained-first, a
	// record inserted after this point stays queued for the next refresh —
	// which the same delete event also triggers — so nothing is lost.
	drained := e.drainDeletedIndexes()

	// initNewCache is OS specific.
	// Based on GOOS, will be implemented by either endpoint_linux, or
	// endpoint_windows.
	err := e.initNewCache()
	if err != nil {
		// Re-queue the drained records so a failed list doesn't lose them; a
		// genuine reuse they describe would otherwise become undetectable.
		for idx := range drained {
			e.recordDeletedIndex(idx)
		}
		return err
	}

	// Handle interface-index reuse before diffing. If netlink reported index N
	// deleted and the re-list now shows a *different* interface at N (a new veth
	// reused the freed index before we sampled), a plain diff sees N in both the
	// old and new cache and emits nothing — leaving the old occupant attached and
	// the new one unattached. Publish a delete for the old occupant now (so
	// consumers detach) and drop it from current, so diffCache/the re-assert below
	// treat the new occupant as freshly created and (re)attach it. Ordering holds:
	// this delete is published before the create re-assert, and delivery is FIFO
	// per subscriber. Pure deletes (N gone, not reused) are left to diffCache.
	for idx := range drained {
		k := key{index: idx}
		old, inCurrent := e.current[k]
		if _, inNew := e.new[k]; !inCurrent || !inNew {
			continue
		}
		e.l.Info("interface index reused; detaching old interface before re-attaching",
			zap.String("old", describeEndpoint(old)), zap.Int("index", idx))
		e.p.Publish(common.PubSubEndpoints, NewEndpointEvent(EndpointDeleted, old))
		delete(e.current, k)
	}

	created, deleted := e.diffCache()

	// Log interfaces appearing/disappearing (the diff only, not the full
	// re-assert below) at info, mirroring the apiserver watcher's IP logging.
	for _, v := range created {
		e.l.Info("New endpoint interface", zap.String("endpoint", describeEndpoint(v)))
	}
	for _, v := range deleted {
		e.l.Info("Deleted endpoint interface", zap.String("endpoint", describeEndpoint(v)))
	}

	// Re-assert every current veth on each refresh (level-triggered): consumers
	// attach idempotently, so a create event dropped before a subscriber was
	// ready self-heals on the next refresh.
	for _, v := range e.new {
		e.p.Publish(common.PubSubEndpoints, NewEndpointEvent(EndpointCreated, v))
	}

	// Publish the deleted veths.
	for _, v := range deleted {
		e.p.Publish(common.PubSubEndpoints, NewEndpointEvent(EndpointDeleted, v))
	}

	// Update the cache and reset the new cache.
	e.current = e.new.deepcopy()
	e.new = nil

	return nil
}

// snapshot returns the current veth set as EndpointCreated events. Registered
// as the pubsub source so a subscriber that joins after startup (e.g.
// packetparser) receives the current set immediately instead of waiting for
// the next refresh. It serves e.current — the same state deletes are diffed
// against — under the same lock Refresh commits it: a subscriber can never
// receive a create whose delete the diff would not later publish. (Listing the
// kernel here instead could hand a subscriber a veth that dies before the next
// Refresh commits it to current, orphaning the create forever.)
func (e *EndpointWatcher) snapshot() []interface{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	events := make([]interface{}, 0, len(e.current))
	for _, v := range e.current {
		events = append(events, NewEndpointEvent(EndpointCreated, v))
	}
	return events
}

// Function to differentiate between two caches.
func (e *EndpointWatcher) diffCache() (created, deleted []interface{}) {
	// Check if there are any new veths.
	for k, v := range e.new {
		if _, ok := e.current[k]; !ok {
			created = append(created, v)
		}
	}

	// Check if there are any deleted veths.
	for k, v := range e.current {
		if _, ok := e.new[k]; !ok {
			deleted = append(deleted, v)
		}
	}
	return
}
