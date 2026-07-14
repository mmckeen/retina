// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
// nolint

package endpoint

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/microsoft/retina/pkg/common"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/pubsub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var errTest = errors.New("test error")

func TestGetWatcher(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	v := Watcher(false)
	assert.NotNil(t, v)

	vAgain := Watcher(false)
	assert.Equal(t, v, vAgain, "Expected the same veth watcher instance")
}

func TestEndpointWatcherStart(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	c := context.Background()

	// When veth is already running.
	v := &EndpointWatcher{
		isRunning: true,
		l:         log.Logger().Named("veth-watcher"),
		p:         pubsub.New(),
	}
	err := v.Init(c)
	assert.NoError(t, err, "Expected no error when starting a running veth watcher")
	assert.Equal(t, true, v.isRunning, "Expected veth watcher to be running")

	// When veth is not running.
	v.isRunning = false
	err = v.Init(c)
	assert.NoError(t, err, "Expected no error when starting a stopped veth watcher")
	assert.Equal(t, true, v.isRunning, "Expected veth watcher to be running")

	// Stop the watcher.
	err = v.Stop(c)
	assert.NoError(t, err, "Expected no error when stopping a running veth watcher")

	// Restart the watcher.
	err = v.Init(c)
	assert.NoError(t, err, "Expected no error when starting a stopped veth watcher")
	assert.Equal(t, true, v.isRunning, "Expected veth watcher to be running")

	// Stop the watcher.
	err = v.Stop(c)
	assert.NoError(t, err, "Expected no error when stopping a running veth watcher")
}

func TestEndpointWatcherStop(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	c := context.Background()

	// When veth is already stopped.
	v := &EndpointWatcher{
		isRunning: false,
		l:         log.Logger().Named("veth-watcher"),
		p:         pubsub.New(),
	}
	err := v.Stop(c)
	assert.NoError(t, err, "Expected no error when stopping a stopped veth watcher")
	assert.Equal(t, false, v.isRunning, "Expected veth watcher to be stopped")

	// Start the watcher.
	err = v.Init(c)
	assert.NoError(t, err, "Expected no error when starting a stopped veth watcher")

	// Stop the watcher.
	err = v.Stop(c)
	assert.NoError(t, err, "Expected no error when stopping a running veth watcher")
	assert.Equal(t, false, v.isRunning, "Expected veth watcher to be stopped")
}

func TestRun(t *testing.T) {
	v := &EndpointWatcher{hooks: hooks{listLinks: func() ([]netlink.Link, error) {
		return []netlink.Link{
			&netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{
					Name: "veth0",
				},
			},
			&netlink.Vxlan{
				LinkAttrs: netlink.LinkAttrs{
					Name: "eth0",
				},
			},
		}, nil
	}}}

	links, err := v.listVeths()
	assert.NoError(t, err, "Expected no error when listing veths")
	assert.Equal(t, 1, len(links), "Expected to find 1 veth")
	assert.Equal(t, "veth0", links[0].Attrs().Name, "Expected to find veth0")
}

func TestDiffCache(t *testing.T) {
	old := cache{
		key{
			index: 0,
		}: netlink.LinkAttrs{
			Name: "veth0",
		},
	}
	new := cache{
		key{
			index: 1,
		}: netlink.LinkAttrs{
			Name: "veth1",
		},
	}
	e := &EndpointWatcher{current: old, new: new}
	c, d := e.diffCache()
	assert.Equal(t, 1, len(c), "Expected to find 1 created veth")
	assert.Equal(t, 1, len(d), "Expected to find 1 deleted veth")
	assert.Equal(t, "veth1", c[0].(netlink.LinkAttrs).Name, "Expected to find veth1")
	assert.Equal(t, "veth0", d[0].(netlink.LinkAttrs).Name, "Expected to find veth0")
}

func TestRefreshAndCallback(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	c := context.Background()

	listLinks := func() ([]netlink.Link, error) {
		return []netlink.Link{
			&netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{
					Name:  "veth0",
					Index: 10,
				},
			},
			&netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{
					Name:  "veth1",
					Index: 11,
				},
			},
		}, nil
	}

	cache := make(cache)
	cache[key{
		index: 12,
	}] = &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: "veth2",
		},
	}

	v := &EndpointWatcher{
		isRunning: true,
		current:   cache,
		l:         log.Logger().Named("veth-watcher"),
		p:         pubsub.New(),
		hooks:     hooks{listLinks: listLinks},
	}

	// When cache is empty.
	assert.Equal(t, 1, len(v.current), "Expected to find 0 veths")

	// Post refresh.
	err := v.Refresh(c)
	assert.NoError(t, err, "Expected no error when refreshing veth cache")
	assert.Equal(t, 2, len(v.current), "Expected to find 2 veths")
	assert.Equal(t, "veth0", v.current[key{
		index: 10,
	}].(netlink.LinkAttrs).Name, "Expected to find veth0")
	assert.Equal(t, "veth1", v.current[key{
		index: 11,
	}].(netlink.LinkAttrs).Name, "Expected to find veth1")
}

func TestRefreshError(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	c := context.Background()

	v := &EndpointWatcher{
		isRunning: true,
		current:   make(cache),
		l:         log.Logger().Named("veth-watcher"),
		p:         pubsub.New(),
		hooks: hooks{listLinks: func() ([]netlink.Link, error) {
			return nil, errTest
		}},
	}

	err := v.Refresh(c)
	assert.Error(t, err, "Expected an error when refreshing veth cache")
}

func TestRefreshReassertsAllCurrent(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	ps := pubsub.New()
	var created atomic.Int32
	fn := pubsub.CallBackFunc(func(msg interface{}) {
		if ev, ok := msg.(*EndpointEvent); ok && ev.Type == EndpointCreated {
			created.Add(1)
		}
	})
	id := ps.Subscribe(common.PubSubEndpoints, &fn)
	defer ps.Unsubscribe(common.PubSubEndpoints, id) //nolint:errcheck // best-effort cleanup in test

	v := &EndpointWatcher{
		current: make(cache),
		l:       log.Logger().Named("veth-watcher"),
		p:       ps,
		hooks: hooks{listLinks: func() ([]netlink.Link, error) {
			return []netlink.Link{
				&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "veth0"}},
			}, nil
		}},
	}

	c := context.Background()
	assert.NoError(t, v.Refresh(c))
	assert.NoError(t, v.Refresh(c))

	// Level-triggered: the veth is re-published on every refresh. Publish runs
	// callbacks asynchronously, so poll. Use >= 2 because a snapshot source may
	// also be registered on the shared pubsub singleton and add replays.
	assert.Eventually(t, func() bool { return created.Load() >= 2 }, time.Second, 10*time.Millisecond,
		"expected the veth to be re-asserted on each refresh")
}

func TestNetlinkTriggersRefresh(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	capturedCh := make(chan chan<- netlink.LinkUpdate, 1)
	v := &EndpointWatcher{
		enableNetlinkEvents: true,
		l:                   log.Logger().Named("veth-watcher"),
		p:                   pubsub.New(),
		current:             make(cache),
		hooks: hooks{
			listLinks: func() ([]netlink.Link, error) {
				return []netlink.Link{
					&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "veth-new"}},
				}, nil
			},
			linkSubscribe: func(ch chan<- netlink.LinkUpdate, _ <-chan struct{}, _ netlink.LinkSubscribeOptions) error {
				capturedCh <- ch
				return nil
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	v.subscribe(ctx)

	ch := <-capturedCh
	ch <- netlink.LinkUpdate{Link: &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "veth-new"}}}

	assert.Eventually(t, func() bool {
		v.mu.Lock()
		defer v.mu.Unlock()
		return len(v.current) == 1
	}, time.Second, 10*time.Millisecond, "expected netlink event to trigger a refresh")
}

// endpointEvent is a captured (type, name) pair for a given interface index.
type endpointEvent struct {
	typ  EventType
	name string
}

// captureEndpointEvents subscribes and records events for a single interface index.
func captureEndpointEvents(t *testing.T, ps pubsub.PubSubInterface, index int) (*sync.Mutex, *[]endpointEvent) {
	t.Helper()
	var mu sync.Mutex
	events := &[]endpointEvent{}
	fn := pubsub.CallBackFunc(func(msg interface{}) {
		e, ok := msg.(*EndpointEvent)
		if !ok {
			return
		}
		attrs, ok := e.Obj.(netlink.LinkAttrs)
		if !ok || attrs.Index != index {
			return
		}
		mu.Lock()
		*events = append(*events, endpointEvent{e.Type, attrs.Name})
		mu.Unlock()
	})
	id := ps.Subscribe(common.PubSubEndpoints, &fn)
	t.Cleanup(func() { ps.Unsubscribe(common.PubSubEndpoints, id) }) //nolint:errcheck // best-effort cleanup in test
	return &mu, events
}

// A veth can be deleted and a new veth can reuse its interface index before the
// watcher re-lists. diffCache alone sees the index in both snapshots and emits
// nothing, so the old occupant stays attached and the new one never attaches.
// The netlink delete record must force a detach of the old occupant followed by
// an attach of the new one. This drives it end-to-end through the netlink reader.
func TestNetlinkDeleteTriggersReattachOnIndexReuse(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	const idx = 4242
	capturedCh := make(chan chan<- netlink.LinkUpdate, 1)
	ps := pubsub.New()
	mu, events := captureEndpointEvents(t, ps, idx)

	v := &EndpointWatcher{
		enableNetlinkEvents: true,
		l:                   log.Logger().Named("veth-watcher"),
		p:                   ps,
		current:             cache{key{index: idx}: netlink.LinkAttrs{Name: "vethA", Index: idx}},
		hooks: hooks{
			listLinks: func() ([]netlink.Link, error) {
				return []netlink.Link{
					&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "vethB", Index: idx}},
				}, nil
			},
			linkSubscribe: func(ch chan<- netlink.LinkUpdate, _ <-chan struct{}, _ netlink.LinkSubscribeOptions) error {
				capturedCh <- ch
				return nil
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v.subscribe(ctx)

	ch := <-capturedCh
	ch <- netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_DELLINK},
		Link:   &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "vethA", Index: idx}},
	}

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		del := -1
		for i, e := range *events {
			if e.typ == EndpointDeleted && e.name == "vethA" {
				del = i
				break
			}
		}
		if del < 0 {
			return false
		}
		for _, e := range (*events)[del+1:] {
			if e.typ == EndpointCreated && e.name == "vethB" {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond,
		"expected netlink delete of a reused index to detach vethA then attach vethB")
}

// A drained delete record must survive a failed re-list: Refresh re-queues it,
// so a reuse that spans the transient failure is still detected on the next
// pass (delete of the old occupant before the create of the new one).
func TestRefreshRequeuesDrainedDeletesOnListFailure(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	const idx = 6001
	ps := pubsub.New()
	mu, events := captureEndpointEvents(t, ps, idx)

	calls := 0
	v := &EndpointWatcher{
		l:       log.Logger().Named("veth-watcher"),
		p:       ps,
		current: cache{key{index: idx}: netlink.LinkAttrs{Name: "vethA", Index: idx}},
		hooks: hooks{listLinks: func() ([]netlink.Link, error) {
			calls++
			if calls == 1 {
				return nil, errTest
			}
			return []netlink.Link{
				&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "vethB", Index: idx}},
			}, nil
		}},
	}
	v.recordDeletedIndex(idx)

	require.Error(t, v.Refresh(context.Background()), "first refresh surfaces the list failure")
	require.NoError(t, v.Refresh(context.Background()))

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		del := -1
		for i, e := range *events {
			if e.typ == EndpointDeleted && e.name == "vethA" {
				del = i
				break
			}
		}
		if del < 0 {
			return false
		}
		for _, e := range (*events)[del+1:] {
			if e.typ == EndpointCreated && e.name == "vethB" {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond,
		"a reuse spanning a failed list must still detach vethA then attach vethB")
}

// A netlink-reported delete for an index that was NOT reused is handled by
// diffCache normally; the reuse path must skip it so the delete isn't published
// twice.
func TestRefreshPlainDeleteEmitsSingleDelete(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	const idx = 5555
	ps := pubsub.New()
	var deletes atomic.Int32
	fn := pubsub.CallBackFunc(func(msg interface{}) {
		e, ok := msg.(*EndpointEvent)
		if !ok {
			return
		}
		if attrs, ok := e.Obj.(netlink.LinkAttrs); ok && attrs.Index == idx && e.Type == EndpointDeleted {
			deletes.Add(1)
		}
	})
	id := ps.Subscribe(common.PubSubEndpoints, &fn)
	defer ps.Unsubscribe(common.PubSubEndpoints, id) //nolint:errcheck // best-effort cleanup in test

	v := &EndpointWatcher{
		current: cache{key{index: idx}: netlink.LinkAttrs{Name: "vethGone", Index: idx}},
		l:       log.Logger().Named("veth-watcher"),
		p:       ps,
		// index gone, not reused
		hooks: hooks{listLinks: func() ([]netlink.Link, error) { return nil, nil }},
	}
	v.recordDeletedIndex(idx)
	assert.NoError(t, v.Refresh(context.Background()))
	assert.NoError(t, v.Refresh(context.Background()))

	assert.Eventually(t, func() bool { return deletes.Load() >= 1 }, time.Second, 10*time.Millisecond,
		"expected the deleted index to be published as deleted")
	// Let any erroneous duplicate arrive before asserting it was published once.
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(1), deletes.Load(), "delete must be published exactly once (no double-emit)")
}

// TestSnapshotReturnsCurrentVeths verifies the pubsub snapshot source serves the
// committed current set as EndpointCreated events, so a subscriber joining after
// startup converges to the same state deletes are diffed against.
func TestSnapshotReturnsCurrentVeths(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	v := &EndpointWatcher{
		l: log.Logger().Named("veth-watcher"),
		current: cache{
			key{index: 7}: netlink.LinkAttrs{Name: "veth0", Index: 7},
			key{index: 8}: netlink.LinkAttrs{Name: "veth1", Index: 8},
		},
	}

	snap := v.snapshot()
	assert.Len(t, snap, 2, "snapshot should include every current veth")
	seen := map[int]bool{}
	for _, item := range snap {
		ev, ok := item.(*EndpointEvent)
		assert.True(t, ok, "snapshot item should be an *EndpointEvent")
		assert.Equal(t, EndpointCreated, ev.Type, "snapshot events should be creates")
		attrs, ok := ev.Obj.(netlink.LinkAttrs)
		assert.True(t, ok, "snapshot event payload should be netlink.LinkAttrs")
		seen[attrs.Index] = true
	}
	assert.True(t, seen[7] && seen[8], "snapshot should carry both veth indexes")
}

// A snapshot must never hand a subscriber a veth the diff state doesn't know
// about: a create served from a fresh kernel list, for a veth that dies before
// the next Refresh commits it to current, would have no matching delete ever —
// the subscriber holds an attachment forever. Serving from current makes this
// impossible: the veth is either committed (its later delete will be diffed and
// published) or absent from the snapshot.
func TestSnapshotServesCommittedStateNotKernelList(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	kernelHas := []netlink.Link{
		&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "veth-uncommitted", Index: 9}},
	}
	v := &EndpointWatcher{
		l:       log.Logger().Named("veth-watcher"),
		current: make(cache), // nothing committed yet
		hooks:   hooks{listLinks: func() ([]netlink.Link, error) { return kernelHas, nil }},
	}

	assert.Empty(t, v.snapshot(),
		"snapshot must not surface veths the diff state has not committed")
}

// The netlink library ends its subscription (closing the updates channel) on any
// receive error, including a socket-buffer overflow. The watcher must resubscribe
// rather than silently lose the fast path for the rest of the process's life.
func TestNetlinkResubscribesAfterClose(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	var calls atomic.Int32
	chs := make(chan chan<- netlink.LinkUpdate, 64)
	v := &EndpointWatcher{
		enableNetlinkEvents: true,
		l:                   log.Logger().Named("veth-watcher"),
		p:                   pubsub.New(),
		current:             make(cache),
		hooks: hooks{
			resubscribeBackoff: 10 * time.Millisecond,
			listLinks:          func() ([]netlink.Link, error) { return nil, nil },
			linkSubscribe: func(ch chan<- netlink.LinkUpdate, _ <-chan struct{}, _ netlink.LinkSubscribeOptions) error {
				calls.Add(1)
				select {
				case chs <- ch:
				default:
				}
				return nil
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v.subscribe(ctx)

	// First subscription is established, then dies (channel closed).
	ch1 := <-chs
	close(ch1)

	assert.Eventually(t, func() bool { return calls.Load() >= 2 }, 2*time.Second, 10*time.Millisecond,
		"expected the watcher to resubscribe after the subscription closed")
}

// Stop must tear down the netlink goroutines Init started, without racing them:
// Init derives an internal context and Stop cancels it (there is no separate
// stop channel to race on). Observable via the per-subscription done channel,
// which runNetlink closes on exit.
func TestStopTearsDownNetlinkGoroutines(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	subDones := make(chan (<-chan struct{}), 1)
	v := &EndpointWatcher{
		enableNetlinkEvents: true,
		l:                   log.Logger().Named("veth-watcher"),
		p:                   pubsub.New(),
		current:             make(cache),
		hooks: hooks{
			resubscribeBackoff: 10 * time.Millisecond,
			listLinks:          func() ([]netlink.Link, error) { return nil, nil },
			linkSubscribe: func(_ chan<- netlink.LinkUpdate, done <-chan struct{}, _ netlink.LinkSubscribeOptions) error {
				select {
				case subDones <- done:
				default:
				}
				return nil
			},
		},
	}

	require.NoError(t, v.Init(context.Background()))
	done := <-subDones
	require.NoError(t, v.Stop(context.Background()))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("netlink goroutine did not exit after Stop")
	}
}

// An interrupted dump (NLM_F_DUMP_INTR) may return incomplete results; listVeths
// must retry for a consistent snapshot rather than surfacing partial data (which
// would look like spurious interface deletes to the reconcile).
func TestListVethsRetriesOnDumpInterrupted(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	calls := 0
	good := []netlink.Link{&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "veth0", Index: 3}}}
	v := &EndpointWatcher{hooks: hooks{listLinks: func() ([]netlink.Link, error) {
		calls++
		if calls < 3 {
			return nil, netlink.ErrDumpInterrupted
		}
		return good, nil
	}}}

	veths, err := v.listVeths()
	require.NoError(t, err, "an interrupted dump should be retried, not surfaced")
	assert.Equal(t, 3, calls, "listVeths should retry until it gets a consistent dump")
	assert.Len(t, veths, 1, "should return the veths from the consistent dump")
}

// A persistently interrupted dump eventually gives up (bounded retries) and
// surfaces the error, so Refresh skips the cycle rather than acting on bad data.
func TestListVethsGivesUpAfterMaxDumpInterrupts(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	calls := 0
	v := &EndpointWatcher{hooks: hooks{listLinks: func() ([]netlink.Link, error) {
		calls++
		return nil, netlink.ErrDumpInterrupted
	}}}

	_, err := v.listVeths()
	require.ErrorIs(t, err, netlink.ErrDumpInterrupted)
	assert.Equal(t, listVethsMaxAttempts, calls, "should retry up to the bound then give up")
}

func TestListVethsError(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	v := &EndpointWatcher{hooks: hooks{listLinks: func() ([]netlink.Link, error) {
		return nil, errTest
	}}}

	_, err := v.listVeths()
	assert.Error(t, err, "Expected an error when listing veths")
}
