// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package pubsub

import (
	"sync"
	"testing"
	"time"

	"github.com/microsoft/retina/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	until = 1 * time.Millisecond
)

func TestNewPubSub(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := New()
	assert.NotNil(t, p)
}

func TestPublish(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := New()
	p.Publish("topic", "msg")
}

func TestSubscribe(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := New()
	cb := CallBackFunc(func(msg interface{}) {})

	uuid := p.Subscribe("topic", &cb)
	assert.NotEmpty(t, uuid)
}

func TestUnsubscribe(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := New()
	cb := CallBackFunc(func(msg interface{}) {})

	uuid := p.Subscribe("topic", &cb)
	err := p.Unsubscribe("topic", uuid)
	assert.NoError(t, err)
}

func TestMultipleSubscribe(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	cb := CallBackFunc(func(msg interface{}) {})

	p := New()
	uuid1 := p.Subscribe("topic", &cb)
	uuid2 := p.Subscribe("topic", &cb)
	assert.NotEmpty(t, uuid1)
	assert.NotEmpty(t, uuid2)
}

func TestPubSub(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ps := New()

	// Publisher 1 publishes a message to topic "topic1"
	ps.Publish("topic1", "Hello from Publisher 1!")

	// Publisher 2 publishes a message to topic "topic2"
	ps.Publish("topic2", "Hello from Publisher 2!")

	cb1 := CallBackFunc(func(msg interface{}) {
		if msg.(string) != "Hello from Publisher 1!" {
			t.Errorf("Expected 'Hello from Publisher 1!', got %s", msg)
		}
	})

	cb2 := CallBackFunc(func(msg interface{}) {
		if msg.(string) != "Hello from Publisher 2!" {
			t.Errorf("Expected 'Hello from Publisher 2!', got %s", msg)
		}
	})

	// Subscriber 1 subscribes to topic "topic1"
	subID1 := ps.Subscribe("topic1", &cb1)
	defer func() {
		// Unsubscribe Subscriber 1
		err := ps.Unsubscribe("topic1", subID1)
		if err != nil {
			t.Errorf("Failed to unsubscribe: %v", err)
		}
	}()

	// Subscriber 2 subscribes to topic "topic2"
	subID2 := ps.Subscribe("topic2", &cb2)
	defer func() {
		// Unsubscribe Subscriber 2
		err := ps.Unsubscribe("topic2", subID2)
		if err != nil {
			t.Errorf("Failed to unsubscribe: %v", err)
		}
	}()

	// Publisher 1 publishes another message to topic "topic1"
	ps.Publish("topic1", "Hello from Publisher 1!")

	// Publisher 2 publishes another message to topic "topic2"
	ps.Publish("topic2", "Hello from Publisher 2!")

	err := ps.Unsubscribe("topic1", "randomid")
	if err != nil {
		t.Errorf("Failed to unsubscribe: %v", err)
	}

	time.Sleep(until)
}

func TestSubscribeReplaysSnapshot(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := New()

	// Source registered before anyone subscribes.
	p.RegisterSource("snap-topic", func() []interface{} {
		return []interface{}{"a", "b"}
	})

	var mu sync.Mutex
	got := map[string]bool{}
	cb := CallBackFunc(func(msg interface{}) {
		mu.Lock()
		got[msg.(string)] = true
		mu.Unlock()
	})

	// Subscriber joins late; it must still receive the current snapshot.
	id := p.Subscribe("snap-topic", &cb)
	defer p.Unsubscribe("snap-topic", id) //nolint:errcheck // best-effort cleanup in test

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return got["a"] && got["b"]
	}, time.Second, 5*time.Millisecond, "expected snapshot replayed to a late subscriber")
}

func TestSnapshotDeliveredBeforeDeltas(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := New()

	p.RegisterSource("order-topic", func() []interface{} {
		return []interface{}{"snapshot-add"}
	})

	var mu sync.Mutex
	var order []string
	cb := CallBackFunc(func(msg interface{}) {
		mu.Lock()
		order = append(order, msg.(string))
		mu.Unlock()
	})

	id := p.Subscribe("order-topic", &cb)
	defer p.Unsubscribe("order-topic", id) //nolint:errcheck // best-effort cleanup in test

	// Subscribe enqueues the snapshot under the lock, so this later delta is
	// ordered after it. FIFO delivery must yield snapshot-then-delta.
	p.Publish("order-topic", "live-delete")

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(order) == 2
	}, time.Second, 5*time.Millisecond, "expected both events delivered")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"snapshot-add", "live-delete"}, order,
		"snapshot must be delivered before later deltas (e.g. deletes)")
}

func TestSnapshotSourceRunsOutsideLock(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := New()

	// A snapshot source that re-enters PubSub (Publish takes the read lock).
	// This deadlocks if snapshot() is invoked while the Subscribe path holds the
	// write lock — the regression this guards against. Real sources instead take
	// their own locks / do I/O, which is the same hazard (deadlock, or stalling
	// every topic across a syscall).
	p.RegisterSource("reentrant-topic", func() []interface{} {
		p.Publish("sink-topic", "from-snapshot")
		return []interface{}{"snap"}
	})

	sink := make(chan string, 1)
	sinkCb := CallBackFunc(func(m interface{}) { sink <- m.(string) })
	p.Subscribe("sink-topic", &sinkCb)

	got := make(chan string, 1)
	cb := CallBackFunc(func(m interface{}) { got <- m.(string) })

	done := make(chan string, 1)
	go func() { done <- p.Subscribe("reentrant-topic", &cb) }()

	// Subscribe must return (no deadlock), the snapshot item must be delivered,
	// and the event the source published must reach the sink subscriber.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Subscribe hung; snapshot() appears to run under the PubSub lock")
	}
	select {
	case v := <-got:
		assert.Equal(t, "snap", v, "snapshot item should be delivered")
	case <-time.After(time.Second):
		t.Fatal("snapshot item not delivered")
	}
	select {
	case v := <-sink:
		assert.Equal(t, "from-snapshot", v, "event published from within snapshot should be delivered")
	case <-time.After(time.Second):
		t.Fatal("event published from within snapshot not delivered")
	}
}

// TestDeltasDuringSubscribeFollowSnapshot pins the subscriber start-gate
// invariant: an event published while the snapshot source is still running (the
// subscriber is already visible to publishers, but delivery hasn't started) must
// buffer and be delivered AFTER the snapshot, never before and never dropped.
func TestDeltasDuringSubscribeFollowSnapshot(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := New()

	sourceEntered := make(chan struct{})
	releaseSource := make(chan struct{})
	p.RegisterSource("gate-topic", func() []interface{} {
		close(sourceEntered)
		<-releaseSource // hold the subscription open while the test publishes
		return []interface{}{"snap"}
	})

	var mu sync.Mutex
	var order []string
	cb := CallBackFunc(func(m interface{}) {
		mu.Lock()
		order = append(order, m.(string))
		mu.Unlock()
	})

	subscribed := make(chan string, 1)
	go func() { subscribed <- p.Subscribe("gate-topic", &cb) }()

	<-sourceEntered
	// Subscriber is registered (visible) but gated; this must buffer, not drop.
	p.Publish("gate-topic", "delta")
	close(releaseSource)

	id := <-subscribed
	defer p.Unsubscribe("gate-topic", id) //nolint:errcheck // best-effort cleanup in test

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(order) == 2
	}, 2*time.Second, 5*time.Millisecond, "both the snapshot and the buffered delta must be delivered")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"snap", "delta"}, order,
		"a delta buffered during subscription must follow the snapshot")
}

// TestPublishDeliversInFIFOOrder pins per-subscriber FIFO: events published
// sequentially to a topic are delivered to a subscriber in publish order. The
// snapshot-ordering tests only cover one live event relative to the snapshot;
// this guards the delta-vs-delta ordering the single drain goroutine provides.
func TestPublishDeliversInFIFOOrder(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := New()

	const n = 100
	var mu sync.Mutex
	var got []int
	cb := CallBackFunc(func(m interface{}) {
		mu.Lock()
		got = append(got, m.(int))
		mu.Unlock()
	})
	id := p.Subscribe("fifo-topic", &cb)
	defer p.Unsubscribe("fifo-topic", id) //nolint:errcheck // best-effort cleanup in test

	// Single sequential publisher: publish order is 0..n-1.
	for i := 0; i < n; i++ {
		p.Publish("fifo-topic", i)
	}

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == n
	}, 2*time.Second, 5*time.Millisecond, "all published events must be delivered")

	mu.Lock()
	defer mu.Unlock()
	want := make([]int, n)
	for i := range want {
		want[i] = i
	}
	assert.Equal(t, want, got, "events must be delivered in publish order (per-subscriber FIFO)")
}

// newTestSubscriber builds a subscriber without starting its drain goroutine,
// so seeded pending events aren't consumed before the assertion.
func newTestSubscriber() *subscriber {
	s := &subscriber{id: "t", topic: "lag-topic", l: log.Logger()}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// enqueue warns on delivery lag — the age of the oldest undelivered event —
// evaluated at enqueue so a stalled consumer is caught, and stays quiet on a
// queue that isn't behind.
func TestEnqueueWarnsOnDeliveryLag(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	// A head that has already waited past the threshold (as a stalled consumer's
	// would) must trip the warning on the next enqueue.
	lagging := newTestSubscriber()
	lagging.pending = []queued{{msg: "old", at: time.Now().Add(-2 * latencyWarnThreshold)}}
	lagging.enqueue("new")
	assert.True(t, lagging.warned, "a head-of-queue older than the latency threshold must warn")

	// A just-enqueued (near-zero-age) head must not warn.
	fresh := newTestSubscriber()
	fresh.enqueue("m1")
	fresh.enqueue("m2")
	assert.False(t, fresh.warned, "a queue that is not behind must not warn")
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := New()

	got := make(chan struct{}, 8)
	cb := CallBackFunc(func(interface{}) { got <- struct{}{} })
	id := p.Subscribe("unsub-topic", &cb)

	p.Publish("unsub-topic", "m1")
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("first event was not delivered")
	}

	require.NoError(t, p.Unsubscribe("unsub-topic", id))

	// After unsubscribe the drain goroutine is stopped and the subscriber removed,
	// so a later publish must not be delivered.
	p.Publish("unsub-topic", "m2")
	select {
	case <-got:
		t.Fatal("event delivered after unsubscribe")
	case <-time.After(200 * time.Millisecond):
	}
}

// RegisterSource keeps only the most recent source for a topic (last writer
// wins) — the semantic the cache's explicit RegisterSnapshotSources wiring
// depends on: whichever component registers last owns the topic's snapshot slot.
func TestRegisterSourceLastWins(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := New()
	topic := PubSubTopic("last-wins-topic")
	p.RegisterSource(topic, func() []interface{} { return []interface{}{"stale"} })
	p.RegisterSource(topic, func() []interface{} { return []interface{}{"current"} })

	got := make(chan interface{}, 2)
	cb := CallBackFunc(func(msg interface{}) { got <- msg })
	id := p.Subscribe(topic, &cb)
	defer p.Unsubscribe(topic, id) //nolint:errcheck // best-effort cleanup in test

	select {
	case msg := <-got:
		assert.Equal(t, "current", msg, "the last registered source must serve the snapshot")
	case <-time.After(2 * time.Second):
		t.Fatal("no snapshot delivered")
	}
	select {
	case msg := <-got:
		t.Fatalf("the overwritten source must not also fire, got: %v", msg)
	case <-time.After(100 * time.Millisecond):
	}
}
