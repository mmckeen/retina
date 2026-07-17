// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package pubsub

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/microsoft/retina/pkg/log"
	"go.uber.org/zap"
)

// latencyWarnThreshold is the delivery lag — the age of the oldest undelivered
// event — at which we warn that a consumer is falling behind. Latency, not queue
// depth: depth is a poor proxy because per-event cost varies by orders of
// magnitude (a re-assert skip is tens of µs, a fresh attach is milliseconds), so
// the same depth can mean tens of ms or several seconds of lag. The queue is
// unbounded (events are never dropped) and the fast path targets ms-scale
// delivery, so a lag this large means the fast path is degraded well before it
// matters.
const latencyWarnThreshold = 1 * time.Second

var (
	p    *PubSub
	once sync.Once
)

// subscriber buffers events in an unbounded, ordered queue drained by a single
// goroutine. Ordering guarantees the initial snapshot is delivered before any
// later event (e.g. a delete). It never drops and never blocks the publisher, so
// one slow subscriber cannot stall the shared publisher. Mirrors client-go's
// shared informer processorListener.
//
// Delivery does not begin until start() runs: Subscribe makes the subscriber
// visible to publishers first (so live events buffer into pending), then start()
// prepends the snapshot ahead of anything buffered and opens the gate. This lets
// snapshot() run outside the PubSub lock — it must never be called under the lock
// because a source may take other locks (or do I/O), which would risk deadlock
// and stall every topic.
type subscriber struct {
	id    string
	topic PubSubTopic
	cb    *CallBackFunc
	l     *log.ZapLogger

	mu      sync.Mutex
	cond    *sync.Cond
	pending []queued
	started bool
	stopped bool
	warned  bool
}

// queued is an event plus the time it was enqueued, so delivery lag (the age of
// the oldest undelivered event) can be measured.
type queued struct {
	msg interface{}
	at  time.Time
}

func newSubscriber(id string, topic PubSubTopic, cb *CallBackFunc, l *log.ZapLogger) *subscriber {
	s := &subscriber{id: id, topic: topic, cb: cb, l: l}
	s.cond = sync.NewCond(&s.mu)
	go s.run()
	return s
}

// enqueue appends an event. It never blocks the publisher and never drops.
func (s *subscriber) enqueue(msg interface{}) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.pending = append(s.pending, queued{msg: msg, at: time.Now()})
	// Warn on delivery lag — the age of the oldest undelivered event — evaluated
	// here at enqueue so a fully stalled consumer (which never dequeues, so a
	// dequeue-time measurement would go silent) is still caught. One-shot until
	// the queue drains, to avoid log spam.
	if age := time.Since(s.pending[0].at); age >= latencyWarnThreshold && !s.warned {
		s.warned = true
		s.l.Warn("pubsub subscriber delivery lag is high; consumer is falling behind",
			zap.String("topic", string(s.topic)), zap.String("uuid", s.id),
			zap.Duration("lag", age), zap.Int("depth", len(s.pending)))
	}
	s.mu.Unlock()
	s.cond.Signal()
}

// start prepends the initial snapshot ahead of any events buffered since the
// subscriber became visible, then opens the delivery gate. Snapshot items are
// therefore delivered before every later event, while events that raced in during
// subscription still follow (idempotent consumers absorb any overlap).
func (s *subscriber) start(snapshot []interface{}) {
	s.mu.Lock()
	if len(snapshot) > 0 {
		now := time.Now()
		q := make([]queued, 0, len(snapshot)+len(s.pending))
		for i := range snapshot {
			q = append(q, queued{msg: snapshot[i], at: now})
		}
		q = append(q, s.pending...)
		s.pending = q
	}
	s.started = true
	s.mu.Unlock()
	s.cond.Signal()
}

func (s *subscriber) run() {
	s.mu.Lock()
	for {
		for !s.stopped && (!s.started || len(s.pending) == 0) {
			s.cond.Wait()
		}
		if s.stopped {
			s.mu.Unlock()
			return
		}
		msg := s.pending[0].msg
		s.pending[0] = queued{} // release references
		s.pending = s.pending[1:]
		if len(s.pending) == 0 {
			s.pending = nil // release backing array once drained
			s.warned = false
		}
		s.mu.Unlock()

		// Callbacks are trusted code; a panic here is a bug and crashes the agent
		// rather than being silently swallowed.
		(*s.cb)(msg)

		s.mu.Lock()
	}
}

func (s *subscriber) stop() {
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	s.cond.Broadcast()
}

type PubSub struct {
	sync.RWMutex
	l *log.ZapLogger
	// subscribers maps a topic to its subscribers keyed by id.
	subscribers map[PubSubTopic]map[string]*subscriber
	// sources maps a topic to a snapshot provider replayed to new subscribers.
	sources map[PubSubTopic]func() []interface{}
}

// New returns the singleton PubSub instance.
func New() *PubSub {
	once.Do(func() {
		p = &PubSub{
			l:           log.Logger().Named(string("PubSub")),
			subscribers: make(map[PubSubTopic]map[string]*subscriber),
			sources:     make(map[PubSubTopic]func() []interface{}),
		}
	})

	return p
}

// RegisterSource registers a snapshot provider for a topic. When a new
// subscriber subscribes, the current snapshot is replayed to it before any
// later event, so a subscriber that registers after events were published still
// converges to the current state (informer-style list-then-watch). Callbacks
// must be idempotent: a snapshot item may duplicate a concurrently published event.
func (p *PubSub) RegisterSource(topic PubSubTopic, snapshot func() []interface{}) {
	p.Lock()
	defer p.Unlock()
	p.sources[topic] = snapshot
}

// Publish enqueues msg to every current subscriber of the topic.
func (p *PubSub) Publish(topic PubSubTopic, msg interface{}) {
	p.RLock()
	defer p.RUnlock()

	subs := p.subscribers[topic]
	if len(subs) == 0 {
		// Not an error: with level-triggered re-assertion, publishing before a
		// subscriber has joined is routine and self-heals on the next refresh.
		p.l.Debug("no subscribers for topic", zap.String("topic", string(topic)))
		return
	}

	for _, s := range subs {
		s.enqueue(msg)
	}
}

// Subscribe registers callback for the topic and returns its id. If a source is
// registered, its current snapshot is delivered to this subscriber before any
// later event (informer-style list-then-watch); callbacks must be idempotent, as
// a snapshot item may overlap a concurrently published event.
//
// The subscriber is made visible under the lock (so live events start buffering),
// but snapshot() is invoked *after* releasing the lock and then prepended ahead of
// anything buffered. This preserves ordering without holding the PubSub lock across
// the source callback, which may take other locks or do I/O.
func (p *PubSub) Subscribe(topic PubSubTopic, callback *CallBackFunc) string {
	id := uuid.New().String()
	s := newSubscriber(id, topic, callback, p.l)

	p.Lock()
	if p.subscribers[topic] == nil {
		p.subscribers[topic] = make(map[string]*subscriber)
	}
	p.subscribers[topic][id] = s
	source := p.sources[topic]
	p.Unlock()

	// Captured outside the lock; ordering is preserved because s buffers any
	// events published in this window and start() prepends the snapshot ahead of
	// them. A snapshot taken here reflects all state up to this point, so nothing
	// is missed: earlier events are in the snapshot, later ones are buffered.
	var snapshot []interface{}
	if source != nil {
		snapshot = source()
	}
	s.start(snapshot)

	p.l.Debug("subscribed to topic", zap.String("topic", string(topic)), zap.String("uuid", id))
	return id
}

// Unsubscribe removes the subscriber and stops its drain goroutine. It does
// NOT wait for a delivery already in flight: the callback may still be running
// (or run once more) after Unsubscribe returns. Callers that tear down state
// the callback uses must synchronize in the callback itself (see packetparser's
// stopping/cbMu handshake).
func (p *PubSub) Unsubscribe(topic PubSubTopic, uuid string) error {
	if uuid == "" {
		return fmt.Errorf("uuid cannot be empty")
	}

	p.Lock()
	var s *subscriber
	if subs, ok := p.subscribers[topic]; ok {
		if s = subs[uuid]; s != nil {
			delete(subs, uuid)
			if len(subs) == 0 {
				delete(p.subscribers, topic)
			}
		}
	}
	p.Unlock()

	if s != nil {
		s.stop()
		p.l.Debug("unsubscribed from topic", zap.String("topic", string(topic)), zap.String("uuid", uuid))
	}
	return nil
}
