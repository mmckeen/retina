// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package endpoint

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// listVethsMaxAttempts bounds how many times listVeths retries a dump that the
// kernel reported interrupted (NLM_F_DUMP_INTR). A dump races a concurrent link
// change; retrying gets a consistent snapshot instead of reconciling against a
// partial one (which would look like spurious deletes).
const listVethsMaxAttempts = 5

const (
	linkUpdateChanSize = 64
	// defaultResubscribeBackoff is the delay before re-establishing a dead
	// netlink subscription.
	defaultResubscribeBackoff = 2 * time.Second
)

// hooks are the watcher's OS-facing dependencies, injectable per instance in
// tests. Instance fields rather than package vars: watcher goroutines outlive a
// test body, so swapping-and-restoring globals races their reads.
type hooks struct {
	listLinks          func() ([]netlink.Link, error)
	linkSubscribe      func(chan<- netlink.LinkUpdate, <-chan struct{}, netlink.LinkSubscribeOptions) error
	resubscribeBackoff time.Duration
}

// osHooks returns the instance hooks with production defaults filled in for any
// zero fields, so a watcher constructed without hooks behaves like production.
func (e *EndpointWatcher) osHooks() hooks {
	h := e.hooks
	if h.listLinks == nil {
		h.listLinks = netlink.LinkList
	}
	if h.linkSubscribe == nil {
		h.linkSubscribe = netlink.LinkSubscribeWithOptions
	}
	if h.resubscribeBackoff == 0 {
		h.resubscribeBackoff = defaultResubscribeBackoff
	}
	return h
}

// subscribe triggers an immediate Refresh whenever a veth appears or disappears,
// removing the up-to-refresh-interval attach delay. Periodic Refresh remains the backstop.
func (e *EndpointWatcher) subscribe(ctx context.Context) {
	if !e.enableNetlinkEvents {
		return
	}
	trigger := make(chan struct{}, 1)
	go e.runNetlink(ctx, trigger)   // keeps a subscription alive, records events
	go e.runRefresher(ctx, trigger) // reconciles when triggered
}

// runNetlink keeps a netlink link subscription alive. The netlink library ends its
// receive goroutine on any receive error, which closes the updates channel. We
// detect that and resubscribe after a backoff,
// and reconcile on every (re)connect so state cannot drift while the fast path was
// down. Periodic Refresh remains the ultimate backstop, so a transient outage only
// adds latency, never a permanent loss of the fast path.
//
// An RTM_DELLINK dropped while the subscription is down is never recorded, so an
// index reuse spanning the outage is invisible to Refresh's reuse detection. That
// is compensated downstream: the level-triggered re-assert redelivers every
// current interface each refresh, and packetparser verifies recorded attachments
// are still live in the kernel before skipping (see createQdiscAndAttach) — TCX
// via the link's ifindex, legacy TC via a targeted per-ifindex filter presence
// query — so a stale attachment self-heals within one refresh (for legacy TC's
// accepted false-alive gaps, see tcAttachmentAlive).
func (e *EndpointWatcher) runNetlink(ctx context.Context, trigger chan<- struct{}) {
	h := e.osHooks()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Per-subscription done channel: closing it lets the netlink library close
		// its socket, so resubscribing doesn't leak the previous one.
		subDone := make(chan struct{})
		updates := make(chan netlink.LinkUpdate, linkUpdateChanSize)
		err := h.linkSubscribe(updates, subDone, netlink.LinkSubscribeOptions{
			ListExisting: true,
			ErrorCallback: func(err error) {
				// The initial ListExisting dump can race a link change; our reconcile
				// re-lists (with its own retry), so this is benign.
				if errors.Is(err, netlink.ErrDumpInterrupted) {
					e.l.Debug("netlink initial dump interrupted; reconcile will re-list", zap.Error(err))
					return
				}
				e.l.Warn("netlink link subscription error", zap.Error(err))
			},
		})
		if err != nil {
			e.l.Error("netlink subscribe failed; retrying", zap.Error(err))
		} else {
			e.l.Info("netlink-driven endpoint refresh enabled")
			// ListExisting replays every current link as an event, so (re)connecting
			// drives a reconcile on its own — catching anything that changed while the
			// subscription was down without an explicit kick here.
			e.readLinkUpdates(ctx, updates, trigger)
		}
		close(subDone) // release this subscription's socket

		select {
		case <-ctx.Done():
			return
		case <-time.After(h.resubscribeBackoff):
		}
	}
}

// readLinkUpdates drains a subscription until it closes (netlink ended it) or the
// watcher stops, returning so runNetlink can resubscribe.
func (e *EndpointWatcher) readLinkUpdates(ctx context.Context, updates <-chan netlink.LinkUpdate, trigger chan<- struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-updates:
			if !ok {
				e.l.Warn("netlink subscription closed; resubscribing")
				return
			}
			if u.Link == nil || u.Type() != "veth" {
				continue
			}
			// RTM_DELLINK carries the veth type, so record the removed index here.
			// Refresh uses it to detect a delete+recreate that reused the index
			// within a single reconcile (see Refresh).
			if u.Header.Type == unix.RTM_DELLINK {
				e.recordDeletedIndex(u.Attrs().Index)
			}
			e.signal(trigger)
		}
	}
}

func (e *EndpointWatcher) runRefresher(ctx context.Context, trigger <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-trigger:
			if err := e.Refresh(ctx); err != nil {
				e.l.Error("netlink-driven refresh failed", zap.Error(err))
			}
		}
	}
}

// signal requests a reconcile without blocking; a pending request coalesces.
func (e *EndpointWatcher) signal(trigger chan<- struct{}) {
	select {
	case trigger <- struct{}{}:
	default:
	}
}

// describeEndpoint renders a veth for logging as "name (index N)".
func describeEndpoint(v interface{}) string {
	if a, ok := v.(netlink.LinkAttrs); ok {
		return fmt.Sprintf("%s (index %d)", a.Name, a.Index)
	}
	return "unknown"
}

func (e *EndpointWatcher) initNewCache() error {
	veths, err := e.listVeths()
	if err != nil {
		return err
	}

	// Reset new cache.
	e.new = make(cache)
	for _, veth := range veths {
		k := key{
			index: veth.Attrs().Index,
		}

		e.new[k] = *veth.Attrs()
	}

	return nil
}

// listVeths returns all veth interfaces, like `ip link show type veth`.
func (e *EndpointWatcher) listVeths() ([]netlink.Link, error) {
	listLinks := e.osHooks().listLinks
	var links []netlink.Link
	var err error
	for range listVethsMaxAttempts {
		links, err = listLinks()
		// On a clean dump (or a non-retryable error) stop; on an interrupted dump
		// the results may be incomplete, so discard and retry for a consistent one.
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			break
		}
	}
	if err != nil {
		return nil, err
	}

	var veths []netlink.Link
	for _, link := range links {
		// Ref: https://github.com/vishvananda/netlink/blob/ced5aaba43e3f25bb5f04860641d3e3dd04a8544/link.go#L367
		// Unfortunately, there is no type/constant defined for "veth" in the netlink package.
		// Version of netlink tested - https://github.com/vishvananda/netlink/tree/v1.2.1-beta.2
		if link.Type() == "veth" {
			veths = append(veths, link)
		}
	}

	return veths, nil
}
