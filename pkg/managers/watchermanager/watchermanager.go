// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package watchermanager

import (
	"context"
	"fmt"
	"time"

	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/watchers/apiserver"
	"github.com/microsoft/retina/pkg/watchers/endpoint"
	"go.uber.org/zap"
)

const (
	// DefaultRefreshRate is the default refresh rate for watchers.
	DefaultRefreshRate = 30 * time.Second
)

func NewWatcherManager(filterMapMaxEntries uint32, refreshRate time.Duration) *WatcherManager {
	if refreshRate <= 0 {
		refreshRate = DefaultRefreshRate
	}
	return &WatcherManager{
		Watchers: []IWatcher{
			endpoint.Watcher(),
			apiserver.Watcher(filterMapMaxEntries),
		},
		l:           log.Logger().Named("watcher-manager"),
		refreshRate: refreshRate,
	}
}

func (wm *WatcherManager) Start(ctx context.Context) error {
	newCtx, cancelCtx := context.WithCancel(ctx)
	wm.cancel = cancelCtx

	for i, w := range wm.Watchers {
		// Init with the cancellable context so any long-lived goroutines a watcher
		// starts (e.g. the endpoint watcher's netlink subscription) are torn down
		// by wm.cancel() on Stop, consistent with runWatcher.
		if err := w.Init(newCtx); err != nil {
			wm.l.Error("init failed", zap.String("watcher_type", fmt.Sprintf("%T", w)), zap.Error(err))
			// Unwind watchers already started so a failed Start leaves nothing
			// running even if the caller never calls Stop.
			cancelCtx()
			for _, started := range wm.Watchers[:i] {
				if stopErr := started.Stop(ctx); stopErr != nil {
					wm.l.Error("failed to stop watcher during unwind", zap.String("watcher_type", fmt.Sprintf("%T", started)), zap.Error(stopErr))
				}
			}
			wm.wg.Wait()
			return err
		}
		wm.wg.Add(1)
		go wm.runWatcher(newCtx, w)
		wm.l.Info("watcher started", zap.String("watcher_type", fmt.Sprintf("%T", w)))
	}
	return nil
}

func (wm *WatcherManager) Stop(ctx context.Context) error {
	if wm.cancel != nil {
		wm.cancel() // cancel all runWatcher
	}
	// Stop every watcher and always wait for the runWatcher goroutines; an early
	// return on the first error would leave the rest running.
	var firstErr error
	for _, w := range wm.Watchers {
		if err := w.Stop(ctx); err != nil {
			wm.l.Error("failed to stop", zap.String("watcher_type", fmt.Sprintf("%T", w)), zap.Error(err))
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	wm.wg.Wait() // wait for all runWatcher to stop
	wm.l.Info("watcher manager stopped")
	return firstErr
}

func (wm *WatcherManager) runWatcher(ctx context.Context, w IWatcher) {
	defer wm.wg.Done() // signal that this runWatcher is done
	// Reconcile once at startup instead of waiting for the first tick. Log and
	// continue on failure so a transient error doesn't permanently kill the watcher.
	if err := w.Refresh(ctx); err != nil {
		wm.l.Error("initial refresh failed", zap.Error(err), zap.String("watcher_type", fmt.Sprintf("%T", w)))
	}
	ticker := time.NewTicker(wm.refreshRate)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			wm.l.Info("watcher stopping...", zap.String("watcher_type", fmt.Sprintf("%T", w)))
			return
		case <-ticker.C:
			// Log and continue so a transient failure doesn't permanently stop
			// reconciliation; the next tick retries.
			if err := w.Refresh(ctx); err != nil {
				wm.l.Error("refresh failed", zap.Error(err), zap.String("watcher_type", fmt.Sprintf("%T", w)))
			}
		}
	}
}
