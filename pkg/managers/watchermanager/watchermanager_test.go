// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package watchermanager

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	kcfg "github.com/microsoft/retina/pkg/config"
	"github.com/microsoft/retina/pkg/log"
	mock "github.com/microsoft/retina/pkg/managers/watchermanager/mocks"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/sync/errgroup"
)

var errInitFailed = errors.New("init failed")

func TestStopWatcherManagerGracefully(t *testing.T) {
	ctl := gomock.NewController(t)
	defer ctl.Finish()
	log.SetupZapLogger(log.GetDefaultLogOpts())
	mgr := NewWatcherManager(kcfg.DefaultFilterMapMaxEntries, 0)

	mockAPIServerWatcher := mock.NewMockIWatcher(ctl)
	mockEndpointWatcher := mock.NewMockIWatcher(ctl)

	mgr.Watchers = []IWatcher{
		mockEndpointWatcher,
		mockAPIServerWatcher,
	}

	mockAPIServerWatcher.EXPECT().Init(gomock.Any()).Return(nil).AnyTimes()
	mockEndpointWatcher.EXPECT().Init(gomock.Any()).Return(nil).AnyTimes()

	mockEndpointWatcher.EXPECT().Refresh(gomock.Any()).Return(nil).AnyTimes()
	mockAPIServerWatcher.EXPECT().Refresh(gomock.Any()).Return(nil).AnyTimes()

	mockEndpointWatcher.EXPECT().Stop(gomock.Any()).Return(nil).AnyTimes()
	mockAPIServerWatcher.EXPECT().Stop(gomock.Any()).Return(nil).AnyTimes()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, errctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return mgr.Start(errctx)
	})
	err := g.Wait()

	mgr.Stop(errctx)
	require.NoError(t, err)
}

func TestWatcherInitFailsGracefully(t *testing.T) {
	ctl := gomock.NewController(t)
	defer ctl.Finish()
	log.SetupZapLogger(log.GetDefaultLogOpts())

	mockAPIServerWatcher := mock.NewMockIWatcher(ctl)
	mockEndpointWatcher := mock.NewMockIWatcher(ctl)

	mgr := NewWatcherManager(kcfg.DefaultFilterMapMaxEntries, 0)
	mgr.Watchers = []IWatcher{
		mockAPIServerWatcher,
		mockEndpointWatcher,
	}

	mockAPIServerWatcher.EXPECT().Init(gomock.Any()).Return(errInitFailed).AnyTimes()
	mockEndpointWatcher.EXPECT().Init(gomock.Any()).Return(errInitFailed).AnyTimes()

	err := mgr.Start(context.Background())
	require.NotNil(t, err, "Expected error when starting watcher manager")
}

// A failed Init partway through Start must unwind: already-started watchers are
// stopped and their runWatcher goroutines joined, so a caller that treats the
// error as fatal (never calling Stop) leaks nothing.
func TestStartUnwindsOnInitFailure(t *testing.T) {
	ctl := gomock.NewController(t)
	defer ctl.Finish()
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	first := mock.NewMockIWatcher(ctl)
	second := mock.NewMockIWatcher(ctl)

	mgr := NewWatcherManager(kcfg.DefaultFilterMapMaxEntries, 0)
	mgr.Watchers = []IWatcher{first, second}

	first.EXPECT().Init(gomock.Any()).Return(nil).Times(1)
	first.EXPECT().Refresh(gomock.Any()).Return(nil).AnyTimes()
	// The unwind must stop the watcher that already started.
	first.EXPECT().Stop(gomock.Any()).Return(nil).Times(1)
	second.EXPECT().Init(gomock.Any()).Return(errInitFailed).Times(1)

	err := mgr.Start(context.Background())
	require.ErrorIs(t, err, errInitFailed)
	// wg.Wait inside Start already joined first's runWatcher; a second Stop must
	// also be safe (idempotent from the caller's perspective).
	first.EXPECT().Stop(gomock.Any()).Return(nil).Times(1)
	second.EXPECT().Stop(gomock.Any()).Return(nil).Times(1)
	require.NoError(t, mgr.Stop(context.Background()))
}

// Stop must attempt every watcher and wait for the goroutines even when one
// watcher's Stop fails; the first error is reported.
func TestStopContinuesPastFailedWatcher(t *testing.T) {
	ctl := gomock.NewController(t)
	defer ctl.Finish()
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	failing := mock.NewMockIWatcher(ctl)
	healthy := mock.NewMockIWatcher(ctl)

	mgr := NewWatcherManager(kcfg.DefaultFilterMapMaxEntries, 0)
	mgr.Watchers = []IWatcher{failing, healthy}

	failing.EXPECT().Stop(gomock.Any()).Return(errInitFailed).Times(1)
	// The second watcher must still be stopped.
	healthy.EXPECT().Stop(gomock.Any()).Return(nil).Times(1)

	err := mgr.Stop(context.Background())
	require.ErrorIs(t, err, errInitFailed)
}

// A watcher must reconcile once at startup, not wait for the first tick.
func TestRunWatcherInitialReconcile(t *testing.T) {
	ctl := gomock.NewController(t)
	defer ctl.Finish()
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	w := mock.NewMockIWatcher(ctl)
	mgr := NewWatcherManager(kcfg.DefaultFilterMapMaxEntries, time.Hour) // no tick fires during the test
	mgr.Watchers = []IWatcher{w}

	refreshed := make(chan struct{}, 1)
	w.EXPECT().Init(gomock.Any()).Return(nil).Times(1)
	w.EXPECT().Refresh(gomock.Any()).DoAndReturn(func(context.Context) error {
		select {
		case refreshed <- struct{}{}:
		default:
		}
		return nil
	}).Times(1)
	w.EXPECT().Stop(gomock.Any()).Return(nil).Times(1)

	require.NoError(t, mgr.Start(context.Background()))
	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a reconcile at startup, before the first tick")
	}
	require.NoError(t, mgr.Stop(context.Background()))
}

// A failing Refresh must not kill the watcher goroutine; the next tick retries.
func TestRunWatcherSurvivesRefreshErrors(t *testing.T) {
	ctl := gomock.NewController(t)
	defer ctl.Finish()
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	w := mock.NewMockIWatcher(ctl)
	mgr := NewWatcherManager(kcfg.DefaultFilterMapMaxEntries, 10*time.Millisecond)
	mgr.Watchers = []IWatcher{w}

	var calls atomic.Int32
	w.EXPECT().Init(gomock.Any()).Return(nil).Times(1)
	w.EXPECT().Refresh(gomock.Any()).DoAndReturn(func(context.Context) error {
		calls.Add(1)
		return errInitFailed
	}).AnyTimes()
	w.EXPECT().Stop(gomock.Any()).Return(nil).Times(1)

	require.NoError(t, mgr.Start(context.Background()))
	require.Eventually(t, func() bool { return calls.Load() >= 3 }, 2*time.Second, 5*time.Millisecond,
		"refresh errors must be logged and retried, not terminate the watcher")
	require.NoError(t, mgr.Stop(context.Background()))
}

func TestWatcherStopWithoutStart(t *testing.T) {
	ctl := gomock.NewController(t)
	defer ctl.Finish()
	log.SetupZapLogger(log.GetDefaultLogOpts())

	mgr := NewWatcherManager(kcfg.DefaultFilterMapMaxEntries, 0)

	err := mgr.Stop(context.Background())
	require.Nil(t, err, "Expected no error when stopping watcher manager without starting it")
}
