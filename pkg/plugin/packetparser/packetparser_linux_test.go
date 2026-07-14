// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package packetparser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	tc "github.com/florianl/go-tc"
	nl "github.com/mdlayher/netlink"
	kcfg "github.com/microsoft/retina/pkg/config"
	"github.com/microsoft/retina/pkg/enricher"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/metrics"
	"github.com/microsoft/retina/pkg/plugin/packetparser/mocks"
	"github.com/microsoft/retina/pkg/utils"
	"github.com/microsoft/retina/pkg/watchers/endpoint"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go.uber.org/mock/gomock"
)

// mockPerfReader is a gomock-based mock for the perfReader interface.
// Defined here (not in mocks/) because perfReader uses the unexported perfRecord type.
type mockPerfReader struct {
	ctrl     *gomock.Controller
	recorder *mockPerfReaderRecorder
}

type mockPerfReaderRecorder struct {
	mock *mockPerfReader
}

func newMockPerfReader(ctrl *gomock.Controller) *mockPerfReader {
	m := &mockPerfReader{ctrl: ctrl}
	m.recorder = &mockPerfReaderRecorder{m}
	return m
}

func (m *mockPerfReader) EXPECT() *mockPerfReaderRecorder { return m.recorder }

func (m *mockPerfReader) Read() (perfRecord, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Read")
	rec, _ := ret[0].(perfRecord)
	err, _ := ret[1].(error)
	return rec, err
}

func (mr *mockPerfReaderRecorder) Read() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Read", reflect.TypeOf((*mockPerfReader)(nil).Read))
}

func (m *mockPerfReader) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	err, _ := ret[0].(error)
	return err
}

func (mr *mockPerfReaderRecorder) Close() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*mockPerfReader)(nil).Close))
}

var errTestRead = errors.New("error")

var errLinkDefunct = errors.New("link is defunct")

var (
	cfgPodLevelEnabled = &kcfg.Config{
		EnablePodLevel:           true,
		BypassLookupIPOfInterest: true,
		EnableConntrackMetrics:   false,
	}
	cfgPodLevelDisabled = &kcfg.Config{
		EnablePodLevel: false,
	}
	cfgDataAggregationLevelLow = &kcfg.Config{
		EnablePodLevel:       true,
		DataAggregationLevel: kcfg.Low,
	}
	cfgDataAggregationLevelHigh = &kcfg.Config{
		EnablePodLevel:       true,
		DataAggregationLevel: kcfg.High,
	}
	cfgConntrackMetricsEnabled = &kcfg.Config{
		EnablePodLevel:           true,
		DataAggregationLevel:     kcfg.High,
		BypassLookupIPOfInterest: true,
		EnableConntrackMetrics:   true,
	}
	cfgRingBufferEnabled = &kcfg.Config{
		EnablePodLevel:             true,
		PacketParserRingBuffer:     kcfg.PacketParserRingBufferEnabled,
		PacketParserRingBufferSize: 4096,
	}
)

func TestCleanAll(t *testing.T) {
	opts := log.GetDefaultLogOpts()
	log.SetupZapLogger(opts)

	p := &packetParser{
		cfg: cfgPodLevelEnabled,
		l:   log.Logger().Named("test"),
	}
	assert.Nil(t, p.cleanAll())

	p.attachmentMap = &sync.Map{}
	assert.Nil(t, p.cleanAll())

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mrtnl := mocks.NewMocknltc(ctrl)
	mrtnl.EXPECT().Close().Return(nil).AnyTimes()
	mrtnl.EXPECT().SetOption(nl.ExtendedAcknowledge, true).Return(nil).AnyTimes()

	mq := mocks.NewMockqdisc(ctrl)
	mq.EXPECT().Delete(gomock.Any()).Return(nil).AnyTimes()

	getQdisc = func(nltc) qdisc {
		return mq
	}

	p.attachmentMap.Store(attachmentKey{1}, &attachmentValue{tc: mrtnl, qdisc: &tc.Object{}})
	p.attachmentMap.Store(attachmentKey{2}, &attachmentValue{tc: mrtnl, qdisc: &tc.Object{}})

	assert.Nil(t, p.cleanAll())

	keyCount := 0
	p.attachmentMap.Range(func(_ interface{}, _ interface{}) bool {
		keyCount++
		return true
	})
	assert.Equal(t, 0, keyCount)
}

func TestClean(t *testing.T) {
	opts := log.GetDefaultLogOpts()
	log.SetupZapLogger(opts)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Test nil.
	p := &packetParser{
		cfg: cfgPodLevelEnabled,
		l:   log.Logger().Named("test"),
	}
	p.clean(nil, nil) // Should not panic.

	// Test tcnl calls.
	mq := mocks.NewMockqdisc(ctrl)
	mq.EXPECT().Delete(gomock.Any()).Return(nil).Times(1)

	mrtnl := mocks.NewMocknltc(ctrl)
	mrtnl.EXPECT().Qdisc().Return(nil).Times(1)
	mrtnl.EXPECT().Close().Return(nil).AnyTimes()
	mrtnl.EXPECT().SetOption(nl.ExtendedAcknowledge, true).Return(nil).AnyTimes()

	getQdisc = func(tcnl nltc) qdisc {
		// Add this verify tcnl.Qdisc() is called twice
		tcnl.Qdisc()
		return mq
	}

	p.clean(mrtnl, &tc.Object{})
}

func TestCleanWithErrors(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	p := &packetParser{
		cfg: cfgPodLevelEnabled,
		l:   log.Logger().Named("test"),
	}

	// Test we try delete qdiscs even if we get errors.
	mq := mocks.NewMockqdisc(ctrl)
	mq.EXPECT().Delete(gomock.Any()).Return(errors.New("error")).Times(1) //nolint:err113 // ignore

	mrtnl := mocks.NewMocknltc(ctrl)
	mrtnl.EXPECT().Close().Return(nil).AnyTimes()
	mrtnl.EXPECT().SetOption(nl.ExtendedAcknowledge, true).Return(nil).AnyTimes()
	mrtnl.EXPECT().Qdisc().Return(nil).AnyTimes()

	getQdisc = func(nltc) qdisc {
		return mq
	}

	p.clean(mrtnl, &tc.Object{})
}

func TestEndpointWatcherCallbackFn_EndpointDeleted(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Initialize packetParser with both maps.
	p := &packetParser{
		cfg:              cfgPodLevelEnabled,
		l:                log.Logger().Named("test"),
		interfaceLockMap: &sync.Map{},
		attachmentMap:    &sync.Map{},
	}

	// Create test interface attributes.
	linkAttr := netlink.LinkAttrs{
		Name:         "test",
		HardwareAddr: []byte("test"),
		NetNsID:      1,
	}
	key := ifaceToKey(linkAttr)

	// The delete path must close only the stale socket — never delete the qdisc:
	// a delete event means the interface is gone or its index was reused, so a
	// clsact at this ifindex may belong to the new occupant. A strict qdisc mock
	// with no expectations turns any Delete into a test failure.
	mq := mocks.NewMockqdisc(ctrl)
	getQdisc = func(nltc) qdisc { return mq }
	oldRtnl := mocks.NewMocknltc(ctrl)
	oldRtnl.EXPECT().Close().Return(nil).Times(1)

	// Pre-populate both maps to simulate existing interface
	p.interfaceLockMap.Store(key, &sync.Mutex{})
	p.attachmentMap.Store(key, &attachmentValue{tc: oldRtnl, qdisc: &tc.Object{}})

	// Create EndpointDeleted event.
	e := &endpoint.EndpointEvent{
		Type: endpoint.EndpointDeleted,
		Obj:  linkAttr,
	}

	// Execute the callback.
	p.endpointWatcherCallbackFn(e)

	// Verify both maps are cleaned up.
	_, attachmentMapExists := p.attachmentMap.Load(key)
	_, lockMapExists := p.interfaceLockMap.Load(key)

	assert.False(t, attachmentMapExists, "attachmentMap entry should be deleted")
	assert.False(t, lockMapExists, "interfaceLockMap entry should be deleted")
}

func TestCreateQdiscAndAttach(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mfilter := mocks.NewMockfilter(ctrl)
	mfilter.EXPECT().Add(gomock.Any()).Return(nil).AnyTimes()

	mq := mocks.NewMockqdisc(ctrl)
	mq.EXPECT().Add(gomock.Any()).Return(nil).AnyTimes()

	mrtnl := mocks.NewMocknltc(ctrl)
	mrtnl.EXPECT().Qdisc().Return(nil).AnyTimes()
	mrtnl.EXPECT().SetOption(nl.ExtendedAcknowledge, true).Return(nil).AnyTimes()

	getQdisc = func(nltc) qdisc {
		return mq
	}

	getFilter = func(nltc) filter {
		return mfilter
	}

	tcOpen = func(*tc.Config) (nltc, error) {
		return mrtnl, nil
	}

	getFD = func(_ *ebpf.Program) int {
		return 1
	}

	pObj := &packetparserObjects{} //nolint:typecheck // generated bpf2go type
	pObj.EndpointIngressFilter = &ebpf.Program{}
	pObj.EndpointEgressFilter = &ebpf.Program{}

	p := &packetParser{
		cfg:              cfgPodLevelEnabled,
		l:                log.Logger().Named("test"),
		objs:             pObj,
		interfaceLockMap: &sync.Map{},
		endpointIngressInfo: &ebpf.ProgramInfo{
			Name: "ingress",
		},
		endpointEgressInfo: &ebpf.ProgramInfo{
			Name: "egress",
		},
		hostIngressInfo: &ebpf.ProgramInfo{
			Name: "ingress",
		},
		hostEgressInfo: &ebpf.ProgramInfo{
			Name: "egress",
		},
		attachmentMap: &sync.Map{},
	}
	linkAttr := netlink.LinkAttrs{
		Name:         "test",
		HardwareAddr: []byte("test"),
		NetNsID:      1,
		Index:        1,
	}
	// Test veth.
	p.createQdiscAndAttach(linkAttr, Veth)

	key := ifaceToKey(linkAttr)
	_, ok := p.attachmentMap.Load(key)
	assert.True(t, ok)

	pObj.HostIngressFilter = &ebpf.Program{}
	pObj.HostEgressFilter = &ebpf.Program{}
	linkAttr2 := netlink.LinkAttrs{
		Name:         "test2",
		HardwareAddr: []byte("test2"),
		NetNsID:      2,
		Index:        2,
	}
	// Test Device.
	p.createQdiscAndAttach(linkAttr2, Device)

	key = ifaceToKey(linkAttr2)
	_, ok = p.attachmentMap.Load(key)
	assert.True(t, ok)
}

// fakeTCXLink fakes a stored TCX link for the liveness check.
type fakeTCXLink struct {
	info   *link.Info
	err    error
	closed bool
}

func (f *fakeTCXLink) Info() (*link.Info, error) { return f.info, f.err }
func (f *fakeTCXLink) Close() error              { f.closed = true; return nil }

func TestTCXInfoAlive(t *testing.T) {
	assert.True(t, tcxInfoAlive(nil), "indeterminate metadata must not churn attachments")
	assert.True(t, tcxInfoAlive(&link.TCXInfo{Ifindex: 42}), "non-zero ifindex is a live attachment")
	assert.False(t, tcxInfoAlive(&link.TCXInfo{Ifindex: 0}), "ifindex 0 marks a defunct link (interface deleted)")
}

// A live recorded attachment must short-circuit the re-assert: no re-attach, the
// stored value untouched.
func TestCreateQdiscAndAttachSkipsLiveAttachment(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	linkAttr := netlink.LinkAttrs{Name: "live", Index: 100}
	seeded := &attachmentValue{
		attachmentType: attachmentTypeTCX,
		tcxIngressLink: &fakeTCXLink{info: &link.Info{}}, // no TCX metadata -> treated alive
		tcxEgressLink:  &fakeTCXLink{info: &link.Info{}},
	}

	p := &packetParser{
		l:             log.Logger().Named("test"),
		attachmentMap: &sync.Map{},
	}
	p.attachmentMap.Store(ifaceToKey(linkAttr), seeded)

	p.createQdiscAndAttach(linkAttr, Veth)

	got, ok := p.attachmentMap.Load(ifaceToKey(linkAttr))
	assert.True(t, ok)
	assert.Same(t, seeded, got.(*attachmentValue), "live attachment must be left untouched")
}

// A stale record (links dead in the kernel: interface deleted with its index
// reused, or programs detached externally) must be dropped and the interface
// re-attached, so the level-triggered re-assert self-heals it.
func TestCreateQdiscAndAttachReplacesStaleAttachment(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mfilter := mocks.NewMockfilter(ctrl)
	mfilter.EXPECT().Add(gomock.Any()).Return(nil).AnyTimes()
	mq := mocks.NewMockqdisc(ctrl)
	mq.EXPECT().Add(gomock.Any()).Return(nil).AnyTimes()
	mrtnl := mocks.NewMocknltc(ctrl)
	mrtnl.EXPECT().Qdisc().Return(nil).AnyTimes()
	mrtnl.EXPECT().SetOption(nl.ExtendedAcknowledge, true).Return(nil).AnyTimes()
	getQdisc = func(nltc) qdisc { return mq }
	getFilter = func(nltc) filter { return mfilter }
	tcOpen = func(*tc.Config) (nltc, error) { return mrtnl, nil }
	getFD = func(_ *ebpf.Program) int { return 1 }

	pObj := &packetparserObjects{} //nolint:typecheck // generated bpf2go type
	pObj.EndpointIngressFilter = &ebpf.Program{}
	pObj.EndpointEgressFilter = &ebpf.Program{}

	linkAttr := netlink.LinkAttrs{Name: "stale", Index: 200}
	deadIngress := &fakeTCXLink{err: errLinkDefunct}
	deadEgress := &fakeTCXLink{err: errLinkDefunct}
	seeded := &attachmentValue{
		attachmentType: attachmentTypeTCX,
		tcxIngressLink: deadIngress,
		tcxEgressLink:  deadEgress,
	}

	p := &packetParser{
		cfg:                 cfgPodLevelEnabled,
		l:                   log.Logger().Named("test"),
		objs:                pObj,
		interfaceLockMap:    &sync.Map{},
		endpointIngressInfo: &ebpf.ProgramInfo{Name: "ingress"},
		endpointEgressInfo:  &ebpf.ProgramInfo{Name: "egress"},
		attachmentMap:       &sync.Map{},
	}
	p.attachmentMap.Store(ifaceToKey(linkAttr), seeded)

	p.createQdiscAndAttach(linkAttr, Veth)

	got, ok := p.attachmentMap.Load(ifaceToKey(linkAttr))
	assert.True(t, ok, "interface must be re-attached after the stale record is dropped")
	assert.NotSame(t, seeded, got.(*attachmentValue), "stale record must be replaced by a fresh attachment")
	assert.True(t, deadIngress.closed && deadEgress.closed, "stale link handles must be closed")
}

// A live legacy-TC attachment (a bpf filter still present on the interface's
// ingress hook) must be left untouched on re-assert — no re-attach, no churn.
func TestCreateQdiscAndAttachSkipsLiveTCAttachment(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const idx = 300
	mfilter := mocks.NewMockfilter(ctrl)
	mfilter.EXPECT().Get(gomock.Any()).Return([]tc.Object{
		{Attribute: tc.Attribute{Kind: "bpf"}},
	}, nil).Times(1)
	getFilter = func(nltc) filter { return mfilter }

	linkAttr := netlink.LinkAttrs{Name: "tc-live", Index: idx}
	seeded := &attachmentValue{
		attachmentType: attachmentTypeTC,
		tc:             mocks.NewMocknltc(ctrl),
		qdisc:          &tc.Object{Msg: tc.Msg{Ifindex: idx}},
	}

	p := &packetParser{
		l:             log.Logger().Named("test"),
		attachmentMap: &sync.Map{},
	}
	p.attachmentMap.Store(ifaceToKey(linkAttr), seeded)

	p.createQdiscAndAttach(linkAttr, Veth)

	got, ok := p.attachmentMap.Load(ifaceToKey(linkAttr))
	assert.True(t, ok)
	assert.Same(t, seeded, got.(*attachmentValue), "live TC attachment must be left untouched")
}

// A dead legacy-TC attachment (no bpf filter — interface deleted, possibly
// index reused — or an unusable probe socket) must be re-attached and the stale
// rtnetlink socket released — WITHOUT deleting the clsact qdisc, which on index
// reuse may belong to the interface's new occupant (no mq.Delete expectation:
// any Delete call fails the test).
func TestCreateQdiscAndAttachReplacesDeadTCAttachment(t *testing.T) {
	cases := []struct {
		name  string
		probe func(msg *tc.Msg) ([]tc.Object, error)
	}{
		{"no filters", func(*tc.Msg) ([]tc.Object, error) { return nil, nil }},
		{"probe error", func(*tc.Msg) ([]tc.Object, error) { return nil, errTestRead }},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			const idx = 302
			mq := mocks.NewMockqdisc(ctrl)
			// Add is the re-attach. No Delete expectation: the dead path must not
			// delete a qdisc it cannot prove is ours.
			mq.EXPECT().Add(gomock.Any()).Return(nil).Times(1)
			getQdisc = func(nltc) qdisc { return mq }

			mfilter := mocks.NewMockfilter(ctrl)
			mfilter.EXPECT().Get(gomock.Any()).DoAndReturn(tt.probe).Times(1)
			mfilter.EXPECT().Add(gomock.Any()).Return(nil).Times(2)
			getFilter = func(nltc) filter { return mfilter }
			getFD = func(_ *ebpf.Program) int { return 1 }

			newRtnl := mocks.NewMocknltc(ctrl)
			newRtnl.EXPECT().SetOption(nl.ExtendedAcknowledge, true).Return(nil).Times(1)
			tcOpen = func(*tc.Config) (nltc, error) { return newRtnl, nil }

			// The stale attachment's socket must be closed when we drop it.
			oldRtnl := mocks.NewMocknltc(ctrl)
			oldRtnl.EXPECT().Close().Return(nil).Times(1)

			pObj := &packetparserObjects{} //nolint:typecheck // generated bpf2go type
			pObj.EndpointIngressFilter = &ebpf.Program{}
			pObj.EndpointEgressFilter = &ebpf.Program{}

			linkAttr := netlink.LinkAttrs{Name: "tc-dead", Index: idx}
			seeded := &attachmentValue{
				attachmentType: attachmentTypeTC,
				tc:             oldRtnl,
				qdisc:          &tc.Object{Msg: tc.Msg{Ifindex: idx}},
			}

			p := &packetParser{
				cfg:                 cfgPodLevelEnabled,
				l:                   log.Logger().Named("test"),
				objs:                pObj,
				interfaceLockMap:    &sync.Map{},
				endpointIngressInfo: &ebpf.ProgramInfo{Name: "ingress"},
				endpointEgressInfo:  &ebpf.ProgramInfo{Name: "egress"},
				attachmentMap:       &sync.Map{},
			}
			p.attachmentMap.Store(ifaceToKey(linkAttr), seeded)

			p.createQdiscAndAttach(linkAttr, Veth)

			got, ok := p.attachmentMap.Load(ifaceToKey(linkAttr))
			assert.True(t, ok, "interface must be re-attached after the dead record is dropped")
			assert.NotSame(t, seeded, got.(*attachmentValue), "dead record must be replaced by a fresh attachment")
		})
	}
}

// A non-fatal SetOption failure must not poison the cleanup path: the attach
// still succeeds and must NOT be torn down afterwards (no qdisc Delete, no
// socket Close — either call fails the test via missing expectations).
func TestAttachViaTCSurvivesSetOptionFailure(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mq := mocks.NewMockqdisc(ctrl)
	mq.EXPECT().Add(gomock.Any()).Return(nil).Times(1)
	getQdisc = func(nltc) qdisc { return mq }

	mfilter := mocks.NewMockfilter(ctrl)
	mfilter.EXPECT().Add(gomock.Any()).Return(nil).Times(2)
	getFilter = func(nltc) filter { return mfilter }
	getFD = func(_ *ebpf.Program) int { return 1 }

	mrtnl := mocks.NewMocknltc(ctrl)
	mrtnl.EXPECT().SetOption(nl.ExtendedAcknowledge, true).Return(errTestRead).Times(1)
	tcOpen = func(*tc.Config) (nltc, error) { return mrtnl, nil }

	pObj := &packetparserObjects{} //nolint:typecheck // generated bpf2go type
	pObj.EndpointIngressFilter = &ebpf.Program{}
	pObj.EndpointEgressFilter = &ebpf.Program{}

	p := &packetParser{
		cfg:                 cfgPodLevelEnabled,
		l:                   log.Logger().Named("test"),
		objs:                pObj,
		endpointIngressInfo: &ebpf.ProgramInfo{Name: "ingress"},
		endpointEgressInfo:  &ebpf.ProgramInfo{Name: "egress"},
		attachmentMap:       &sync.Map{},
	}

	linkAttr := netlink.LinkAttrs{Name: "tc-optfail", Index: 310}
	p.attachViaTC(linkAttr, Veth)

	_, ok := p.attachmentMap.Load(ifaceToKey(linkAttr))
	assert.True(t, ok, "attach must survive a non-fatal SetOption failure")
}

// A failed attach must release the rtnetlink socket — the failure returns
// shadow err, so a defer keyed on err instead of an explicit flag never runs,
// leaking one fd per failed attach, once per refresh under the re-assert. The
// clsact qdisc is undone only if we created it: a pre-existing one may belong
// to another agent (no Delete expectation in that case — a Delete call fails
// the test).
func TestAttachViaTCReleasesSocketOnFailedAttach(t *testing.T) {
	cases := []struct {
		name        string
		qdiscAddErr error
		wantDelete  bool
	}{
		{"qdisc created by us", nil, true},
		{"qdisc pre-existing (possibly another agent's)", os.ErrExist, false},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mq := mocks.NewMockqdisc(ctrl)
			mq.EXPECT().Add(gomock.Any()).Return(tt.qdiscAddErr).Times(1)
			if tt.wantDelete {
				mq.EXPECT().Delete(gomock.Any()).Return(nil).Times(1) // undo our own qdisc
			}
			getQdisc = func(nltc) qdisc { return mq }

			mfilter := mocks.NewMockfilter(ctrl)
			mfilter.EXPECT().Add(gomock.Any()).Return(errTestRead).Times(1) // ingress add fails
			getFilter = func(nltc) filter { return mfilter }
			getFD = func(_ *ebpf.Program) int { return 1 }

			mrtnl := mocks.NewMocknltc(ctrl)
			mrtnl.EXPECT().SetOption(nl.ExtendedAcknowledge, true).Return(nil).Times(1)
			mrtnl.EXPECT().Close().Return(nil).Times(1) // the fd must be released
			tcOpen = func(*tc.Config) (nltc, error) { return mrtnl, nil }

			pObj := &packetparserObjects{} //nolint:typecheck // generated bpf2go type
			pObj.EndpointIngressFilter = &ebpf.Program{}
			pObj.EndpointEgressFilter = &ebpf.Program{}

			p := &packetParser{
				cfg:                 cfgPodLevelEnabled,
				l:                   log.Logger().Named("test"),
				objs:                pObj,
				endpointIngressInfo: &ebpf.ProgramInfo{Name: "ingress"},
				endpointEgressInfo:  &ebpf.ProgramInfo{Name: "egress"},
				attachmentMap:       &sync.Map{},
			}

			linkAttr := netlink.LinkAttrs{Name: "tc-addfail", Index: 311}
			p.attachViaTC(linkAttr, Veth)

			_, ok := p.attachmentMap.Load(ifaceToKey(linkAttr))
			assert.False(t, ok, "failed attach must not be recorded")
		})
	}
}

// Stop must wait for a callback already past the stopping check: the cbMu
// barrier holds teardown until the in-flight attach finishes, so its Store is
// visible to cleanAll and the attachment is released rather than leaked.
func TestStopWaitsForInFlightCallback(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	entered := make(chan struct{})
	release := make(chan struct{})
	mq := mocks.NewMockqdisc(ctrl)
	mq.EXPECT().Add(gomock.Any()).DoAndReturn(func(*tc.Object) error {
		close(entered)
		<-release
		return nil
	}).Times(1)
	mq.EXPECT().Delete(gomock.Any()).Return(nil).Times(1) // cleanAll releases the attachment
	getQdisc = func(nltc) qdisc { return mq }

	mfilter := mocks.NewMockfilter(ctrl)
	mfilter.EXPECT().Add(gomock.Any()).Return(nil).Times(2)
	getFilter = func(nltc) filter { return mfilter }
	getFD = func(_ *ebpf.Program) int { return 1 }

	mrtnl := mocks.NewMocknltc(ctrl)
	mrtnl.EXPECT().SetOption(nl.ExtendedAcknowledge, true).Return(nil).Times(1)
	mrtnl.EXPECT().Close().Return(nil).Times(1) // via cleanAll
	tcOpen = func(*tc.Config) (nltc, error) { return mrtnl, nil }

	pObj := &packetparserObjects{} //nolint:typecheck // generated bpf2go type
	pObj.EndpointIngressFilter = &ebpf.Program{}
	pObj.EndpointEgressFilter = &ebpf.Program{}

	p := &packetParser{
		cfg:                 cfgPodLevelEnabled,
		l:                   log.Logger().Named("test"),
		objs:                pObj,
		interfaceLockMap:    &sync.Map{},
		endpointIngressInfo: &ebpf.ProgramInfo{Name: "ingress"},
		endpointEgressInfo:  &ebpf.ProgramInfo{Name: "egress"},
		attachmentMap:       &sync.Map{},
	}

	// Deliver a create on a separate goroutine, as the pubsub drain goroutine would.
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		p.endpointWatcherCallbackFn(endpoint.NewEndpointEvent(endpoint.EndpointCreated,
			netlink.LinkAttrs{Name: "in-flight", Index: 330}))
	}()
	<-entered // callback is now mid-attach, inside cbMu
	// The callback captured the program pointers before blocking; drop objs so
	// Stop doesn't Close zero-value bpf2go objects (ordered by the entered chan).
	p.objs = nil

	stopDone := make(chan struct{})
	go func() {
		defer close(stopDone)
		_ = p.Stop()
	}()

	select {
	case <-stopDone:
		t.Fatal("Stop returned while a callback was still in flight")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	<-callbackDone
	select {
	case <-stopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not complete after the in-flight callback finished")
	}

	// cleanAll must have observed the Store (mock expectations above) and reset the map.
	count := 0
	p.attachmentMap.Range(func(_, _ interface{}) bool { count++; return true })
	assert.Zero(t, count, "the in-flight attachment must be cleaned by Stop, not leaked")
}

// After Stop, an endpoint delivery still in flight (pubsub does not join it)
// must be a no-op. The parser's maps are nil here, so a broken guard panics.
func TestStopQuiescesEndpointCallback(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	p := &packetParser{l: log.Logger().Named("test")}
	require.NoError(t, p.Stop())

	ev := endpoint.NewEndpointEvent(endpoint.EndpointCreated, netlink.LinkAttrs{Name: "late", Index: 320})
	assert.NotPanics(t, func() { p.endpointWatcherCallbackFn(ev) },
		"a delivery after Stop must be dropped by the stopping guard")
}

// The delete callback must detach a TCX attachment via cleanTCX (closing both
// links) and drop the map entry — the TCX counterpart of the TC clean path.
func TestEndpointWatcherCallbackFn_EndpointDeletedTCX(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())

	p := &packetParser{
		cfg:              cfgPodLevelEnabled,
		l:                log.Logger().Named("test"),
		interfaceLockMap: &sync.Map{},
		attachmentMap:    &sync.Map{},
	}
	linkAttr := netlink.LinkAttrs{Name: "tcx-del", Index: 301}
	key := ifaceToKey(linkAttr)
	ingress := &fakeTCXLink{info: &link.Info{}}
	egress := &fakeTCXLink{info: &link.Info{}}
	p.interfaceLockMap.Store(key, &sync.Mutex{})
	p.attachmentMap.Store(key, &attachmentValue{
		attachmentType: attachmentTypeTCX,
		tcxIngressLink: ingress,
		tcxEgressLink:  egress,
	})

	p.endpointWatcherCallbackFn(&endpoint.EndpointEvent{Type: endpoint.EndpointDeleted, Obj: linkAttr})

	_, ok := p.attachmentMap.Load(key)
	assert.False(t, ok, "attachmentMap entry should be deleted")
	assert.True(t, ingress.closed && egress.closed, "TCX links should be closed on delete")
	_, lockOK := p.interfaceLockMap.Load(key)
	assert.False(t, lockOK, "interfaceLockMap entry should be deleted")
}

func TestReadData_Error(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mperf := newMockPerfReader(ctrl)
	mperf.EXPECT().Read().Return(perfRecord{}, errTestRead).AnyTimes()

	menricher := enricher.NewMockEnricherInterface(ctrl) //nolint:typecheck
	menricher.EXPECT().Write(gomock.Any()).Times(0)

	p := &packetParser{
		cfg:    cfgPodLevelEnabled,
		l:      log.Logger().Named("test"),
		reader: mperf,
	}
	p.readData()

	// Lost samples.
	mperf.EXPECT().Read().Return(perfRecord{
		LostSamples: 1,
	}, nil).AnyTimes()
	p.readData()
}

func TestReadData_RingBufClosed(t *testing.T) {
	log.SetupZapLogger(log.GetDefaultLogOpts()) //nolint:errcheck // ignore
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mperf := newMockPerfReader(ctrl)
	mperf.EXPECT().Read().Return(perfRecord{}, ringbuf.ErrClosed).AnyTimes()

	menricher := enricher.NewMockEnricherInterface(ctrl) //nolint:typecheck
	menricher.EXPECT().Write(gomock.Any()).Times(0)

	p := &packetParser{
		cfg:    cfgRingBufferEnabled,
		l:      log.Logger().Named("test"),
		reader: mperf,
	}
	p.readData()
}

func TestReadDataPodLevelEnabled(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	bpfEvent := &packetparserPacket{ //nolint:typecheck
		SrcIp:            uint32(83886272), // 192.0.0.5
		DstIp:            uint32(16777226), // 10.0.0.1
		Proto:            uint8(6),         // TCP
		ObservationPoint: uint8(1),         // TO Endpoint
		SrcPort:          uint16(80),
		DstPort:          uint16(443),
	}
	bytes, _ := json.Marshal(bpfEvent)
	record := perfRecord{
		LostSamples: 0,
		RawSample:   bytes,
	}

	mperf := newMockPerfReader(ctrl)
	mperf.EXPECT().Read().Return(record, nil).MinTimes(1)

	menricher := enricher.NewMockEnricherInterface(ctrl) //nolint:typecheck
	menricher.EXPECT().Write(gomock.Any()).MinTimes(1)

	p := &packetParser{
		cfg:            cfgPodLevelEnabled,
		l:              log.Logger().Named("test"),
		reader:         mperf,
		enricher:       menricher,
		recordsChannel: make(chan perfRecord, buffer),
	}

	mICounterVec := metrics.NewMockCounterVec(ctrl)
	mICounterVec.EXPECT().WithLabelValues(gomock.Any()).Return(prometheus.NewCounter(prometheus.CounterOpts{})).AnyTimes()

	metrics.LostEventsCounter = mICounterVec

	mParsedPacketsCounter := metrics.NewMockCounterVec(ctrl)
	mParsedPacketsCounter.EXPECT().WithLabelValues(gomock.Any()).
		Return(prometheus.NewCounter(prometheus.CounterOpts{})).AnyTimes()
	metrics.ParsedPacketsCounter = mParsedPacketsCounter

	exCh := make(chan *v1.Event, 10)
	p.SetupChannel(exCh)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	p.run(ctx)

	// Test we get the event.
	select {
	case <-exCh:
	default:
		t.Fatal("Expected event in external channel, got none")
	}
}

func TestStartPodLevelDisabled(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := &packetParser{
		cfg: cfgPodLevelDisabled,
		l:   log.Logger().Named("test"),
	}
	ctx := context.Background()
	err := p.Start(ctx)
	require.NoError(t, err)
}

func TestStartWithDataAggregationLevelLow(t *testing.T) {
	log.SetupZapLogger(log.GetDefaultLogOpts()) // nolint:errcheck // ignore
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockFilter := mocks.NewMockfilter(ctrl)
	mQdisc := mocks.NewMockqdisc(ctrl)

	// We are expecting one call to Add since we are invoking createQdiscAndAttach for eth0
	mockFilter.EXPECT().Add(gomock.Any()).Return(nil).Times(2)
	mQdisc.EXPECT().Add(gomock.Any()).Return(nil).Times(1)

	mockRtnl := mocks.NewMocknltc(ctrl)
	mockRtnl.EXPECT().SetOption(nl.ExtendedAcknowledge, true).Return(nil).Times(1)

	bpfEvent := &packetparserPacket{
		SrcIp:            uint32(83886272), // 192.0.0.5
		DstIp:            uint32(16777226), // 10.0.0.1
		Proto:            uint8(6),         // TCP
		ObservationPoint: uint8(1),         // TO Endpoint
		SrcPort:          uint16(80),
		DstPort:          uint16(443),
	}
	bytes, err := json.Marshal(bpfEvent) // nolint:musttag // ignore
	require.NoError(t, err)
	record := perfRecord{
		LostSamples: 0,
		RawSample:   bytes,
	}

	mockReader := newMockPerfReader(ctrl)
	mockReader.EXPECT().Read().Return(record, nil).MinTimes(1)

	getQdisc = func(_ nltc) qdisc {
		return mQdisc
	}

	getFilter = func(_ nltc) filter {
		return mockFilter
	}

	tcOpen = func(_ *tc.Config) (nltc, error) {
		return mockRtnl, nil
	}

	getFD = func(_ *ebpf.Program) int {
		return 1
	}

	pObj := &packetparserObjects{}
	pObj.EndpointIngressFilter = &ebpf.Program{}
	pObj.EndpointEgressFilter = &ebpf.Program{}

	p := &packetParser{
		cfg:              cfgDataAggregationLevelLow,
		l:                log.Logger().Named("test"),
		objs:             pObj,
		reader:           mockReader,
		recordsChannel:   make(chan perfRecord, buffer),
		interfaceLockMap: &sync.Map{},
		endpointIngressInfo: &ebpf.ProgramInfo{
			Name: "ingress",
		},
		endpointEgressInfo: &ebpf.ProgramInfo{
			Name: "egress",
		},
		hostIngressInfo: &ebpf.ProgramInfo{
			Name: "ingress",
		},
		hostEgressInfo: &ebpf.ProgramInfo{
			Name: "egress",
		},
		attachmentMap: &sync.Map{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err = p.Start(ctx)
	require.NoError(t, err)
}

func TestStartWithDataAggregationLevelHigh(t *testing.T) {
	log.SetupZapLogger(log.GetDefaultLogOpts()) // nolint:errcheck // ignore
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockFilter := mocks.NewMockfilter(ctrl)
	mQdisc := mocks.NewMockqdisc(ctrl)

	// We are not expecting any calls to Add since we are not invoking createQdiscAndAttach for eth0
	mockFilter.EXPECT().Add(gomock.Any()).Return(nil).Times(0)
	mQdisc.EXPECT().Add(gomock.Any()).Return(nil).Times(0)

	mockRtnl := mocks.NewMocknltc(ctrl)

	bpfEvent := &packetparserPacket{
		SrcIp:            uint32(83886272), // 192.0.0.5
		DstIp:            uint32(16777226), // 10.0.0.1
		Proto:            uint8(6),         // TCP
		ObservationPoint: uint8(1),         // TO Endpoint
		SrcPort:          uint16(80),
		DstPort:          uint16(443),
	}
	bytes, err := json.Marshal(bpfEvent) // nolint:musttag // ignore
	require.NoError(t, err)
	record := perfRecord{
		LostSamples: 0,
		RawSample:   bytes,
	}

	mockReader := newMockPerfReader(ctrl)
	mockReader.EXPECT().Read().Return(record, nil).MinTimes(1)

	getQdisc = func(_ nltc) qdisc {
		return mQdisc
	}

	getFilter = func(_ nltc) filter {
		return mockFilter
	}

	tcOpen = func(_ *tc.Config) (nltc, error) {
		return mockRtnl, nil
	}

	getFD = func(_ *ebpf.Program) int {
		return 1
	}

	pObj := &packetparserObjects{}
	pObj.EndpointIngressFilter = &ebpf.Program{}
	pObj.EndpointEgressFilter = &ebpf.Program{}

	p := &packetParser{
		cfg:              cfgDataAggregationLevelHigh,
		l:                log.Logger().Named("test"),
		objs:             pObj,
		reader:           mockReader,
		recordsChannel:   make(chan perfRecord, buffer),
		interfaceLockMap: &sync.Map{},
		endpointIngressInfo: &ebpf.ProgramInfo{
			Name: "ingress",
		},
		endpointEgressInfo: &ebpf.ProgramInfo{
			Name: "egress",
		},
		hostIngressInfo: &ebpf.ProgramInfo{
			Name: "ingress",
		},
		hostEgressInfo: &ebpf.ProgramInfo{
			Name: "egress",
		},
		attachmentMap: &sync.Map{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err = p.Start(ctx)
	require.NoError(t, err)
}

func TestInitPodLevelDisabled(t *testing.T) {
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := &packetParser{
		cfg: cfgPodLevelDisabled,
		l:   log.Logger().Named("test"),
	}
	err := p.Init()
	require.NoError(t, err)
}

func TestPacketParseGenerate(t *testing.T) {
	takeBackup()
	defer restoreBackup()

	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	// Get the directory of the current test file.
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to determine test file path")
	}
	currDir := path.Dir(filename)
	dynamicHeaderPath := fmt.Sprintf("%s/%s/%s", currDir, bpfSourceDir, dynamicHeaderFileName)

	tests := []struct {
		name             string
		cfg              *kcfg.Config
		expectedContents string
	}{
		{
			name: "PodLevelEnabled",
			cfg:  cfgPodLevelEnabled,
			expectedContents: "#define BYPASS_LOOKUP_IP_OF_INTEREST 1\n" +
				"#define DATA_AGGREGATION_LEVEL 0\n" +
				"#define DATA_SAMPLING_RATE 0\n",
		},
		{
			name: "ConntrackMetricsEnabled",
			cfg:  cfgConntrackMetricsEnabled,
			expectedContents: "#define BYPASS_LOOKUP_IP_OF_INTEREST 1\n" +
				"#define ENABLE_CONNTRACK_METRICS 1\n" +
				"#define DATA_AGGREGATION_LEVEL 1\n" +
				"#define DATA_SAMPLING_RATE 0\n",
		},
		{
			name: "DataAggregationLevelLow",
			cfg:  cfgDataAggregationLevelLow,
			expectedContents: "#define BYPASS_LOOKUP_IP_OF_INTEREST 0\n" +
				"#define DATA_AGGREGATION_LEVEL 0\n" +
				"#define DATA_SAMPLING_RATE 0\n",
		},
		{
			name: "DataAggregationLevelHigh",
			cfg:  cfgDataAggregationLevelHigh,
			expectedContents: "#define BYPASS_LOOKUP_IP_OF_INTEREST 0\n" +
				"#define DATA_AGGREGATION_LEVEL 1\n" +
				"#define DATA_SAMPLING_RATE 0\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Instantiate the packetParser struct with a mocked logger and context.
			p := &packetParser{
				cfg: tt.cfg,
				l:   log.Logger().Named(name),
			}
			ctx := context.Background()

			// Call the Generate function and check if it returns an error.
			if err := p.Generate(ctx); err != nil {
				t.Fatalf("failed to generate PacketParser header: %v", err)
			}

			// Verify that the dynamic header file was created in the expected location and contains the expected contents.
			if _, err := os.Stat(dynamicHeaderPath); os.IsNotExist(err) {
				t.Fatalf("dynamic header file does not exist: %v", err)
			}

			actualContents, err := os.ReadFile(dynamicHeaderPath)
			if err != nil {
				t.Fatalf("failed to read dynamic header file: %v", err)
			}
			if string(actualContents) != tt.expectedContents {
				t.Errorf("unexpected dynamic header file contents: got %q, want %q", string(actualContents), tt.expectedContents)
			}
		})
	}
}

func TestCompile(t *testing.T) {
	takeBackup()
	defer restoreBackup()

	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	p := &packetParser{
		cfg: cfgPodLevelEnabled,
		l:   log.Logger().Named(name),
	}
	dir, _ := absPath()
	expectedOutputFile := fmt.Sprintf("%s/%s", dir, bpfObjectFileName)

	err := os.Remove(expectedOutputFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Expected no error. Error: %+v", err)
	}

	err = p.Generate(context.Background())
	if err != nil {
		t.Fatalf("Expected no error. Error: %+v", err)
	}

	err = p.Compile(context.Background())
	if err != nil {
		t.Fatalf("Expected no error. Error: %+v", err)
	}
	if _, err := os.Stat(expectedOutputFile); errors.Is(err, os.ErrNotExist) {
		t.Fatalf("File %+v doesn't exist", expectedOutputFile)
	}
}

func TestCompileRingBuffer(t *testing.T) {
	takeBackup()
	defer restoreBackup()

	log.SetupZapLogger(log.GetDefaultLogOpts()) //nolint:errcheck // ignore
	p := &packetParser{
		cfg: cfgRingBufferEnabled,
		l:   log.Logger().Named(name),
	}
	dir, _ := absPath()
	expectedOutputFile := fmt.Sprintf("%s/%s", dir, bpfObjectFileName)

	err := os.Remove(expectedOutputFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Expected no error. Error: %+v", err)
	}

	err = p.Generate(context.Background())
	if err != nil {
		t.Fatalf("Expected no error. Error: %+v", err)
	}

	err = p.Compile(context.Background())
	if err != nil {
		t.Fatalf("Expected no error. Error: %+v", err)
	}
	if _, err := os.Stat(expectedOutputFile); errors.Is(err, os.ErrNotExist) {
		t.Fatalf("File %+v doesn't exist", expectedOutputFile)
	}
}

func TestEnsureRingBufKernelSupported(t *testing.T) {
	orig := getKernelVersion
	defer func() { getKernelVersion = orig }()

	tests := []struct {
		name      string
		major     int
		minor     int
		patch     int
		errExists bool
	}{
		{"Supported", 5, 8, 0, false},
		{"Supported newer", 6, 1, 0, false},
		{"Not supported old major", 4, 15, 0, true},
		{"Not supported old minor", 5, 7, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getKernelVersion = func() (utils.KernelVersion, error) {
				return utils.KernelVersion{
					Major: tt.major,
					Minor: tt.minor,
					Patch: tt.patch,
				}, nil
			}
			err := ensureRingBufKernelSupported()
			if tt.errExists {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	t.Run("Kernel version error", func(t *testing.T) {
		getKernelVersion = func() (utils.KernelVersion, error) {
			return utils.KernelVersion{}, errors.New("failed to get kernel version") //nolint:err113 // ignore
		}
		err := ensureRingBufKernelSupported()
		assert.Error(t, err)
	})
}

// Helpers.
func takeBackup() {
	// Get the directory of the current test file.
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("failed to determine test file path")
	}
	currDir := path.Dir(filename)
	dynamicHeaderPath := fmt.Sprintf("%s/%s/%s", currDir, bpfSourceDir, dynamicHeaderFileName)

	// Rename the dynamic header file if it already exists.
	if _, err := os.Stat(dynamicHeaderPath); err == nil {
		if err := os.Rename(dynamicHeaderPath, fmt.Sprintf("%s.bak", dynamicHeaderPath)); err != nil {
			panic(fmt.Sprintf("failed to rename existing dynamic header file: %v", err))
		}
	}
}

func restoreBackup() {
	// Get the directory of the current test file.
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("failed to determine test file path")
	}
	currDir := path.Dir(filename)
	dynamicHeaderPath := fmt.Sprintf("%s/%s/%s", currDir, bpfSourceDir, dynamicHeaderFileName)

	// Remove the dynamic header file generated during test.
	os.RemoveAll(dynamicHeaderPath)

	// Restore the dynamic header file if it was renamed.
	if _, err := os.Stat(fmt.Sprintf("%s.bak", dynamicHeaderPath)); err == nil {
		if err := os.Rename(fmt.Sprintf("%s.bak", dynamicHeaderPath), dynamicHeaderPath); err != nil {
			panic(fmt.Sprintf("failed to restore dynamic header file: %v", err))
		}
	}
}
