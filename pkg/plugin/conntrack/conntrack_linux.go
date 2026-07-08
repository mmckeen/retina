// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// package conntrack implements a conntrack plugin for Retina.
package conntrack

import (
	"context"
	"fmt"
	"path"
	"runtime"
	"time"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/microsoft/retina/internal/ktime"
	"github.com/microsoft/retina/pkg/enricher"
	"github.com/microsoft/retina/pkg/loader"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/metrics"
	plugincommon "github.com/microsoft/retina/pkg/plugin/common"
	_ "github.com/microsoft/retina/pkg/plugin/conntrack/_cprog" // nolint // This is needed so cprog is included when vendoring
	"github.com/microsoft/retina/pkg/utils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var conntrackMetricsEnabled = false // conntrack metrics global variable

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@master -cflags "-g -O2 -Wall -D__TARGET_ARCH_${GOARCH} -Wall" -target ${GOARCH} -type ct_v4_key conntrack ./_cprog/conntrack.c -- -I../lib/_${GOARCH} -I../lib/common/libbpf/_src -I../lib/common/libbpf/_include/linux -I../lib/common/libbpf/_include/uapi/linux -I../lib/common/libbpf/_include/asm

// Init initializes the conntrack eBPF map in the kernel for the first time.
// This function should be called in the init container since
// it requires securityContext.privileged to be true.
func Init() error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return errors.Wrapf(err, "failed to remove memlock limit")
	}

	objs := &conntrackObjects{}
	err := loadConntrackObjects(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: plugincommon.MapPath,
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to load conntrack objects")
	}
	return nil
}

// New returns a new Conntrack instance.
func New() (*Conntrack, error) {
	ct := &Conntrack{
		l:           log.Logger().Named("conntrack"),
		gcFrequency: defaultGCFrequency,
	}

	objs := &conntrackObjects{}
	err := loadConntrackObjects(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: plugincommon.MapPath,
		},
	})
	if err != nil {
		ct.l.Error("loadConntrackObjects failed", zap.Error(err))
		return nil, errors.Wrap(err, "failed to load conntrack objects")
	}

	ct.objs = objs
	// Get the conntrack map from the objects
	ct.ctMap = objs.RetinaConntrack
	return ct, nil
}

// Build dynamic header path
func BuildDynamicHeaderPath() string {
	// Get absolute path to this file during runtime.
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	currDir := path.Dir(filename)
	return fmt.Sprintf("%s/%s/%s", currDir, bpfSourceDir, dynamicHeaderFileName)
}

// Generate dynamic header file for conntrack eBPF program.
func GenerateDynamic(ctx context.Context, dynamicHeaderPath string, conntrackMetrics int) error {
	st := fmt.Sprintf("#define ENABLE_CONNTRACK_METRICS %d\n", conntrackMetrics)
	err := loader.WriteFile(ctx, dynamicHeaderPath, st)
	if err != nil {
		return errors.Wrap(err, "failed to write conntrack dynamic header")
	}
	// set a global variable
	if conntrackMetrics == 1 {
		conntrackMetricsEnabled = true
	}
	return nil
}

// Run starts the Conntrack garbage collection loop.
func (ct *Conntrack) Run(ctx context.Context) error {
	ticker := time.NewTicker(ct.gcFrequency)
	defer ticker.Stop()

	ct.l.Info("Starting Conntrack GC loop")

	for {
		select {
		case <-ctx.Done():
			ct.l.Info("Stopping conntrack GC loop")
			if ct.objs != nil {
				err := ct.objs.Close()
				if err != nil {
					ct.l.Error("objs.Close failed", zap.Error(err))
					return errors.Wrap(err, "failed to close conntrack objects")
				}
			}
			return nil
		case <-ticker.C:
			var key conntrackCtV4Key
			var value conntrackCtEntry

			var noOfCtEntries, entriesDeleted int
			// List of keys to be deleted
			var keysToDelete []conntrackCtV4Key
			// Connections with unreported bytes, flushed as reap flows (paced) after iteration.
			var reapItems []reapItem

			// metrics counters
			var packetsCountTx, packetsCountRx, totConnections uint32
			var bytesCountTx, bytesCountRx uint64

			iter := ct.ctMap.Iterate()
			for iter.Next(&key, &value) {
				noOfCtEntries++
				// Check if the connection is closing or has expired
				if ktime.MonotonicOffset.Seconds()+float64(value.EvictionTime) < float64((time.Now().Unix())) {
					// Iterating a hash map from which keys are being deleted is not safe.
					// So, we store the keys to be deleted in a list and delete them after the iteration.
					keyCopy := key // Copy the key to avoid using the same key in the next iteration
					keysToDelete = append(keysToDelete, keyCopy)
					// Collect connections with unreported bytes; flushed as reap flows after
					// iteration so short-lived/idle connections aren't lost when reaped here.
					// The composite literal snapshots key/value by value (no explicit copy needed).
					if value.BytesSeenSinceLastReportTxDir > 0 || value.BytesSeenSinceLastReportRxDir > 0 {
						reapItems = append(reapItems, reapItem{key: key, value: value})
					}
				}
				// Log the conntrack entry
				srcIP := utils.Int2ip(key.SrcIp).To4()
				dstIP := utils.Int2ip(key.DstIp).To4()
				sourcePortShort := uint32(utils.HostToNetShort(key.SrcPort))
				destinationPortShort := uint32(utils.HostToNetShort(key.DstPort))

				// Add conntrack metrics.
				if conntrackMetricsEnabled {
					// Basic metrics, node-level
					ctMeta := value.ConntrackMetadata
					totConnections++
					bytesCountTx += ctMeta.BytesTxCount
					bytesCountRx += ctMeta.BytesRxCount
					packetsCountTx += ctMeta.PacketsTxCount
					packetsCountRx += ctMeta.PacketsRxCount
				}

				ct.l.Debug("conntrack entry",
					zap.String("src_ip", srcIP.String()),
					zap.Uint32("src_port", sourcePortShort),
					zap.String("dst_ip", dstIP.String()),
					zap.Uint32("dst_port", destinationPortShort),
					zap.String("proto", decodeProto(key.Proto)),
					zap.Uint32("eviction_time", value.EvictionTime),
					zap.Uint8("traffic_direction", value.TrafficDirection),
					zap.String("flags_seen_tx_dir", decodeFlags(value.FlagsSeenTxDir)),
					zap.String("flags_seen_rx_dir", decodeFlags(value.FlagsSeenRxDir)),
					zap.Uint32("last_reported_tx_dir", value.LastReportTxDir),
					zap.Uint32("last_reported_rx_dir", value.LastReportRxDir),
					zap.Bool("is_direction_unknown", value.IsDirectionUnknown),
				)
			}
			if err := iter.Err(); err != nil {
				ct.l.Error("Iterate failed", zap.Error(err))
			}

			// create metrics
			if conntrackMetricsEnabled {
				metrics.ConntrackPacketsTx.WithLabelValues().Set(float64(packetsCountTx))
				metrics.ConntrackBytesTx.WithLabelValues().Set(float64(bytesCountTx))
				metrics.ConntrackPacketsRx.WithLabelValues().Set(float64(packetsCountRx))
				metrics.ConntrackBytesRx.WithLabelValues().Set(float64(bytesCountRx))
				metrics.ConntrackTotalConnections.WithLabelValues().Set(float64(totConnections))
			}

			// Delete the conntrack entries
			for _, key := range keysToDelete {
				if err := ct.ctMap.Delete(key); err != nil {
					// Should only happen in a high connection churn scenario
					ct.l.Debug("Delete failed", zap.Error(err))
				} else {
					entriesDeleted++
				}
			}

			// Flush reap flows spread across the GC interval so a pass trickles into
			// the enricher ring instead of bursting it.
			ct.emitReapFlows(reapItems)
			ct.l.Debug("conntrack GC completed", zap.Int("number_of_entries", noOfCtEntries), zap.Int("entries_deleted", entriesDeleted))
		}
	}
}

// reapItem is a by-value snapshot of a conntrack entry to flush as a reap flow.
type reapItem struct {
	key   conntrackCtV4Key
	value conntrackCtEntry
}

const (
	reapEmitBatchSize        = 256
	reapEmitIntervalFraction = 80 // percent of the GC interval to spread reap emits across
)

// emitReapFlows flushes reap flows evenly across most of the GC interval so a GC
// pass trickles into the enricher ring instead of bursting it. Emission is paced
// per batch to finish within reapEmitIntervalFraction of the interval, leaving
// headroom before the next tick.
func (ct *Conntrack) emitReapFlows(items []reapItem) {
	if len(items) == 0 {
		return
	}
	batches := (len(items) + reapEmitBatchSize - 1) / reapEmitBatchSize
	pause := (ct.gcFrequency * reapEmitIntervalFraction / 100) / time.Duration(batches)
	for i := range items {
		ct.emitReapFlow(items[i].key, items[i].value)
		if (i+1)%reapEmitBatchSize == 0 {
			time.Sleep(pause)
		}
	}
}

// emitReapFlow flushes bytes/packets/flags observed since the last report for a
// connection being reaped, one flow per direction with unreported data.
func (ct *Conntrack) emitReapFlow(key conntrackCtV4Key, value conntrackCtEntry) {
	e := enricher.Instance()
	if e == nil {
		return
	}
	reason := reapReason(key.Proto, &value)
	if value.BytesSeenSinceLastReportTxDir > 0 {
		f := value.FlagsSeenSinceLastReportTxDir
		ct.writeReapFlow(e, &key, &value, false, value.BytesSeenSinceLastReportTxDir, value.PacketsSeenSinceLastReportTxDir,
			utils.TCPFlagCounts{Syn: f.Syn, Ack: f.Ack, Fin: f.Fin, Rst: f.Rst, Psh: f.Psh, Urg: f.Urg, Ece: f.Ece, Cwr: f.Cwr, Ns: f.Ns}, reason)
	}
	if value.BytesSeenSinceLastReportRxDir > 0 {
		f := value.FlagsSeenSinceLastReportRxDir
		ct.writeReapFlow(e, &key, &value, true, value.BytesSeenSinceLastReportRxDir, value.PacketsSeenSinceLastReportRxDir,
			utils.TCPFlagCounts{Syn: f.Syn, Ack: f.Ack, Fin: f.Fin, Rst: f.Rst, Psh: f.Psh, Urg: f.Urg, Ece: f.Ece, Cwr: f.Cwr, Ns: f.Ns}, reason)
	}
}

// reapReason classifies why a conntrack entry reached GC reaping, from its proto
// and the flags seen across both directions.
func reapReason(proto uint8, value *conntrackCtEntry) string {
	switch proto {
	case protoUDP:
		return reapReasonUDPIdle
	case protoTCP:
		flags := value.FlagsSeenTxDir | value.FlagsSeenRxDir
		switch {
		case flags&TCP_RST != 0:
			return reapReasonTCPRst
		case flags&TCP_FIN != 0:
			return reapReasonTCPFin
		default:
			return reapReasonTCPIdle
		}
	default:
		return reapReasonOther
	}
}

const (
	reapReasonUDPIdle = "udp_idle"
	reapReasonTCPRst  = "tcp_rst"
	reapReasonTCPFin  = "tcp_fin"
	reapReasonTCPIdle = "tcp_idle"
	reapReasonOther   = "other"
)

func (ct *Conntrack) writeReapFlow(e *enricher.Enricher, key *conntrackCtV4Key, value *conntrackCtEntry, isReply bool, bytesSeen, packetsSeen uint32, prevFlags utils.TCPFlagCounts, reason string) {
	// No current packet in a reap flow: carry counts as previously-observed, minus
	// one packet since forward metrics add one for the (here absent) reporting packet.
	prevPackets := uint32(0)
	if packetsSeen > 0 {
		prevPackets = packetsSeen - 1
	}
	// CurrentTCPFlags nil and TCPID 0: a reap flow has no current packet.
	fl := utils.BuildForwardedFlow(ct.l, utils.ForwardFlowParams{
		Timestamp:                 time.Now().UnixNano(),
		SourceIP:                  utils.Int2ip(key.SrcIp).To4(),
		DestIP:                    utils.Int2ip(key.DstIp).To4(),
		SourcePort:                uint32(utils.HostToNetShort(key.SrcPort)),
		DestPort:                  uint32(utils.HostToNetShort(key.DstPort)),
		Proto:                     key.Proto,
		ObservationPoint:          reapObservationPoint(value.TrafficDirection),
		IsReply:                   isReply,
		TrafficDirection:          value.TrafficDirection,
		PreviouslyObservedBytes:   bytesSeen,
		PreviouslyObservedPackets: prevPackets,
		PreviouslyObservedFlags:   prevFlags,
	})
	if fl == nil {
		return
	}
	e.Write(&v1.Event{Event: fl, Timestamp: fl.GetTime()})
	metrics.ConntrackReapFlowsCounter.WithLabelValues(reason).Inc()
}

func reapObservationPoint(trafficDirection uint8) uint8 {
	switch trafficDirection {
	case 2: // egress
		return 3 // to network
	case 1: // ingress
		return 2 // from network
	default:
		return 0
	}
}
