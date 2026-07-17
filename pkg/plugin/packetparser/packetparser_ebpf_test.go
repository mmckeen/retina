// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build ebpf && linux

package packetparser

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	tc "github.com/florianl/go-tc"
	"github.com/gopacket/gopacket/layers"
	"github.com/microsoft/retina/pkg/loader"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/plugin/ebpftest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

const (
	// Observation points from conntrack.h
	observationPointFromEndpoint = 0x00
	observationPointToEndpoint   = 0x01
	observationPointFromNetwork  = 0x02
	observationPointToNetwork    = 0x03

	// TC_ACT_UNSPEC is -1 in C, which becomes 0xFFFFFFFF as uint32.
	tcActUnspec = 0xFFFFFFFF

	// Protocol numbers
	protoTCP = 6
	protoUDP = 17

	// Traffic directions from conntrack.h
	trafficDirectionUnknown = 0x00
	trafficDirectionIngress = 0x01
	trafficDirectionEgress  = 0x02

	// perfReaderTimeout is how long to wait for a perf event.
	perfReaderTimeout = 500 * time.Millisecond
)

// loadTestObjects loads the packetparser eBPF programs and maps for testing.
func loadTestObjects(t testing.TB) (*packetparserObjects, *perf.Reader) {
	t.Helper()
	ebpftest.RequirePrivileged(t)

	spec, err := loadPacketparser()
	require.NoError(t, err)

	ebpftest.RemoveMapPinning(spec)

	var objs packetparserObjects
	err = spec.LoadAndAssign(&objs, nil)
	require.NoError(t, err)
	t.Cleanup(func() { objs.Close() })

	reader, err := perf.NewReader(objs.RetinaPacketparserEvents, os.Getpagesize()*4)
	require.NoError(t, err)
	t.Cleanup(func() { reader.Close() })

	return &objs, reader
}

func TestEndpointIngressFilter_TCP(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.0.1")
	dstIP := net.ParseIP("10.0.0.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	pkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: 12345,
		DstPort: 80,
		SYN:     true,
		SeqNum:  1000,
	})

	ret := ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)
	assert.Equal(t, uint32(tcActUnspec), ret, "expected TC_ACT_UNSPEC return value")

	event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok, "expected a perf event")

	assert.Equal(t, ebpftest.IPToNative("10.0.0.1"), event.SrcIp)
	assert.Equal(t, ebpftest.IPToNative("10.0.0.2"), event.DstIp)
	assert.Equal(t, ebpftest.PortToNetwork(12345), event.SrcPort)
	assert.Equal(t, ebpftest.PortToNetwork(80), event.DstPort)
	assert.Equal(t, uint8(protoTCP), event.Proto)
	assert.Equal(t, uint8(observationPointFromEndpoint), event.ObservationPoint)
	assert.NotZero(t, event.T_nsec, "timestamp should be set")
	assert.Equal(t, uint32(len(pkt)), event.Bytes)

	// SYN flag should be set (bit 1)
	assert.NotZero(t, event.Flags&0x02, "SYN flag should be set")
}

func TestAllObservationPoints(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.1.1")
	dstIP := net.ParseIP("10.0.1.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	tests := []struct {
		name     string
		prog     *ebpf.Program
		expected uint8
	}{
		{"endpoint_ingress", objs.EndpointIngressFilter, observationPointFromEndpoint},
		{"endpoint_egress", objs.EndpointEgressFilter, observationPointToEndpoint},
		{"host_ingress", objs.HostIngressFilter, observationPointFromNetwork},
		{"host_egress", objs.HostEgressFilter, observationPointToNetwork},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
				SrcIP:   srcIP,
				DstIP:   dstIP,
				SrcPort: 1111,
				DstPort: 2222,
				SYN:     true,
			})

			ebpftest.RunProgram(t, tc.prog, pkt)

			event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
			require.True(t, ok, "expected a perf event")
			assert.Equal(t, tc.expected, event.ObservationPoint)
		})
	}
}

func TestTCPFlags(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.2.1")
	dstIP := net.ParseIP("10.0.2.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	// TCP flags bitmask as computed by the eBPF program:
	// fin=bit0, syn=bit1, rst=bit2, psh=bit3, ack=bit4, urg=bit5, ece=bit6, cwr=bit7
	tests := []struct {
		name     string
		opts     ebpftest.TCPPacketOpts
		expected uint16
	}{
		{
			name: "SYN",
			opts: ebpftest.TCPPacketOpts{
				SrcIP: srcIP, DstIP: dstIP, SrcPort: 1000, DstPort: 80,
				SYN: true,
			},
			expected: 0x02, // syn=bit1
		},
		{
			name: "ACK",
			opts: ebpftest.TCPPacketOpts{
				SrcIP: srcIP, DstIP: dstIP, SrcPort: 1001, DstPort: 80,
				ACK: true,
			},
			expected: 0x10, // ack=bit4
		},
		{
			name: "SYN+ACK",
			opts: ebpftest.TCPPacketOpts{
				SrcIP: srcIP, DstIP: dstIP, SrcPort: 1002, DstPort: 80,
				SYN: true, ACK: true,
			},
			expected: 0x12, // syn=bit1 | ack=bit4
		},
		{
			name: "FIN",
			opts: ebpftest.TCPPacketOpts{
				SrcIP: srcIP, DstIP: dstIP, SrcPort: 1003, DstPort: 80,
				FIN: true, ACK: true,
			},
			expected: 0x11, // fin=bit0 | ack=bit4
		},
		{
			name: "RST",
			opts: ebpftest.TCPPacketOpts{
				SrcIP: srcIP, DstIP: dstIP, SrcPort: 1004, DstPort: 80,
				RST: true,
			},
			expected: 0x04, // rst=bit2
		},
		{
			name: "PSH+ACK",
			opts: ebpftest.TCPPacketOpts{
				SrcIP: srcIP, DstIP: dstIP, SrcPort: 1005, DstPort: 80,
				PSH: true, ACK: true,
			},
			expected: 0x18, // psh=bit3 | ack=bit4
		},
		{
			name: "URG",
			opts: ebpftest.TCPPacketOpts{
				SrcIP: srcIP, DstIP: dstIP, SrcPort: 1006, DstPort: 80,
				URG: true,
			},
			expected: 0x20, // urg=bit5
		},
		{
			name: "ECE",
			opts: ebpftest.TCPPacketOpts{
				SrcIP: srcIP, DstIP: dstIP, SrcPort: 1007, DstPort: 80,
				ECE: true,
			},
			expected: 0x40, // ece=bit6
		},
		{
			name: "CWR",
			opts: ebpftest.TCPPacketOpts{
				SrcIP: srcIP, DstIP: dstIP, SrcPort: 1008, DstPort: 80,
				CWR: true,
			},
			expected: 0x80, // cwr=bit7
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt := ebpftest.BuildTCPPacket(tc.opts)
			ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)

			event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
			require.True(t, ok, "expected a perf event")
			assert.Equal(t, tc.expected, event.Flags, "TCP flags mismatch")
		})
	}
}

func TestTCPTimestamps(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.3.1")
	dstIP := net.ParseIP("10.0.3.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	t.Run("with_timestamps", func(t *testing.T) {
		pkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: 5000,
			DstPort: 443,
			SYN:     true,
			TSval:   12345678,
			TSecr:   87654321,
		})

		ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)

		event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
		require.True(t, ok, "expected a perf event")
		assert.Equal(t, uint32(12345678), event.TcpMetadata.Tsval)
		assert.Equal(t, uint32(87654321), event.TcpMetadata.Tsecr)
	})

	t.Run("without_timestamps", func(t *testing.T) {
		pkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: 5001,
			DstPort: 443,
			SYN:     true,
		})

		ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)

		event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
		require.True(t, ok, "expected a perf event")
		assert.Zero(t, event.TcpMetadata.Tsval, "TSval should be zero when no timestamp option")
		assert.Zero(t, event.TcpMetadata.Tsecr, "TSecr should be zero when no timestamp option")
	})
}

func TestUDPPacket(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.4.1")
	dstIP := net.ParseIP("10.0.4.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	pkt := ebpftest.BuildUDPPacket(ebpftest.UDPPacketOpts{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: 53000,
		DstPort: 53,
	})

	ret := ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)
	assert.Equal(t, uint32(tcActUnspec), ret)

	event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok, "expected a perf event")

	assert.Equal(t, ebpftest.IPToNative("10.0.4.1"), event.SrcIp)
	assert.Equal(t, ebpftest.IPToNative("10.0.4.2"), event.DstIp)
	assert.Equal(t, ebpftest.PortToNetwork(53000), event.SrcPort)
	assert.Equal(t, ebpftest.PortToNetwork(53), event.DstPort)
	assert.Equal(t, uint8(protoUDP), event.Proto)
	// UDP packets have flags=1 in the eBPF program.
	assert.Equal(t, uint16(1), event.Flags)
}

func TestFilterMapFiltering(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.5.1")
	dstIP := net.ParseIP("10.0.5.2")

	// Don't populate the filter map — neither IP should match.
	pkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: 6000,
		DstPort: 80,
		SYN:     true,
	})

	t.Run("no_match_no_event", func(t *testing.T) {
		ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)
		ebpftest.AssertNoPerfEvent(t, reader, perfReaderTimeout)
	})

	t.Run("match_after_adding_ip", func(t *testing.T) {
		ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP)
		ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)

		event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
		require.True(t, ok, "expected a perf event after adding IP to filter")
		assert.Equal(t, ebpftest.IPToNative("10.0.5.1"), event.SrcIp)
	})
}

func TestNonTCPUDP_NoEvent(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.6.1")
	dstIP := net.ParseIP("10.0.6.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	// ICMP is protocol 1 — the eBPF program only handles TCP and UDP.
	pkt := ebpftest.BuildICMPPacket(srcIP, dstIP)

	ret := ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)
	assert.Equal(t, uint32(tcActUnspec), ret, "should still return TC_ACT_UNSPEC")

	ebpftest.AssertNoPerfEvent(t, reader, perfReaderTimeout)
}

func TestNonIPv4_NoEvent(t *testing.T) {
	objs, reader := loadTestObjects(t)

	tests := []struct {
		name      string
		etherType layers.EthernetType
	}{
		{"ARP", layers.EthernetTypeARP},
		{"IPv6", layers.EthernetTypeIPv6},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt := ebpftest.BuildNonIPPacket(tc.etherType)

			ret := ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)
			assert.Equal(t, uint32(tcActUnspec), ret)

			ebpftest.AssertNoPerfEvent(t, reader, perfReaderTimeout)
		})
	}
}

func TestMalformedPackets(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.7.1")
	dstIP := net.ParseIP("10.0.7.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	t.Run("runt_packet", func(t *testing.T) {
		// BPF_PROG_TEST_RUN requires at least ETH_HLEN (14) bytes for TC programs.
		// The kernel rejects shorter inputs with EINVAL.
		pkt := ebpftest.BuildRuntPacket()
		_, err := objs.EndpointIngressFilter.Run(&ebpf.RunOptions{Data: pkt})
		assert.Error(t, err, "kernel should reject packets shorter than ETH_HLEN")
	})

	t.Run("truncated_ip", func(t *testing.T) {
		pkt := ebpftest.BuildTruncatedIPPacket()
		ret := ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)
		assert.Equal(t, uint32(tcActUnspec), ret)
		ebpftest.AssertNoPerfEvent(t, reader, perfReaderTimeout)
	})

	t.Run("truncated_tcp", func(t *testing.T) {
		// Note: BPF_PROG_TEST_RUN may pad sk_buff to minimum frame size,
		// which means the eBPF bounds check can pass even for truncated packets.
		// This test verifies the program doesn't crash on short TCP headers.
		pkt := ebpftest.BuildTruncatedTCPPacket(srcIP, dstIP)
		ret := ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)
		assert.Equal(t, uint32(tcActUnspec), ret)

		// Drain any event that may have been emitted due to kernel padding.
		reader.SetDeadline(time.Now().Add(100 * time.Millisecond))
		reader.Read() //nolint:errcheck
	})
}

func TestReturnValue(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.8.1")
	dstIP := net.ParseIP("10.0.8.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	programs := []*ebpf.Program{
		objs.EndpointIngressFilter,
		objs.EndpointEgressFilter,
		objs.HostIngressFilter,
		objs.HostEgressFilter,
	}

	// Test with various packet types (all >= ETH_HLEN to satisfy kernel).
	packets := [][]byte{
		ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
			SrcIP: srcIP, DstIP: dstIP, SrcPort: 8000, DstPort: 80, SYN: true,
		}),
		ebpftest.BuildUDPPacket(ebpftest.UDPPacketOpts{
			SrcIP: srcIP, DstIP: dstIP, SrcPort: 8001, DstPort: 53,
		}),
		ebpftest.BuildNonIPPacket(layers.EthernetTypeARP),
		ebpftest.BuildTruncatedIPPacket(),
	}

	for _, prog := range programs {
		for _, pkt := range packets {
			ret := ebpftest.RunProgram(t, prog, pkt)
			assert.Equal(t, uint32(tcActUnspec), ret)

			// Drain any perf event.
			reader.SetDeadline(time.Now().Add(50 * time.Millisecond))
			reader.Read() //nolint:errcheck
		}
	}
}

func TestPacketBytesField(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.9.1")
	dstIP := net.ParseIP("10.0.9.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	payloadSizes := []int{0, 100, 1000}

	for _, payloadSize := range payloadSizes {
		pkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
			SrcIP:       srcIP,
			DstIP:       dstIP,
			SrcPort:     9000,
			DstPort:     80,
			SYN:         true,
			PayloadSize: payloadSize,
		})

		ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)

		event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
		require.True(t, ok, "expected a perf event")
		assert.Equal(t, uint32(len(pkt)), event.Bytes, "Bytes field should equal packet length (payload size: %d)", payloadSize)
	}
}

func TestConntrackMapUpdated(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.10.1")
	dstIP := net.ParseIP("10.0.10.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	pkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: 10000,
		DstPort: 80,
		SYN:     true,
	})

	// First run — should create a new conntrack entry.
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)
	_, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok, "expected a perf event on first run")

	// Check that the conntrack map now has an entry for this flow.
	lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.10.1", "10.0.10.2", 10000, 80, protoTCP)
}

func TestConntrackIsReply(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.11.1")
	dstIP := net.ParseIP("10.0.11.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	// Send SYN: 10.0.11.1:20000 → 10.0.11.2:80 (new connection, forward direction).
	synPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 20000, DstPort: 80, SYN: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, synPkt)
	event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok, "expected perf event for SYN")
	assert.False(t, event.IsReply, "SYN packet should not be a reply")

	// Send SYN-ACK: 10.0.11.2:80 → 10.0.11.1:20000 (reply direction — reversed 5-tuple).
	synAckPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: dstIP, DstIP: srcIP, SrcPort: 80, DstPort: 20000, SYN: true, ACK: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, synAckPkt)
	event, ok = ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok, "expected perf event for SYN-ACK")
	assert.True(t, event.IsReply, "SYN-ACK with reversed 5-tuple should be a reply")

	// Send another packet in forward direction: 10.0.11.1:20000 → 10.0.11.2:80.
	ackPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 20000, DstPort: 80, ACK: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, ackPkt)
	event, ok = ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok, "expected perf event for ACK")
	assert.False(t, event.IsReply, "forward direction ACK should not be a reply")
}

func TestConntrackTrafficDirection(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.12.1")
	dstIP := net.ParseIP("10.0.12.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	// For a NEW connection, traffic_direction is derived from the observation point:
	//   FROM_ENDPOINT (0x00) or TO_NETWORK (0x03) → EGRESS (0x02)
	//   TO_ENDPOINT   (0x01) or FROM_NETWORK (0x02) → INGRESS (0x01)
	tests := []struct {
		name              string
		prog              *ebpf.Program
		srcPort           uint16
		expectedDirection uint8
	}{
		{"endpoint_ingress→egress", objs.EndpointIngressFilter, 30000, trafficDirectionEgress},
		{"endpoint_egress→ingress", objs.EndpointEgressFilter, 30001, trafficDirectionIngress},
		{"host_ingress→ingress", objs.HostIngressFilter, 30002, trafficDirectionIngress},
		{"host_egress→egress", objs.HostEgressFilter, 30003, trafficDirectionEgress},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
				SrcIP: srcIP, DstIP: dstIP, SrcPort: tc.srcPort, DstPort: 80, SYN: true,
			})
			ebpftest.RunProgram(t, tc.prog, pkt)

			event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
			require.True(t, ok, "expected a perf event")
			assert.Equal(t, tc.expectedDirection, event.TrafficDirection,
				"unexpected traffic direction for observation point")
		})
	}
}

// lookupConntrackEntry looks up a conntrack entry by 5-tuple and returns it.
func lookupConntrackEntry(t *testing.T, ctMap *ebpf.Map, srcIP, dstIP string, srcPort, dstPort uint16, proto uint8) packetparserCtEntry {
	t.Helper()
	ctKey := packetparserCtV4Key{
		SrcIp:   ebpftest.IPToNative(srcIP),
		DstIp:   ebpftest.IPToNative(dstIP),
		SrcPort: ebpftest.PortToNetwork(srcPort),
		DstPort: ebpftest.PortToNetwork(dstPort),
		Proto:   proto,
	}
	var entry packetparserCtEntry
	err := ctMap.Lookup(ctKey, &entry)
	require.NoError(t, err, "conntrack entry not found for %s:%d → %s:%d proto=%d",
		srcIP, srcPort, dstIP, dstPort, proto)
	return entry
}

// drainPerfEvent reads and discards one perf event if available.
func drainPerfEvent(reader *perf.Reader, timeout time.Duration) {
	reader.SetDeadline(time.Now().Add(timeout))
	reader.Read() //nolint:errcheck
}

// compileOpts controls the dynamic.h flags for a custom-compiled eBPF variant.
type compileOpts struct {
	bypassFilter     int
	enableConntrack  bool
	aggregationLevel int
	samplingRate     int
	enableRingBuf    bool
}

// compileAndLoadVariantBase compiles the packetparser eBPF program with custom
// dynamic.h settings and returns loaded objects + perf/ringbuf reader.
// Requires clang to be installed.
func compileAndLoadVariantBase(t *testing.T, opts compileOpts) (*packetparserObjects, *perf.Reader, *ringbuf.Reader) {
	t.Helper()
	ebpftest.RequirePrivileged(t)

	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("skipping: clang not available for eBPF compilation")
	}

	// Get source directory (uses runtime.Caller to find the file path).
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok, "failed to get current file path")
	dir := path.Dir(filename)

	// Write custom packetparser dynamic.h, restore on cleanup.
	ppDynamic := fmt.Sprintf("%s/%s/%s", dir, bpfSourceDir, dynamicHeaderFileName)
	origPP, err := os.ReadFile(ppDynamic)
	require.NoError(t, err)
	t.Cleanup(func() { os.WriteFile(ppDynamic, origPP, 0o644) }) //nolint:errcheck

	var st string
	st += fmt.Sprintf("#define BYPASS_LOOKUP_IP_OF_INTEREST %d\n", opts.bypassFilter)
	if opts.enableConntrack {
		st += "#define ENABLE_CONNTRACK_METRICS 1\n"
	}
	st += fmt.Sprintf("#define DATA_AGGREGATION_LEVEL %d\n", opts.aggregationLevel)
	st += fmt.Sprintf("#define DATA_SAMPLING_RATE %d\n", opts.samplingRate)
	require.NoError(t, os.WriteFile(ppDynamic, []byte(st), 0o644))

	// Write conntrack dynamic.h if conntrack metrics enabled.
	ctDynamic := fmt.Sprintf("%s/../conntrack/%s/%s", dir, bpfSourceDir, dynamicHeaderFileName)
	origCT, err := os.ReadFile(ctDynamic)
	require.NoError(t, err)
	t.Cleanup(func() { os.WriteFile(ctDynamic, origCT, 0o644) }) //nolint:errcheck

	if opts.enableConntrack {
		require.NoError(t, os.WriteFile(ctDynamic, []byte("#define ENABLE_CONNTRACK_METRICS 1\n#define CT_REPORT_INTERVAL 30\n"), 0o644))
	}

	// Compile the eBPF program.
	bpfSourceFile := fmt.Sprintf("%s/%s/%s", dir, bpfSourceDir, bpfSourceFileName)
	outputFile := fmt.Sprintf("%s/packetparser_test.o", t.TempDir())

	arch := runtime.GOARCH
	targetArch := "-D__TARGET_ARCH_x86"
	if arch == "arm64" {
		targetArch = "-D__TARGET_ARCH_arm64"
	}

	log.SetupZapLogger(log.GetDefaultLogOpts()) //nolint:errcheck

	cflags := []string{
		"-target", "bpf", "-Wall", targetArch, "-g", "-O2",
		"-c", bpfSourceFile, "-o", outputFile,
		fmt.Sprintf("-I%s/../lib/_%s", dir, arch),
		fmt.Sprintf("-I%s/../lib/common/libbpf/_src", dir),
		fmt.Sprintf("-I%s/../lib/common/libbpf/_include/linux", dir),
		fmt.Sprintf("-I%s/../lib/common/libbpf/_include/uapi/linux", dir),
		fmt.Sprintf("-I%s/../lib/common/libbpf/_include/asm", dir),
		fmt.Sprintf("-I%s/../filter/_cprog/", dir),
		fmt.Sprintf("-I%s/../conntrack/_cprog/", dir),
	}
	if opts.enableRingBuf {
		cflags = append(cflags, "-DUSE_RING_BUFFER", "-DRING_BUFFER_SIZE=4096")
	}

	err = loader.CompileEbpf(context.Background(), cflags...)
	require.NoError(t, err, "failed to compile eBPF program")

	// Load the compiled object.
	spec, err := ebpf.LoadCollectionSpec(outputFile)
	require.NoError(t, err)
	ebpftest.RemoveMapPinning(spec)

	var objs packetparserObjects
	err = spec.LoadAndAssign(&objs, nil)
	require.NoError(t, err)
	t.Cleanup(func() { objs.Close() })

	var pReader *perf.Reader
	var rReader *ringbuf.Reader
	if opts.enableRingBuf {
		rReader, err = ringbuf.NewReader(objs.RetinaPacketparserEvents)
		require.NoError(t, err)
		t.Cleanup(func() { rReader.Close() })
	} else {
		pReader, err = perf.NewReader(objs.RetinaPacketparserEvents, os.Getpagesize()*4)
		require.NoError(t, err)
		t.Cleanup(func() { pReader.Close() })
	}

	return &objs, pReader, rReader
}

func compileAndLoadVariant(t *testing.T, opts compileOpts) (*packetparserObjects, *perf.Reader) {
	objs, pReader, _ := compileAndLoadVariantBase(t, opts)
	return objs, pReader
}

func compileAndLoadRingBufVariant(t *testing.T, opts compileOpts) (*packetparserObjects, *ringbuf.Reader) {
	opts.enableRingBuf = true
	objs, _, rReader := compileAndLoadVariantBase(t, opts)
	return objs, rReader
}

func TestConntrackMetricsEnabled(t *testing.T) {
	objs, reader := compileAndLoadVariant(t, compileOpts{
		bypassFilter:     1, // skip filter for simplicity
		enableConntrack:  true,
		aggregationLevel: 0, // LOW — always emit
		samplingRate:     1,
	})

	srcIP := net.ParseIP("10.0.13.1")
	dstIP := net.ParseIP("10.0.13.2")

	// Send SYN (creates conntrack entry).
	synPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 40000, DstPort: 80, SYN: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, synPkt)
	_, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok)

	// Send a second packet in the same direction (existing forward connection).
	ackPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 40000, DstPort: 80, ACK: true,
		PayloadSize: 100,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, ackPkt)
	event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok)

	// With ENABLE_CONNTRACK_METRICS, the conntrack_metadata should be populated.
	// After 2 packets in TX direction, packets_tx_count should be >= 1.
	assert.True(t, event.ConntrackMetadata.PacketsTxCount >= 1,
		"expected packets_tx_count >= 1, got %d", event.ConntrackMetadata.PacketsTxCount)
	assert.True(t, event.ConntrackMetadata.BytesTxCount > 0,
		"expected bytes_tx_count > 0, got %d", event.ConntrackMetadata.BytesTxCount)

	// Send a reply packet (reverse direction).
	replyPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: dstIP, DstIP: srcIP, SrcPort: 80, DstPort: 40000, ACK: true,
		PayloadSize: 200,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, replyPkt)
	event, ok = ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok)

	assert.True(t, event.IsReply, "reverse packet should be is_reply")
	assert.True(t, event.ConntrackMetadata.PacketsRxCount >= 1,
		"expected packets_rx_count >= 1, got %d", event.ConntrackMetadata.PacketsRxCount)
	assert.True(t, event.ConntrackMetadata.BytesRxCount > 0,
		"expected bytes_rx_count > 0, got %d", event.ConntrackMetadata.BytesRxCount)
}

func TestHighAggregationLevel(t *testing.T) {
	objs, reader := compileAndLoadVariant(t, compileOpts{
		bypassFilter:     1,
		enableConntrack:  false,
		aggregationLevel: 1, // HIGH — only emit when report.report is true
		samplingRate:     1, // sample everything
	})

	srcIP := net.ParseIP("10.0.14.1")
	dstIP := net.ParseIP("10.0.14.2")

	// First SYN packet should be reported (new connection).
	synPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 50000, DstPort: 80, SYN: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, synPkt)
	event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok, "first SYN should be reported at HIGH aggregation")
	assert.Equal(t, uint8(protoTCP), event.Proto)

	// Send several identical ACK packets. At HIGH aggregation, the conntrack
	// logic suppresses repeated reports until new flags appear or a timeout.
	ackPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 50000, DstPort: 80, ACK: true,
	})
	emittedCount := 0
	for i := 0; i < 5; i++ {
		ebpftest.RunProgram(t, objs.EndpointIngressFilter, ackPkt)
		_, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, 100*time.Millisecond)
		if ok {
			emittedCount++
		}
	}
	// At HIGH aggregation, not all 5 identical ACK packets should be reported.
	// The first ACK introduces a new flag (ACK vs SYN), so it should be reported.
	// Subsequent identical ACKs may be suppressed.
	t.Logf("HIGH aggregation: %d/5 ACK packets emitted events", emittedCount)
	assert.True(t, emittedCount < 5,
		"HIGH aggregation should suppress some repeated packets, but all %d were emitted", emittedCount)
}

func TestHighAggregationPreviouslyObserved(t *testing.T) {
	objs, reader := compileAndLoadVariant(t, compileOpts{
		bypassFilter:     1,
		enableConntrack:  false,
		aggregationLevel: 1, // HIGH
		samplingRate:     1,
	})

	srcIP := net.ParseIP("10.0.15.1")
	dstIP := net.ParseIP("10.0.15.2")

	// Send SYN to create the connection.
	synPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 60000, DstPort: 80, SYN: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, synPkt)
	_, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok)

	// Send multiple packets to accumulate stats, then send a packet with a new
	// flag to trigger a report that includes previously_observed_* fields.
	ackPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 60000, DstPort: 80, ACK: true,
		PayloadSize: 50,
	})
	for i := 0; i < 3; i++ {
		ebpftest.RunProgram(t, objs.EndpointIngressFilter, ackPkt)
		// Drain any events.
		reader.SetDeadline(time.Now().Add(50 * time.Millisecond))
		reader.Read() //nolint:errcheck
	}

	// Send FIN to introduce a new flag — this should trigger a report.
	finPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 60000, DstPort: 80, FIN: true, ACK: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, finPkt)
	event, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok, "FIN should trigger a report due to new flag")

	// At HIGH aggregation, the report should include accumulated stats.
	// previously_observed_packets counts packets seen since last report.
	t.Logf("previously_observed_packets=%d, previously_observed_bytes=%d",
		event.PreviouslyObservedPackets, event.PreviouslyObservedBytes)
	assert.True(t, event.PreviouslyObservedPackets > 0,
		"expected previously_observed_packets > 0 at HIGH aggregation")
}

// =============================================================================
// Conntrack map-state verification tests
// =============================================================================

func TestConntrackEntryCreation(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.20.1")
	dstIP := net.ParseIP("10.0.20.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	pkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 20000, DstPort: 80, SYN: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)
	_, ok := ebpftest.ReadPerfEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok)

	entry := lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.20.1", "10.0.20.2", 20000, 80, protoTCP)

	// FlagsSeenTxDir: SYN = 0x02.
	assert.Equal(t, uint8(0x02), entry.FlagsSeenTxDir, "should have SYN in TX flags")
	// No reply yet.
	assert.Equal(t, uint8(0x00), entry.FlagsSeenRxDir, "RX flags should be empty")
	// Direction is known because we saw SYN.
	assert.False(t, entry.IsDirectionUnknown, "direction should be known for SYN")
	// EndpointIngressFilter = FROM_ENDPOINT → EGRESS.
	assert.Equal(t, uint8(trafficDirectionEgress), entry.TrafficDirection)
	// Eviction time must be set.
	assert.NotZero(t, entry.EvictionTime, "eviction time should be non-zero")
	// Sampled + reported → "since last report" counters are 0.
	assert.Equal(t, uint32(0), entry.PacketsSeenSinceLastReportTxDir)
	assert.Equal(t, uint32(0), entry.BytesSeenSinceLastReportTxDir)
}

func TestConntrackFlagAccumulation(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.21.1")
	dstIP := net.ParseIP("10.0.21.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	// Step 1: SYN → flags_seen_tx_dir = SYN (0x02).
	synPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 21000, DstPort: 80, SYN: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, synPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	entry := lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.21.1", "10.0.21.2", 21000, 80, protoTCP)
	assert.Equal(t, uint8(0x02), entry.FlagsSeenTxDir, "after SYN")

	// Step 2: ACK → flags_seen_tx_dir = SYN|ACK (0x12).
	ackPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 21000, DstPort: 80, ACK: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, ackPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	entry = lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.21.1", "10.0.21.2", 21000, 80, protoTCP)
	assert.Equal(t, uint8(0x12), entry.FlagsSeenTxDir, "after ACK: should be SYN|ACK")

	// Step 3: PSH+ACK → flags_seen_tx_dir = SYN|PSH|ACK (0x1A).
	pshPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 21000, DstPort: 80, PSH: true, ACK: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, pshPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	entry = lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.21.1", "10.0.21.2", 21000, 80, protoTCP)
	assert.Equal(t, uint8(0x1A), entry.FlagsSeenTxDir, "after PSH+ACK: should be SYN|PSH|ACK")
}

func TestConntrackReplyUpdatesEntry(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.22.1")
	dstIP := net.ParseIP("10.0.22.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	// Forward SYN: 10.0.22.1:22000 → 10.0.22.2:80.
	synPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 22000, DstPort: 80, SYN: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, synPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	entry := lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.22.1", "10.0.22.2", 22000, 80, protoTCP)
	assert.Equal(t, uint8(0x02), entry.FlagsSeenTxDir, "initial TX: SYN")
	assert.Equal(t, uint8(0x00), entry.FlagsSeenRxDir, "initial RX: empty")

	// Reply SYN-ACK: 10.0.22.2:80 → 10.0.22.1:22000 (reverse 5-tuple).
	// Conntrack finds the entry via reverse key lookup and updates RX fields.
	synAckPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: dstIP, DstIP: srcIP, SrcPort: 80, DstPort: 22000, SYN: true, ACK: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, synAckPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	// Entry is still under the forward (initiator's) key.
	entry = lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.22.1", "10.0.22.2", 22000, 80, protoTCP)
	// TX unchanged.
	assert.Equal(t, uint8(0x02), entry.FlagsSeenTxDir, "TX should still be SYN")
	// RX updated with SYN|ACK.
	assert.Equal(t, uint8(0x12), entry.FlagsSeenRxDir, "RX should be SYN|ACK after reply")

	// Forward ACK: 10.0.22.1:22000 → 10.0.22.2:80.
	ackPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 22000, DstPort: 80, ACK: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, ackPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	entry = lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.22.1", "10.0.22.2", 22000, 80, protoTCP)
	// TX accumulates ACK.
	assert.Equal(t, uint8(0x12), entry.FlagsSeenTxDir, "TX should be SYN|ACK after handshake")
	// RX unchanged.
	assert.Equal(t, uint8(0x12), entry.FlagsSeenRxDir, "RX still SYN|ACK")
}

func TestConntrackDirectionUnknown(t *testing.T) {
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.23.1")
	dstIP := net.ParseIP("10.0.23.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	// Send PSH+ACK as the first packet (simulates missed SYN — ongoing connection).
	pkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 23000, DstPort: 80, PSH: true, ACK: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)
	drainPerfEvent(reader, perfReaderTimeout)

	// ACK flag is set → _ct_handle_tcp_connection treats as reply → stored under reverse key.
	entry := lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.23.2", "10.0.23.1", 80, 23000, protoTCP)

	assert.True(t, entry.IsDirectionUnknown,
		"IsDirectionUnknown should be true for non-SYN first packet")
	// Flags stored in RX direction (treated as reply due to ACK).
	assert.Equal(t, uint8(0x18), entry.FlagsSeenRxDir, "RX should have PSH|ACK (0x18)")
	assert.Equal(t, uint8(0x00), entry.FlagsSeenTxDir, "TX should be empty")
}

func TestConntrackSinceLastReportAccumulation(t *testing.T) {
	// At HIGH aggregation, packets that don't introduce new flags are suppressed.
	// Their bytes and packet counts accumulate in "since last report" counters.
	objs, reader := compileAndLoadVariant(t, compileOpts{
		bypassFilter:     1,
		enableConntrack:  false,
		aggregationLevel: 1, // HIGH
		samplingRate:     1,
	})

	srcIP := net.ParseIP("10.0.24.1")
	dstIP := net.ParseIP("10.0.24.2")

	// SYN creates the entry (reported — SYN is a should_report flag).
	synPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 24000, DstPort: 80, SYN: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, synPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	// First ACK introduces new flag → reported → counters reset.
	ackPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 24000, DstPort: 80, ACK: true,
		PayloadSize: 100,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, ackPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	// Subsequent identical ACKs: no new flags, within 30s → NOT reported → counters accumulate.
	for i := 0; i < 3; i++ {
		ebpftest.RunProgram(t, objs.EndpointIngressFilter, ackPkt)
		drainPerfEvent(reader, 100*time.Millisecond)
	}

	entry := lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.24.1", "10.0.24.2", 24000, 80, protoTCP)

	// 3 non-reported ACK packets should have accumulated.
	assert.True(t, entry.PacketsSeenSinceLastReportTxDir >= 3,
		"expected PacketsSeenSinceLastReportTxDir >= 3, got %d",
		entry.PacketsSeenSinceLastReportTxDir)
	assert.True(t, entry.BytesSeenSinceLastReportTxDir > 0,
		"expected BytesSeenSinceLastReportTxDir > 0, got %d",
		entry.BytesSeenSinceLastReportTxDir)

	// FlagsSeenSinceLastReportTxDir should have ACK counts.
	assert.True(t, entry.FlagsSeenSinceLastReportTxDir.Ack >= 3,
		"expected ACK flag count >= 3 since last report, got %d",
		entry.FlagsSeenSinceLastReportTxDir.Ack)
}

func TestConntrackCounterResetOnReport(t *testing.T) {
	// Verify that "since last report" counters reset to 0 when a report is emitted.
	objs, reader := compileAndLoadVariant(t, compileOpts{
		bypassFilter:     1,
		enableConntrack:  false,
		aggregationLevel: 1, // HIGH
		samplingRate:     1,
	})

	srcIP := net.ParseIP("10.0.25.1")
	dstIP := net.ParseIP("10.0.25.2")

	// SYN → reported.
	synPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 25000, DstPort: 80, SYN: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, synPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	// First ACK → reported (new flag), counters reset.
	ackPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 25000, DstPort: 80, ACK: true,
		PayloadSize: 100,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, ackPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	// Send 3 more ACKs to accumulate counters.
	for i := 0; i < 3; i++ {
		ebpftest.RunProgram(t, objs.EndpointIngressFilter, ackPkt)
		drainPerfEvent(reader, 100*time.Millisecond)
	}

	// Verify counters accumulated.
	entry := lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.25.1", "10.0.25.2", 25000, 80, protoTCP)
	require.True(t, entry.PacketsSeenSinceLastReportTxDir >= 3,
		"precondition: counters should be accumulated before FIN")

	// Send FIN+ACK → FIN is a should_report flag → report triggered → counters reset.
	finPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 25000, DstPort: 80, FIN: true, ACK: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, finPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	entry = lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.25.1", "10.0.25.2", 25000, 80, protoTCP)
	assert.Equal(t, uint32(0), entry.PacketsSeenSinceLastReportTxDir,
		"counters should be 0 after FIN report")
	assert.Equal(t, uint32(0), entry.BytesSeenSinceLastReportTxDir,
		"byte counters should be 0 after FIN report")
	assert.Equal(t, uint32(0), entry.FlagsSeenSinceLastReportTxDir.Ack,
		"flag counts should be 0 after FIN report")
}

func TestConntrackMetadataCountersInMap(t *testing.T) {
	// With ENABLE_CONNTRACK_METRICS, the ConntrackMetadata lifetime counters
	// are updated on every packet and never reset.
	objs, reader := compileAndLoadVariant(t, compileOpts{
		bypassFilter:     1,
		enableConntrack:  true,
		aggregationLevel: 0, // LOW — always emit
		samplingRate:     1,
	})

	srcIP := net.ParseIP("10.0.26.1")
	dstIP := net.ParseIP("10.0.26.2")

	// Forward SYN.
	synPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 26000, DstPort: 80, SYN: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, synPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	entry := lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.26.1", "10.0.26.2", 26000, 80, protoTCP)
	// _ct_create_new_tcp_connection sets packets_tx_count=1.
	assert.Equal(t, uint32(1), entry.ConntrackMetadata.PacketsTxCount, "initial TX packets")
	assert.True(t, entry.ConntrackMetadata.BytesTxCount > 0, "initial TX bytes > 0")
	assert.Equal(t, uint32(0), entry.ConntrackMetadata.PacketsRxCount, "initial RX packets")
	assert.Equal(t, uint64(0), entry.ConntrackMetadata.BytesRxCount, "initial RX bytes")

	// Send 2 more forward packets.
	ackPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 26000, DstPort: 80, ACK: true,
		PayloadSize: 200,
	})
	for i := 0; i < 2; i++ {
		ebpftest.RunProgram(t, objs.EndpointIngressFilter, ackPkt)
		drainPerfEvent(reader, perfReaderTimeout)
	}

	entry = lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.26.1", "10.0.26.2", 26000, 80, protoTCP)
	// 1 SYN + 2 ACK = 3 TX packets.
	assert.Equal(t, uint32(3), entry.ConntrackMetadata.PacketsTxCount, "3 TX packets total")

	// Send a reply packet.
	replyPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: dstIP, DstIP: srcIP, SrcPort: 80, DstPort: 26000, ACK: true,
		PayloadSize: 300,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, replyPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	entry = lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.26.1", "10.0.26.2", 26000, 80, protoTCP)
	// TX unchanged.
	assert.Equal(t, uint32(3), entry.ConntrackMetadata.PacketsTxCount, "TX still 3")
	// RX incremented.
	assert.Equal(t, uint32(1), entry.ConntrackMetadata.PacketsRxCount, "1 RX packet")
	assert.True(t, entry.ConntrackMetadata.BytesRxCount > 0, "RX bytes > 0")
}

func TestConntrackEvictionTimeExtended(t *testing.T) {
	// Verify that EvictionTime is extended on subsequent packets.
	objs, reader := loadTestObjects(t)

	srcIP := net.ParseIP("10.0.27.1")
	dstIP := net.ParseIP("10.0.27.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	// SYN: eviction_time = now + CT_SYN_TIMEOUT (60s).
	synPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 27000, DstPort: 80, SYN: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, synPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	entry := lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.27.1", "10.0.27.2", 27000, 80, protoTCP)
	synEviction := entry.EvictionTime
	assert.NotZero(t, synEviction)

	// ACK: eviction_time = now + CT_CONNECTION_LIFETIME_TCP (360s) — should be larger.
	ackPkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: 27000, DstPort: 80, ACK: true,
	})
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, ackPkt)
	drainPerfEvent(reader, perfReaderTimeout)

	entry = lookupConntrackEntry(t, objs.RetinaConntrack,
		"10.0.27.1", "10.0.27.2", 27000, 80, protoTCP)
	assert.True(t, entry.EvictionTime > synEviction,
		"eviction time should increase after ACK (60s SYN timeout → 360s established), got %d → %d",
		synEviction, entry.EvictionTime)
}

func TestEndpointIngressFilter_TCP_RingBuf(t *testing.T) {
	if err := ensureRingBufKernelSupported(); err != nil {
		t.Skipf("ring buffer not supported: %v", err)
	}

	objs, reader := compileAndLoadRingBufVariant(t, compileOpts{
		bypassFilter:     1,
		enableConntrack:  false,
		aggregationLevel: 0,
		samplingRate:     1,
	})

	srcIP := net.ParseIP("10.0.0.1")
	dstIP := net.ParseIP("10.0.0.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	pkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: 12345,
		DstPort: 80,
		SYN:     true,
		SeqNum:  1000,
	})

	// Run program
	ret := ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)
	assert.Equal(t, uint32(tcActUnspec), ret, "expected TC_ACT_UNSPEC return value")

	// Read event from Ring Buffer
	event, ok := ebpftest.ReadRingBufEvent[packetparserPacket](t, reader, perfReaderTimeout)
	require.True(t, ok, "expected a ringbuf event")

	assert.Equal(t, ebpftest.IPToNative("10.0.0.1"), event.SrcIp)
	assert.Equal(t, ebpftest.IPToNative("10.0.0.2"), event.DstIp)
	assert.Equal(t, ebpftest.PortToNetwork(12345), event.SrcPort)
	assert.Equal(t, ebpftest.PortToNetwork(80), event.DstPort)
	assert.Equal(t, uint8(protoTCP), event.Proto)
}

func TestRingBufReaderWrapper(t *testing.T) {
	if err := ensureRingBufKernelSupported(); err != nil {
		t.Skipf("ring buffer not supported: %v", err)
	}

	objs, reader := compileAndLoadRingBufVariant(t, compileOpts{
		bypassFilter:     1,
		enableConntrack:  false,
		aggregationLevel: 0,
		samplingRate:     1,
	})

	wrapper := &ringBufReaderWrapper{reader: reader}

	srcIP := net.ParseIP("10.0.0.1")
	dstIP := net.ParseIP("10.0.0.2")
	ebpftest.PopulateFilterMap(t, objs.RetinaFilter, srcIP, dstIP)

	pkt := ebpftest.BuildTCPPacket(ebpftest.TCPPacketOpts{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: 54321,
		DstPort: 80,
		SYN:     true,
		SeqNum:  2000,
	})

	// Run program to generate an event
	ebpftest.RunProgram(t, objs.EndpointIngressFilter, pkt)

	// Test Read() behavior
	rec, err := wrapper.Read()
	require.NoError(t, err)
	require.NotNil(t, rec.RawSample)

	// Test Close() behavior
	err = wrapper.Close()
	require.NoError(t, err)

	// After closing, Read() should return ringbuf.ErrClosed
	_, err = wrapper.Read()
	assert.ErrorIs(t, err, ringbuf.ErrClosed)
}

// TestTCXLinkLivenessAcrossInterfaceDelete verifies the attachment liveness
// probe against a real kernel: a TCX link on a live veth reports its interface
// index, and reports Ifindex 0 (defunct) once the veth is deleted — the signal
// createQdiscAndAttach uses to drop a stale attachment record and re-attach when
// an interface index is reused. Requires kernel 6.6+ (TCX) and NET_ADMIN.
func TestTCXLinkLivenessAcrossInterfaceDelete(t *testing.T) {
	objs, _ := loadTestObjects(t)

	la := netlink.NewLinkAttrs()
	la.Name = "rtnlive0"
	veth := &netlink.Veth{LinkAttrs: la, PeerName: "rtnlive0p"}
	// Remove any leftover from a previously failed run.
	if old, err := netlink.LinkByName(la.Name); err == nil {
		_ = netlink.LinkDel(old)
	}
	require.NoError(t, netlink.LinkAdd(veth))
	deleted := false
	t.Cleanup(func() {
		if !deleted {
			_ = netlink.LinkDel(veth)
		}
	})

	created, err := netlink.LinkByName(la.Name)
	require.NoError(t, err)
	idx := created.Attrs().Index

	tcx, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.EndpointIngressFilter,
		Attach:    ebpf.AttachTCXIngress,
		Interface: idx,
		Anchor:    link.Head(),
	})
	if errors.Is(err, ebpf.ErrNotSupported) {
		t.Skipf("TCX not supported on this kernel: %v", err)
	}
	require.NoError(t, err)
	t.Cleanup(func() { tcx.Close() })

	// Alive: the probe sees the real interface index.
	info, err := tcx.Info()
	require.NoError(t, err)
	tcxInfo := info.TCX()
	require.NotNil(t, tcxInfo, "expected TCX metadata on a TCX link")
	assert.Equal(t, uint32(idx), tcxInfo.Ifindex, "live link must report its interface index")
	assert.True(t, tcxLinkAlive(tcx), "link on a live interface must probe alive")

	// Delete the interface: the kernel auto-detaches, and the surviving link
	// handle must probe defunct.
	require.NoError(t, netlink.LinkDel(veth))
	deleted = true

	assert.Eventually(t, func() bool { return !tcxLinkAlive(tcx) },
		2*time.Second, 10*time.Millisecond,
		"link must probe dead after its interface is deleted")
}

// TestCreateQdiscAndAttachTC exercises the real legacy-TC path
// (createQdiscAndAttach -> attachViaTC -> go-tc clsact qdisc + BPF filters) and
// the real tcAttachmentAlive probe against a live kernel. Requires NET_ADMIN.
func TestCreateQdiscAndAttachTC(t *testing.T) {
	objs, _ := loadTestObjects(t)

	// This binary (-tags=ebpf) also compiles the unit tests, which mutate these
	// package-var seams to gomock fakes without restoring them. Reset them to the
	// real implementations so this test drives the actual kernel, regardless of
	// test execution order.
	getQdisc = func(tcnl nltc) qdisc { return tcnl.Qdisc() }
	getFilter = func(tcnl nltc) filter { return tcnl.Filter() }
	tcOpen = func(config *tc.Config) (nltc, error) { return tc.Open(config) }
	getFD = func(e *ebpf.Program) int { return e.FD() }

	la := netlink.NewLinkAttrs()
	la.Name = "rtntcatt"
	veth := &netlink.Veth{LinkAttrs: la, PeerName: "rtntcattp"}
	if old, err := netlink.LinkByName(la.Name); err == nil {
		_ = netlink.LinkDel(old)
	}
	require.NoError(t, netlink.LinkAdd(veth))
	deleted := false
	t.Cleanup(func() {
		if !deleted {
			_ = netlink.LinkDel(veth)
		}
	})

	created, err := netlink.LinkByName(la.Name)
	require.NoError(t, err)
	attrs := *created.Attrs()

	p := &packetParser{
		l:                   log.Logger().Named("test"),
		objs:                objs,
		attachmentMap:       &sync.Map{},
		endpointIngressInfo: &ebpf.ProgramInfo{Name: "endpoint_ingress"},
		endpointEgressInfo:  &ebpf.ProgramInfo{Name: "endpoint_egress"},
		tcxSupported:        false, // force the legacy TC path
	}
	t.Cleanup(func() { _ = p.cleanAll() })

	p.createQdiscAndAttach(attrs, Veth)

	value, ok := p.attachmentMap.Load(ifaceToKey(attrs))
	require.True(t, ok, "expected a recorded attachment after TC attach")
	av := value.(*attachmentValue)
	require.Equal(t, attachmentTypeTC, av.attachmentType, "should attach via legacy TC when TCX is disabled")
	assert.True(t, p.attachmentAlive(av), "freshly attached clsact qdisc must probe alive")

	// A re-assert while live must be a no-op (idempotent skip).
	p.createQdiscAndAttach(attrs, Veth)
	value2, _ := p.attachmentMap.Load(ifaceToKey(attrs))
	assert.Same(t, av, value2.(*attachmentValue), "live re-assert must not re-attach")

	// Delete the interface: the kernel removes the clsact qdisc, so the probe
	// must report the attachment dead.
	require.NoError(t, netlink.LinkDel(veth))
	deleted = true
	assert.Eventually(t, func() bool { return !p.attachmentAlive(av) },
		2*time.Second, 10*time.Millisecond,
		"attachment must probe dead after its interface (and clsact qdisc) is deleted")
}

// BenchmarkTCLivenessProbe measures the cost of a single legacy-TC liveness
// probe (attachmentAlive -> a targeted per-ifindex filter query on the clsact
// ingress hook) as the number of attached interfaces grows. Flat ns/op across N
// shows the per-probe cost is O(1), keeping a full re-assert sweep over N
// attachments at O(N) — a system-wide qdisc dump here would make the sweep
// O(N^2). It is not run by CI (needs -bench and NET_ADMIN); run on a privileged
// host with:
//
//	go test -tags=ebpf -run='^$' -bench=BenchmarkTCLivenessProbe ./pkg/plugin/packetparser/
//
// TCX's probe is one per-link Info() syscall, also O(1) (see its benchmark).
func BenchmarkTCLivenessProbe(b *testing.B) {
	objs, _ := loadTestObjects(b)

	// -tags=ebpf also compiles the mock-mutating unit tests; use the real impls.
	getQdisc = func(tcnl nltc) qdisc { return tcnl.Qdisc() }
	getFilter = func(tcnl nltc) filter { return tcnl.Filter() }
	tcOpen = func(config *tc.Config) (nltc, error) { return tc.Open(config) }
	getFD = func(e *ebpf.Program) int { return e.FD() }

	for _, n := range []int{50, 100, 200} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			p := &packetParser{
				l:                   log.Logger().Named("bench"),
				objs:                objs,
				attachmentMap:       &sync.Map{},
				endpointIngressInfo: &ebpf.ProgramInfo{Name: "endpoint_ingress"},
				endpointEgressInfo:  &ebpf.ProgramInfo{Name: "endpoint_egress"},
				tcxSupported:        false, // force legacy TC
			}
			var veths []*netlink.Veth
			b.Cleanup(func() {
				_ = p.cleanAll()
				for _, v := range veths {
					_ = netlink.LinkDel(v)
				}
			})

			// Setup (untimed): create and attach N veths via the real TC path.
			var probeKey attachmentKey
			for i := 0; i < n; i++ {
				la := netlink.NewLinkAttrs()
				la.Name = fmt.Sprintf("rtnbench%d", i)
				veth := &netlink.Veth{LinkAttrs: la, PeerName: fmt.Sprintf("rtnbenchp%d", i)}
				if old, err := netlink.LinkByName(la.Name); err == nil {
					_ = netlink.LinkDel(old)
				}
				require.NoError(b, netlink.LinkAdd(veth))
				veths = append(veths, veth)
				created, err := netlink.LinkByName(la.Name)
				require.NoError(b, err)
				attrs := *created.Attrs()
				p.createQdiscAndAttach(attrs, Veth)
				probeKey = ifaceToKey(attrs)
			}
			val, ok := p.attachmentMap.Load(probeKey)
			require.True(b, ok, "expected an attachment to probe")
			av := val.(*attachmentValue)

			// Timed: one liveness probe per iteration. b.Loop keeps the setup
			// above out of the measured region and runs it only once.
			for b.Loop() {
				if !p.attachmentAlive(av) {
					b.Fatal("attachment should probe alive")
				}
			}
		})
	}
}

// BenchmarkTCXLivenessProbe is the TCX counterpart of BenchmarkTCLivenessProbe.
// A TCX probe is a single per-link Info() syscall, so ns/op should stay flat as
// N grows. Both transports now probe O(1); TCX remains cheaper (no netlink
// round-trips). Requires kernel 6.6+ (TCX) and NET_ADMIN.
// Run alongside the TC benchmark:
//
//	go test -tags=ebpf -run='^$' -bench='BenchmarkTC.*LivenessProbe' ./pkg/plugin/packetparser/
func BenchmarkTCXLivenessProbe(b *testing.B) {
	objs, _ := loadTestObjects(b)
	if !isTCXSupported() {
		b.Skip("TCX not supported on this kernel")
	}
	// The TCX path uses link.AttachTCX directly and none of the mutable TC seams,
	// so no reset is needed here.

	for _, n := range []int{50, 100, 200} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			p := &packetParser{
				l:                   log.Logger().Named("bench"),
				objs:                objs,
				attachmentMap:       &sync.Map{},
				endpointIngressInfo: &ebpf.ProgramInfo{Name: "endpoint_ingress"},
				endpointEgressInfo:  &ebpf.ProgramInfo{Name: "endpoint_egress"},
				tcxSupported:        true, // force TCX
			}
			var veths []*netlink.Veth
			b.Cleanup(func() {
				_ = p.cleanAll()
				for _, v := range veths {
					_ = netlink.LinkDel(v)
				}
			})

			// Setup (untimed): create and attach N veths via the real TCX path.
			var probeKey attachmentKey
			for i := 0; i < n; i++ {
				la := netlink.NewLinkAttrs()
				la.Name = fmt.Sprintf("rtnxbench%d", i)
				veth := &netlink.Veth{LinkAttrs: la, PeerName: fmt.Sprintf("rtnxbenchp%d", i)}
				if old, err := netlink.LinkByName(la.Name); err == nil {
					_ = netlink.LinkDel(old)
				}
				require.NoError(b, netlink.LinkAdd(veth))
				veths = append(veths, veth)
				created, err := netlink.LinkByName(la.Name)
				require.NoError(b, err)
				attrs := *created.Attrs()
				p.createQdiscAndAttach(attrs, Veth)
				probeKey = ifaceToKey(attrs)
			}
			val, ok := p.attachmentMap.Load(probeKey)
			require.True(b, ok, "expected an attachment to probe")
			av := val.(*attachmentValue)
			require.Equal(b, attachmentTypeTCX, av.attachmentType, "setup must use the TCX path")

			for b.Loop() {
				if !p.attachmentAlive(av) {
					b.Fatal("attachment should probe alive")
				}
			}
		})
	}
}
