// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package metrics

import (
	"slices"
	"strconv"
	"strings"
	"time"

	v1 "github.com/cilium/cilium/api/v1/flow"
	api "github.com/microsoft/retina/crd/api/v1alpha1"
	"github.com/microsoft/retina/pkg/exporter"
	"github.com/microsoft/retina/pkg/log"
	metricsinit "github.com/microsoft/retina/pkg/metrics"
	"github.com/microsoft/retina/pkg/utils"
	"go.uber.org/zap"
)

const (
	TotalCountName = "adv_forward_count"

	// TODO remove bytes as it is not being populated
	TotalBytesName = "adv_forward_bytes"

	TotalCountDesc = "Total number of forwarded packets"
	TotalBytesDesc = "Total number of forwarded bytes"
)

type ForwardMetrics struct {
	baseMetricInterface
	forwardMetric metricsinit.GaugeVec
	// bytesMetric metricsinit.IGaugeVec
	metricName string
}

func NewForwardCountMetrics(ctxOptions *api.MetricsContextOptions, fl *log.ZapLogger, isLocalContext enrichmentContext, ttl time.Duration) *ForwardMetrics {
	if ctxOptions == nil || !strings.Contains(strings.ToLower(ctxOptions.MetricName), "forward") {
		return nil
	}

	l := fl.Named("forward-metricsmodule")
	l.Info("Creating forward count metrics", zap.Any("options", ctxOptions))
	fm := ForwardMetrics{}
	fm.baseMetricInterface = newBaseMetricsObject(ctxOptions, fl, isLocalContext, fm.expire, ttl)
	return &fm
}

func (f *ForwardMetrics) Init(metricName string) {
	switch metricName {
	case utils.ForwardPacketsGaugeName:
		f.forwardMetric = exporter.CreatePrometheusGaugeVecForMetric(
			exporter.AdvancedRegistry,
			TotalCountName,
			TotalCountDesc,
			f.getLabels()...)
	case utils.ForwardBytesGaugeName:
		f.forwardMetric = exporter.CreatePrometheusGaugeVecForMetric(
			exporter.AdvancedRegistry,
			TotalBytesName,
			TotalBytesDesc,
			f.getLabels()...)
	default:
		f.getLogger().Error("unknown metric name", zap.String("name", metricName))
	}
	f.metricName = metricName
}

func (f *ForwardMetrics) getLabels() []string {
	labels := []string{
		utils.Direction,
	}

	if !f.isAdvanced() {
		return labels
	}

	if f.sourceCtx() != nil {
		labels = append(labels, f.sourceCtx().getLabels()...)
		f.getLogger().Info("src labels", zap.Any("labels", labels))
	}

	if f.destinationCtx() != nil {
		labels = append(labels, f.destinationCtx().getLabels()...)
		f.getLogger().Info("dst labels", zap.Any("labels", labels))
	}

	if slices.Contains(f.additionalLabels(), utils.IsReply) {
		labels = append(labels, utils.IsReply)
	}

	return labels
}

func (f *ForwardMetrics) Clean() {
	exporter.UnregisterMetric(exporter.AdvancedRegistry, metricsinit.ToPrometheusType(f.forwardMetric))
	f.clean()
}

// TODO: update ProcessFlow with bytes metrics. We are only accounting for count.
// bytes metrics needs some additional work in ebpf and in this func to get the skb length
func (f *ForwardMetrics) ProcessFlow(flow *v1.Flow) {
	// Flow does not have bytes section at the moment,
	// so we will update only packet count
	if flow == nil {
		return
	}

	if flow.Verdict != v1.Verdict_FORWARDED {
		return
	}

	if f.isLocalContext() {
		// when localcontext is enabled, we do not need the context options for both src and dst
		// metrics aggregation will be on a single pod basis and not the src/dst pod combination basis.
		f.processLocalCtxFlow(flow)
		return
	}

	labels := []string{
		flow.TrafficDirection.String(),
	}
	// reverseLabels mirror labels with source/destination roles and direction
	// swapped, so the opposite direction's counts (flushed on terminal delete)
	// are attributed to the reply direction.
	reverseLabels := []string{
		reverseTrafficDirection(flow.TrafficDirection).String(),
	}

	if !f.isAdvanced() {
		f.update(flow, labels, reverseLabels)
		return
	}

	if f.sourceCtx() != nil {
		srcLabels := f.sourceCtx().getValues(flow)
		if len(srcLabels) > 0 {
			labels = append(labels, srcLabels...)
			reverseLabels = append(reverseLabels, f.sourceCtx().getReverseValues(flow)...)
		}
	}

	if f.destinationCtx() != nil {
		dstLabel := f.destinationCtx().getValues(flow)
		if len(dstLabel) > 0 {
			labels = append(labels, dstLabel...)
			reverseLabels = append(reverseLabels, f.destinationCtx().getReverseValues(flow)...)
		}
	}

	if slices.Contains(f.additionalLabels(), utils.IsReply) {
		labels = append(labels, strconv.FormatBool(flow.GetIsReply().GetValue()))
		reverseLabels = append(reverseLabels, strconv.FormatBool(!flow.GetIsReply().GetValue()))
	}

	f.update(flow, labels, reverseLabels)
	f.getLogger().Debug("forward count metric is added", zap.Any("labels", labels))
}

func (f *ForwardMetrics) processLocalCtxFlow(flow *v1.Flow) {
	labelValuesMap := f.sourceCtx().getLocalCtxValues(flow)
	if labelValuesMap == nil {
		return
	}
	// Ingress values: this pod is the destination in the forward direction, so its
	// reverse-direction traffic is egress (same pod labels).
	if len(labelValuesMap[ingress]) > 0 {
		labels := append([]string{ingress}, labelValuesMap[ingress]...)
		reverseLabels := append([]string{egress}, labelValuesMap[ingress]...)
		f.update(flow, labels, reverseLabels)
		f.getLogger().Debug("forward count metric in INGRESS in local ctx", zap.Any("labels", labels))
	}

	// Egress values: this pod is the source, so its reverse-direction traffic is
	// ingress (same pod labels).
	if len(labelValuesMap[egress]) > 0 {
		labels := append([]string{egress}, labelValuesMap[egress]...)
		reverseLabels := append([]string{ingress}, labelValuesMap[egress]...)
		f.update(flow, labels, reverseLabels)
		f.getLogger().Debug("forward count metric in EGRESS in local ctx", zap.Any("labels", labels))
	}
}

func (f *ForwardMetrics) expire(labels []string) bool {
	var d bool
	if f.forwardMetric != nil {
		d = f.forwardMetric.DeleteLabelValues(labels...)
		if d {
			metricsinit.MetricsExpiredCounter.WithLabelValues(f.metricName).Inc()
		}
	}
	return d
}

func (f *ForwardMetrics) update(fl *v1.Flow, labels, reverseLabels []string) {
	var updated bool
	switch f.metricName {
	case utils.ForwardPacketsGaugeName:
		updated = true
		f.forwardMetric.WithLabelValues(labels...).Add(float64(utils.PreviouslyObservedPackets(fl) + 1))
		// Opposite direction's packets flushed on terminal delete (no +1: there is
		// no current packet in that direction), attributed to the reply direction.
		if rev := utils.PreviouslyObservedPacketsReverse(fl); rev > 0 && reverseLabels != nil {
			f.forwardMetric.WithLabelValues(reverseLabels...).Add(float64(rev))
			f.updated(reverseLabels)
		}
	case utils.ForwardBytesGaugeName:
		updated = true
		f.forwardMetric.WithLabelValues(labels...).Add(float64(utils.PacketSize(fl) + utils.PreviouslyObservedBytes(fl)))
		if rev := utils.PreviouslyObservedBytesReverse(fl); rev > 0 && reverseLabels != nil {
			f.forwardMetric.WithLabelValues(reverseLabels...).Add(float64(rev))
			f.updated(reverseLabels)
		}
	}
	if updated {
		f.updated(labels)
	}
}
