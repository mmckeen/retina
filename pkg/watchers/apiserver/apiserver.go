// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package apiserver

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/microsoft/retina/pkg/common"
	cc "github.com/microsoft/retina/pkg/controllers/cache"
	"github.com/microsoft/retina/pkg/log"
	fm "github.com/microsoft/retina/pkg/managers/filtermanager"
	"github.com/microsoft/retina/pkg/pubsub"
	"github.com/microsoft/retina/pkg/utils"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	kcfg "sigs.k8s.io/controller-runtime/pkg/client/config"
)

const (
	filterManagerRetries = 3
	hostLookupRetries    = 6 // 6 retries for a total of 63 seconds.
)

type ApiServerWatcher struct {
	isRunning           bool
	l                   *log.ZapLogger
	mu                  sync.Mutex // guards current against concurrent snapshot reads
	current             cache
	new                 cache
	apiServerHostName   string
	hostResolver        IHostResolver
	filterManager       fm.IFilterManager
	restConfig          *rest.Config
	client              kclient.Client
	filterMapMaxEntries uint32
}

var a *ApiServerWatcher

// Watcher creates a new ApiServerWatcher instance.
func Watcher(filterMapMaxEntries uint32) *ApiServerWatcher {
	if a == nil {
		a = &ApiServerWatcher{
			isRunning:           false,
			l:                   log.Logger().Named("apiserver-watcher"),
			current:             make(cache),
			hostResolver:        net.DefaultResolver,
			filterMapMaxEntries: filterMapMaxEntries,
		}
	}

	return a
}

func (a *ApiServerWatcher) Init(ctx context.Context) error {
	if a.isRunning {
		a.l.Info("apiserver watcher is already running")
		return nil
	}

	// Get filter manager.
	if a.filterManager == nil {
		var err error
		a.filterManager, err = fm.Init(filterManagerRetries, a.filterMapMaxEntries)
		if err != nil {
			a.l.Error("failed to init filter manager", zap.Error(err))
			return fmt.Errorf("failed to init filter manager: %w", err)
		}
	}

	// Get  kubeconfig.
	if a.restConfig == nil {
		config, err := kcfg.GetConfig()
		if err != nil {
			a.l.Error("failed to get kubeconfig", zap.Error(err))
			return fmt.Errorf("failed to get kubeconfig: %w", err)
		}
		a.restConfig = config
	}

	if a.client == nil {
		c, err := kclient.New(a.restConfig, kclient.Options{})
		if err != nil {
			a.l.Error("failed to create kubernetes client", zap.Error(err))
			return fmt.Errorf("failed to create kubernetes client: %w", err)
		}
		a.client = c
	}

	hostName, err := a.getHostName()
	if err != nil {
		a.l.Error("failed to get host name", zap.Error(err))
		return fmt.Errorf("failed to get host name: %w", err)
	}
	a.apiServerHostName = hostName

	// Register the snapshot source so a subscriber that joins after the watcher
	// replays the current apiserver IP set immediately.
	pubsub.New().RegisterSource(common.PubSubAPIServer, a.snapshot)

	a.isRunning = true

	return nil
}

// snapshot returns the current apiserver IPs as a single add event. Registered
// as the pubsub source so late subscribers converge to the current set. It
// applies the same IPv4 filter as Refresh's publishes: an IPv6 IP handed out
// here would never be re-asserted nor deleted by the publish path, leaving the
// subscriber with it forever.
func (a *ApiServerWatcher) snapshot() []interface{} {
	a.mu.Lock()
	ips := make([]string, 0, len(a.current))
	for k := range a.current {
		if net.ParseIP(k).To4() == nil {
			a.l.Warn("skipping non-IPv4 apiserver IP in snapshot", zap.String("ip", k))
			continue
		}
		ips = append(ips, k)
	}
	a.mu.Unlock()
	if len(ips) == 0 {
		return nil
	}
	return []interface{}{cc.NewCacheEvent(cc.EventTypeAddAPIServerIPs, common.NewAPIServerObject(ips))}
}

// Stop stops the ApiServerWatcher.
func (a *ApiServerWatcher) Stop(ctx context.Context) error {
	if !a.isRunning {
		a.l.Info("apiserver watcher is not running")
		return nil
	}
	a.isRunning = false
	return nil
}

func (a *ApiServerWatcher) Refresh(ctx context.Context) error {
	err := a.initNewCache(ctx)
	if err != nil {
		a.l.Error("failed to initialize new cache", zap.Error(err))
		return err
	}

	// created is only for operator-visible logging; adds are re-asserted from the
	// full current set below. deleted drives removals.
	created, deleted := a.diffCache()
	for _, v := range created {
		a.l.Info("New Apiserver IP", zap.Any("ip", v))
	}
	for _, v := range deleted {
		a.l.Info("Deleted Apiserver IP", zap.Any("ip", v))
	}

	// currentIPs is the full live set (a.new); by construction it excludes
	// anything in deleted (deleted = a.current - a.new). The filter map is
	// IPv4-keyed, so skip anything To4 can't represent (e.g. IPv6 on dual-stack)
	// — appending the nil would otherwise be re-asserted every refresh.
	currentIPs := make([]net.IP, 0, len(a.new))
	for k := range a.new {
		if ip := net.ParseIP(k).To4(); ip != nil {
			currentIPs = append(currentIPs, ip)
		} else {
			a.l.Warn("skipping non-IPv4 apiserver IP", zap.String("ip", k))
		}
	}
	deletedIPs := make([]net.IP, 0, len(deleted))
	for _, v := range deleted {
		if ip := net.ParseIP(v.(string)).To4(); ip != nil {
			deletedIPs = append(deletedIPs, ip)
		} else {
			a.l.Warn("skipping non-IPv4 apiserver IP", zap.String("ip", v.(string)))
		}
	}

	// Commit current before publishing. snapshot() (served to new subscribers)
	// reads a.current, so committing first ensures a subscriber joining during
	// this refresh never sees a snapshot that still contains an IP whose delete we
	// are about to publish — otherwise it would get the stale add via snapshot but
	// miss the delete and keep the IP forever. currentIPs/deletedIPs are already
	// captured above, so the publishes below are unaffected.
	a.mu.Lock()
	a.current = a.new.deepcopy()
	a.mu.Unlock()
	a.new = nil

	// Publish deletes BEFORE the add re-assert. The cache keys all apiserver IPs
	// under one endpoint (kubernetes-apiserver) and handles a delete by dropping
	// the whole entry, so a delete published after the add would wipe the set
	// just asserted and leave the cache without an apiserver endpoint until the
	// next refresh. Delete-then-add converges immediately; the per-IP consumers
	// are order-insensitive since the two sets are disjoint.
	if len(deletedIPs) > 0 {
		a.publish(deletedIPs, cc.EventTypeDeleteAPIServerIPs)
		if err := a.filterManager.DeleteIPs(deletedIPs, "apiserver-watcher", fm.RequestMetadata{RuleID: "apiserver-watcher"}); err != nil {
			a.l.Error("Failed to delete IPs from filter manager", zap.Error(err))
		}
	}

	// Re-assert all current IPs every refresh (level-triggered, idempotent):
	// consumers self-heal a missed add regardless of subscribe timing, and this
	// retries any filter-map add that previously failed.
	if len(currentIPs) > 0 {
		a.publish(currentIPs, cc.EventTypeAddAPIServerIPs)
		if err := a.filterManager.AddIPs(currentIPs, "apiserver-watcher", fm.RequestMetadata{RuleID: "apiserver-watcher"}); err != nil {
			a.l.Error("Failed to add IPs to filter manager", zap.Error(err))
		}
	}

	return nil
}

func (a *ApiServerWatcher) initNewCache(ctx context.Context) error {
	svcIPs, err := a.ipsFromService(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve ips from kubernetes service: %w", err)
	}

	endpointIPs, err := a.ipsFromEndpointSlice(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve ips from kubernetes endpointslices: %w", err)
	}

	ips, err := a.resolveIPs(ctx, a.apiServerHostName)
	if err != nil {
		return fmt.Errorf("failed to resolve IPs: %w", err)
	}

	ips = append(ips, endpointIPs...)
	ips = append(ips, svcIPs...)

	// Reset new cache.
	a.new = make(cache)
	for _, ip := range ips {
		a.new[ip] = struct{}{}
	}
	return nil
}

func (a *ApiServerWatcher) diffCache() (created, deleted []interface{}) {
	// Check if there are any new IPs.
	for k := range a.new {
		if _, ok := a.current[k]; !ok {
			created = append(created, k)
		}
	}

	// Check if there are any deleted IPs.
	for k := range a.current {
		if _, ok := a.new[k]; !ok {
			deleted = append(deleted, k)
		}
	}
	return
}

func (a *ApiServerWatcher) resolveIPs(ctx context.Context, host string) ([]string, error) {
	// perform a DNS lookup for the host URL using the net.DefaultResolver which uses the local resolver.
	// Possible errors  here are:
	// 	- Canceled context: The context was canceled before the lookup completed.
	// 	-DNS server errors ie NXDOMAIN, SERVFAIL.
	// 	- Network errors ie timeout, unreachable DNS server.
	// 	-Other DNS-related errors encapsulated in a DNSError.
	var hostIPs []string
	var err error

	retryFunc := func() error {
		hostIPs, err = a.hostResolver.LookupHost(ctx, host)
		if err != nil {
			return fmt.Errorf("APIServer LookupHost failed: %w", err)
		}
		return nil
	}

	// Retry the lookup for hostIPs in case of failure.
	err = utils.Retry(retryFunc, hostLookupRetries)
	if err != nil {
		return nil, err
	}

	if len(hostIPs) == 0 {
		a.l.Debug("no IPs found for host", zap.String("host", host))
	}

	return hostIPs, nil
}

// ipsFromService retrieves IP addresses from the master service "kubernetes" in the default namespace.
// These IPs are used as a virtual-ip to the kube-apiserver.
func (a *ApiServerWatcher) ipsFromService(ctx context.Context) ([]string, error) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubernetes",
			Namespace: "default",
		},
	}
	if err := a.client.Get(ctx, kclient.ObjectKeyFromObject(svc), svc); err != nil {
		return nil, fmt.Errorf("retrieving kubernetes service: %w", err)
	}
	return svc.Spec.ClusterIPs, nil
}

// ipsFromEndpointSlice retrieves IP addresses from the EndpointSlices that
// back the "kubernetes" service in the default namespace. These IPs are the
// addresses for the kube-apiserver.
func (a *ApiServerWatcher) ipsFromEndpointSlice(ctx context.Context) ([]string, error) {
	var sliceList discoveryv1.EndpointSliceList
	if err := a.client.List(ctx, &sliceList,
		kclient.InNamespace("default"),
		kclient.MatchingLabels{discoveryv1.LabelServiceName: "kubernetes"},
	); err != nil {
		return nil, fmt.Errorf("retrieving kubernetes endpointslices: %w", err)
	}
	ips := []string{}
	for i := range sliceList.Items {
		for _, ep := range sliceList.Items[i].Endpoints {
			ips = append(ips, ep.Addresses...)
		}
	}
	return ips, nil
}

func (a *ApiServerWatcher) publish(netIPs []net.IP, eventType cc.EventType) {
	if len(netIPs) == 0 {
		return
	}

	ipsToPublish := []string{}
	for _, ip := range netIPs {
		ipsToPublish = append(ipsToPublish, ip.String())
	}
	ps := pubsub.New()
	ps.Publish(common.PubSubAPIServer, cc.NewCacheEvent(eventType, common.NewAPIServerObject(ipsToPublish)))
	a.l.Debug("Published event", zap.Any("eventType", eventType), zap.Any("netIPs", ipsToPublish))
}

func (a *ApiServerWatcher) getHostName() (string, error) {
	// Parse the host URL.
	hostURL := a.restConfig.Host
	parsedURL, err := url.ParseRequestURI(hostURL)
	if err != nil {
		log.Logger().Error("failed to parse URL", zap.String("url", hostURL), zap.Error(err))
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	// Extract the host name from the URL.
	host := strings.TrimPrefix(parsedURL.Host, "www.")
	if colonIndex := strings.IndexByte(host, ':'); colonIndex != -1 {
		host = host[:colonIndex]
	}
	return host, nil
}
