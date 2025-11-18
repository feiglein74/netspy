package watch

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netspy/pkg/discovery"
)

// PopulateFromDNSCache fills deviceStates with cached DNS names
func PopulateFromDNSCache(deviceStates map[string]*DeviceState) {
	cache := discovery.ReadDNSCache()
	for ip, hostname := range cache {
		if state, exists := deviceStates[ip]; exists {
			if state.Host.Hostname == "" {
				state.Host.Hostname = hostname
				state.Host.HostnameSource = "dns-cache"
				state.Host.DeviceType = discovery.DetectDeviceType(
					state.Host.Hostname,
					state.Host.MAC,
					state.Host.Vendor,
					state.Host.Ports,
				)
			}
		}
	}
}

// PerformInitialDNSLookups performs fast DNS lookups immediately after scan
func PerformInitialDNSLookups(ctx context.Context, deviceStates map[string]*DeviceState) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 50)
	for ipStr, state := range deviceStates {
		if state.Status != "online" || state.Host.Hostname != "" {
			continue
		}
		wg.Add(1)
		go func(ip string, s *DeviceState) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			}
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				if names, err := net.LookupAddr(parsedIP.String()); err == nil && len(names) > 0 {
					hostname := strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
					if hostname != "" {
						s.Host.Hostname = hostname
						s.Host.HostnameSource = "dns"
						s.LastHostnameLookup = time.Now()
						s.Host.DeviceType = discovery.DetectDeviceType(s.Host.Hostname, s.Host.MAC, s.Host.Vendor, s.Host.Ports)
					}
				}
			}
		}(ipStr, state)
	}
	wg.Wait()
}

// PerformBackgroundDNSLookups performs slow background hostname resolution
func PerformBackgroundDNSLookups(ctx context.Context, deviceStates map[string]*DeviceState, activeThreads *int32, threadConfig ThreadConfig) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threadConfig.DNS)
	retryInterval := 5 * time.Minute
	for ipStr, state := range deviceStates {
		if state.Status != "online" {
			continue
		}
		if state.Host.Hostname != "" && time.Since(state.LastHostnameLookup) < retryInterval {
			continue
		}
		if state.Host.Hostname == "" && !state.LastHostnameLookup.IsZero() && time.Since(state.LastHostnameLookup) < retryInterval {
			continue
		}
		wg.Add(1)
		go func(ip string, s *DeviceState) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case semaphore <- struct{}{}:
				atomic.AddInt32(activeThreads, 1)
				defer func() {
					atomic.AddInt32(activeThreads, -1)
					<-semaphore
				}()
			}
			s.LastHostnameLookup = time.Now()
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				result := discovery.ResolveBackground(parsedIP, 3*time.Second)
				if result.Hostname != "" {
					s.Host.Hostname = result.Hostname
					s.Host.HostnameSource = result.Source
				}
			}
			if s.Host.Hostname != "" || s.Host.HostnameSource != "" {
				s.Host.DeviceType = discovery.DetectDeviceType(s.Host.Hostname, s.Host.MAC, s.Host.Vendor, s.Host.Ports)
			}
		}(ipStr, state)
	}
	wg.Wait()
}
