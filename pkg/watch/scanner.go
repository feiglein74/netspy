package watch

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"netspy/pkg/discovery"
	"netspy/pkg/scanner"
)

// pingHost sends an ICMP ping using the system ping command
// Works on Windows, Linux, and macOS without admin rights
func pingHost(ip string, timeout time.Duration) bool {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		// Windows: -n count, -w timeout in milliseconds
		timeoutMs := int(timeout.Milliseconds())
		if timeoutMs < 1 {
			timeoutMs = 1
		}
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", timeoutMs), ip)
	case "darwin":
		// macOS: -c count, -W timeout in milliseconds
		timeoutMs := int(timeout.Milliseconds())
		if timeoutMs < 1 {
			timeoutMs = 1
		}
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutMs), ip)
	default:
		// Linux: -c count, -W timeout in seconds (minimum 1)
		timeoutSec := int(timeout.Seconds())
		if timeoutSec < 1 {
			timeoutSec = 1
		}
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSec), ip)
	}

	// Run silently - we only care about triggering ARP, not the result
	_ = cmd.Run()
	return true
}

// PerformScanQuiet performs a scan based on the selected mode without output
func PerformScanQuiet(ctx context.Context, network string, netCIDR *net.IPNet, mode string, activeThreads *int32, threadConfig ThreadConfig) []scanner.Host {
	var hosts []scanner.Host
	var err error

	switch mode {
	case "hybrid":
		hosts, err = PerformHybridScanQuiet(ctx, netCIDR, activeThreads, threadConfig)
	case "arp":
		hosts, err = PerformARPScanQuiet(ctx, netCIDR, activeThreads, threadConfig)
	case "fast", "thorough", "conservative":
		hosts, err = PerformNormalScan(network, mode, activeThreads, threadConfig)
	default:
		return nil
	}

	if err != nil {
		return hosts
	}

	// Gateway-Flags setzen (heuristische Erkennung)
	scanner.SetGatewayFlags(hosts, netCIDR)

	return hosts
}

// PerformHybridScanQuiet performs hybrid scan (ARP + details) without output
func PerformHybridScanQuiet(ctx context.Context, netCIDR *net.IPNet, activeThreads *int32, threadConfig ThreadConfig) ([]scanner.Host, error) {
	// Prüfe ob das Ziel-Netzwerk lokal oder fremd ist
	isLocal, _ := discovery.IsLocalSubnet(netCIDR)

	var finalHosts []scanner.Host

	// Nur ARP versuchen wenn lokales Netzwerk
	if isLocal {
		allHosts := []scanner.Host{}

		// Read existing ARP table first (quietly)
		existingHosts := ReadCurrentARPTableQuiet(netCIDR)
		allHosts = append(allHosts, existingHosts...)

		// Populate ARP table
		if err := PopulateARPTableQuiet(ctx, netCIDR); err != nil {
			return allHosts, err
		}

		// Read refreshed ARP table (quietly)
		finalHosts = ReadCurrentARPTableQuiet(netCIDR)

		// Add localhost if it's in the network range
		localhostIP := GetLocalhostIP(netCIDR)
		if localhostIP != nil {
			localMAC := GetLocalMAC()
			finalHosts = append(finalHosts, scanner.Host{
				IP:         localhostIP,
				MAC:        localMAC,
				Vendor:     "localhost",
				DeviceType: "This Computer",
				Online:     true,
			})
		}
	}

	// SSDP/UPnP Discovery wird NICHT im ersten Scan gesetzt!
	// Grund: HTTP title detection (z.B. "Hue") hat höhere Priorität
	// SSDP wird später im Background-DNS-Lookup als letzter Fallback verwendet

	// Fallback zu TCP-Scanning wenn keine ARP-Hosts gefunden (fremdes Subnet oder ARP fehlgeschlagen)
	if len(finalHosts) == 0 {
		// Generate all IPs in network
		ips := discovery.GenerateIPsFromCIDR(netCIDR)

		// Scanner configuration (dynamic based on network size)
		config := scanner.Config{
			Concurrency: threadConfig.Scan,
			Timeout:     500 * time.Millisecond,
			Fast:        false,
			Thorough:    false,
			Quiet:       true,
		}

		s := scanner.New(config)
		tcpHosts, err := s.ScanHosts(ips, activeThreads)
		if err != nil {
			return nil, err
		}

		finalHosts = tcpHosts
	}

	// Skip RTT measurement in watch mode - we'll get RTT from reachability checks
	// This makes the first scan much faster
	return finalHosts, nil
}

// PerformARPScanQuiet performs ARP-based scan without output
func PerformARPScanQuiet(ctx context.Context, netCIDR *net.IPNet, activeThreads *int32, threadConfig ThreadConfig) ([]scanner.Host, error) {
	// Prüfe ob das Ziel-Netzwerk lokal oder fremd ist
	isLocal, _ := discovery.IsLocalSubnet(netCIDR)

	var hosts []scanner.Host

	// Nur ARP versuchen wenn lokales Netzwerk
	if isLocal {
		// Populate ARP table
		if err := PopulateARPTableQuiet(ctx, netCIDR); err != nil {
			return nil, err
		}

		// Read ARP table quietly
		hosts = ReadCurrentARPTableQuiet(netCIDR)
	}

	// Fallback zu TCP-Scanning wenn keine ARP-Hosts gefunden (fremdes Subnet oder ARP fehlgeschlagen)
	if len(hosts) == 0 {
		// Generate all IPs in network
		ips := discovery.GenerateIPsFromCIDR(netCIDR)

		// Scanner configuration (dynamic based on network size)
		config := scanner.Config{
			Concurrency: threadConfig.Scan,
			Timeout:     500 * time.Millisecond,
			Fast:        false,
			Thorough:    false,
			Quiet:       true,
		}

		s := scanner.New(config)
		tcpHosts, err := s.ScanHosts(ips, activeThreads)
		if err != nil {
			return nil, err
		}

		hosts = tcpHosts
	}

	return hosts, nil
}

// PerformNormalScan performs normal TCP/Ping scan
func PerformNormalScan(network string, mode string, activeThreads *int32, threadConfig ThreadConfig) ([]scanner.Host, error) {
	// Parse network input
	_, netCIDR, err := net.ParseCIDR(network)
	if err != nil {
		return nil, fmt.Errorf("invalid network specification: %v", err)
	}

	// Generate all IPs in network
	hosts := discovery.GenerateIPsFromCIDR(netCIDR)

	// Create scanner config based on mode
	var config scanner.Config
	switch mode {
	case "fast":
		config = scanner.Config{
			Concurrency: threadConfig.Scan,
			Timeout:     200 * time.Millisecond,
			Fast:        true,
			Thorough:    false,
			Quiet:       true,
		}
	case "thorough":
		config = scanner.Config{
			Concurrency: threadConfig.Scan,
			Timeout:     1000 * time.Millisecond,
			Fast:        false,
			Thorough:    true,
			Quiet:       true,
		}
	case "conservative":
		config = scanner.Config{
			Concurrency: threadConfig.Scan,
			Timeout:     500 * time.Millisecond,
			Fast:        false,
			Thorough:    false,
			Quiet:       true,
		}
	default:
		config = scanner.Config{
			Concurrency: threadConfig.Scan,
			Timeout:     500 * time.Millisecond,
			Fast:        false,
			Thorough:    false,
			Quiet:       true,
		}
	}

	s := scanner.New(config)
	results, err := s.ScanHosts(hosts, activeThreads)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %v", err)
	}

	return results, nil
}

// ReadCurrentARPTableQuiet reads ARP table without any output (for watch mode)
func ReadCurrentARPTableQuiet(network *net.IPNet) []scanner.Host {
	arpScanner := discovery.NewARPScanner(500 * time.Millisecond)
	arpEntries, err := arpScanner.ScanARPTableQuiet(network)
	if err != nil {
		return nil
	}

	var hosts []scanner.Host
	for _, entry := range arpEntries {
		vendor := discovery.GetMACVendor(entry.MAC.String())
		host := scanner.Host{
			IP:         entry.IP,
			MAC:        entry.MAC.String(),
			Vendor:     vendor,
			RTT:        entry.RTT,
			Online:     entry.Online,
			DeviceType: discovery.DetectDeviceType("", entry.MAC.String(), vendor, nil),
		}
		hosts = append(hosts, host)
	}

	return hosts
}

// PopulateARPTableQuiet populates ARP table by pinging all IPs without output
// Uses ICMP ping (system command) for better device detection
func PopulateARPTableQuiet(ctx context.Context, network *net.IPNet) error {
	ips := discovery.GenerateIPsFromCIDR(network)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 100) // Limit concurrent pings

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(targetIP net.IP) {
			defer wg.Done()
			defer func() { <-semaphore }()

			// Use ICMP ping via system command (works without admin rights)
			pingHost(targetIP.String(), 50*time.Millisecond)
		}(ip)
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond) // Wait for ARP table to update
	return nil
}

// GetLocalhostIP returns the local IP address in the given network, or nil if not found
func GetLocalhostIP(network *net.IPNet) net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Check if IP is in the target network
			if ip != nil && network.Contains(ip) && ip.To4() != nil {
				return ip
			}
		}
	}
	return nil
}

// GetLocalMAC returns the MAC address of the primary network interface
func GetLocalMAC() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range interfaces {
		// Skip loopback and interfaces without MAC
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}

		// Get addresses for this interface
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// Check if interface has a valid IP
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && ip.To4() != nil {
				return iface.HardwareAddr.String()
			}
		}
	}
	return ""
}

// PerformQuickReachabilityCheck performs a quick reachability check on hosts
func PerformQuickReachabilityCheck(ctx context.Context, deviceStates map[string]*DeviceState, activeThreads *int32, threadConfig ThreadConfig) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threadConfig.Reachability)

	for ipStr, state := range deviceStates {
		if state.Status != "online" {
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

			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				return
			}

			// Quick TCP connection attempt on common port
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(parsedIP.String(), "80"), 200*time.Millisecond)
			if err == nil {
				_ = conn.Close()
			}
		}(ipStr, state)
	}

	wg.Wait()
}
