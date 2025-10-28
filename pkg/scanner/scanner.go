package scanner

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"netspy/pkg/discovery"
)

// Host represents a discovered network host
type Host struct {
	IP               net.IP        `json:"ip"`
	Hostname         string        `json:"hostname,omitempty"`
	HostnameSource   string        `json:"hostname_source,omitempty"` // "netbios", "dns", "vendor"
	MAC              string        `json:"mac,omitempty"`
	Vendor           string        `json:"vendor,omitempty"`
	DeviceType       string        `json:"device_type,omitempty"` // "Smartphone", "Computer", "IoT", etc.
	HTTPBanner       string        `json:"http_banner,omitempty"` // HTTP server banner (e.g., "nginx/1.18.0")
	RTT              time.Duration `json:"rtt,omitempty"`
	Ports            []int         `json:"ports,omitempty"`
	Online           bool          `json:"online"`
}

// Config holds scanner configuration
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Ports       []int
	RateLimit   time.Duration
	Fast        bool
	Thorough    bool
	Quiet       bool // Suppress progress output
}

// Scanner performs network discovery
type Scanner struct {
	config Config
	pinger *discovery.Pinger
}

// New creates a new scanner instance
func New(config Config) *Scanner {
	if !config.Quiet {
		fmt.Printf("🔧 Scanner mode: ")
		if config.Fast {
			fmt.Printf("Fast (speed over accuracy)\n")
		} else if config.Thorough {
			fmt.Printf("Thorough (accuracy over speed)\n")
		} else {
			fmt.Printf("Balanced (good speed + accuracy)\n")
		}

		fmt.Printf("🔧 Config: %d workers, %v timeout\n",
			config.Concurrency, config.Timeout)
	}

	return &Scanner{
		config: config,
		pinger: discovery.NewPinger(config.Timeout, config.Fast, config.Thorough),
	}
}

// ScanHosts scans with mode-appropriate strategy
func (s *Scanner) ScanHosts(ips []net.IP) ([]Host, error) {
	var (
		results   []Host
		mutex     sync.Mutex
		wg        sync.WaitGroup
		completed int64
	)

	semaphore := make(chan struct{}, s.config.Concurrency)
	total := len(ips)

	if !s.config.Quiet {
		fmt.Printf("🚀 Scanning %d hosts...\n", total)
	}
	start := time.Now()

	// Pre-allocate results
	results = make([]Host, 0, total/4) // Estimate 25% response rate

	for _, ip := range ips {
		wg.Add(1)

		go func(targetIP net.IP) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			host := s.scanHost(targetIP)

			// Add all hosts for thorough mode, only online for others
			if host.Online || s.config.Thorough {
				mutex.Lock()
				results = append(results, host)
				mutex.Unlock()
			}

			// Progress tracking (only if not quiet)
			if !s.config.Quiet {
				done := atomic.AddInt64(&completed, 1)
				if done%20 == 0 || done == int64(total) {
					elapsed := time.Since(start)
					rate := float64(done) / elapsed.Seconds()
					online := 0
					mutex.Lock()
					for _, h := range results {
						if h.Online {
							online++
						}
					}
					mutex.Unlock()
					fmt.Printf("⏳ %d/%d scanned, %d found (%.0f/sec)\n",
						done, total, online, rate)
				}
			}
		}(ip)
	}

	wg.Wait()

	elapsed := time.Since(start)
	onlineCount := 0
	for _, h := range results {
		if h.Online {
			onlineCount++
		}
	}

	if !s.config.Quiet {
		fmt.Printf("✅ Scan completed in %.1fs (%.0f hosts/sec)\n",
			elapsed.Seconds(), float64(total)/elapsed.Seconds())
		fmt.Printf("📊 Found %d online hosts out of %d scanned\n\n", onlineCount, total)
	}

	return results, nil
}

// scanHost with mode-appropriate detection
func (s *Scanner) scanHost(ip net.IP) Host {
	host := Host{
		IP:     ip,
		Online: false,
	}

	// Use appropriate ping method
	if rtt, err := s.pinger.Ping(ip); err == nil {
		host.Online = true
		host.RTT = rtt

		// Hostname lookup (skip in fast mode)
		if !s.config.Fast {
			if names, err := net.LookupAddr(ip.String()); err == nil && len(names) > 0 {
				host.Hostname = names[0]
			}
		}

		// Port scanning if requested
		if len(s.config.Ports) > 0 {
			host.Ports = s.scanPorts(ip, s.config.Ports)
		}
	}

	return host
}

// scanPorts performs port scanning
func (s *Scanner) scanPorts(ip net.IP, ports []int) []int {
	var openPorts []int
	var mutex sync.Mutex
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip.String(), p), s.config.Timeout/2); err == nil {
				conn.Close()
				mutex.Lock()
				openPorts = append(openPorts, p)
				mutex.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}
