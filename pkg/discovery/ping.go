package discovery

import (
	"fmt"
	"net"
	"time"
)

// Pinger performs conservative host detection
type Pinger struct {
	timeout  time.Duration
	fast     bool
	thorough bool
}

// NewPinger creates a new pinger instance
func NewPinger(timeout time.Duration, fast, thorough bool) *Pinger {
	return &Pinger{
		timeout:  timeout,
		fast:     fast,
		thorough: thorough,
	}
}

// Ping uses conservative detection to minimize false positives
func (p *Pinger) Ping(ip net.IP) (time.Duration, error) {
	start := time.Now()

	if p.fast {
		return p.fastPing(ip, start)
	} else if p.thorough {
		return p.thoroughPing(ip, start)
	} else {
		return p.conservativePing(ip, start)
	}
}

// conservativePing uses only the most reliable detection methods
func (p *Pinger) conservativePing(ip net.IP, start time.Time) (time.Duration, error) {
	// Only try ports that give reliable results
	reliablePorts := []string{"22", "80", "443"}

	// Use shorter timeouts to avoid hanging on filtered ports
	portTimeout := p.timeout / time.Duration(len(reliablePorts))
	if portTimeout > 300*time.Millisecond {
		portTimeout = 300 * time.Millisecond
	}

	for _, port := range reliablePorts {
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), portTimeout); err == nil {
			conn.Close()
			return time.Since(start), nil
		}
	}

	return 0, fmt.Errorf("no reliable response")
}

// fastPing minimal detection for speed
func (p *Pinger) fastPing(ip net.IP, start time.Time) (time.Duration, error) {
	// Only try HTTP
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "80"), p.timeout); err == nil {
		conn.Close()
		return time.Since(start), nil
	}

	// Try HTTPS as backup
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "443"), p.timeout/2); err == nil {
		conn.Close()
		return time.Since(start), nil
	}

	return 0, fmt.Errorf("no response")
}

// thoroughPing tries more ports but with validation
func (p *Pinger) thoroughPing(ip net.IP, start time.Time) (time.Duration, error) {
	// Try common ports but validate responses
	commonPorts := []string{"22", "23", "25", "53", "80", "110", "143", "443", "993", "995", "3389"}

	portTimeout := p.timeout / time.Duration(len(commonPorts))
	if portTimeout < 100*time.Millisecond {
		portTimeout = 100 * time.Millisecond
	}

	for _, port := range commonPorts {
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), portTimeout); err == nil {
			conn.Close()
			// Validate this isn't a false positive by trying a second connection
			if conn2, err2 := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), portTimeout); err2 == nil {
				conn2.Close()
				return time.Since(start), nil
			}
		}
	}

	return 0, fmt.Errorf("no validated response")
}

// GenerateIPsFromCIDR generates IP addresses
func GenerateIPsFromCIDR(network *net.IPNet) []net.IP {
	ip := network.IP.Mask(network.Mask)
	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	numHosts := 1 << hostBits
	maxHosts := numHosts - 2

	ips := make([]net.IP, 0, maxHosts)

	if maxHosts > 254 {
		fmt.Printf("📡 Scanning %d hosts\n", maxHosts)
		fmt.Printf("💡 Tip: Use --arp for most accurate results on local networks\n")
	}

	for i := 1; i < numHosts-1; i++ {
		currentIP := make(net.IP, len(ip))
		copy(currentIP, ip)

		for j := len(currentIP) - 1; j >= 0; j-- {
			currentIP[j] += byte(i >> (8 * (len(currentIP) - 1 - j)))
			if currentIP[j] != 0 {
				break
			}
		}

		if network.Contains(currentIP) {
			ips = append(ips, currentIP)
		}
	}

	return ips
}
