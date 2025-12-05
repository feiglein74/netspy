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
	// 22=SSH, 80=HTTP, 443=HTTPS, 445=SMB(Windows), 135=RPC(Windows)
	reliablePorts := []string{"22", "80", "443", "445", "135"}

	// Use shorter timeouts to avoid hanging on filtered ports
	portTimeout := p.timeout / time.Duration(len(reliablePorts))
	if portTimeout > 300*time.Millisecond {
		portTimeout = 300 * time.Millisecond
	}

	for _, port := range reliablePorts {
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), portTimeout); err == nil {
			_ = conn.Close() // Ignore close error
			return time.Since(start), nil
		}
	}

	return 0, fmt.Errorf("no reliable response")
}

// fastPing minimal detection for speed
func (p *Pinger) fastPing(ip net.IP, start time.Time) (time.Duration, error) {
	// Try HTTP first (most common)
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "80"), p.timeout); err == nil {
		_ = conn.Close() // Ignore close error
		return time.Since(start), nil
	}

	// Try HTTPS
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "443"), p.timeout/2); err == nil {
		_ = conn.Close() // Ignore close error
		return time.Since(start), nil
	}

	// Try Windows SMB (common for Windows machines without web services)
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "445"), p.timeout/2); err == nil {
		_ = conn.Close() // Ignore close error
		return time.Since(start), nil
	}

	return 0, fmt.Errorf("no response")
}

// thoroughPing tries more ports but with validation
func (p *Pinger) thoroughPing(ip net.IP, start time.Time) (time.Duration, error) {
	// Try common ports but validate responses
	// Added 135 (Windows RPC) and 445 (Windows SMB) for better Windows detection
	commonPorts := []string{"22", "23", "25", "53", "80", "110", "135", "143", "445", "443", "993", "995", "3389"}

	portTimeout := p.timeout / time.Duration(len(commonPorts))
	if portTimeout < 100*time.Millisecond {
		portTimeout = 100 * time.Millisecond
	}

	for _, port := range commonPorts {
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), portTimeout); err == nil {
			_ = conn.Close() // Ignore close error
			// Validate this isn't a false positive by trying a second connection
			if conn2, err2 := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), portTimeout); err2 == nil {
				_ = conn2.Close() // Ignore close error
				return time.Since(start), nil
			}
		}
	}

	return 0, fmt.Errorf("no validated response")
}

// incrementIP increments an IP address by offset
func incrementIP(ip net.IP, offset int) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)

	for j := len(result) - 1; j >= 0 && offset > 0; j-- {
		add := offset & 0xFF
		sum := int(result[j]) + add
		result[j] = byte(sum & 0xFF)
		offset = (offset >> 8) + (sum >> 8)
	}

	return result
}

// GenerateIPsFromCIDR generates IP addresses
func GenerateIPsFromCIDR(network *net.IPNet) []net.IP {
	ip := network.IP.Mask(network.Mask)
	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	numHosts := 1 << hostBits

	// Handle /32 edge case (single host)
	if ones == 32 || ones == 128 {
		return []net.IP{ip}
	}

	// Handle /31 edge case (point-to-point)
	if numHosts == 2 {
		return []net.IP{
			incrementIP(ip, 0),
			incrementIP(ip, 1),
		}
	}

	maxHosts := numHosts - 2
	ips := make([]net.IP, 0, maxHosts)

	// Hinweis entfernt - stört tview-Modus
	_ = maxHosts // Compiler-Warnung vermeiden

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
