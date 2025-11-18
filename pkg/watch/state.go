package watch

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"netspy/pkg/scanner"

	"github.com/fatih/color"
)

// DeviceState verfolgt den Zustand eines entdeckten Geräts über die Zeit
type DeviceState struct {
	Host                scanner.Host
	FirstSeen           time.Time
	FirstSeenScan       int           // Scan number when first detected (for "new" indicator)
	LastSeen            time.Time
	Status              string        // "online" or "offline"
	StatusSince         time.Time     // When current status started
	FlapCount           int           // Number of times status has changed (flapping counter)
	TotalOfflineTime    time.Duration // Accumulated time spent offline (for continuous uptime calculation)
	LastHostnameLookup  time.Time     // When we last tried to resolve hostname (for retry mechanism)
}

// ThreadConfig holds thread count configuration for different operations
type ThreadConfig struct {
	Scan         int // Scanner threads (TCP/Ping)
	Reachability int // Quick reachability check threads
	DNS          int // DNS/mDNS/NetBIOS lookup threads
}

// SortColumn represents which column to sort by
type SortColumn int

const (
	SortByIP SortColumn = iota
	SortByHostname
	SortByMAC
	SortByVendor
	SortByDeviceType
	SortByRTT
	SortByFirstSeen
	SortByUptime
	SortByFlaps
)

// SortState tracks current sort configuration
type SortState struct {
	Column    SortColumn
	Ascending bool
	mu        sync.RWMutex
}

// Toggle switches sort column or reverses direction
func (s *SortState) Toggle(col SortColumn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Column == col {
		s.Ascending = !s.Ascending
	} else {
		s.Column = col
		s.Ascending = true
	}
}

// Get returns current sort column and direction
func (s *SortState) Get() (SortColumn, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Column, s.Ascending
}

// SortIPs sorts IP addresses based on the current sort state
func SortIPs(ips []string, states map[string]*DeviceState, sortState *SortState, referenceTime time.Time) {
	col, asc := sortState.Get()

	sort.Slice(ips, func(i, j int) bool {
		stateI := states[ips[i]]
		stateJ := states[ips[j]]

		var less bool
		switch col {
		case SortByIP:
			less = CompareIPs(ips[i], ips[j])
		case SortByHostname:
			hostI := GetHostname(stateI.Host)
			hostJ := GetHostname(stateJ.Host)
			if hostI == hostJ {
				// Secondary sort by IP for stable ordering
				less = CompareIPs(ips[i], ips[j])
			} else {
				less = hostI < hostJ
			}
		case SortByMAC:
			macI := stateI.Host.MAC
			macJ := stateJ.Host.MAC
			if macI == macJ {
				// Secondary sort by IP for stable ordering
				less = CompareIPs(ips[i], ips[j])
			} else {
				less = macI < macJ
			}
		case SortByVendor:
			vendorI := GetVendor(stateI.Host)
			vendorJ := GetVendor(stateJ.Host)
			if vendorI == vendorJ {
				// Secondary sort by IP for stable ordering
				less = CompareIPs(ips[i], ips[j])
			} else {
				less = vendorI < vendorJ
			}
		case SortByDeviceType:
			typeI := stateI.Host.DeviceType
			typeJ := stateJ.Host.DeviceType
			if typeI == typeJ {
				// Secondary sort by IP for stable ordering
				less = CompareIPs(ips[i], ips[j])
			} else {
				less = typeI < typeJ
			}
		case SortByRTT:
			if stateI.Host.RTT == stateJ.Host.RTT {
				// Secondary sort by IP for stable ordering
				less = CompareIPs(ips[i], ips[j])
			} else {
				less = stateI.Host.RTT < stateJ.Host.RTT
			}
		case SortByFirstSeen:
			if stateI.FirstSeen.Equal(stateJ.FirstSeen) {
				// Secondary sort by IP for stable ordering
				less = CompareIPs(ips[i], ips[j])
			} else {
				less = stateI.FirstSeen.Before(stateJ.FirstSeen)
			}
		case SortByUptime:
			// Calculate uptime for comparison
			var uptimeI, uptimeJ time.Duration
			if stateI.Status == "online" {
				totalTimeI := referenceTime.Sub(stateI.FirstSeen)
				uptimeI = totalTimeI - stateI.TotalOfflineTime
			} else {
				uptimeI = referenceTime.Sub(stateI.StatusSince)
			}
			if stateJ.Status == "online" {
				totalTimeJ := referenceTime.Sub(stateJ.FirstSeen)
				uptimeJ = totalTimeJ - stateJ.TotalOfflineTime
			} else {
				uptimeJ = referenceTime.Sub(stateJ.StatusSince)
			}
			if uptimeI == uptimeJ {
				// Secondary sort by IP for stable ordering
				less = CompareIPs(ips[i], ips[j])
			} else {
				less = uptimeI < uptimeJ
			}
		case SortByFlaps:
			if stateI.FlapCount == stateJ.FlapCount {
				// Secondary sort by IP for stable ordering
				less = CompareIPs(ips[i], ips[j])
			} else {
				less = stateI.FlapCount < stateJ.FlapCount
			}
		default:
			less = CompareIPs(ips[i], ips[j])
		}

		if !asc {
			less = !less
		}
		return less
	})
}

// GetSortIndicator returns the sort indicator (↑ or ↓) for a column, or empty string
func GetSortIndicator(currentCol SortColumn, targetCol SortColumn, ascending bool) string {
	if currentCol == targetCol {
		if ascending {
			return " ↑"
		}
		return " ↓"
	}
	return ""
}

// UnderlineChar underlines a specific character in a string (case-insensitive)
// Example: underlineChar("Hostname", 'h') → "H̲ostname"
func UnderlineChar(s string, char rune) string {
	charLower := strings.ToLower(string(char))
	charUpper := strings.ToUpper(string(char))

	for i, c := range s {
		if string(c) == charLower || string(c) == charUpper {
			// Found the character - underline it
			return s[:i] + "\033[4m" + string(c) + "\033[24m" + s[i+1:]
		}
	}
	return s // Character not found, return unchanged
}

// CalculateThreads determines optimal thread counts based on network size
func CalculateThreads(netCIDR *net.IPNet, maxThreadsOverride int) ThreadConfig {
	// Count hosts in network
	ones, bits := netCIDR.Mask.Size()
	hostCount := 1 << uint(bits-ones) // 2^(bits-ones)

	// If user specified max threads, scale all thread types proportionally
	if maxThreadsOverride > 0 {
		// Scale: 50% scan, 30% reachability, 20% DNS
		return ThreadConfig{
			Scan:         int(float64(maxThreadsOverride) * 0.50),
			Reachability: int(float64(maxThreadsOverride) * 0.30),
			DNS:          int(float64(maxThreadsOverride) * 0.20),
		}
	}

	// Auto-calculate based on network size
	switch {
	case hostCount <= 16: // /28 or smaller
		return ThreadConfig{Scan: 10, Reachability: 10, DNS: 5}
	case hostCount <= 64: // /26
		return ThreadConfig{Scan: 20, Reachability: 20, DNS: 8}
	case hostCount <= 256: // /24 (most common home/office networks)
		return ThreadConfig{Scan: 40, Reachability: 30, DNS: 10}
	case hostCount <= 1024: // /22
		return ThreadConfig{Scan: 80, Reachability: 50, DNS: 15}
	default: // /16+ (large enterprise networks)
		return ThreadConfig{Scan: 150, Reachability: 80, DNS: 20}
	}
}

// CompareIPs compares two IP addresses for sorting
func CompareIPs(ip1, ip2 string) bool {
	// Parse IPs for proper binary comparison
	parsedIP1 := net.ParseIP(ip1)
	parsedIP2 := net.ParseIP(ip2)

	if parsedIP1 == nil || parsedIP2 == nil {
		// Fallback to string comparison if parsing fails
		return ip1 < ip2
	}

	// Convert to 4-byte representation for IPv4
	parsedIP1 = parsedIP1.To4()
	parsedIP2 = parsedIP2.To4()

	if parsedIP1 == nil || parsedIP2 == nil {
		// Fallback to string comparison
		return ip1 < ip2
	}

	// Compare byte by byte
	for i := 0; i < len(parsedIP1); i++ {
		if parsedIP1[i] != parsedIP2[i] {
			return parsedIP1[i] < parsedIP2[i]
		}
	}

	return false
}

// GetHostname returns the hostname or "-"
func GetHostname(host scanner.Host) string {
	if host.Hostname != "" {
		// DEBUG: Farbige Kennzeichnung für SSDP-gelernte Namen
		if host.HostnameSource == "SSDP" {
			return color.MagentaString(host.Hostname)
		}
		return host.Hostname
	}
	return "-"
}

// GetVendor returns the vendor or "-"
func GetVendor(host scanner.Host) string {
	if host.Vendor != "" {
		return host.Vendor
	}
	return "-"
}
