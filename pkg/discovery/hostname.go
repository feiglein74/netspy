package discovery

import (
	"net"
	"strings"
	"time"
)

// HostnameResult enthält den aufgelösten Hostnamen und seine Quelle
type HostnameResult struct {
	Hostname string
	Source   string // "dns", "mdns", "netbios", "llmnr"
}

// ResolveHostname versucht mehrere Methoden um einen Hostnamen aufzulösen
// Versucht Methoden in Reihenfolge von Zuverlässigkeit und Geschwindigkeit:
// 1. DNS (am schnellsten, zuverlässigsten)
// 2. mDNS (Apple/IoT-Geräte)
// 3. NetBIOS (Windows-Geräte)
// 4. LLMNR (Windows-Fallback)
func ResolveHostname(ip net.IP, timeout time.Duration) HostnameResult {
	// Method 1: DNS reverse lookup (fastest, try first)
	if names, err := net.LookupAddr(ip.String()); err == nil && len(names) > 0 {
		hostname := cleanHostname(names[0])
		if hostname != "" {
			return HostnameResult{
				Hostname: hostname,
				Source:   "dns",
			}
		}
	}

	// Method 2: mDNS/Bonjour (for Apple devices, IoT, Linux)
	// Try this before NetBIOS as it's faster and works for more device types
	if name, err := QueryMDNSName(ip, timeout/2); err == nil && name != "" {
		return HostnameResult{
			Hostname: cleanHostname(name),
			Source:   "mdns",
		}
	}

	// Method 3: NetBIOS (for Windows devices)
	if name, err := QueryNetBIOSName(ip, timeout/2); err == nil && name != "" {
		return HostnameResult{
			Hostname: cleanHostname(name),
			Source:   "netbios",
		}
	}

	// Method 4: LLMNR (Windows fallback)
	if name, err := QueryLLMNRDirect(ip, timeout/2); err == nil && name != "" {
		return HostnameResult{
			Hostname: cleanHostname(name),
			Source:   "llmnr",
		}
	}

	// No hostname found
	return HostnameResult{
		Hostname: "",
		Source:   "",
	}
}

// ResolveFast attempts only fast methods (DNS + mDNS)
// Use this for initial scans where speed is important
func ResolveFast(ip net.IP, timeout time.Duration) HostnameResult {
	// Try DNS first
	if names, err := net.LookupAddr(ip.String()); err == nil && len(names) > 0 {
		hostname := cleanHostname(names[0])
		if hostname != "" {
			return HostnameResult{
				Hostname: hostname,
				Source:   "dns",
			}
		}
	}

	// Try mDNS (fast for Apple/IoT devices)
	if name, err := QueryMDNSName(ip, timeout); err == nil && name != "" {
		return HostnameResult{
			Hostname: cleanHostname(name),
			Source:   "mdns",
		}
	}

	return HostnameResult{
		Hostname: "",
		Source:   "",
	}
}

// ResolveBackground performs slow resolution methods in background
// Use this for watch mode where we want thorough resolution
func ResolveBackground(ip net.IP, timeout time.Duration) HostnameResult {
	// Try NetBIOS first (good for Windows)
	if name, err := QueryNetBIOSName(ip, timeout/2); err == nil && name != "" {
		return HostnameResult{
			Hostname: cleanHostname(name),
			Source:   "netbios",
		}
	}

	// Try LLMNR
	if name, err := QueryLLMNRDirect(ip, timeout/2); err == nil && name != "" {
		return HostnameResult{
			Hostname: cleanHostname(name),
			Source:   "llmnr",
		}
	}

	// Try mDNS as last resort
	if name, err := QueryMDNSName(ip, timeout/2); err == nil && name != "" {
		return HostnameResult{
			Hostname: cleanHostname(name),
			Source:   "mdns",
		}
	}

	// Fallback to DNS
	if names, err := net.LookupAddr(ip.String()); err == nil && len(names) > 0 {
		hostname := cleanHostname(names[0])
		if hostname != "" {
			return HostnameResult{
				Hostname: hostname,
				Source:   "dns",
			}
		}
	}

	return HostnameResult{
		Hostname: "",
		Source:   "",
	}
}

// cleanHostname removes unwanted suffixes and formats the hostname
func cleanHostname(hostname string) string {
	if hostname == "" {
		return ""
	}

	// Remove trailing dot
	hostname = strings.TrimSuffix(hostname, ".")

	// Remove common suffixes but keep domain info
	// We keep .local, .home, etc. as they provide context

	// Trim whitespace
	hostname = strings.TrimSpace(hostname)

	return hostname
}

// GetSourceEmoji returns an emoji for the hostname source
func GetSourceEmoji(source string) string {
	switch source {
	case "dns":
		return "🌐" // Globe - standard DNS
	case "mdns":
		return "📡" // Satellite - mDNS/Bonjour
	case "netbios":
		return "💻" // Computer - NetBIOS (Windows)
	case "llmnr":
		return "🔗" // Link - LLMNR
	case "vendor":
		return "[tag]" // Label - from vendor database
	default:
		return ""
	}
}
