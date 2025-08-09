package discovery

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// ARPScanner performs ARP-based host discovery
type ARPScanner struct {
	timeout time.Duration
}

// NewARPScanner creates a new ARP scanner
func NewARPScanner(timeout time.Duration) *ARPScanner {
	return &ARPScanner{
		timeout: timeout,
	}
}

// ARPEntry represents an ARP table entry
type ARPEntry struct {
	IP     net.IP
	MAC    net.HardwareAddr
	RTT    time.Duration
	Online bool
}

// ScanARPTable reads the actual system ARP table
func (a *ARPScanner) ScanARPTable(network *net.IPNet) ([]ARPEntry, error) {
	fmt.Printf("📋 Reading system ARP table...\n")

	// Get ARP table entries
	arpEntries, err := a.getSystemARPTable()
	if err != nil {
		return nil, fmt.Errorf("failed to read ARP table: %v", err)
	}

	// Filter entries that are in our target network
	var filteredEntries []ARPEntry
	for _, entry := range arpEntries {
		if network.Contains(entry.IP) {
			filteredEntries = append(filteredEntries, entry)
		}
	}

	fmt.Printf("✅ Found %d hosts in ARP table for network %s\n", len(filteredEntries), network.String())
	return filteredEntries, nil
}

// getSystemARPTable reads the system's ARP table
func (a *ARPScanner) getSystemARPTable() ([]ARPEntry, error) {
	switch runtime.GOOS {
	case "windows":
		return a.getWindowsARPTable()
	case "linux":
		return a.getLinuxARPTable()
	case "darwin":
		return a.getMacARPTable()
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// getWindowsARPTable reads ARP table on Windows
func (a *ARPScanner) getWindowsARPTable() ([]ARPEntry, error) {
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run arp command: %v", err)
	}

	return a.parseWindowsARPOutput(string(output))
}

// parseWindowsARPOutput parses Windows arp -a output
func (a *ARPScanner) parseWindowsARPOutput(output string) ([]ARPEntry, error) {
	var entries []ARPEntry

	// Windows arp -a format:
	// Interface: 192.168.1.100 --- 0x5
	//   Internet Address      Physical Address      Type
	//   192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic
	//   192.168.1.254        11-22-33-44-55-66     dynamic

	lines := strings.Split(output, "\n")

	// Regex to match IP and MAC address lines
	// Matches: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
	arpRegex := regexp.MustCompile(`^\s+(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9\-]{17})\s+\w+`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if matches := arpRegex.FindStringSubmatch(line); matches != nil {
			ipStr := matches[1]
			macStr := matches[2]

			// Parse IP
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}

			// Parse MAC (convert Windows format aa-bb-cc-dd-ee-ff to standard)
			macStr = strings.ReplaceAll(macStr, "-", ":")
			mac, err := net.ParseMAC(macStr)
			if err != nil {
				continue
			}

			// Skip multicast and broadcast MACs
			if mac[0]&0x01 != 0 || strings.Contains(macStr, "ff:ff:ff:ff:ff:ff") {
				continue
			}

			entries = append(entries, ARPEntry{
				IP:     ip,
				MAC:    mac,
				RTT:    0, // ARP table doesn't provide RTT
				Online: true,
			})
		}
	}

	return entries, nil
}

// getLinuxARPTable reads ARP table on Linux
func (a *ARPScanner) getLinuxARPTable() ([]ARPEntry, error) {
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run arp command: %v", err)
	}

	return a.parseLinuxARPOutput(string(output))
}

// parseLinuxARPOutput parses Linux arp -a output
func (a *ARPScanner) parseLinuxARPOutput(output string) ([]ARPEntry, error) {
	var entries []ARPEntry

	// Linux arp -a format:
	// gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
	// host1 (192.168.1.100) at 11:22:33:44:55:66 [ether] on eth0

	lines := strings.Split(output, "\n")
	arpRegex := regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\) at ([a-fA-F0-9:]{17})`)

	for _, line := range lines {
		if matches := arpRegex.FindStringSubmatch(line); matches != nil {
			ipStr := matches[1]
			macStr := matches[2]

			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}

			mac, err := net.ParseMAC(macStr)
			if err != nil {
				continue
			}

			// Skip multicast MACs
			if mac[0]&0x01 != 0 {
				continue
			}

			entries = append(entries, ARPEntry{
				IP:     ip,
				MAC:    mac,
				RTT:    0,
				Online: true,
			})
		}
	}

	return entries, nil
}

// getMacARPTable reads ARP table on macOS
func (a *ARPScanner) getMacARPTable() ([]ARPEntry, error) {
	// macOS uses similar format to Linux
	return a.getLinuxARPTable()
}

// RefreshARPTable tries to populate ARP table by pinging broadcast/common IPs
func (a *ARPScanner) RefreshARPTable(network *net.IPNet) error {
	fmt.Printf("🔄 Refreshing ARP table (this may take a moment)...\n")

	// Generate a few IPs to ping to populate ARP table
	ips := GenerateIPsFromCIDR(network)

	// Limit to first 50 IPs for ARP refresh to avoid spam
	maxRefresh := 50
	if len(ips) > maxRefresh {
		ips = ips[:maxRefresh]
	}

	// Ping IPs quickly to populate ARP table
	for _, ip := range ips {
		go func(targetIP net.IP) {
			// Very short ping just to trigger ARP
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetIP.String(), "80"), 100*time.Millisecond)
			if err == nil {
				conn.Close()
			}
		}(ip)
	}

	// Wait a bit for ARP entries to populate
	time.Sleep(2 * time.Second)
	return nil
}
