package watch

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
)

// SplitIPNetworkHost splits an IP into network and host parts based on CIDR
// Returns (networkPart, hostPart, ok). If splitting fails, ok is false.
func SplitIPNetworkHost(ip string, cidr *net.IPNet) (string, string, bool) {
	if cidr == nil {
		return "", "", false
	}

	// Parse the IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", "", false
	}

	// Get CIDR mask size (e.g., 24 for /24)
	maskBits, _ := cidr.Mask.Size()

	// Split IP into octets
	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		return "", "", false
	}

	// Determine split point based on mask
	// /8 → 1 octet network, 3 octets host
	// /16 → 2 octets network, 2 octets host
	// /24 → 3 octets network, 1 octet host
	// /32 → all network, no host (special case)
	var networkOctets int
	if maskBits <= 8 {
		networkOctets = 1
	} else if maskBits <= 16 {
		networkOctets = 2
	} else if maskBits <= 24 {
		networkOctets = 3
	} else {
		// /32 or other edge cases - no host part
		return "", "", false
	}

	// Build network part + host part
	networkPart := strings.Join(octets[:networkOctets], ".") + "."
	hostPart := strings.Join(octets[networkOctets:], ".")

	return networkPart, hostPart, true
}

// ParseNetworkInputSimple generates all IPs from a CIDR network
func ParseNetworkInputSimple(network *net.IPNet) []net.IP {
	// Calculate the number of hosts
	ones, bits := network.Mask.Size()
	hostCount := 1 << uint(bits-ones)

	// Generate IPs
	ips := make([]net.IP, 0, hostCount)
	ip := make(net.IP, len(network.IP))
	copy(ip, network.IP)

	for {
		if network.Contains(ip) {
			newIP := make(net.IP, len(ip))
			copy(newIP, ip)
			ips = append(ips, newIP)
		}

		// Increment IP
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] != 0 {
				break
			}
		}

		// Check if we've wrapped around
		if !network.Contains(ip) {
			break
		}
	}

	return ips
}

// NetworkInterface represents a detected network interface
type NetworkInterface struct {
	Name    string
	IP      string
	Network string
}

// DetectAndSelectNetwork detects network interfaces and prompts user
func DetectAndSelectNetwork() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to detect network interfaces: %v", err)
	}
	networkMap := make(map[string]NetworkInterface)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			var ipNet *net.IPNet
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				ipNet = v
			case *net.IPAddr:
				continue
			}
			if ip == nil || ip.To4() == nil {
				continue
			}
			networkAddr := ipNet.IP.Mask(ipNet.Mask)
			ones, _ := ipNet.Mask.Size()
			networkCIDR := fmt.Sprintf("%s/%d", networkAddr.String(), ones)
			if _, exists := networkMap[networkCIDR]; !exists {
				networkMap[networkCIDR] = NetworkInterface{
					Name:    iface.Name,
					IP:      ip.String(),
					Network: networkCIDR,
				}
			}
		}
	}
	if len(networkMap) == 0 {
		return "", fmt.Errorf("no active network interfaces found")
	}
	var availableNetworks []NetworkInterface
	for _, netif := range networkMap {
		availableNetworks = append(availableNetworks, netif)
	}
	if len(availableNetworks) == 1 {
		fmt.Printf("Auto-detected network: %s (your IP: %s on %s)\n\n",
			availableNetworks[0].Network, availableNetworks[0].IP, availableNetworks[0].Name)
		return availableNetworks[0].Network, nil
	}
	fmt.Println("Multiple networks detected:")
	for i, netif := range availableNetworks {
		fmt.Printf("  %d. %s (your IP: %s on %s)\n", i+1, netif.Network, netif.IP, netif.Name)
	}
	fmt.Print("\nSelect network [1-", len(availableNetworks), "]: ")
	var selection int
	_, err = fmt.Scanln(&selection)
	if err != nil || selection < 1 || selection > len(availableNetworks) {
		return "", fmt.Errorf("invalid selection")
	}
	selectedNetwork := availableNetworks[selection-1]
	fmt.Printf("Selected: %s (your IP: %s on %s)\n\n",
		selectedNetwork.Network, selectedNetwork.IP, selectedNetwork.Name)
	return selectedNetwork.Network, nil
}

// CopyScreenToClipboard kopiert den Screen-Buffer in die Zwischenablage
func CopyScreenToClipboard(screenBuffer *bytes.Buffer, screenBufferMux *sync.Mutex) error {
	screenBufferMux.Lock()
	content := screenBuffer.String()
	screenBufferMux.Unlock()

	// Plattformabhängiges Kopieren in die Zwischenablage
	var cmd *exec.Cmd
	switch {
	case CommandExists("pbcopy"): // macOS
		cmd = exec.Command("pbcopy")
	case CommandExists("xclip"): // Linux mit X11
		cmd = exec.Command("xclip", "-selection", "clipboard")
	case CommandExists("wl-copy"): // Linux mit Wayland
		cmd = exec.Command("wl-copy")
	case CommandExists("clip.exe"): // Windows (WSL) oder Windows
		cmd = exec.Command("clip.exe")
	default:
		return fmt.Errorf("kein Clipboard-Tool gefunden (pbcopy/xclip/wl-copy/clip.exe)")
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("fehler beim Öffnen der stdin-Pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("fehler beim Starten des Clipboard-Tools: %v", err)
	}

	_, err = io.WriteString(stdin, content)
	if err != nil {
		return fmt.Errorf("fehler beim Schreiben in die Zwischenablage: %v", err)
	}

	stdin.Close()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("fehler beim Warten auf Clipboard-Tool: %v", err)
	}

	return nil
}

// CommandExists prüft ob ein Kommando verfügbar ist
func CommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
