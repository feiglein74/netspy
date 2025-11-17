package discovery

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// SSDPDevice repräsentiert ein via SSDP entdecktes Gerät
type SSDPDevice struct {
	IP       string
	Location string
	Server   string
	ST       string // Service Type
	USN      string // Unique Service Name
}

// DiscoverSSDPDevices sendet SSDP M-SEARCH Multicast und sammelt Antworten
func DiscoverSSDPDevices(timeout time.Duration) ([]SSDPDevice, error) {
	// SSDP Multicast-Adresse und Port
	multicastAddr := "239.255.255.250:1900"

	// M-SEARCH Request
	searchRequest := "M-SEARCH * HTTP/1.1\r\n" +
		"Host: 239.255.255.250:1900\r\n" +
		"Man: \"ssdp:discover\"\r\n" +
		"MX: 3\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"

	// UDP Connection erstellen
	addr, err := net.ResolveUDPAddr("udp4", multicastAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve multicast address: %w", err)
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Timeout setzen
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// M-SEARCH Request senden
	if _, err := conn.WriteToUDP([]byte(searchRequest), addr); err != nil {
		return nil, fmt.Errorf("failed to send M-SEARCH: %w", err)
	}

	// Antworten sammeln
	devices := make([]SSDPDevice, 0)
	seenIPs := make(map[string]bool)
	buffer := make([]byte, 8192)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			// Timeout erreicht - normal
			break
		}

		if n == 0 {
			continue
		}

		// Parse Response
		response := string(buffer[:n])
		device := parseSSDPResponse(response, remoteAddr.IP.String())

		// Nur eindeutige IPs speichern
		if device.IP != "" && !seenIPs[device.IP] {
			devices = append(devices, device)
			seenIPs[device.IP] = true
		}
	}

	return devices, nil
}

// parseSSDPResponse parst eine SSDP-Antwort
func parseSSDPResponse(response string, ip string) SSDPDevice {
	device := SSDPDevice{IP: ip}

	scanner := bufio.NewScanner(strings.NewReader(response))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		// Header parsen
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToUpper(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch key {
		case "LOCATION":
			device.Location = value
		case "SERVER":
			device.Server = value
		case "ST":
			device.ST = value
		case "USN":
			device.USN = value
		}
	}

	return device
}

// GetSSDPDeviceName extrahiert einen sinnvollen Device-Namen aus SSDP-Daten
func GetSSDPDeviceName(device SSDPDevice) string {
	// 1. Versuche aus Server-Header (z.B. "Windows/10 UPnP/1.0 ...")
	if device.Server != "" {
		// Extrahiere OS-Info
		parts := strings.Fields(device.Server)
		if len(parts) > 0 {
			// Erste Komponente ist meist OS oder Vendor
			os := parts[0]
			// Entferne Version nach /
			if idx := strings.Index(os, "/"); idx > 0 {
				os = os[:idx]
			}
			return os
		}
	}

	// 2. Versuche aus Service Type (z.B. "urn:schemas-upnp-org:device:MediaRenderer:1")
	if device.ST != "" && strings.Contains(device.ST, "device:") {
		parts := strings.Split(device.ST, ":")
		for i, part := range parts {
			if part == "device" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}

	// 3. Fallback: "UPnP Device"
	return "UPnP"
}
