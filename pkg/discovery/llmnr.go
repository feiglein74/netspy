package discovery

import (
	"fmt"
	"net"
	"time"
)

const (
	llmnrAddress = "224.0.0.252:5355"
	llmnrTimeout = 1 * time.Second
)

// QueryLLMNRName performs a Link-Local Multicast Name Resolution query
// Used by Windows systems as a fallback when DNS fails
func QueryLLMNRName(ip net.IP, timeout time.Duration) (string, error) {
	// LLMNR works differently - we need to query by hostname
	// Since we don't know the hostname, we'll try reverse lookup
	// This is a simplified implementation that listens for LLMNR traffic

	// For now, we'll attempt a reverse PTR query similar to mDNS
	addr, err := net.ResolveUDPAddr("udp4", llmnrAddress)
	if err != nil {
		return "", fmt.Errorf("failed to resolve LLMNR address: %v", err)
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return "", fmt.Errorf("failed to dial LLMNR: %v", err)
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(timeout))

	// Build LLMNR query
	query := buildLLMNRQuery(ip)
	if query == nil {
		return "", fmt.Errorf("failed to build LLMNR query")
	}

	// Send query
	_, err = conn.Write(query)
	if err != nil {
		return "", fmt.Errorf("failed to send LLMNR query: %v", err)
	}

	// Read response
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("no LLMNR response: %v", err)
	}

	// Parse response
	hostname := parseLLMNRResponse(buffer[:n])
	if hostname == "" {
		return "", fmt.Errorf("no hostname in LLMNR response")
	}

	return hostname, nil
}

// buildLLMNRQuery creates an LLMNR query packet for reverse lookup
func buildLLMNRQuery(ip net.IP) []byte {
	// Convert IP to reverse notation
	reversed := reverseIP(ip)
	if reversed == "" {
		return nil
	}

	// LLMNR header (similar to DNS but with different flags)
	query := []byte{
		0x00, 0x00, // Transaction ID
		0x00, 0x00, // Flags (standard query)
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
	}

	// Question: PTR record for reversed IP
	question := encodeDNSName(reversed + ".in-addr.arpa")
	query = append(query, question...)
	query = append(query, 0x00, 0x0C) // Type: PTR
	query = append(query, 0x00, 0x01) // Class: IN

	return query
}

// parseLLMNRResponse extracts hostname from LLMNR response
func parseLLMNRResponse(data []byte) string {
	if len(data) < 12 {
		return ""
	}

	// Check if it's a response (QR bit set)
	if data[2]&0x80 == 0 {
		return ""
	}

	// Get number of answers
	answerCount := int(data[6])<<8 | int(data[7])
	if answerCount == 0 {
		return ""
	}

	// Skip header (12 bytes) and question section
	pos := 12

	// Skip question section (name + type + class)
	for pos < len(data) && data[pos] != 0 {
		if data[pos] >= 0xC0 {
			// Compressed name pointer
			pos += 2
			break
		}
		pos += int(data[pos]) + 1
	}
	if pos < len(data) && data[pos] == 0 {
		pos++ // Skip terminator
	}
	pos += 4 // Skip type and class

	// Parse answer section
	for i := 0; i < answerCount && pos < len(data); i++ {
		// Skip name
		for pos < len(data) && data[pos] != 0 {
			if data[pos] >= 0xC0 {
				pos += 2
				break
			}
			pos += int(data[pos]) + 1
		}
		if pos < len(data) && data[pos] == 0 {
			pos++
		}

		if pos+10 > len(data) {
			break
		}

		recordType := int(data[pos])<<8 | int(data[pos+1])
		pos += 8 // Skip type, class, TTL

		dataLen := int(data[pos])<<8 | int(data[pos+1])
		pos += 2

		if pos+dataLen > len(data) {
			break
		}

		// PTR record (type 12) or A record (type 1)
		if recordType == 12 {
			hostname := decodeDNSName(data, pos)
			if hostname != "" {
				// Remove trailing dot
				if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
					hostname = hostname[:len(hostname)-1]
				}
				return hostname
			}
		}

		pos += dataLen
	}

	return ""
}

// QueryLLMNRDirect performs a direct LLMNR query to a specific IP
// This is more effective than multicast for known IPs
func QueryLLMNRDirect(ip net.IP, timeout time.Duration) (string, error) {
	// Try to connect directly to the host's LLMNR port
	addr := fmt.Sprintf("%s:5355", ip.String())

	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("failed to connect to LLMNR port: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// Build PTR query
	query := buildLLMNRQuery(ip)
	if query == nil {
		return "", fmt.Errorf("failed to build LLMNR query")
	}

	// Send query
	_, err = conn.Write(query)
	if err != nil {
		return "", fmt.Errorf("failed to send LLMNR query: %v", err)
	}

	// Read response
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("no LLMNR response: %v", err)
	}

	// Parse response
	hostname := parseLLMNRResponse(buffer[:n])
	if hostname == "" {
		return "", fmt.Errorf("no hostname in response")
	}

	return hostname, nil
}
