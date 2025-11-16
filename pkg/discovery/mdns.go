package discovery

import (
	"fmt"
	"net"
	"time"
)

const (
	mdnsAddress = "224.0.0.251:5353"
	mdnsTimeout = 1 * time.Second
)

// QueryMDNSName performs a multicast DNS query to resolve hostname
// Used by Apple devices (iPhone, iPad, Mac), Linux, and many IoT devices
func QueryMDNSName(ip net.IP, timeout time.Duration) (string, error) {
	// Create UDP connection for multicast
	addr, err := net.ResolveUDPAddr("udp4", mdnsAddress)
	if err != nil {
		return "", fmt.Errorf("failed to resolve mDNS address: %v", err)
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return "", fmt.Errorf("failed to dial mDNS: %v", err)
	}
	defer func() { _ = conn.Close() }() // Ignore close error

	// Set deadline
	_ = conn.SetDeadline(time.Now().Add(timeout)) // Ignore error - connection will timeout anyway

	// Build mDNS PTR query for reverse IP lookup
	query := buildMDNSQuery(ip)
	if query == nil {
		return "", fmt.Errorf("failed to build mDNS query")
	}

	// Send query
	_, err = conn.Write(query)
	if err != nil {
		return "", fmt.Errorf("failed to send mDNS query: %v", err)
	}

	// Read response
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("no mDNS response: %v", err)
	}

	// Parse response
	hostname := parseMDNSResponse(buffer[:n])
	if hostname == "" {
		return "", fmt.Errorf("no hostname in mDNS response")
	}

	return hostname, nil
}

// buildMDNSQuery creates a DNS query packet for PTR record
func buildMDNSQuery(ip net.IP) []byte {
	// Convert IP to reverse notation: 1.0.0.10 -> 10.0.0.1.in-addr.arpa
	reversed := reverseIP(ip)
	if reversed == "" {
		return nil
	}

	// DNS header
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

// reverseIP converts IP to reverse notation
func reverseIP(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0])
}

// encodeDNSName encodes a domain name in DNS format
func encodeDNSName(name string) []byte {
	var result []byte
	labels := []byte(name)

	start := 0
	for i := 0; i <= len(labels); i++ {
		if i == len(labels) || labels[i] == '.' {
			length := i - start
			result = append(result, byte(length))
			result = append(result, labels[start:i]...)
			start = i + 1
		}
	}
	result = append(result, 0x00) // Terminator

	return result
}

// parseMDNSResponse extracts hostname from mDNS response
func parseMDNSResponse(data []byte) string {
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
		nameStart := pos
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

		// PTR record (type 12) contains the hostname
		if recordType == 12 {
			hostname := decodeDNSName(data, pos)
			if hostname != "" {
				// Remove .local suffix if present
				if len(hostname) > 6 && hostname[len(hostname)-6:] == ".local" {
					hostname = hostname[:len(hostname)-6]
				}
				// Remove trailing dot
				if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
					hostname = hostname[:len(hostname)-1]
				}
				return hostname
			}
		}

		pos += dataLen
		_ = nameStart
	}

	return ""
}

// decodeDNSName decodes a DNS name from the packet
func decodeDNSName(data []byte, offset int) string {
	var name []byte
	pos := offset
	jumped := false
	jumpPos := 0

	for pos < len(data) {
		length := int(data[pos])

		if length == 0 {
			break
		}

		// Compression pointer
		if length >= 0xC0 {
			if !jumped {
				jumpPos = pos + 2
			}
			pos = ((length & 0x3F) << 8) | int(data[pos+1])
			jumped = true
			continue
		}

		pos++
		if pos+length > len(data) {
			break
		}

		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, data[pos:pos+length]...)
		pos += length
	}

	if jumped && jumpPos > 0 {
		_ = jumpPos
	}

	return string(name)
}
