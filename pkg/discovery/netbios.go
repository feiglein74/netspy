package discovery

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// NetBIOS Name Service Query
// RFC 1002 - PROTOCOL STANDARD FOR A NetBIOS SERVICE ON A TCP/UDP TRANSPORT

// QueryNetBIOSName queries a host's NetBIOS name using UDP port 137
func QueryNetBIOSName(ip net.IP, timeout time.Duration) (string, error) {
	// NetBIOS Name Service uses UDP port 137
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), "137"), timeout)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }() // Ignore close error

	// Set read deadline
	_ = conn.SetReadDeadline(time.Now().Add(timeout)) // Ignore error - connection will timeout anyway

	// Build NetBIOS Name Query packet
	query := buildNetBIOSQuery()

	// Send query
	_, err = conn.Write(query)
	if err != nil {
		return "", err
	}

	// Read response (max 512 bytes for NetBIOS)
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return "", err
	}

	// Parse response
	name, err := parseNetBIOSResponse(response[:n])
	if err != nil {
		return "", err
	}

	return name, nil
}

// buildNetBIOSQuery creates a NetBIOS Name Query packet for "*" (wildcard query)
func buildNetBIOSQuery() []byte {
	query := make([]byte, 50)

	// Transaction ID (2 bytes) - random
	binary.BigEndian.PutUint16(query[0:2], 0x1234)

	// Flags (2 bytes)
	// 0x0010 = Standard Query, Recursion Desired
	binary.BigEndian.PutUint16(query[2:4], 0x0010)

	// Questions: 1
	binary.BigEndian.PutUint16(query[4:6], 1)

	// Answer RRs: 0
	binary.BigEndian.PutUint16(query[6:8], 0)

	// Authority RRs: 0
	binary.BigEndian.PutUint16(query[8:10], 0)

	// Additional RRs: 0
	binary.BigEndian.PutUint16(query[10:12], 0)

	// Query Name: "*" encoded in NetBIOS format
	// NetBIOS names are 16 bytes, encoded as 32 bytes
	pos := 12

	// Length of encoded name (32 bytes)
	query[pos] = 0x20
	pos++

	// Encode "*" (0x2A) in NetBIOS format
	// Each byte is split into two 4-bit nibbles and encoded as A-P (0x41-0x50)
	name := "*               " // 16 bytes (padded with spaces)
	for i := 0; i < 16; i++ {
		c := name[i]
		query[pos] = 'A' + (c >> 4)
		query[pos+1] = 'A' + (c & 0x0F)
		pos += 2
	}

	// Null terminator for name
	query[pos] = 0x00
	pos++

	// Type: NBSTAT (0x0021)
	binary.BigEndian.PutUint16(query[pos:pos+2], 0x0021)
	pos += 2

	// Class: IN (0x0001)
	binary.BigEndian.PutUint16(query[pos:pos+2], 0x0001)

	return query[:pos]
}

// parseNetBIOSResponse extracts the computer name from a NetBIOS response
func parseNetBIOSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("response too short")
	}

	// Check if it's a response (QR bit set)
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x8000 == 0 {
		return "", fmt.Errorf("not a response")
	}

	// Check for errors
	rcode := flags & 0x000F
	if rcode != 0 {
		return "", fmt.Errorf("NetBIOS error code: %d", rcode)
	}

	// Answer count
	answers := binary.BigEndian.Uint16(response[6:8])
	if answers == 0 {
		return "", fmt.Errorf("no answers")
	}

	// Skip to answer section
	// Question section: skip encoded name + type + class
	pos := 12

	// Skip query name (ends with 0x00)
	for pos < len(response) && response[pos] != 0x00 {
		length := int(response[pos])
		pos += length + 1
	}
	pos++ // Skip null terminator

	// Skip query type (2) and class (2)
	pos += 4

	if pos+10 > len(response) {
		return "", fmt.Errorf("malformed response")
	}

	// Answer section
	// Skip name pointer (2 bytes)
	pos += 2

	// Skip type (2), class (2), TTL (4)
	pos += 8

	// RData length
	rdataLen := binary.BigEndian.Uint16(response[pos : pos+2])
	pos += 2

	if pos+int(rdataLen) > len(response) {
		return "", fmt.Errorf("invalid rdata length")
	}

	// Number of names in the response
	if rdataLen < 1 {
		return "", fmt.Errorf("no names in response")
	}

	numNames := int(response[pos])
	pos++

	if numNames == 0 {
		return "", fmt.Errorf("zero names")
	}

	// Parse each name (each entry is 18 bytes: 16 bytes name + 2 bytes flags)
	for i := 0; i < numNames && pos+18 <= len(response); i++ {
		nameBytes := response[pos : pos+16]
		flags := binary.BigEndian.Uint16(response[pos+16 : pos+18])

		// Flags format:
		// G bit (Group name): bit 15
		// Name type: bits 0-1
		//   00 = Unique name
		//   10 = Group name

		// We want unique workstation names (type 0x00)
		nameType := nameBytes[15]

		// Type 0x00 = Workstation/Computer name
		// Type 0x20 = File Server Service
		// Type 0x03 = Messenger Service
		if nameType == 0x00 && (flags&0x8000) == 0 { // Unique name, not group
			// Trim spaces and null bytes
			name := strings.TrimRight(string(nameBytes[:15]), " \x00")
			if name != "" && name != "*" {
				return name, nil
			}
		}

		pos += 18
	}

	return "", fmt.Errorf("no workstation name found")
}
