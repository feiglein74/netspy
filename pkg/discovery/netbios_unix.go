//go:build !windows

package discovery

import (
	"net"
	"time"
)

// QueryNetBIOSNameNative uses the UDP-based NetBIOS query on Unix systems
// Falls back to the standard UDP method since nbtstat is not available
func QueryNetBIOSNameNative(ip net.IP) (string, error) {
	// On Unix systems, use the UDP-based query with a reasonable timeout
	return QueryNetBIOSName(ip, 3*time.Second)
}
