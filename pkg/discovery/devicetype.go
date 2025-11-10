package discovery

import (
	"strings"
)

// DeviceType-Konstanten
const (
	DeviceTypeSmartphone = "Smartphone"
	DeviceTypeTablet     = "Tablet"
	DeviceTypeComputer   = "Computer"
	DeviceTypeIoT        = "IoT Device"
	DeviceTypeNetwork    = "Network Equipment"
	DeviceTypePrinter    = "Printer"
	DeviceTypeServer     = "Server"
	DeviceTypeUnknown    = "Unknown"
)

// DetectDeviceType bestimmt den Gerätetyp basierend auf verfügbaren Informationen
func DetectDeviceType(hostname, mac, vendor string, ports []int) string {
	hostname = strings.ToLower(hostname)
	vendor = strings.ToLower(vendor)

	// 1. Check for randomized MAC (privacy feature on smartphones)
	if isLocallyAdministeredMAC(mac) && vendor == "" {
		// High confidence this is a smartphone with MAC randomization
		if containsAny(hostname, []string{"iphone", "android", "mobile"}) {
			return DeviceTypeSmartphone + " (Privacy)"
		}
		// Default to smartphone for locally-administered MACs without vendor
		return DeviceTypeSmartphone + " (Privacy)"
	}

	// 2. Hostname pattern matching (most reliable)
	deviceType := detectByHostname(hostname)
	if deviceType != DeviceTypeUnknown {
		return deviceType
	}

	// 3. Vendor-based detection
	deviceType = detectByVendor(vendor)
	if deviceType != DeviceTypeUnknown {
		return deviceType
	}

	// 4. Port-based OS fingerprinting
	deviceType = detectByPorts(ports)
	if deviceType != DeviceTypeUnknown {
		return deviceType
	}

	return DeviceTypeUnknown
}

// detectByHostname identifiziert Gerätetyp anhand von Hostname-Mustern
func detectByHostname(hostname string) string {
	// Apple devices
	if containsAny(hostname, []string{"iphone"}) {
		return "iPhone"
	}
	if containsAny(hostname, []string{"ipad"}) {
		return "iPad"
	}
	if containsAny(hostname, []string{"macbook", "imac", "mac-", "macos"}) {
		return "Mac"
	}
	if containsAny(hostname, []string{"appletv", "apple-tv"}) {
		return "Apple TV"
	}

	// Android devices
	if containsAny(hostname, []string{"android-", "android_"}) {
		return "Android Phone"
	}
	if containsAny(hostname, []string{"galaxy", "samsung"}) {
		return "Samsung Phone"
	}
	if containsAny(hostname, []string{"pixel"}) {
		return "Google Pixel"
	}

	// Windows devices
	if containsAny(hostname, []string{"desktop-", "-pc", "windows", "win10", "win11"}) {
		return "Windows PC"
	}
	if containsAny(hostname, []string{"laptop"}) {
		return "Laptop"
	}

	// Linux devices
	if containsAny(hostname, []string{"ubuntu", "debian", "fedora", "centos", "arch", "linux"}) {
		return "Linux Computer"
	}

	// Network equipment
	if containsAny(hostname, []string{"router", "gateway", "switch", "ap-", "access-point"}) {
		return DeviceTypeNetwork
	}

	// IoT devices
	if containsAny(hostname, []string{"hue-", "philips-hue", "ring-", "nest-", "alexa", "echo-"}) {
		return DeviceTypeIoT
	}
	if containsAny(hostname, []string{"smarttv", "smart-tv", "roku", "chromecast", "firetv"}) {
		return "Smart TV"
	}
	if containsAny(hostname, []string{"camera", "cam-", "ipcam"}) {
		return "IP Camera"
	}

	// Printers
	if containsAny(hostname, []string{"printer", "print-", "hp-", "canon-", "epson-", "brother-"}) {
		return DeviceTypePrinter
	}

	// Servers
	if containsAny(hostname, []string{"server", "srv-", "nas", "storage"}) {
		return DeviceTypeServer
	}

	return DeviceTypeUnknown
}

// detectByVendor identifiziert Gerätetyp anhand von MAC-Vendor
func detectByVendor(vendor string) string {
	// Apple devices (likely consumer devices)
	if strings.Contains(vendor, "apple") {
		return "Apple Device"
	}

	// Smartphone manufacturers
	if containsAny(vendor, []string{"samsung", "huawei", "xiaomi", "oppo", "vivo", "oneplus"}) {
		return DeviceTypeSmartphone
	}
	if containsAny(vendor, []string{"google"}) {
		return "Google Device"
	}

	// Network equipment vendors
	if containsAny(vendor, []string{"cisco", "ubiquiti", "tp-link", "netgear", "asus router", "d-link", "mikrotik"}) {
		return DeviceTypeNetwork
	}

	// Printer vendors
	if containsAny(vendor, []string{"hewlett packard", "hp ", "canon", "epson", "brother", "xerox", "lexmark"}) {
		return DeviceTypePrinter
	}

	// IoT device vendors
	if containsAny(vendor, []string{"philips", "ring", "nest", "amazon", "sonos", "lifx"}) {
		return DeviceTypeIoT
	}

	// Computer/server vendors
	if containsAny(vendor, []string{"dell", "lenovo", "hp inc", "microsoft", "intel", "asustek", "gigabyte", "msi"}) {
		return DeviceTypeComputer
	}

	return DeviceTypeUnknown
}

// detectByPorts führt OS-Fingerprinting basierend auf offenen Ports durch
func detectByPorts(ports []int) string {
	if len(ports) == 0 {
		return DeviceTypeUnknown
	}

	hasPort := func(port int) bool {
		for _, p := range ports {
			if p == port {
				return true
			}
		}
		return false
	}

	// Windows signatures
	if hasPort(445) || hasPort(135) || hasPort(139) {
		return "Windows Computer"
	}
	if hasPort(3389) {
		return "Windows Server (RDP)"
	}

	// Unix/Linux server signatures
	if hasPort(22) {
		if hasPort(80) || hasPort(443) {
			return "Linux Server"
		}
		return "Unix/Linux System"
	}

	// Printer signature
	if hasPort(631) || hasPort(9100) {
		return DeviceTypePrinter
	}

	// Web server/IoT
	if hasPort(8080) || hasPort(8443) {
		return "Web Server/IoT"
	}

	// Database servers
	if hasPort(3306) || hasPort(5432) || hasPort(27017) {
		return "Database Server"
	}

	return DeviceTypeUnknown
}

// isLocallyAdministeredMAC prüft ob MAC-Adresse locally-administered Bit gesetzt hat
func isLocallyAdministeredMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	// Check the second character (second nibble of first octet)
	secondChar := strings.ToUpper(string(mac[1]))
	return secondChar == "2" || secondChar == "3" || secondChar == "6" ||
	       secondChar == "7" || secondChar == "A" || secondChar == "B" ||
	       secondChar == "E" || secondChar == "F"
}

// containsAny prüft ob String einen der Teilstrings enthält
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
