package discovery

import (
	"net"
	"sync"
)

// gatewayCache speichert erkannte Gateways für Netzwerke
var (
	gatewayCache      = make(map[string]net.IP)
	gatewayCacheMutex sync.RWMutex
)

// IsLikelyGateway prüft ob eine IP wahrscheinlich ein Gateway ist
// Kombiniert lokale Default-Gateway-Erkennung mit heuristischer Analyse
func IsLikelyGateway(ip net.IP, network *net.IPNet) bool {
	// 1. Prüfe ob es das lokale Default-Gateway ist
	if IsGateway(ip) {
		return true
	}

	// 2. Wenn die IP im lokalen Netzwerk liegt, verlasse dich auf Default-Gateway
	localGateway := GetDefaultGateway()
	if localGateway != nil && network.Contains(localGateway) {
		// Wir sind im lokalen Netzwerk - nur das Default-Gateway ist relevant
		return false
	}

	// 3. Für entfernte Netzwerke: Heuristische Analyse
	return isHeuristicGateway(ip, network)
}

// isHeuristicGateway verwendet Heuristiken um potenzielle Gateways zu erkennen
func isHeuristicGateway(ip net.IP, network *net.IPNet) bool {
	if ip == nil || network == nil {
		return false
	}

	// Prüfe Cache zuerst
	networkKey := network.String()
	gatewayCacheMutex.RLock()
	cachedGateway, found := gatewayCache[networkKey]
	gatewayCacheMutex.RUnlock()

	if found {
		return ip.Equal(cachedGateway)
	}

	// Heuristik 1: Typische Gateway-IPs (.1, .254)
	// Verwende nur IP-Muster ohne Port-Scan für bessere Performance
	if isCommonGatewayIP(ip, network) {
		// Cache das Ergebnis
		gatewayCacheMutex.Lock()
		gatewayCache[networkKey] = ip
		gatewayCacheMutex.Unlock()
		return true
	}

	return false
}

// isCommonGatewayIP prüft ob die IP einem typischen Gateway-Muster entspricht
func isCommonGatewayIP(ip net.IP, network *net.IPNet) bool {
	if !network.Contains(ip) {
		return false
	}

	// Hole den Host-Teil der IP
	ip4 := ip.To4()
	if ip4 == nil {
		return false // Nur IPv4 unterstützt
	}

	networkIP := network.IP.To4()
	if networkIP == nil {
		return false
	}

	// Berechne Netzmaske
	maskSize, _ := network.Mask.Size()

	// Für /24 Netzwerke: Prüfe letztes Oktett
	if maskSize == 24 {
		lastOctet := ip4[3]
		return lastOctet == 1 || lastOctet == 254
	}

	// Für /16 Netzwerke: Prüfe letzte zwei Oktette
	if maskSize == 16 {
		return (ip4[2] == 0 && ip4[3] == 1) || // x.x.0.1
			(ip4[2] == 0 && ip4[3] == 254) || // x.x.0.254
			(ip4[2] == 1 && ip4[3] == 1) // x.x.1.1
	}

	// Für /8 Netzwerke: Prüfe letzte drei Oktette
	if maskSize == 8 {
		return (ip4[1] == 0 && ip4[2] == 0 && ip4[3] == 1) || // x.0.0.1
			(ip4[1] == 0 && ip4[2] == 0 && ip4[3] == 254) // x.0.0.254
	}

	// Für andere Netzmasken: Prüfe ob es die erste oder letzte nutzbare IP ist
	firstIP := getFirstUsableIP(network)
	lastIP := getLastUsableIP(network)

	return ip.Equal(firstIP) || ip.Equal(lastIP)
}

// getFirstUsableIP gibt die erste nutzbare IP im Netzwerk zurück
func getFirstUsableIP(network *net.IPNet) net.IP {
	ip := make(net.IP, len(network.IP))
	copy(ip, network.IP)

	// Inkrementiere um 1 (Netzwerkadresse überspringen)
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}

	return ip
}

// getLastUsableIP gibt die letzte nutzbare IP im Netzwerk zurück
func getLastUsableIP(network *net.IPNet) net.IP {
	ip := make(net.IP, len(network.IP))
	for i := range ip {
		ip[i] = network.IP[i] | ^network.Mask[i]
	}

	// Dekrementiere um 1 (Broadcast-Adresse überspringen)
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]--
		if ip[i] != 255 {
			break
		}
	}

	return ip
}

// ClearGatewayCache löscht den Gateway-Cache
func ClearGatewayCache() {
	gatewayCacheMutex.Lock()
	defer gatewayCacheMutex.Unlock()
	gatewayCache = make(map[string]net.IP)
}
