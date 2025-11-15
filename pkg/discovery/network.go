package discovery

import (
	"net"
)

// GetLocalNetworks gibt alle lokalen Netzwerk-Interfaces zurück
func GetLocalNetworks() ([]*net.IPNet, error) {
	var localNetworks []*net.IPNet

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		// Skip loopback und inaktive Interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ipNet *net.IPNet
			switch v := addr.(type) {
			case *net.IPNet:
				ipNet = v
			case *net.IPAddr:
				ipNet = &net.IPNet{IP: v.IP, Mask: v.IP.DefaultMask()}
			}

			// Nur IPv4, keine Loopback
			if ipNet != nil && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
				localNetworks = append(localNetworks, ipNet)
			}
		}
	}

	return localNetworks, nil
}

// IsLocalSubnet prüft ob ein Netzwerk im gleichen Subnet wie ein lokales Interface ist
func IsLocalSubnet(targetNetwork *net.IPNet) (bool, *net.IPNet) {
	localNets, err := GetLocalNetworks()
	if err != nil {
		return false, nil
	}

	for _, localNet := range localNets {
		// Prüfe ob das Ziel-Netzwerk mit dem lokalen Netzwerk überlappt
		if networksOverlap(localNet, targetNetwork) {
			return true, localNet
		}
	}

	return false, nil
}

// networksOverlap prüft ob zwei Netzwerke sich überschneiden
func networksOverlap(net1, net2 *net.IPNet) bool {
	// Prüfe ob net1 net2 enthält oder umgekehrt
	return net1.Contains(net2.IP) || net2.Contains(net1.IP)
}

// GetLocalIP gibt die erste lokale nicht-loopback IPv4 Adresse zurück
func GetLocalIP() net.IP {
	localNets, err := GetLocalNetworks()
	if err != nil || len(localNets) == 0 {
		return nil
	}
	return localNets[0].IP
}
