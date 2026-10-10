package watch

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"netspy/pkg/discovery"
	"netspy/pkg/scanner"
)

// demoHost beschreibt ein fiktives Gerät für den Demo-Modus
type demoHost struct {
	last     byte
	hostname string
	mac      string
	vendor   string
	rtt      time.Duration
	ports    []int
	gateway  bool
	fromScan int  // Erst ab diesem Scan sichtbar (simuliert neue Geräte)
	flapping bool // Wechselt zwischen online/offline (simuliert instabile Geräte)
}

// demoHosts sind frei erfundene Geräte (MACs fiktiv, keine echten Netzdaten)
var demoHosts = []demoHost{
	{1, "router.home.lan", "3c:a6:2f:10:00:01", "AVM GmbH", 2 * time.Millisecond, []int{53, 80, 443}, true, 1, false},
	{5, "nas.home.lan", "00:11:32:aa:01:05", "Synology Incorporated", 3 * time.Millisecond, []int{22, 80, 443, 445, 5000}, false, 1, false},
	{10, "printer.home.lan", "3c:2a:f4:5e:00:0a", "Brother Industries, LTD.", 8 * time.Millisecond, []int{80, 443, 631, 9100}, false, 1, false},
	{12, "office-pc.home.lan", "d8:bb:c1:22:33:0c", "Micro-Star INTL CO., LTD.", 1 * time.Millisecond, []int{135, 445, 3389}, false, 1, false},
	{17, "macbook-air.home.lan", "f0:18:98:44:55:11", "Apple, Inc.", 6 * time.Millisecond, nil, false, 1, false},
	{23, "iphone.home.lan", "a4:83:e7:66:77:17", "Apple, Inc.", 41 * time.Millisecond, nil, false, 1, true},
	{31, "raspberrypi.home.lan", "dc:a6:32:88:99:1f", "Raspberry Pi Trading Ltd", 4 * time.Millisecond, []int{22, 1883, 8123}, false, 1, false},
	{42, "shelly-plug.home.lan", "e8:68:e7:12:34:2a", "Espressif Inc.", 12 * time.Millisecond, []int{80}, false, 1, false},
	{50, "hue-bridge.home.lan", "00:17:88:ab:cd:32", "Philips Lighting BV", 9 * time.Millisecond, []int{80, 443}, false, 1, false},
	{64, "sonos-kitchen.home.lan", "48:a6:b8:ef:01:40", "Sonos, Inc.", 15 * time.Millisecond, []int{1400}, false, 1, false},
	{77, "ap-upstairs.home.lan", "74:83:c2:23:45:4d", "Ubiquiti Inc", 3 * time.Millisecond, []int{22, 443}, false, 2, false},
	{88, "android-tablet.home.lan", "4a:1e:07:9c:58:58", "", 63 * time.Millisecond, nil, false, 3, false},
}

// PerformDemoScan liefert fiktive Hosts aus dem Dokumentationsnetz 192.0.2.0/24 (RFC 5737).
// Gedacht für Screenshots/GIFs: keine echten Geräte, keine Pakete ins reale Netz.
// Aufruf: netspy watch 192.0.2.0/24 --mode demo
func PerformDemoScan(ctx context.Context, progress *int32, scanNum int) []scanner.Host {
	// Kurzen Scan-Fortschritt simulieren, damit der Spinner sichtbar ist
	for i := int32(1); i <= 254; i += 32 {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(80 * time.Millisecond):
			atomic.StoreInt32(progress, i)
		}
	}
	atomic.StoreInt32(progress, 254)

	var hosts []scanner.Host
	for _, d := range demoHosts {
		if scanNum < d.fromScan {
			continue
		}
		if d.flapping && scanNum%3 == 2 {
			continue
		}
		hosts = append(hosts, scanner.Host{
			IP:             net.IPv4(192, 0, 2, d.last).To4(),
			Hostname:       d.hostname,
			HostnameSource: "mdns",
			MAC:            d.mac,
			Vendor:         d.vendor,
			DeviceType:     discovery.DetectDeviceType(d.hostname, d.mac, d.vendor, d.ports),
			RTT:            d.rtt,
			Ports:          d.ports,
			Online:         true,
			IsGateway:      d.gateway,
		})
	}
	return hosts
}
