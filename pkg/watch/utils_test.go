package watch

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"netspy/pkg/scanner"
)

var _ = Describe("Watch-Hilfsfunktionen", func() {
	Describe("parseNetworkInput", func() {
		DescribeTable("akzeptiert CIDR und einzelne IPs",
			func(input, expected string) {
				netCIDR, s, err := parseNetworkInput(input)
				Expect(err).NotTo(HaveOccurred())
				Expect(s).To(Equal(expected))
				Expect(netCIDR.String()).To(Equal(expected))
			},
			Entry("CIDR", "192.0.2.0/24", "192.0.2.0/24"),
			Entry("CIDR mit Host-Anteil wird auf Netz normalisiert", "192.0.2.77/24", "192.0.2.0/24"),
			Entry("einzelne IP wird zu /24", "192.0.2.77", "192.0.2.0/24"),
			Entry("Leerzeichen werden entfernt", "  10.0.0.0/16 ", "10.0.0.0/16"),
		)

		DescribeTable("lehnt ungültige Eingaben ab",
			func(input string) {
				_, _, err := parseNetworkInput(input)
				Expect(err).To(HaveOccurred())
			},
			Entry("leer", ""),
			Entry("nur Leerzeichen", "   "),
			Entry("kein Netz", "hallo"),
			Entry("Maske zu groß", "192.0.2.0/33"),
		)
	})

	Describe("countHosts", func() {
		DescribeTable("zählt nutzbare Hosts ohne Netz- und Broadcast-Adresse",
			func(cidr string, expected int) {
				Expect(countHosts(mustCIDR(cidr))).To(Equal(expected))
			},
			Entry("/24", "192.0.2.0/24", 254),
			Entry("/23", "10.0.0.0/23", 510),
			Entry("/16", "10.0.0.0/16", 65534),
			Entry("/30", "192.0.2.0/30", 2),
			Entry("/31 (Punkt-zu-Punkt)", "192.0.2.0/31", 2),
			Entry("/32", "192.0.2.1/32", 1),
		)

		It("liefert 0 ohne Netz", func() {
			Expect(countHosts(nil)).To(Equal(0))
		})
	})

	Describe("SplitIPNetworkHost", func() {
		DescribeTable("trennt an der Oktettgrenze der Maske",
			func(ip, cidr, network, host string) {
				n, h, ok := SplitIPNetworkHost(ip, mustCIDR(cidr))
				Expect(ok).To(BeTrue())
				Expect(n).To(Equal(network))
				Expect(h).To(Equal(host))
			},
			Entry("/24", "192.0.2.15", "192.0.2.0/24", "192.0.2.", "15"),
			Entry("/16", "172.16.4.15", "172.16.0.0/16", "172.16.", "4.15"),
			Entry("/8", "10.1.2.3", "10.0.0.0/8", "10.", "1.2.3"),
			Entry("/20 rundet auf /24", "10.0.4.3", "10.0.0.0/20", "10.0.4.", "3"),
		)

		It("liefert ok=false bei ungültiger IP, ohne Netz oder bei Masken über /24", func() {
			_, _, ok := SplitIPNetworkHost("kein-ip", mustCIDR("192.0.2.0/24"))
			Expect(ok).To(BeFalse())
			_, _, ok = SplitIPNetworkHost("192.0.2.1", nil)
			Expect(ok).To(BeFalse())
			_, _, ok = SplitIPNetworkHost("192.0.2.1", mustCIDR("192.0.2.0/28"))
			Expect(ok).To(BeFalse())
		})
	})

	Describe("FormatDuration", func() {
		DescribeTable("liefert immer zweistellige Einheiten",
			func(d time.Duration, expected string) {
				Expect(FormatDuration(d)).To(Equal(expected))
			},
			Entry("negativ wird 0", -5*time.Second, "00m00s"),
			Entry("Sekunden", 7*time.Second, "00m07s"),
			Entry("Minuten", 59*time.Minute+59*time.Second, "59m59s"),
			Entry("genau 1 Stunde", time.Hour, "01h00m"),
			Entry("Stunden", 23*time.Hour+5*time.Minute, "23h05m"),
			Entry("Tage", 3*24*time.Hour+4*time.Hour, "03d04h"),
			Entry("mehr als 99 Tage", 120*24*time.Hour, "120d00h"),
		)
	})

	Describe("IsLocallyAdministered", func() {
		DescribeTable("erkennt das Locally-Administered-Bit",
			func(mac string, expected bool) {
				Expect(IsLocallyAdministered(mac)).To(Equal(expected))
			},
			Entry("Privacy-MAC x2", "02:00:5e:10:00:01", true),
			Entry("Privacy-MAC xA, Großbuchstaben", "DA:A1:19:00:00:01", true),
			Entry("Privacy-MAC mit Bindestrichen", "a6-11-22-33-44-55", true),
			Entry("Hersteller-MAC", "00:0c:29:54:fe:c9", false),
			Entry("leer", "", false),
			Entry("Platzhalter", "-", false),
			Entry("Unsinn", "zz:00", false),
		)
	})

	Describe("parsePortList", func() {
		It("liest einzelne Ports, Bereiche und icmp", func() {
			Expect(parsePortList("22, 80-82,icmp,,443")).To(Equal([]string{"22", "80", "81", "82", "icmp", "443"}))
		})

		It("begrenzt Bereiche auf 101 Ports", func() {
			ports := parsePortList("1-65535")
			Expect(ports).To(HaveLen(101))
			Expect(ports[0]).To(Equal("1"))
			Expect(ports[100]).To(Equal("101"))
		})

		It("übernimmt ungültige Bereiche unverändert", func() {
			Expect(parsePortList("90-80")).To(Equal([]string{"90-80"}))
		})
	})

	Describe("getServiceName", func() {
		It("kennt Standarddienste und liefert sonst '-'", func() {
			Expect(getServiceName("22")).To(Equal("ssh"))
			Expect(getServiceName("ICMP")).To(Equal("ping"))
			Expect(getServiceName("12345")).To(Equal("-"))
		})
	})

	Describe("matchesFilter", func() {
		var (
			w     *TviewApp
			state *DeviceState
		)

		BeforeEach(func() {
			w = &TviewApp{}
			state = &DeviceState{
				Status: "online",
				Host: scanner.Host{
					Hostname:   "nas.example",
					MAC:        "00:11:32:aa:bb:cc",
					Vendor:     "Synology",
					DeviceType: "NAS",
				},
			}
		})

		DescribeTable("bildet die Tabellenspalten und Kurzformen auf die Filterfelder ab",
			func(expr string, expected bool) {
				w.filterText = expr
				Expect(w.matchesFilter("192.0.2.5", state)).To(Equal(expected))
			},
			Entry("leerer Filter passt immer", "", true),
			Entry("vendor", "vendor=synology", true),
			Entry("Kurzform v", "v=synology", true),
			Entry("hostname → host", "hostname=nas", true),
			Entry("type → device", "type=nas", true),
			Entry("status", "s=offline", false),
			Entry("ip", "ip=192.0.2.5", true),
			Entry("anderer Hersteller", "vendor=apple", false),
		)
	})
})
