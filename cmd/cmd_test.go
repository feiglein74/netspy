package cmd

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"netspy/pkg/discovery"
)

var _ = Describe("Cmd", func() {
	Describe("getVersion", func() {
		var orig string

		BeforeEach(func() {
			orig = Version
			DeferCleanup(func() { Version = orig })
		})

		// Regression 0.2.0: Release-Builds setzen Version per ldflags auf den Tag ("v0.2.0"),
		// die Ausgabe zeigte dann "vv0.2.0"
		It("entfernt das führende v aus dem Git-Tag", func() {
			Version = "v1.2.3"
			Expect(getVersion()).To(Equal("1.2.3"))
		})

		It("lässt eine Version ohne v unverändert", func() {
			Version = "1.2.3"
			Expect(getVersion()).To(Equal("1.2.3"))
		})
	})

	Describe("parseTargetNetwork", func() {
		DescribeTable("liest CIDR und einzelne IPs",
			func(input string, singleIPBits int, expected string) {
				netCIDR, err := parseTargetNetwork(input, singleIPBits)
				Expect(err).NotTo(HaveOccurred())
				Expect(netCIDR.String()).To(Equal(expected))
			},
			Entry("CIDR bleibt CIDR", "192.0.2.0/24", 32, "192.0.2.0/24"),
			Entry("CIDR mit Host-Anteil wird normalisiert", "192.0.2.77/24", 32, "192.0.2.0/24"),
			Entry("scan: einzelne IP = genau dieser Host", "192.0.2.7", 32, "192.0.2.7/32"),
			Entry("watch: einzelne IP = ihr /24", "192.0.2.7", 24, "192.0.2.0/24"),
			Entry("Leerzeichen werden entfernt", " 192.0.2.7 ", 32, "192.0.2.7/32"),
			Entry("einzelne IPv6 = /128", "2001:db8::1", 24, "2001:db8::1/128"),
		)

		// Regression: "netspy scan 127.0.0.1" brach mit "invalid CIDR" ab
		It("liefert für eine einzelne IP beim Scan genau einen Host", func() {
			netCIDR, err := parseTargetNetwork("192.0.2.7", 32)
			Expect(err).NotTo(HaveOccurred())
			ips := discovery.GenerateIPsFromCIDR(netCIDR)
			Expect(ips).To(HaveLen(1))
			Expect(ips[0].String()).To(Equal("192.0.2.7"))
		})

		It("lehnt ungültige Eingaben ab", func() {
			for _, input := range []string{"", "kein-netz", "192.0.2.0/33", "300.1.1.1"} {
				_, err := parseTargetNetwork(input, 32)
				Expect(err).To(HaveOccurred(), "Eingabe %q", input)
			}
		})
	})

	Describe("createScanConfig", func() {
		BeforeEach(func() {
			origMode, origConc, origTimeout := scanMode, concurrent, timeout
			DeferCleanup(func() { scanMode, concurrent, timeout = origMode, origConc, origTimeout })
			concurrent, timeout = 0, 0
		})

		DescribeTable("setzt Standardwerte je Modus",
			func(mode string, workers int, to time.Duration) {
				scanMode = mode
				cfg := createScanConfig()
				Expect(cfg.Concurrency).To(Equal(workers))
				Expect(cfg.Timeout).To(Equal(to))
			},
			Entry("conservative", "conservative", 40, 500*time.Millisecond),
			Entry("fast", "fast", 100, 200*time.Millisecond),
			Entry("thorough", "thorough", 20, 1500*time.Millisecond),
		)

		It("übernimmt --concurrent und --timeout", func() {
			scanMode, concurrent, timeout = "fast", 7, 3*time.Second
			cfg := createScanConfig()
			Expect(cfg.Concurrency).To(Equal(7))
			Expect(cfg.Timeout).To(Equal(3 * time.Second))
			Expect(cfg.Fast).To(BeTrue())
		})
	})
})
