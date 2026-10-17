package watch

import (
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"netspy/pkg/scanner"
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	Expect(err).NotTo(HaveOccurred())
	return n
}

var _ = Describe("Watch-State", func() {
	Describe("CompareIPs", func() {
		It("vergleicht numerisch statt als Text", func() {
			Expect(CompareIPs("192.0.2.9", "192.0.2.10")).To(BeTrue())
			Expect(CompareIPs("192.0.2.10", "192.0.2.9")).To(BeFalse())
			Expect(CompareIPs("10.0.0.1", "9.255.255.255")).To(BeFalse())
		})

		It("liefert false für gleiche IPs", func() {
			Expect(CompareIPs("192.0.2.1", "192.0.2.1")).To(BeFalse())
		})

		It("fällt bei ungültigen Eingaben auf Textvergleich zurück", func() {
			Expect(CompareIPs("abc", "abd")).To(BeTrue())
		})
	})

	Describe("SortState", func() {
		It("sortiert beim ersten Klick aufsteigend und kehrt beim zweiten um", func() {
			s := &SortState{Column: SortByIP, Ascending: true}

			s.Toggle(SortByVendor)
			col, asc := s.Get()
			Expect(col).To(Equal(SortByVendor))
			Expect(asc).To(BeTrue())

			s.Toggle(SortByVendor)
			_, asc = s.Get()
			Expect(asc).To(BeFalse())
		})
	})

	Describe("SortIPs", func() {
		var states map[string]*DeviceState
		now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

		BeforeEach(func() {
			states = map[string]*DeviceState{
				"192.0.2.10": {Host: scanner.Host{Vendor: "Beta", RTT: 5 * time.Millisecond}, FlapCount: 1,
					Status: "online", FirstSeen: now.Add(-10 * time.Minute)},
				"192.0.2.2": {Host: scanner.Host{Vendor: "Alpha", RTT: 20 * time.Millisecond}, FlapCount: 3,
					Status: "online", FirstSeen: now.Add(-60 * time.Minute)},
				"192.0.2.3": {Host: scanner.Host{Vendor: "Alpha", RTT: 1 * time.Millisecond}, FlapCount: 1,
					Status: "offline", StatusSince: now.Add(-1 * time.Minute)},
			}
		})

		sorted := func(col SortColumn, asc bool) []string {
			ips := []string{"192.0.2.10", "192.0.2.2", "192.0.2.3"}
			SortIPs(ips, states, &SortState{Column: col, Ascending: asc}, now)
			return ips
		}

		It("sortiert nach IP numerisch", func() {
			Expect(sorted(SortByIP, true)).To(Equal([]string{"192.0.2.2", "192.0.2.3", "192.0.2.10"}))
			Expect(sorted(SortByIP, false)).To(Equal([]string{"192.0.2.10", "192.0.2.3", "192.0.2.2"}))
		})

		It("sortiert gleiche Werte stabil nach IP", func() {
			Expect(sorted(SortByVendor, true)).To(Equal([]string{"192.0.2.2", "192.0.2.3", "192.0.2.10"}))
			Expect(sorted(SortByFlaps, true)).To(Equal([]string{"192.0.2.3", "192.0.2.10", "192.0.2.2"}))
		})

		It("sortiert nach RTT", func() {
			Expect(sorted(SortByRTT, true)).To(Equal([]string{"192.0.2.3", "192.0.2.10", "192.0.2.2"}))
		})

		It("sortiert nach Uptime (offline zählt die Dauer seit Statuswechsel)", func() {
			// .3 seit 1 min offline, .10 seit 10 min online, .2 seit 60 min online
			Expect(sorted(SortByUptime, true)).To(Equal([]string{"192.0.2.3", "192.0.2.10", "192.0.2.2"}))
		})
	})

	Describe("GetSortIndicator", func() {
		It("zeigt nur an der aktiven Spalte einen Pfeil", func() {
			Expect(GetSortIndicator(SortByIP, SortByIP, true)).To(Equal(" ↑"))
			Expect(GetSortIndicator(SortByIP, SortByIP, false)).To(Equal(" ↓"))
			Expect(GetSortIndicator(SortByIP, SortByMAC, true)).To(BeEmpty())
		})
	})

	Describe("CalculateThreads", func() {
		DescribeTable("passt die Thread-Anzahl automatisch an die Netzgröße an",
			func(cidr string, expected ThreadConfig) {
				Expect(CalculateThreads(mustCIDR(cidr), 0)).To(Equal(expected))
			},
			Entry("/28", "192.0.2.0/28", ThreadConfig{Scan: 10, Reachability: 10, DNS: 5}),
			Entry("/26", "192.0.2.0/26", ThreadConfig{Scan: 20, Reachability: 20, DNS: 8}),
			Entry("/24", "192.0.2.0/24", ThreadConfig{Scan: 40, Reachability: 30, DNS: 10}),
			Entry("/22", "10.0.0.0/22", ThreadConfig{Scan: 80, Reachability: 50, DNS: 15}),
			Entry("/16", "10.0.0.0/16", ThreadConfig{Scan: 150, Reachability: 80, DNS: 20}),
		)

		It("teilt --max-threads auf (50 % Scan, 30 % Erreichbarkeit, 20 % DNS)", func() {
			Expect(CalculateThreads(mustCIDR("192.0.2.0/24"), 100)).To(Equal(ThreadConfig{Scan: 50, Reachability: 30, DNS: 20}))
		})

		// Ein Semaphore mit Kapazität 0 blockiert für immer
		DescribeTable("liefert bei kleinem --max-threads mindestens einen Thread pro Art",
			func(maxThreads int) {
				cfg := CalculateThreads(mustCIDR("192.0.2.0/24"), maxThreads)
				Expect(cfg.Scan).To(BeNumerically(">=", 1), "Scan")
				Expect(cfg.Reachability).To(BeNumerically(">=", 1), "Reachability")
				Expect(cfg.DNS).To(BeNumerically(">=", 1), "DNS")
			},
			Entry("1", 1),
			Entry("3", 3),
			Entry("4", 4),
		)
	})

	Describe("GetHostname / GetVendor", func() {
		It("liefert '-' für leere Werte", func() {
			Expect(GetHostname(scanner.Host{})).To(Equal("-"))
			Expect(GetVendor(scanner.Host{})).To(Equal("-"))
			Expect(GetVendor(scanner.Host{Vendor: "Acme"})).To(Equal("Acme"))
		})
	})
})
