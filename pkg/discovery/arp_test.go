package discovery_test

import (
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"netspy/pkg/discovery"
)

var _ = Describe("ARP Scanner", func() {
	Describe("NewARPScanner", func() {
		It("should create a new ARP scanner", func() {
			scanner := discovery.NewARPScanner(500 * time.Millisecond)
			Expect(scanner).NotTo(BeNil())
		})
	})

	Describe("ARPEntry", func() {
		Context("when creating ARP entries", func() {
			It("should have all required fields", func() {
				entry := discovery.ARPEntry{
					IP:     net.ParseIP("192.168.1.1"),
					MAC:    net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
					Online: true,
					RTT:    10 * time.Millisecond,
				}

				Expect(entry.IP.String()).To(Equal("192.168.1.1"))
				Expect(entry.MAC.String()).To(Equal("aa:bb:cc:dd:ee:ff"))
				Expect(entry.Online).To(BeTrue())
				Expect(entry.RTT).To(Equal(10 * time.Millisecond))
			})
		})
	})

	Describe("ScanARPTable", func() {
		Context("with localhost network", func() {
			It("should scan without errors", func() {
				scanner := discovery.NewARPScanner(500 * time.Millisecond)
				_, network, _ := net.ParseCIDR("127.0.0.0/8")

				_, err := scanner.ScanARPTable(network)

				// Sollte keinen Fehler werfen
				Expect(err).NotTo(HaveOccurred())
				// Entries können leer sein (nil slice oder leeres slice), beides ist okay
				// Wichtig ist nur, dass kein Fehler auftritt
			})
		})
	})
})
