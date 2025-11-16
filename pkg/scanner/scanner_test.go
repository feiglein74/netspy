package scanner_test

import (
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"netspy/pkg/scanner"
)

var _ = Describe("Scanner", func() {
	Describe("Creating a new scanner", func() {
		Context("with default configuration", func() {
			It("should create a scanner with conservative defaults", func() {
				config := scanner.Config{
					Concurrency: 40,
					Timeout:     500 * time.Millisecond,
					Quiet:       true,
				}

				s := scanner.New(config)
				Expect(s).NotTo(BeNil())
			})
		})

		Context("with fast mode", func() {
			It("should create a scanner with fast configuration", func() {
				config := scanner.Config{
					Concurrency: 100,
					Timeout:     200 * time.Millisecond,
					Fast:        true,
					Quiet:       true,
				}

				s := scanner.New(config)
				Expect(s).NotTo(BeNil())
			})
		})

		Context("with thorough mode", func() {
			It("should create a scanner with thorough configuration", func() {
				config := scanner.Config{
					Concurrency: 20,
					Timeout:     1500 * time.Millisecond,
					Thorough:    true,
					Quiet:       true,
				}

				s := scanner.New(config)
				Expect(s).NotTo(BeNil())
			})
		})
	})

	Describe("Host struct", func() {
		Context("when creating a host", func() {
			It("should have all required fields", func() {
				host := scanner.Host{
					IP:         net.ParseIP("192.168.1.1"),
					Hostname:   "router.local",
					MAC:        "aa:bb:cc:dd:ee:ff",
					Vendor:     "Test Vendor",
					DeviceType: "Network Equipment",
					Online:     true,
				}

				Expect(host.IP.String()).To(Equal("192.168.1.1"))
				Expect(host.Hostname).To(Equal("router.local"))
				Expect(host.MAC).To(Equal("aa:bb:cc:dd:ee:ff"))
				Expect(host.Vendor).To(Equal("Test Vendor"))
				Expect(host.DeviceType).To(Equal("Network Equipment"))
				Expect(host.Online).To(BeTrue())
			})
		})
	})

	Describe("Scanning hosts", func() {
		Context("with localhost", func() {
			It("should scan localhost without errors", func() {
				config := scanner.Config{
					Concurrency: 10,
					Timeout:     1 * time.Second,
					Quiet:       true,
				}

				s := scanner.New(config)
				ips := []net.IP{net.ParseIP("127.0.0.1")}

				results, err := s.ScanHosts(ips)

				Expect(err).NotTo(HaveOccurred())
				// Localhost kann offline erscheinen wenn keine üblichen Ports offen sind
				// Scanner gibt nur online hosts zurück, daher kann results leer sein
				// Wichtig ist dass kein Fehler auftritt
				Expect(results).NotTo(BeNil())
			})
		})

		Context("with invalid IP", func() {
			It("should handle invalid IPs gracefully", func() {
				config := scanner.Config{
					Concurrency: 10,
					Timeout:     500 * time.Millisecond,
					Quiet:       true,
				}

				s := scanner.New(config)
				// 192.0.2.0/24 ist TEST-NET-1 (sollte nie online sein)
				ips := []net.IP{net.ParseIP("192.0.2.1")}

				results, err := s.ScanHosts(ips)

				Expect(err).NotTo(HaveOccurred())
				Expect(results).NotTo(BeNil())
			})
		})
	})
})
