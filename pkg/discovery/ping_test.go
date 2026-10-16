package discovery_test

import (
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"netspy/pkg/discovery"
)

var _ = Describe("Ping", func() {
	Describe("NewPinger", func() {
		Context("with different modes", func() {
			It("should create a pinger in fast mode", func() {
				pinger := discovery.NewPinger(500*time.Millisecond, true, false)
				Expect(pinger).NotTo(BeNil())
			})

			It("should create a pinger in thorough mode", func() {
				pinger := discovery.NewPinger(1500*time.Millisecond, false, true)
				Expect(pinger).NotTo(BeNil())
			})

			It("should create a pinger in conservative mode", func() {
				pinger := discovery.NewPinger(500*time.Millisecond, false, false)
				Expect(pinger).NotTo(BeNil())
			})
		})
	})

	Describe("GenerateIPsFromCIDR", func() {
		Context("with small subnet", func() {
			It("should generate all IPs for /30", func() {
				_, network, _ := net.ParseCIDR("192.168.1.0/30")
				ips := discovery.GenerateIPsFromCIDR(network)

				// /30 hat 4 IPs total: Netzwerk (.0), 2 Hosts (.1, .2), Broadcast (.3)
				// Aber wir scannen nur Hosts (ohne .0 und .3)
				Expect(ips).To(HaveLen(2))
				Expect(ips[0].String()).To(Equal("192.168.1.1"))
				Expect(ips[1].String()).To(Equal("192.168.1.2"))
			})

			It("should generate all IPs for /29", func() {
				_, network, _ := net.ParseCIDR("10.0.0.0/29")
				ips := discovery.GenerateIPsFromCIDR(network)

				// /29 hat 8 IPs total, aber wir scannen nur 6 Hosts (ohne .0 und .7)
				Expect(ips).To(HaveLen(6))
				Expect(ips[0].String()).To(Equal("10.0.0.1"))
				Expect(ips[5].String()).To(Equal("10.0.0.6"))
			})
		})

		Context("with /24 subnet", func() {
			It("should generate 254 host IPs (excluding network and broadcast)", func() {
				_, network, _ := net.ParseCIDR("192.168.1.0/24")
				ips := discovery.GenerateIPsFromCIDR(network)

				// /24 hat 256 IPs total, aber wir scannen nur 254 Hosts (ohne .0 und .255)
				Expect(ips).To(HaveLen(254))
				Expect(ips[0].String()).To(Equal("192.168.1.1"))
				Expect(ips[253].String()).To(Equal("192.168.1.254"))
			})
		})

		Context("with subnets larger than /24", func() {
			// Regression: Bis 0.2.0 sprang die Zählung nach .255 auf .0.1 zurück,
			// Adressen ab dem zweiten /24-Block wurden nie gescannt
			It("should generate 510 unique host IPs for /23", func() {
				_, network, _ := net.ParseCIDR("10.0.0.0/23")
				ips := discovery.GenerateIPsFromCIDR(network)

				Expect(ips).To(HaveLen(510))
				Expect(ips[0].String()).To(Equal("10.0.0.1"))
				Expect(ips[254].String()).To(Equal("10.0.0.255"))
				Expect(ips[255].String()).To(Equal("10.0.1.0"))
				Expect(ips[256].String()).To(Equal("10.0.1.1"))
				Expect(ips[509].String()).To(Equal("10.0.1.254"))

				seen := make(map[string]bool, len(ips))
				for _, ip := range ips {
					seen[ip.String()] = true
				}
				Expect(seen).To(HaveLen(510))
			})

			It("should generate 65534 unique host IPs for /16", func() {
				_, network, _ := net.ParseCIDR("172.16.0.0/16")
				ips := discovery.GenerateIPsFromCIDR(network)

				Expect(ips).To(HaveLen(65534))
				Expect(ips[0].String()).To(Equal("172.16.0.1"))
				Expect(ips[65533].String()).To(Equal("172.16.255.254"))

				seen := make(map[string]bool, len(ips))
				for _, ip := range ips {
					seen[ip.String()] = true
				}
				Expect(seen).To(HaveLen(65534))
			})
		})

		Context("with single host /32", func() {
			It("should generate single IP", func() {
				_, network, _ := net.ParseCIDR("192.168.1.1/32")
				ips := discovery.GenerateIPsFromCIDR(network)

				Expect(ips).To(HaveLen(1))
				Expect(ips[0].String()).To(Equal("192.168.1.1"))
			})
		})
	})
})
