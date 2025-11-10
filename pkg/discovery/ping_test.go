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

				// /30 hat 4 IPs: Netzwerk, 2 Hosts, Broadcast
				Expect(ips).To(HaveLen(4))
			})

			It("should generate all IPs for /29", func() {
				_, network, _ := net.ParseCIDR("10.0.0.0/29")
				ips := discovery.GenerateIPsFromCIDR(network)

				// /29 hat 8 IPs
				Expect(ips).To(HaveLen(8))
			})
		})

		Context("with /24 subnet", func() {
			It("should generate 256 IPs", func() {
				_, network, _ := net.ParseCIDR("192.168.1.0/24")
				ips := discovery.GenerateIPsFromCIDR(network)

				Expect(ips).To(HaveLen(256))
				Expect(ips[0].String()).To(Equal("192.168.1.0"))
				Expect(ips[255].String()).To(Equal("192.168.1.255"))
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
