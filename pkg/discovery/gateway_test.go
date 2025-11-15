package discovery_test

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"netspy/pkg/discovery"
)

var _ = Describe("Gateway Detection", func() {
	Describe("GetDefaultGateway", func() {
		Context("on any platform", func() {
			It("should return a valid IP or nil", func() {
				gateway := discovery.GetDefaultGateway()
				// Gateway kann nil sein wenn keine Netzwerkverbindung besteht
				// oder eine gültige IP-Adresse
				if gateway != nil {
					Expect(gateway.To4()).NotTo(BeNil(), "Gateway sollte eine gültige IPv4-Adresse sein")
				}
			})
		})
	})

	Describe("IsGateway", func() {
		Context("when checking gateway IP", func() {
			It("should correctly identify the gateway", func() {
				gateway := discovery.GetDefaultGateway()
				if gateway != nil {
					isGw := discovery.IsGateway(gateway)
					Expect(isGw).To(BeTrue())
				} else {
					Skip("Kein Gateway verfügbar")
				}
			})

			It("should return false for non-gateway IPs", func() {
				// TEST-NET-1 ist garantiert kein Gateway
				testIP := net.ParseIP("192.0.2.1")
				isGw := discovery.IsGateway(testIP)
				Expect(isGw).To(BeFalse())
			})
		})
	})

	Describe("IsLikelyGateway (Heuristic)", func() {
		var (
			network24 *net.IPNet
			network16 *net.IPNet
			network8  *net.IPNet
		)

		BeforeEach(func() {
			_, network24, _ = net.ParseCIDR("192.168.1.0/24")
			_, network16, _ = net.ParseCIDR("172.16.0.0/16")
			_, network8, _ = net.ParseCIDR("10.0.0.0/8")
			discovery.ClearGatewayCache()
		})

		Context("for /24 networks", func() {
			It("should detect .1 as likely gateway", func() {
				ip := net.ParseIP("192.168.1.1")
				Expect(discovery.IsLikelyGateway(ip, network24)).To(BeTrue())
			})

			It("should detect .254 as likely gateway", func() {
				ip := net.ParseIP("192.168.1.254")
				Expect(discovery.IsLikelyGateway(ip, network24)).To(BeTrue())
			})

			It("should NOT detect .2 as gateway", func() {
				ip := net.ParseIP("192.168.1.2")
				Expect(discovery.IsLikelyGateway(ip, network24)).To(BeFalse())
			})
		})

		Context("for /16 networks", func() {
			It("should detect .0.1 as likely gateway", func() {
				ip := net.ParseIP("172.16.0.1")
				Expect(discovery.IsLikelyGateway(ip, network16)).To(BeTrue())
			})

			It("should detect .1.1 as likely gateway", func() {
				ip := net.ParseIP("172.16.1.1")
				Expect(discovery.IsLikelyGateway(ip, network16)).To(BeTrue())
			})
		})

		Context("for /8 networks", func() {
			It("should detect .0.0.1 as likely gateway", func() {
				ip := net.ParseIP("10.0.0.1")
				Expect(discovery.IsLikelyGateway(ip, network8)).To(BeTrue())
			})

			It("should detect .0.0.254 as likely gateway", func() {
				ip := net.ParseIP("10.0.0.254")
				Expect(discovery.IsLikelyGateway(ip, network8)).To(BeTrue())
			})
		})

		Context("edge cases", func() {
			It("should handle nil IP", func() {
				Expect(discovery.IsLikelyGateway(nil, network24)).To(BeFalse())
			})

			It("should handle IP outside network", func() {
				ip := net.ParseIP("10.0.0.1")
				Expect(discovery.IsLikelyGateway(ip, network24)).To(BeFalse())
			})
		})
	})
})
