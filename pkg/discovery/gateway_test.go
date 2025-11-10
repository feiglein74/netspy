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
})
