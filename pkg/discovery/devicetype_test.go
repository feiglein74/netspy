package discovery_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"netspy/pkg/discovery"
)

var _ = Describe("Device Type Detection", func() {
	Describe("DetectDeviceType", func() {
		Context("by hostname", func() {
			It("should detect iPhones", func() {
				deviceType := discovery.DetectDeviceType("iPhone-von-Max", "", "", nil)
				Expect(deviceType).To(Equal("Smartphone"))
			})

			It("should detect Android devices", func() {
				deviceType := discovery.DetectDeviceType("android-1234567890", "", "", nil)
				Expect(deviceType).To(Equal("Smartphone"))
			})

			It("should detect computers", func() {
				deviceType := discovery.DetectDeviceType("DESKTOP-ABC123", "", "", nil)
				Expect(deviceType).To(Equal("Computer"))
			})

			It("should detect IoT devices", func() {
				deviceType := discovery.DetectDeviceType("tasmota_12345", "", "", nil)
				Expect(deviceType).To(Equal("IoT Device"))
			})
		})

		Context("by vendor", func() {
			It("should detect Apple devices", func() {
				deviceType := discovery.DetectDeviceType("", "", "Apple", nil)
				Expect(deviceType).To(Equal("Computer"))
			})

			It("should detect Espressif IoT devices", func() {
				deviceType := discovery.DetectDeviceType("", "", "Espressif", nil)
				Expect(deviceType).To(Equal("IoT Device"))
			})

			It("should detect Raspberry Pi", func() {
				deviceType := discovery.DetectDeviceType("", "", "Raspberry Pi Foundation", nil)
				Expect(deviceType).To(Equal("Computer"))
			})
		})

		Context("by open ports", func() {
			It("should detect Windows systems by port 445", func() {
				ports := []int{445, 135}
				deviceType := discovery.DetectDeviceType("", "", "", ports)
				Expect(deviceType).To(ContainSubstring("Windows"))
			})

			It("should detect SSH servers", func() {
				ports := []int{22}
				deviceType := discovery.DetectDeviceType("", "", "", ports)
				// Should detect as some kind of Server with SSH/Unix/Linux
				Expect(deviceType).To(ContainSubstring("Server"))
				Expect(deviceType).To(Or(ContainSubstring("Linux"), ContainSubstring("Unix")))
			})

			It("should detect web servers", func() {
				ports := []int{80, 443}
				deviceType := discovery.DetectDeviceType("", "", "", ports)
				Expect(deviceType).To(ContainSubstring("Server"))
			})
		})

		Context("with locally-administered MAC", func() {
			It("should detect smartphone privacy mode", func() {
				// Locally-administered MAC (2nd char is 2, 6, A, or E)
				deviceType := discovery.DetectDeviceType("", "02:00:00:00:00:00", "", nil)
				Expect(deviceType).To(Equal("Smartphone (Privacy)"))
			})
		})

		Context("with no information", func() {
			It("should return Unknown", func() {
				deviceType := discovery.DetectDeviceType("", "", "", nil)
				Expect(deviceType).To(Equal("Unknown"))
			})
		})
	})
})
