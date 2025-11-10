package discovery_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"netspy/pkg/discovery"
)

var _ = Describe("MAC Vendor Detection", func() {
	Describe("GetMACVendor", func() {
		Context("with well-known MAC addresses", func() {
			It("should identify Apple devices", func() {
				// Apple OUI: 00:03:93
				vendor := discovery.GetMACVendor("00:03:93:12:34:56")
				Expect(vendor).To(ContainSubstring("Apple"))
			})

			It("should identify Espressif devices", func() {
				// Espressif OUI: 60:01:94
				vendor := discovery.GetMACVendor("60:01:94:aa:bb:cc")
				Expect(vendor).To(Equal("Espressif"))
			})

			It("should handle MAC addresses with dashes", func() {
				vendor := discovery.GetMACVendor("00-03-93-12-34-56")
				Expect(vendor).To(ContainSubstring("Apple"))
			})

			It("should handle MAC addresses without separators", func() {
				vendor := discovery.GetMACVendor("000393123456")
				Expect(vendor).To(ContainSubstring("Apple"))
			})
		})

		Context("with unknown MAC addresses", func() {
			It("should return empty string for unknown vendors", func() {
				vendor := discovery.GetMACVendor("ff:ff:ff:ff:ff:ff")
				Expect(vendor).To(BeEmpty())
			})
		})

		Context("with invalid MAC addresses", func() {
			It("should handle empty MAC addresses", func() {
				vendor := discovery.GetMACVendor("")
				Expect(vendor).To(BeEmpty())
			})

			It("should handle malformed MAC addresses", func() {
				vendor := discovery.GetMACVendor("not-a-mac")
				Expect(vendor).To(BeEmpty())
			})
		})
	})
})
