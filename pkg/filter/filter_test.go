package filter_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"netspy/pkg/filter"
)

func TestFilter(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Filter Suite")
}

var _ = Describe("Filter Package", func() {

	Describe("Filter.Match", func() {
		var fields map[string]string

		BeforeEach(func() {
			fields = map[string]string{
				"ip":     "192.168.1.100",
				"host":   "myrouter.local",
				"mac":    "aa:bb:cc:dd:ee:ff",
				"vendor": "Apple Inc.",
				"device": "Router",
				"status": "online",
			}
		})

		Context("Einfache Filter", func() {
			It("sollte leeren Filter immer matchen", func() {
				f := filter.New("")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte exakten Wert matchen", func() {
				f := filter.New("online")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte nicht-existierenden Wert nicht matchen", func() {
				f := filter.New("offline")
				Expect(f.Match(fields)).To(BeFalse())
			})
		})

		Context("Spalten-Filter (column=value)", func() {
			It("sollte ip=... matchen", func() {
				f := filter.New("ip=192.168.1.100")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte host=... matchen", func() {
				f := filter.New("host=myrouter.local")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte vendor=... mit Substring matchen", func() {
				f := filter.New("vendor=Apple")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte status=... matchen", func() {
				f := filter.New("status=online")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte unbekannte Spalte nicht matchen", func() {
				f := filter.New("unknown=value")
				Expect(f.Match(fields)).To(BeFalse())
			})
		})

		Context("Aliase", func() {
			It("sollte Alias auflösen", func() {
				f := filter.New("h=myrouter").WithAliases(map[string]string{"h": "host"})
				Expect(f.Match(fields)).To(BeTrue())
			})
		})

		Context("Wildcards", func() {
			It("sollte * am Ende matchen", func() {
				f := filter.New("ip=192.168.*")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte * am Anfang matchen", func() {
				f := filter.New("host=*local")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte * in der Mitte matchen", func() {
				f := filter.New("mac=aa:bb:*:ff")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte nicht matchendes Wildcard ablehnen", func() {
				f := filter.New("ip=10.*")
				Expect(f.Match(fields)).To(BeFalse())
			})
		})

		Context("NOT Operator", func() {
			It("sollte !offline matchen wenn online", func() {
				f := filter.New("!offline")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte !online nicht matchen wenn online", func() {
				f := filter.New("!online")
				Expect(f.Match(fields)).To(BeFalse())
			})

			It("sollte NOT als Wort erkennen", func() {
				f := filter.New("NOT offline")
				Expect(f.Match(fields)).To(BeTrue())
			})
		})

		Context("AND Operator", func() {
			It("sollte && mit zwei wahren Teilen matchen", func() {
				f := filter.New("online && Apple")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte && mit einem falschen Teil nicht matchen", func() {
				f := filter.New("online && Samsung")
				Expect(f.Match(fields)).To(BeFalse())
			})

			It("sollte AND als Wort erkennen", func() {
				f := filter.New("online AND Apple")
				Expect(f.Match(fields)).To(BeTrue())
			})
		})

		Context("OR Operator", func() {
			It("sollte || mit einem wahren Teil matchen", func() {
				f := filter.New("Samsung || Apple")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte || mit zwei falschen Teilen nicht matchen", func() {
				f := filter.New("Samsung || Huawei")
				Expect(f.Match(fields)).To(BeFalse())
			})

			It("sollte OR als Wort erkennen", func() {
				f := filter.New("Samsung OR Apple")
				Expect(f.Match(fields)).To(BeTrue())
			})
		})

		Context("Klammern", func() {
			It("sollte einfache Klammern evaluieren", func() {
				f := filter.New("(vendor=Apple)")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte OR in Klammern vor AND evaluieren", func() {
				// (Samsung || Apple) && online = (false || true) && true = true
				f := filter.New("(vendor=Samsung || vendor=Apple) && status=online")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte verschachtelte Klammern evaluieren", func() {
				// ((Apple || Samsung) && online) = ((true || false) && true) = true
				f := filter.New("((vendor=Apple || vendor=Samsung) && status=online)")
				Expect(f.Match(fields)).To(BeTrue())
			})
		})

		Context("CIDR Filter", func() {
			It("sollte IP im CIDR-Bereich matchen", func() {
				f := filter.New("192.168.1.0/24").WithIPField("ip")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte IP außerhalb CIDR nicht matchen", func() {
				f := filter.New("10.0.0.0/8").WithIPField("ip")
				Expect(f.Match(fields)).To(BeFalse())
			})
		})

		Context("IP-Bereich Filter", func() {
			It("sollte IP im Bereich matchen", func() {
				f := filter.New("192.168.1.50-150").WithIPField("ip")
				Expect(f.Match(fields)).To(BeTrue())
			})

			It("sollte IP außerhalb Bereich nicht matchen", func() {
				f := filter.New("192.168.1.1-50").WithIPField("ip")
				Expect(f.Match(fields)).To(BeFalse())
			})
		})
	})

	Describe("Validate", func() {
		It("sollte leeren Filter akzeptieren", func() {
			err := filter.Validate("")
			Expect(err).To(BeNil())
		})

		It("sollte gültigen Filter akzeptieren", func() {
			err := filter.Validate("vendor=Apple && status=online")
			Expect(err).To(BeNil())
		})

		It("sollte unbalancierte Klammern ablehnen", func() {
			err := filter.Validate("(vendor=Apple")
			Expect(err).NotTo(BeNil())
		})

		It("sollte && am Anfang ablehnen", func() {
			err := filter.Validate("&& vendor=Apple")
			Expect(err).NotTo(BeNil())
		})

		It("sollte || am Ende ablehnen", func() {
			err := filter.Validate("vendor=Apple ||")
			Expect(err).NotTo(BeNil())
		})

		It("sollte ungültiges CIDR ablehnen", func() {
			err := filter.Validate("192.168.1.0/99")
			Expect(err).NotTo(BeNil())
		})

		It("sollte gültiges CIDR akzeptieren", func() {
			err := filter.Validate("192.168.1.0/24")
			Expect(err).To(BeNil())
		})

		It("sollte ungültigen IP-Bereich ablehnen", func() {
			err := filter.Validate("192.168.1.1-999")
			Expect(err).NotTo(BeNil())
		})

		It("sollte gültigen IP-Bereich akzeptieren", func() {
			err := filter.Validate("192.168.1.1-50")
			Expect(err).To(BeNil())
		})
	})

	Describe("NormalizeOperators", func() {
		It("sollte AND zu && konvertieren", func() {
			result := filter.NormalizeOperators("a AND b")
			Expect(result).To(Equal("a && b"))
		})

		It("sollte OR zu || konvertieren", func() {
			result := filter.NormalizeOperators("a OR b")
			Expect(result).To(Equal("a || b"))
		})

		It("sollte NOT zu ! konvertieren", func() {
			result := filter.NormalizeOperators("NOT offline")
			Expect(result).To(Equal("!offline"))
		})

		It("sollte gemischte Operatoren konvertieren", func() {
			result := filter.NormalizeOperators("a AND b OR NOT c")
			Expect(result).To(Equal("a && b || !c"))
		})
	})

	Describe("Matcher Funktionen", func() {
		Describe("IsIPRange", func() {
			It("sollte gültigen IP-Bereich erkennen", func() {
				Expect(filter.IsIPRange("192.168.1.1-50")).To(BeTrue())
			})

			It("sollte ungültigen IP-Bereich ablehnen", func() {
				Expect(filter.IsIPRange("192.168.1.1")).To(BeFalse())
				Expect(filter.IsIPRange("abc")).To(BeFalse())
			})
		})

		Describe("MatchCIDR", func() {
			It("sollte IP im CIDR matchen", func() {
				Expect(filter.MatchCIDR("192.168.1.0/24", "192.168.1.100")).To(BeTrue())
			})

			It("sollte IP außerhalb CIDR nicht matchen", func() {
				Expect(filter.MatchCIDR("192.168.1.0/24", "192.168.2.1")).To(BeFalse())
			})
		})

		Describe("MatchIPRange", func() {
			It("sollte IP im Bereich matchen", func() {
				Expect(filter.MatchIPRange("192.168.1.50-150", "192.168.1.100")).To(BeTrue())
			})

			It("sollte IP außerhalb Bereich nicht matchen", func() {
				Expect(filter.MatchIPRange("192.168.1.50-150", "192.168.1.200")).To(BeFalse())
			})
		})

		Describe("MatchWildcard", func() {
			It("sollte Wildcard am Ende matchen", func() {
				Expect(filter.MatchWildcard("192.168.*", []string{"192.168.1.1"})).To(BeTrue())
			})

			It("sollte Wildcard am Anfang matchen", func() {
				Expect(filter.MatchWildcard("*local", []string{"myrouter.local"})).To(BeTrue())
			})
		})
	})
})
