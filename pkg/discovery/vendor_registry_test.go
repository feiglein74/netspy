package discovery

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Testdaten im Format der IEEE-CSV-Dateien. Der Block 58:47:CA ist in
// MA-M-Blöcke unterteilt, der MA-L-Eintrag nennt deshalb nur die
// Registrierungsstelle.
const (
	testCSVMAL = `Registry,Assignment,Organization Name,Organization Address
MA-L,286FB9,"Nokia Shanghai Bell Co., Ltd.","No.388 Ning Qiao Road Shanghai CN"
MA-L,5847CA,IEEE Registration Authority,"445 Hoes Lane Piscataway NJ US"
`

	testCSVMAM = `Registry,Assignment,Organization Name,Organization Address
MA-M,5847CA7,"Shenzhen Meigao Electronic Equipment Co.,Ltd","Longgang District Shenzhen CN"
`

	testCSVMAS = `Registry,Assignment,Organization Name,Organization Address
MA-S,5847CA8AB,"Beispielfirma GmbH","Musterstadt DE"
`
)

var _ = Describe("IEEE Vendor Registry", func() {
	// Baut die Registry-Tabellen aus den Testdaten auf
	BeforeEach(func() {
		tables := map[int]string{
			6: testCSVMAL,
			7: testCSVMAM,
			9: testCSVMAS,
		}

		registryMux.Lock()
		registryTables = make(map[int]map[string]string)
		registryMux.Unlock()

		for prefixLen, data := range tables {
			table, err := parseRegistryCSV(strings.NewReader(data), prefixLen)
			Expect(err).ToNot(HaveOccurred())

			registryMux.Lock()
			registryTables[prefixLen] = table
			registryMux.Unlock()
		}
	})

	AfterEach(func() {
		registryMux.Lock()
		registryTables = make(map[int]map[string]string)
		registryMux.Unlock()
	})

	Describe("parseRegistryCSV", func() {
		It("überspringt die Kopfzeile", func() {
			table, err := parseRegistryCSV(strings.NewReader(testCSVMAM), 7)
			Expect(err).ToNot(HaveOccurred())
			Expect(table).To(HaveLen(1))
			Expect(table).ToNot(HaveKey("ASSIGNM"))
		})

		It("übernimmt nur Einträge mit passender Präfixlänge", func() {
			// MA-L-Daten haben 6 Zeichen, hier werden 7 erwartet
			table, err := parseRegistryCSV(strings.NewReader(testCSVMAL), 7)
			Expect(err).ToNot(HaveOccurred())
			Expect(table).To(BeEmpty())
		})
	})

	Describe("lookupRegistryVendor", func() {
		It("bevorzugt MA-M gegenüber MA-L bei unterteilten Blöcken", func() {
			// 58:47:CA ist als MA-L der IEEE zugeordnet, der Hersteller
			// steht erst im MA-M-Block 5847CA7
			vendor := lookupRegistryVendor("5847CA7710EE")
			Expect(vendor).To(Equal("Shenzhen Meigao Electronic Equipment Co.,Ltd"))
		})

		It("bevorzugt MA-S als längstes Präfix", func() {
			vendor := lookupRegistryVendor("5847CA8AB123")
			Expect(vendor).To(Equal("Beispielfirma GmbH"))
		})

		It("liefert den MA-L-Eintrag bei nicht unterteilten Blöcken", func() {
			vendor := lookupRegistryVendor("286FB9112233")
			Expect(vendor).To(Equal("Nokia Shanghai Bell Co., Ltd."))
		})

		It("liefert nichts für unbekannte Präfixe", func() {
			vendor := lookupRegistryVendor("FFFFFFFFFFFF")
			Expect(vendor).To(BeEmpty())
		})

		It("kommt mit zu kurzen Eingaben zurecht", func() {
			Expect(lookupRegistryVendor("5847")).To(BeEmpty())
		})
	})

	Describe("isRegistrySentinel", func() {
		It("erkennt Platzhalter der Registrierungsstellen", func() {
			Expect(isRegistrySentinel("IEEE Registration Authority")).To(BeTrue())
			Expect(isRegistrySentinel("Private")).To(BeTrue())
		})

		It("lässt echte Herstellernamen durch", func() {
			Expect(isRegistrySentinel("Apple, Inc.")).To(BeFalse())
			Expect(isRegistrySentinel("Espressif Inc.")).To(BeFalse())
		})
	})

	Describe("normalizeMACHex", func() {
		It("entfernt alle gängigen Trennzeichen", func() {
			Expect(normalizeMACHex("58:47:ca:77:10:ee")).To(Equal("5847CA7710EE"))
			Expect(normalizeMACHex("58-47-CA-77-10-EE")).To(Equal("5847CA7710EE"))
			Expect(normalizeMACHex("5847.CA77.10EE")).To(Equal("5847CA7710EE"))
		})

		It("weist Eingaben ohne gültige Hex-Zeichen zurück", func() {
			Expect(normalizeMACHex("not-a-mac")).To(BeEmpty())
			Expect(normalizeMACHex("")).To(BeEmpty())
			Expect(normalizeMACHex("12:34")).To(BeEmpty())
		})
	})
})
