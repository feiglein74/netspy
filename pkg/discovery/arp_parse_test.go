package discovery

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Die Parser sind reine Funktionen und werden auf jeder Plattform mit
// Beispielausgaben aller drei Betriebssysteme getestet.

// entryStrings macht die Einträge als "IP MAC" vergleichbar
func entryStrings(entries []ARPEntry) []string {
	result := make([]string, 0, len(entries))
	for _, e := range entries {
		result = append(result, e.IP.String()+" "+e.MAC.String())
	}
	return result
}

var _ = Describe("ARP-Parser", func() {
	var a *ARPScanner

	BeforeEach(func() {
		a = &ARPScanner{}
	})

	Describe("parseWindowsARPOutput", func() {
		It("parst die deutsche Ausgabe mit CRLF und überspringt Broadcast und Multicast", func() {
			// Format von arp -a unter Windows 11 (deutsch), Zeilenenden CRLF
			output := strings.Join([]string{
				"",
				"Schnittstelle: 192.168.88.1 --- 0x2",
				"  Internetadresse       Physische Adresse     Typ",
				"  192.168.88.31         00-0c-29-54-fe-c9     dynamisch ",
				"  192.168.88.255        ff-ff-ff-ff-ff-ff     statisch  ",
				"  224.0.0.22            01-00-5e-00-00-16     statisch  ",
				"  239.255.255.250       01-00-5e-7f-ff-fa     statisch  ",
				"",
				"Schnittstelle: 192.0.2.10 --- 0x5",
				"  Internetadresse       Physische Adresse     Typ",
				"  192.0.2.1             02-00-5e-10-00-01     dynamisch ",
				"",
			}, "\r\n")

			entries, err := a.parseWindowsARPOutput(output)

			Expect(err).NotTo(HaveOccurred())
			Expect(entryStrings(entries)).To(Equal([]string{
				"192.168.88.31 00:0c:29:54:fe:c9",
				"192.0.2.1 02:00:5e:10:00:01",
			}))
			Expect(entries[0].Online).To(BeTrue())
		})

		It("parst die englische Ausgabe", func() {
			output := "\nInterface: 192.0.2.10 --- 0x5\n" +
				"  Internet Address      Physical Address      Type\n" +
				"  192.0.2.1             AA-BB-CC-DD-EE-F0     dynamic\n"

			entries, err := a.parseWindowsARPOutput(output)

			Expect(err).NotTo(HaveOccurred())
			Expect(entryStrings(entries)).To(Equal([]string{"192.0.2.1 aa:bb:cc:dd:ee:f0"}))
		})

		It("ignoriert Kopfzeilen und liefert bei leerer Ausgabe keine Einträge", func() {
			entries, err := a.parseWindowsARPOutput("Schnittstelle: 192.0.2.10 --- 0x5\r\n")

			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty())
		})
	})

	Describe("parseLinuxARPOutput", func() {
		It("parst Einträge und überspringt unvollständige", func() {
			output := "gateway (192.0.2.1) at aa:bb:cc:dd:ee:f0 [ether] on eth0\n" +
				"? (192.0.2.50) at 00:11:22:33:44:55 [ether] on eth0\n" +
				"? (192.0.2.99) at <incomplete> on eth0\n"

			entries, err := a.parseLinuxARPOutput(output)

			Expect(err).NotTo(HaveOccurred())
			Expect(entryStrings(entries)).To(Equal([]string{
				"192.0.2.1 aa:bb:cc:dd:ee:f0",
				"192.0.2.50 00:11:22:33:44:55",
			}))
		})

		It("überspringt Multicast-MACs", func() {
			output := "? (224.0.0.251) at 01:00:5e:00:00:fb [ether] on eth0\n"

			entries, err := a.parseLinuxARPOutput(output)

			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty())
		})
	})

	Describe("parseMacARPOutput", func() {
		It("ergänzt fehlende führende Nullen und überspringt incomplete und Broadcast", func() {
			output := "? (192.0.2.1) at 24:5a:4c:95:bf:f5 on en0 ifscope [ethernet]\n" +
				"host (192.0.2.51) at 70:3:9f:60:e8:a4 on en0 ifscope [ethernet]\n" +
				"? (192.0.2.60) at (incomplete) on en0 ifscope [ethernet]\n" +
				"? (192.0.2.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"

			entries, err := a.parseMacARPOutput(output)

			Expect(err).NotTo(HaveOccurred())
			Expect(entryStrings(entries)).To(Equal([]string{
				"192.0.2.1 24:5a:4c:95:bf:f5",
				"192.0.2.51 70:03:9f:60:e8:a4",
			}))
		})
	})

	Describe("normalizeMacAddress", func() {
		DescribeTable("füllt einstellige Segmente mit führender Null auf",
			func(input, expected string) {
				Expect(normalizeMacAddress(input)).To(Equal(expected))
			},
			Entry("ein kurzes Segment", "70:3:9f:60:e8:a4", "70:03:9f:60:e8:a4"),
			Entry("mehrere kurze Segmente", "0:1:2:3:4:5", "00:01:02:03:04:05"),
			Entry("bereits vollständig", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
		)
	})
})
