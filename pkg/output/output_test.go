package output

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"netspy/pkg/scanner"
)

// captureStdout liefert alles, was f auf os.Stdout schreibt
func captureStdout(f func() error) string {
	orig := os.Stdout
	r, w, err := os.Pipe()
	Expect(err).NotTo(HaveOccurred())
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()

	Expect(f()).To(Succeed())
	Expect(w.Close()).To(Succeed())
	return <-done
}

var _ = Describe("Output", func() {
	Describe("Truncate", func() {
		BeforeEach(func() {
			TruncateConfig.Enabled = true
			TruncateConfig.ShowInfo = true
		})

		It("lässt kurze Texte unverändert", func() {
			Expect(Truncate("router", 16)).To(Equal("router"))
			Expect(Truncate("genau-16-zeichen", 16)).To(Equal("genau-16-zeichen"))
		})

		It("kürzt nicht mit --full-output", func() {
			SetFullOutput(true)
			defer SetFullOutput(false)
			long := strings.Repeat("x", 50)
			Expect(Truncate(long, 16)).To(Equal(long))
		})

		It("kürzt kurze Spalten mit Ellipsis auf die Spaltenbreite", func() {
			Expect(Truncate("abcdefghij", 6)).To(Equal("abcde…"))
		})

		// Design-Prinzip "Transparenz": [+N] muss die tatsächlich versteckten Zeichen nennen
		It("nennt in [+N] die Anzahl der tatsächlich versteckten Zeichen", func() {
			s := "wohnzimmer-fernseher-samsung" // 28 Zeichen
			result := Truncate(s, 16)

			m := regexp.MustCompile(`^(.*)…\[\+(\d+)\]$`).FindStringSubmatch(result)
			Expect(m).NotTo(BeNil(), "Ergebnis: %q", result)
			shown := m[1]
			hidden, _ := strconv.Atoi(m[2])
			Expect(strings.HasPrefix(s, shown)).To(BeTrue())
			Expect(hidden).To(Equal(utf8.RuneCountInString(s)-utf8.RuneCountInString(shown)), "Ergebnis: %q", result)
		})

		It("hält die Spaltenbreite in Zeichen ein", func() {
			for _, maxLen := range []int{4, 6, 10, 16, 23} {
				result := Truncate(strings.Repeat("a", 40), maxLen)
				Expect(utf8.RuneCountInString(result)).To(BeNumerically("<=", maxLen), "maxLen %d: %q", maxLen, result)
			}
		})

		It("zerschneidet keine Umlaute (gültiges UTF-8)", func() {
			for _, maxLen := range []int{3, 4, 5, 6, 10, 16} {
				result := Truncate("Küchenradio-Wohnküche-Süd", maxLen)
				Expect(utf8.ValidString(result)).To(BeTrue(), "maxLen %d: %q", maxLen, result)
				Expect(utf8.RuneCountInString(result)).To(BeNumerically("<=", maxLen), "maxLen %d: %q", maxLen, result)
			}
		})
	})

	Describe("TruncateMAC", func() {
		It("kürzt MAC-Adressen nie", func() {
			Expect(TruncateMAC("00:11:22:33:44:55", 5)).To(Equal("00:11:22:33:44:55"))
		})
	})

	Describe("TerminalSize", func() {
		DescribeTable("ordnet die Breite einer Layout-Stufe zu",
			func(width int, narrow, medium, wide bool) {
				ts := TerminalSize{Width: width, Height: 40}
				Expect(ts.IsNarrow()).To(Equal(narrow))
				Expect(ts.IsMedium()).To(Equal(medium))
				Expect(ts.IsWide()).To(Equal(wide))
			},
			Entry("99 schmal", 99, true, false, false),
			Entry("100 mittel", 100, false, true, false),
			Entry("139 mittel", 139, false, true, false),
			Entry("140 breit", 140, false, false, true),
		)

		It("ist unter 80 Spalten oder 15 Zeilen zu klein", func() {
			Expect(TerminalSize{Width: 79, Height: 40}.IsTooSmall()).To(BeTrue())
			Expect(TerminalSize{Width: 80, Height: 14}.IsTooSmall()).To(BeTrue())
			Expect(TerminalSize{Width: 80, Height: 15}.IsTooSmall()).To(BeFalse())
		})
	})

	Describe("PrintResults", func() {
		hosts := []scanner.Host{
			{IP: net.ParseIP("192.0.2.10"), Online: true, Hostname: "nas", MAC: "00:11:32:aa:bb:cc",
				Vendor: "Synology Incorporated", RTT: 1500 * time.Microsecond, Ports: []int{22, 443}},
			{IP: net.ParseIP("192.0.2.2"), Online: true, Vendor: "Nokia Shanghai Bell Co., Ltd."},
			{IP: net.ParseIP("192.0.2.3"), Online: false},
		}

		Describe("JSON", func() {
			It("gibt nur Online-Hosts als gültiges JSON aus, numerisch nach IP sortiert", func() {
				out := captureStdout(func() error { return PrintResults(hosts, "json") })

				var parsed []map[string]any
				Expect(json.Unmarshal([]byte(out), &parsed)).To(Succeed())
				Expect(parsed).To(HaveLen(2))
				Expect(parsed[0]["ip"]).To(Equal("192.0.2.2"))
				Expect(parsed[1]["ip"]).To(Equal("192.0.2.10"))
			})
		})

		Describe("CSV", func() {
			It("gibt gültiges CSV aus, auch wenn ein Feld ein Komma enthält", func() {
				out := captureStdout(func() error { return PrintResults(hosts, "csv") })

				records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
				Expect(err).NotTo(HaveOccurred(), "Ausgabe:\n%s", out)
				Expect(records).To(HaveLen(3))
				Expect(records[0]).To(Equal([]string{"IP", "Hostname", "RTT", "MAC", "Vendor", "DeviceType", "Ports"}))
				Expect(records[1]).To(Equal([]string{"192.0.2.2", "", "", "", "Nokia Shanghai Bell Co., Ltd.", "", ""}))
				Expect(records[2]).To(Equal([]string{"192.0.2.10", "nas", "1.50", "00:11:32:aa:bb:cc", "Synology Incorporated", "", "22;443"}))
			})
		})
	})
})
