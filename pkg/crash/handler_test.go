package crash

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// captureOutput liefert alles, was f auf os.Stdout und os.Stderr schreibt
func captureOutput(f func()) string {
	origOut, origErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	Expect(err).NotTo(HaveOccurred())
	os.Stdout, os.Stderr = w, w
	defer func() { os.Stdout, os.Stderr = origOut, origErr }()

	done := make(chan string)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()

	f()
	Expect(w.Close()).To(Succeed())
	return <-done
}

var _ = Describe("Crash", func() {
	// Sentinel und Crash-Log in einen Temp-Ordner umleiten
	BeforeEach(func() {
		dir := GinkgoT().TempDir()
		origLog, origSentinel := crashLogFile, sentinelFile
		crashLogFile = filepath.Join(dir, "netspy_crash.log")
		sentinelFile = filepath.Join(dir, ".netspy.running")
		DeferCleanup(func() {
			crashLogFile, sentinelFile = origLog, origSentinel
		})
	})

	Describe("formatBytes", func() {
		DescribeTable("formatiert mit 1024er-Einheiten",
			func(b uint64, expected string) {
				Expect(formatBytes(b)).To(Equal(expected))
			},
			Entry("Bytes", uint64(512), "512 B"),
			Entry("genau 1 KB", uint64(1024), "1.0 KB"),
			Entry("KB", uint64(1536), "1.5 KB"),
			Entry("MB", uint64(5*1024*1024), "5.0 MB"),
			Entry("GB", uint64(3*1024*1024*1024), "3.0 GB"),
		)
	})

	Describe("formatCrashLog", func() {
		It("enthält Fehler, Umgebung und Stacktrace", func() {
			log := formatCrashLog(CrashInfo{
				Time:       time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
				Error:      errors.New("kaputt"),
				GoVersion:  "go1.27",
				OS:         "linux",
				Arch:       "amd64",
				StackTrace: "goroutine 1 [running]:",
			})

			Expect(log).To(ContainSubstring("CRASH REPORT - 2026-01-02 03:04:05"))
			Expect(log).To(ContainSubstring("Error: kaputt"))
			Expect(log).To(ContainSubstring("OS/Arch: linux/amd64"))
			Expect(log).To(ContainSubstring("goroutine 1 [running]:"))
		})
	})

	Describe("RecoverAndLog", func() {
		It("fängt einen Panic ab, schreibt ihn ins Crash-Log und läuft weiter", func() {
			out := captureOutput(func() {
				func() {
					defer RecoverAndLog("testTask")
					panic("absichtlich")
				}()
			})

			Expect(out).To(ContainSubstring("Fehler in testTask wurde abgefangen: absichtlich"))
			content, err := os.ReadFile(crashLogFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(content)).To(ContainSubstring("recovered in 'testTask': absichtlich"))
		})

		It("tut ohne Panic nichts", func() {
			func() {
				defer RecoverAndLog("testTask")
			}()
			Expect(crashLogFile).NotTo(BeAnExistingFile())
		})
	})

	Describe("Sentinel", func() {
		It("meldet nach sauberem Ende keinen unsauberen Lauf", func() {
			captureOutput(func() {
				Expect(StartSentinel()).To(BeFalse())
			})
			Expect(sentinelFile).To(BeAnExistingFile())

			StopSentinel()
			Expect(sentinelFile).NotTo(BeAnExistingFile())

			captureOutput(func() {
				Expect(StartSentinel()).To(BeFalse())
			})
		})

		It("meldet einen von außen beendeten Lauf ohne Crash-Report", func() {
			captureOutput(func() { StartSentinel() })

			// Kein StopSentinel: Prozess wurde von außen beendet
			out := captureOutput(func() {
				Expect(StartSentinel()).To(BeTrue())
			})
			Expect(out).To(ContainSubstring("nicht sauber beendet"))
			Expect(out).To(ContainSubstring("Kein Crash-Report"))
		})

		It("meldet einen Crash-Report, wenn der letzte Lauf abgestürzt ist", func() {
			captureOutput(func() { StartSentinel() })
			logCrash(CrashInfo{Time: time.Now(), Error: "absichtlich"})

			out := captureOutput(func() {
				Expect(StartSentinel()).To(BeTrue())
			})
			Expect(out).To(ContainSubstring("Crash-Report gefunden"))
		})

		It("hält einen alten Crash-Report aus einem früheren Lauf nicht für den aktuellen", func() {
			// Früherer Absturz, Crash-Log liegt seitdem im Verzeichnis
			logCrash(CrashInfo{Time: time.Now(), Error: "alter Absturz"})
			old := time.Now().Add(-24 * time.Hour)
			Expect(os.Chtimes(crashLogFile, old, old)).To(Succeed())

			// Letzter Lauf wurde von außen beendet, nicht abgestürzt
			captureOutput(func() { StartSentinel() })
			out := captureOutput(func() {
				Expect(StartSentinel()).To(BeTrue())
			})
			Expect(out).To(ContainSubstring("Kein Crash-Report"))
		})
	})
})
