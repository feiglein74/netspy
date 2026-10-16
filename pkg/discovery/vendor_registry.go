package discovery

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"netspy/pkg/crash"
)

// IEEE-Registry: Lokaler Cache der drei MAC-Zuteilungsregister.
//
// Die IEEE vergibt MAC-Blöcke in drei Größen: MA-L belegt die ersten 24 Bit,
// MA-M die ersten 28 Bit und MA-S die ersten 36 Bit. Ein MA-L-Block kann in
// kleinere MA-M- oder MA-S-Blöcke unterteilt sein. Der MA-L-Eintrag trägt
// dann den Namen der Registrierungsstelle statt eines Herstellers.
//
// Der Lookup ist deshalb ein Longest-Prefix-Match: Das längste passende
// Präfix gewinnt, also MA-S vor MA-M vor MA-L.
//
// Datenschutz: Es werden ausschließlich die vollständigen Registry-Dateien
// heruntergeladen, niemals einzelne MAC-Adressen abgefragt. Der Abruf verrät
// dem Server damit nichts über das lokale Netz. Der Lookup selbst läuft rein
// lokal, es verlässt keine MAC-Adresse den Rechner.

// registrySource beschreibt eine der drei IEEE-Registry-Dateien
type registrySource struct {
	name      string // Dateiname im Cache-Verzeichnis
	url       string
	prefixLen int // Länge des Präfixes in Hex-Zeichen
}

// registrySources ist nach Präfixlänge absteigend sortiert, damit der
// Lookup das längste Präfix zuerst prüft
var registrySources = []registrySource{
	{name: "oui36.csv", url: "https://standards-oui.ieee.org/oui36/oui36.csv", prefixLen: 9},
	{name: "mam.csv", url: "https://standards-oui.ieee.org/oui28/mam.csv", prefixLen: 7},
	{name: "oui.csv", url: "https://standards-oui.ieee.org/oui/oui.csv", prefixLen: 6},
}

// registryMaxAge legt fest, ab wann eine zwischengespeicherte Datei
// im Hintergrund erneuert wird
const registryMaxAge = 30 * 24 * time.Hour

var (
	// registryTables bildet die Präfixlänge auf die jeweilige Zuordnung
	// Präfix -> Herstellername ab
	registryTables  = make(map[int]map[string]string)
	registryMux     sync.RWMutex
	registryDirOnce sync.Once
	registryDirPath string
)

// registryDir liefert das Cache-Verzeichnis für die Registry-Dateien
func registryDir() string {
	registryDirOnce.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		registryDirPath = filepath.Join(home, ".netspy", "registry")
	})
	return registryDirPath
}

// InitVendorRegistry lädt die zwischengespeicherten Registry-Dateien und
// stößt bei fehlenden oder veralteten Dateien einen Download im Hintergrund
// an. Der Aufruf blockiert nicht auf Netzwerk-Zugriffen.
func InitVendorRegistry() {
	dir := registryDir()
	if dir == "" {
		return
	}

	// Vorhandenen Cache sofort laden, damit der erste Scan Daten hat
	loadRegistryCache(dir)

	go func() {
		defer crash.RecoverAndLog("discovery.vendorRegistry")
		refreshRegistry(dir)
	}()
}

// loadRegistryCache liest alle vorhandenen Registry-Dateien aus dem Cache
func loadRegistryCache(dir string) {
	for _, src := range registrySources {
		loadRegistryFile(dir, src)
	}
}

// loadRegistryFile liest eine einzelne Registry-Datei und übernimmt sie
func loadRegistryFile(dir string, src registrySource) {
	file, err := os.Open(filepath.Join(dir, src.name))
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	table, err := parseRegistryCSV(file, src.prefixLen)
	if err != nil || len(table) == 0 {
		return
	}

	registryMux.Lock()
	registryTables[src.prefixLen] = table
	registryMux.Unlock()
}

// parseRegistryCSV liest eine IEEE-CSV-Datei im Format
// "Registry,Assignment,Organization Name,Organization Address"
func parseRegistryCSV(r io.Reader, prefixLen int) (map[string]string, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1 // Adressfeld enthält gelegentlich Kommata
	reader.LazyQuotes = true

	table := make(map[string]string)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Einzelne fehlerhafte Zeilen überspringen, Rest weiterlesen
			if _, ok := err.(*csv.ParseError); ok {
				continue
			}
			return table, err
		}

		if len(record) < 3 {
			continue
		}

		assignment := strings.ToUpper(strings.TrimSpace(record[1]))
		vendor := strings.TrimSpace(record[2])

		// Filtert die Kopfzeile und unpassende Einträge aus
		if len(assignment) != prefixLen || vendor == "" {
			continue
		}

		table[assignment] = vendor
	}

	return table, nil
}

// lookupRegistryVendor sucht den Hersteller per Longest-Prefix-Match.
// macHex ist die MAC ohne Trennzeichen in Großbuchstaben.
func lookupRegistryVendor(macHex string) string {
	registryMux.RLock()
	defer registryMux.RUnlock()

	// registrySources ist absteigend sortiert, das längste Präfix gewinnt
	for _, src := range registrySources {
		if len(macHex) < src.prefixLen {
			continue
		}

		table, ok := registryTables[src.prefixLen]
		if !ok {
			continue
		}

		if vendor, ok := table[macHex[:src.prefixLen]]; ok {
			return vendor
		}
	}

	return ""
}

// refreshRegistry lädt fehlende oder veraltete Registry-Dateien neu
func refreshRegistry(dir string) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return
	}

	for _, src := range registrySources {
		path := filepath.Join(dir, src.name)

		// Aktuelle Dateien überspringen
		if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) < registryMaxAge {
			continue
		}

		if err := downloadRegistry(src, path); err != nil {
			continue
		}

		// Frisch geladene Datei sofort übernehmen
		loadRegistryFile(dir, src)
	}
}

// downloadRegistry lädt eine Registry-Datei und ersetzt die zwischen-
// gespeicherte Fassung erst nach vollständigem Download
func downloadRegistry(src registrySource, path string) error {
	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	resp, err := client.Get(src.url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d für %s", resp.StatusCode, src.name)
	}

	// Erst in eine temporäre Datei schreiben, damit ein abgebrochener
	// Download den vorhandenen Cache nicht beschädigt
	tmpPath := path + ".tmp"
	file, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	if _, err := io.Copy(file, resp.Body); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return err
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, path)
}
