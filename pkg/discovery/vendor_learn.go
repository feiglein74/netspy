package discovery

import (
	"bufio"
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

// LearnedVendors speichert dynamisch gelernte MAC-Vendors
var (
	learnedVendors     = make(map[string]string)
	learnedVendorsMux  sync.RWMutex
	learnedVendorsFile string
	lookupInProgress   = make(map[string]bool) // Track ongoing lookups
	lookupMux          sync.Mutex
)

// Rate-Limiting für api.macvendors.com: Der kostenlose Tarif erlaubt etwa
// eine Anfrage pro Sekunde. Das Semaphor mit Kapazität 1 serialisiert die
// parallel gestarteten Lookup-Goroutinen, vendorAPILastCall hält zusätzlich
// den Mindestabstand zwischen zwei Anfragen ein.
var (
	vendorAPISem      = make(chan struct{}, 1)
	vendorAPILastCall time.Time
)

// vendorAPIMinInterval ist der Mindestabstand zwischen zwei API-Anfragen
const vendorAPIMinInterval = time.Second

// InitLearnedVendors initialisiert die Learned-Vendors-Datei
func InitLearnedVendors() error {
	// Finde das Executable-Verzeichnis
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exeDir := filepath.Dir(exe)
	learnedVendorsFile = filepath.Join(exeDir, "vendor_learned.txt")

	// Lade bestehende Einträge
	return loadLearnedVendors()
}

// loadLearnedVendors lädt die Learned-Vendors aus der Datei
func loadLearnedVendors() error {
	file, err := os.Open(learnedVendorsFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Datei existiert noch nicht - das ist OK
			return nil
		}
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Ignoriere Kommentare und leere Zeilen
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse Zeile: "AA:BB:CC = Vendor Name"
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		oui := strings.TrimSpace(parts[0])
		vendor := strings.TrimSpace(parts[1])

		// Platzhalter der Registrierungsstellen überspringen, sie würden
		// den korrekten Registry-Treffer überschatten
		if oui != "" && vendor != "" && !isRegistrySentinel(vendor) {
			learnedVendorsMux.Lock()
			learnedVendors[oui] = vendor
			learnedVendorsMux.Unlock()
		}
	}

	return scanner.Err()
}

// GetLearnedVendor versucht zuerst aus learned vendors, dann fallback zu builtin
func GetLearnedVendor(mac string) string {
	if mac == "" || len(mac) < 8 {
		return ""
	}

	// OUI extrahieren (erste 3 Oktette)
	oui := strings.ToUpper(mac[:8]) // AA:BB:CC

	// 1. Versuche aus learned vendors
	learnedVendorsMux.RLock()
	if vendor, ok := learnedVendors[oui]; ok {
		learnedVendorsMux.RUnlock()
		return vendor
	}
	learnedVendorsMux.RUnlock()

	// 2. Fallback zu builtin vendors
	if vendor, ok := ouiDatabase[oui]; ok {
		return vendor
	}

	return ""
}

// LookupAndLearnVendor schlägt unbekannte Vendors online nach und speichert sie
// Wird asynchron aufgerufen um den Scan nicht zu blockieren
func LookupAndLearnVendor(mac string) {
	if mac == "" || len(mac) < 8 {
		return
	}

	oui := strings.ToUpper(mac[:8])

	// Check if already known or lookup in progress
	lookupMux.Lock()
	if lookupInProgress[oui] {
		lookupMux.Unlock()
		return
	}

	// Check if we already know this vendor
	learnedVendorsMux.RLock()
	_, learnedExists := learnedVendors[oui]
	learnedVendorsMux.RUnlock()

	_, builtinExists := ouiDatabase[oui]

	if learnedExists || builtinExists {
		lookupMux.Unlock()
		return
	}

	// Mark as in progress
	lookupInProgress[oui] = true
	lookupMux.Unlock()

	// Perform lookup asynchronously
	go func() {
		defer crash.RecoverAndLog("discovery.vendorLookup")
		defer func() {
			lookupMux.Lock()
			delete(lookupInProgress, oui)
			lookupMux.Unlock()
		}()

		vendor := queryMACVendorAPI(mac)
		if vendor != "" && !isRegistrySentinel(vendor) {
			_ = saveLearnedVendor(oui, vendor)
		}
	}()
}

// isRegistrySentinel erkennt Platzhalter-Namen der Registrierungsstellen.
//
// Solche Namen stehen für einen unterteilten Block und benennen keinen
// Hersteller. Sie dürfen nicht gelernt werden, da ein gelernter Eintrag
// Vorrang hat und den korrekten Registry-Treffer dauerhaft überschatten
// würde. Die Auflösung übernimmt in diesen Fällen die IEEE-Registry.
func isRegistrySentinel(vendor string) bool {
	normalized := strings.ToLower(vendor)

	sentinels := []string{
		"ieee registration authority",
		"private",
	}

	for _, sentinel := range sentinels {
		if strings.Contains(normalized, sentinel) {
			return true
		}
	}

	return false
}

// queryMACVendorAPI fragt api.macvendors.com nach dem Vendor
func queryMACVendorAPI(mac string) string {
	// Semaphor belegen: Nur eine Anfrage gleichzeitig
	vendorAPISem <- struct{}{}
	defer func() {
		// Zeitpunkt des Aufrufs merken, danach Semaphor freigeben
		vendorAPILastCall = time.Now()
		<-vendorAPISem
	}()

	// Mindestabstand zur vorherigen Anfrage abwarten
	if wait := vendorAPIMinInterval - time.Since(vendorAPILastCall); wait > 0 {
		time.Sleep(wait)
	}

	// API: https://api.macvendors.com/{mac}
	url := fmt.Sprintf("https://api.macvendors.com/%s", mac)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	vendor := strings.TrimSpace(string(body))

	// Kürze lange Vendor-Namen
	if len(vendor) > 30 {
		// Versuche sinnvolle Kürzungen
		vendor = shortenVendorName(vendor)
	}

	return vendor
}

// shortenVendorName kürzt lange Vendor-Namen sinnvoll
func shortenVendorName(name string) string {
	// Entferne häufige Suffixe
	name = strings.TrimSuffix(name, " Inc.")
	name = strings.TrimSuffix(name, " Inc")
	name = strings.TrimSuffix(name, " LLC")
	name = strings.TrimSuffix(name, " Ltd.")
	name = strings.TrimSuffix(name, " Ltd")
	name = strings.TrimSuffix(name, " Corporation")
	name = strings.TrimSuffix(name, " Corp.")
	name = strings.TrimSuffix(name, " Corp")
	name = strings.TrimSuffix(name, " GmbH")
	name = strings.TrimSuffix(name, " Co., Ltd.")
	name = strings.TrimSuffix(name, " Company")

	// Wenn immer noch zu lang, schneide ab
	if len(name) > 25 {
		name = name[:25]
	}

	return strings.TrimSpace(name)
}

// saveLearnedVendor speichert einen neu gelernten Vendor in die Datei
func saveLearnedVendor(oui, vendor string) error {
	// Füge zu Map hinzu
	learnedVendorsMux.Lock()
	learnedVendors[oui] = vendor
	learnedVendorsMux.Unlock()

	// Erstelle Datei falls nicht vorhanden
	if _, err := os.Stat(learnedVendorsFile); os.IsNotExist(err) {
		// Schreibe Header
		header := `# NetSpy Learned MAC Vendors
# Automatisch erweitert durch API-Lookups (api.macvendors.com)
# Format: OUI = Vendor Name
# Sie können diese Datei manuell bearbeiten

`
		if err := os.WriteFile(learnedVendorsFile, []byte(header), 0644); err != nil {
			return err
		}
	}

	// Append neuen Eintrag
	file, err := os.OpenFile(learnedVendorsFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	line := fmt.Sprintf("%s = %s\n", oui, vendor)
	_, err = file.WriteString(line)
	return err
}
