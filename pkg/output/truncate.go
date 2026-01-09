package output

import "fmt"

// TruncateConfig steuert das Truncation-Verhalten für Ausgaben
// Gemäß DESIGN-PRINCIPLES.md: "Vollständigkeit vor Kürze"
var TruncateConfig = struct {
	// Enabled aktiviert responsive Truncation (Default: true)
	// Mit --full-output wird dies auf false gesetzt
	Enabled bool
	// ShowInfo zeigt "[+N chars]" bei Kürzung (Transparenz-Prinzip)
	ShowInfo bool
}{
	Enabled:  true,
	ShowInfo: true,
}

// SetFullOutput setzt den FullOutput-Modus (deaktiviert Truncation)
func SetFullOutput(full bool) {
	TruncateConfig.Enabled = !full
}

// Truncate kürzt einen String auf maxLen Zeichen wenn TruncateConfig.Enabled
// Respektiert das Design-Prinzip "Transparenz bei Modifikationen"
func Truncate(s string, maxLen int) string {
	if !TruncateConfig.Enabled || maxLen <= 0 || len(s) <= maxLen {
		return s
	}

	// Mindestens 4 Zeichen für "…" oder "[+N]"
	if maxLen < 4 {
		return s[:maxLen]
	}

	hidden := len(s) - maxLen + 1 // +1 für das "…"

	if TruncateConfig.ShowInfo && maxLen >= 10 {
		// Transparente Kürzung mit Info: "text…[+15]"
		suffix := fmt.Sprintf("…[+%d]", hidden)
		if len(suffix) < maxLen {
			return s[:maxLen-len(suffix)] + suffix
		}
	}

	// Einfache Kürzung mit Ellipsis
	return s[:maxLen-1] + "…"
}

// TruncateMAC gibt MAC-Adressen IMMER vollständig zurück
// MAC-Adressen sind immer 17 Zeichen - Kürzung macht keinen Sinn
// (1 Zeichen sparen + "…" hinzufügen = gleiche Länge, aber Info verloren)
func TruncateMAC(mac string, _ int) string {
	// MAC-Adressen werden NIEMALS gekürzt
	// Das maxLen-Argument wird ignoriert (für API-Kompatibilität behalten)
	return mac
}
