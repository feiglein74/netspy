// Package filter bietet wiederverwendbare Filterlogik für Tabellen und Listen.
// Unterstützt boolesche Ausdrücke (AND, OR, NOT), Klammern, Spalten-Filter,
// Wildcards, CIDR und IP-Bereiche.
//
// Beispiele:
//   - Einfach: "apple" (sucht in allen Feldern)
//   - Spalte: "vendor=Apple" (sucht nur in Vendor-Spalte)
//   - Wildcard: "192.168.*" oder "*router*"
//   - Boolean: "apple && online" oder "apple || samsung"
//   - Negation: "!offline" oder "NOT offline"
//   - Klammern: "(vendor=Apple || vendor=Samsung) && status=online"
//   - CIDR: "10.0.113.0/28"
//   - IP-Bereich: "10.0.113.11-13"
package filter

import (
	"regexp"
	"strings"
)

// Filter repräsentiert einen konfigurierten Filter
type Filter struct {
	// Expression ist der aktive Filter-Ausdruck
	Expression string

	// FieldAliases definiert Kurzformen für Feldnamen
	// z.B. {"h": "host", "v": "vendor", "hostname": "host"}
	FieldAliases map[string]string

	// IPField ist der Feldname für IP-spezifische Filter (CIDR, Range)
	// Default: "ip"
	IPField string

	// CaseSensitive aktiviert Groß/Kleinschreibung-Unterscheidung
	// Default: false (case-insensitive)
	CaseSensitive bool
}

// New erstellt einen neuen Filter mit Standard-Konfiguration
func New(expression string) *Filter {
	return &Filter{
		Expression: expression,
		IPField:    "ip",
	}
}

// WithAliases setzt Feld-Aliase (fluent API)
func (f *Filter) WithAliases(aliases map[string]string) *Filter {
	f.FieldAliases = aliases
	return f
}

// WithIPField setzt das IP-Feld für CIDR/Range-Filter (fluent API)
func (f *Filter) WithIPField(field string) *Filter {
	f.IPField = field
	return f
}

// CaseSensitiveMode aktiviert Groß/Kleinschreibung (fluent API)
func (f *Filter) CaseSensitiveMode(enabled bool) *Filter {
	f.CaseSensitive = enabled
	return f
}

// Match prüft ob die gegebenen Felder zum Filter passen
// fields ist eine Map von Feldname → Wert (z.B. {"ip": "192.168.1.1", "host": "router"})
func (f *Filter) Match(fields map[string]string) bool {
	if f.Expression == "" {
		return true
	}

	// Felder normalisieren (lowercase falls nicht case-sensitive)
	normalizedFields := make(map[string]string, len(fields))
	for k, v := range fields {
		key := k
		val := v
		if !f.CaseSensitive {
			key = strings.ToLower(k)
			val = strings.ToLower(v)
		}
		normalizedFields[key] = val
	}

	// Alle Feldwerte für Suche ohne Präfix
	allValues := make([]string, 0, len(normalizedFields))
	for _, v := range normalizedFields {
		allValues = append(allValues, v)
	}

	// Expression normalisieren (AND/OR/NOT → &&/||/!)
	expr := NormalizeOperators(f.Expression)
	if !f.CaseSensitive {
		expr = strings.ToLower(expr)
	}

	return f.evaluateExpression(expr, normalizedFields, allValues)
}

// evaluateExpression evaluiert einen Filter-Ausdruck mit Klammern
func (f *Filter) evaluateExpression(expr string, fields map[string]string, allValues []string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}

	// Klammern verarbeiten (von innen nach außen)
	for strings.Contains(expr, "(") {
		// Innerste Klammer finden
		start := strings.LastIndex(expr, "(")
		if start == -1 {
			break
		}
		end := strings.Index(expr[start:], ")")
		if end == -1 {
			break // Ungültige Klammer
		}
		end += start

		// Inhalt der Klammer evaluieren
		inner := expr[start+1 : end]
		result := f.evaluateExpression(inner, fields, allValues)

		// Ergebnis als Platzhalter einsetzen
		placeholder := "__TRUE__"
		if !result {
			placeholder = "__FALSE__"
		}
		expr = expr[:start] + placeholder + expr[end+1:]
	}

	// OR hat niedrigste Priorität
	if strings.Contains(expr, "||") {
		orParts := strings.Split(expr, "||")
		for _, orPart := range orParts {
			orPart = strings.TrimSpace(orPart)
			if orPart == "" {
				continue
			}
			if f.evaluateAndExpression(orPart, fields, allValues) {
				return true
			}
		}
		return false
	}

	return f.evaluateAndExpression(expr, fields, allValues)
}

// evaluateAndExpression evaluiert einen AND-Ausdruck
func (f *Filter) evaluateAndExpression(expr string, fields map[string]string, allValues []string) bool {
	if strings.Contains(expr, "&&") {
		parts := strings.Split(expr, "&&")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !f.evaluateSingleTerm(part, fields, allValues) {
				return false
			}
		}
		return true
	}
	return f.evaluateSingleTerm(expr, fields, allValues)
}

// evaluateSingleTerm evaluiert einen einzelnen Filter-Term
func (f *Filter) evaluateSingleTerm(term string, fields map[string]string, allValues []string) bool {
	term = strings.TrimSpace(term)

	// Platzhalter von Klammer-Auswertung
	if term == "__TRUE__" || term == "__true__" {
		return true
	}
	if term == "__FALSE__" || term == "__false__" {
		return false
	}

	// NOT-Operator
	negated := false
	if strings.HasPrefix(term, "!") {
		negated = true
		term = strings.TrimSpace(term[1:])
	}

	if term == "" {
		return !negated
	}

	var matches bool

	// Spalten-Filter prüfen (z.B. vendor=Apple)
	if strings.Contains(term, "=") {
		parts := strings.SplitN(term, "=", 2)
		if len(parts) == 2 {
			column := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// Alias auflösen
			if f.FieldAliases != nil {
				if resolved, ok := f.FieldAliases[column]; ok {
					column = resolved
				}
			}

			if fieldValue, ok := fields[column]; ok {
				matches = MatchValue(value, fieldValue)
			} else {
				matches = false // Unbekannte Spalte
			}
		} else {
			matches = false
		}
	} else {
		// Kein Spalten-Präfix - in allen Feldern suchen
		// IP-Feld für spezielle Filter extrahieren
		ipValue := ""
		if f.IPField != "" {
			ipValue = fields[f.IPField]
		}
		matches = matchAllFields(term, allValues, ipValue)
	}

	if negated {
		return !matches
	}
	return matches
}

// matchAllFields prüft einen Filter gegen alle Felder
func matchAllFields(filter string, fields []string, ipField string) bool {
	// CIDR-Filter
	if strings.Contains(filter, "/") && ipField != "" {
		return MatchCIDR(filter, ipField)
	}

	// IP-Range-Filter
	if IsIPRange(filter) && ipField != "" {
		return MatchIPRange(filter, ipField)
	}

	// Wildcard-Filter
	if strings.Contains(filter, "*") {
		return MatchWildcard(filter, fields)
	}

	// Substring-Match (für Benutzerfreundlichkeit)
	// Suche in allen Feldern nach dem Filter als Substring
	for _, field := range fields {
		if field != "" && strings.Contains(field, filter) {
			return true
		}
	}
	return false
}

// NormalizeOperators ersetzt Wort-Operatoren durch Symbole
// AND/and → &&, OR/or → ||, NOT/not → !
func NormalizeOperators(text string) string {
	result := text
	// AND Varianten
	for _, word := range []string{" AND ", " and ", " And "} {
		result = strings.ReplaceAll(result, word, " && ")
	}
	// OR Varianten
	for _, word := range []string{" OR ", " or ", " Or "} {
		result = strings.ReplaceAll(result, word, " || ")
	}
	// NOT am Anfang oder nach Operator
	for _, word := range []string{"NOT ", "not ", "Not "} {
		result = strings.ReplaceAll(result, word, "!")
	}
	return result
}

// MatchValue prüft ob ein Wert zum Filter passt (mit Wildcard-Support)
func MatchValue(filter, value string) bool {
	if filter == "" {
		return true
	}
	if value == "" {
		return false
	}

	// Wildcard-Support
	if strings.Contains(filter, "*") {
		pattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(filter), "\\*", ".*") + "$"
		matched, _ := regexp.MatchString(pattern, value)
		return matched
	}

	// Substring-Match (für Benutzerfreundlichkeit)
	return strings.Contains(value, filter)
}
