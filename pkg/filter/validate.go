package filter

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// ValidationError beschreibt einen Validierungsfehler
type ValidationError struct {
	Message string
	Term    string // Der fehlerhafte Teil
}

func (e ValidationError) Error() string {
	if e.Term != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.Term)
	}
	return e.Message
}

// Validate prüft ob ein Filter-Ausdruck syntaktisch korrekt ist
// Gibt nil zurück wenn gültig, sonst einen ValidationError
func Validate(expression string) error {
	if expression == "" {
		return nil
	}

	// Klammern prüfen
	openCount := strings.Count(expression, "(")
	closeCount := strings.Count(expression, ")")
	if openCount != closeCount {
		return ValidationError{
			Message: "Unbalanced parentheses",
			Term:    fmt.Sprintf("(%d open, %d close)", openCount, closeCount),
		}
	}

	// Normalisiere Operatoren
	normalized := NormalizeOperators(expression)

	// Leere Operanden prüfen (z.B. "&& &&" oder "||" am Anfang)
	if strings.Contains(normalized, "&&&") || strings.Contains(normalized, "|||") {
		return ValidationError{
			Message: "Invalid operator sequence",
		}
	}
	trimmed := strings.TrimSpace(normalized)
	if strings.HasPrefix(trimmed, "&&") || strings.HasPrefix(trimmed, "||") {
		return ValidationError{
			Message: "Expression cannot start with AND/OR",
		}
	}
	if strings.HasSuffix(trimmed, "&&") || strings.HasSuffix(trimmed, "||") {
		return ValidationError{
			Message: "Expression cannot end with AND/OR",
		}
	}

	// Prüfe alle Teile rekursiv
	return validateExpressionParts(normalized)
}

// validateExpressionParts prüft alle Teile eines Ausdrucks
func validateExpressionParts(expr string) error {
	// Klammern entfernen für Validierung
	for strings.Contains(expr, "(") {
		start := strings.LastIndex(expr, "(")
		if start == -1 {
			break
		}
		end := strings.Index(expr[start:], ")")
		if end == -1 {
			return ValidationError{Message: "Unclosed parenthesis"}
		}
		end += start

		// Inhalt der Klammer validieren
		inner := expr[start+1 : end]
		if err := validateExpressionParts(inner); err != nil {
			return err
		}

		// Klammer durch Platzhalter ersetzen
		expr = expr[:start] + "__VALID__" + expr[end+1:]
	}

	// OR-Split
	orParts := strings.Split(expr, "||")
	for _, orPart := range orParts {
		if err := validateAndParts(orPart); err != nil {
			return err
		}
	}

	return nil
}

// validateAndParts prüft AND-verknüpfte Teile
func validateAndParts(expr string) error {
	andParts := strings.Split(expr, "&&")
	for _, part := range andParts {
		part = strings.TrimSpace(part)
		if part == "" || part == "__VALID__" {
			continue
		}
		if err := validateSingleTerm(part); err != nil {
			return err
		}
	}
	return nil
}

// validateSingleTerm prüft einen einzelnen Filter-Term
func validateSingleTerm(term string) error {
	term = strings.TrimSpace(term)
	if term == "" || term == "__VALID__" {
		return nil
	}

	// NOT-Prefix entfernen
	if strings.HasPrefix(term, "!") {
		term = strings.TrimSpace(term[1:])
	}
	if term == "" {
		return nil
	}

	// Spalten-Filter: column=value
	if strings.Contains(term, "=") {
		parts := strings.SplitN(term, "=", 2)
		if len(parts) != 2 {
			return ValidationError{
				Message: "Invalid column filter syntax",
				Term:    term,
			}
		}
		column := strings.TrimSpace(parts[0])
		if column == "" {
			return ValidationError{
				Message: "Empty column name",
				Term:    term,
			}
		}
		// Value kann leer sein (sucht nach leeren Werten)
		return nil
	}

	// CIDR validieren (z.B. 10.0.113.0/28)
	if strings.Contains(term, "/") {
		_, _, err := net.ParseCIDR(term)
		if err != nil {
			return ValidationError{
				Message: "Invalid CIDR notation",
				Term:    term,
			}
		}
		return nil
	}

	// IP-Bereich validieren (z.B. 10.0.113.11-13)
	if IsIPRange(term) {
		lastDot := strings.LastIndex(term, ".")
		rangePart := term[lastDot+1:]
		rangeParts := strings.Split(rangePart, "-")
		start, _ := strconv.Atoi(rangeParts[0])
		end, _ := strconv.Atoi(rangeParts[1])
		if start < 0 || start > 255 || end < 0 || end > 255 {
			return ValidationError{
				Message: "IP range values must be 0-255",
				Term:    term,
			}
		}
		return nil
	}

	// Wildcard-Pattern validieren
	if strings.Contains(term, "*") {
		regexPattern := WildcardToRegex(term)
		_, err := regexp.Compile(regexPattern)
		if err != nil {
			return ValidationError{
				Message: "Invalid wildcard pattern",
				Term:    term,
			}
		}
	}

	return nil
}

// ValidateString gibt einen Fehler-String zurück (leer wenn gültig)
// Kompatibilitätsfunktion für einfache Nutzung
func ValidateString(expression string) string {
	err := Validate(expression)
	if err != nil {
		return err.Error()
	}
	return ""
}
