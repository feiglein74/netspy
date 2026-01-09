package filter

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// IsIPRange prüft ob der Filter ein IP-Bereich ist (z.B. 10.0.113.11-13)
func IsIPRange(filter string) bool {
	// Muss mindestens einen Punkt und einen Bindestrich enthalten
	// Format: x.x.x.start-end
	if !strings.Contains(filter, ".") || !strings.Contains(filter, "-") {
		return false
	}

	// Letztes Oktett muss den Bereich enthalten
	lastDot := strings.LastIndex(filter, ".")
	if lastDot == -1 || lastDot >= len(filter)-1 {
		return false
	}

	lastOctet := filter[lastDot+1:]
	parts := strings.Split(lastOctet, "-")
	if len(parts) != 2 {
		return false
	}

	// Beide Teile müssen Zahlen sein
	_, err1 := strconv.Atoi(parts[0])
	_, err2 := strconv.Atoi(parts[1])
	return err1 == nil && err2 == nil
}

// MatchIPRange prüft ob eine IP in einem Bereich liegt (z.B. 10.0.113.11-13)
func MatchIPRange(filter string, ipField string) bool {
	if ipField == "" {
		return false
	}

	// Filter parsen: 10.0.113.11-13
	lastDot := strings.LastIndex(filter, ".")
	if lastDot == -1 {
		return false
	}

	prefix := filter[:lastDot+1] // "10.0.113."
	rangePart := filter[lastDot+1:]
	parts := strings.Split(rangePart, "-")
	if len(parts) != 2 {
		return false
	}

	start, err1 := strconv.Atoi(parts[0])
	end, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}

	// IP-Feld parsen
	ipLastDot := strings.LastIndex(ipField, ".")
	if ipLastDot == -1 {
		return false
	}

	ipPrefix := ipField[:ipLastDot+1]
	ipLastOctet := ipField[ipLastDot+1:]

	// Prefix muss übereinstimmen
	if ipPrefix != prefix {
		return false
	}

	// Letztes Oktett der IP parsen
	ipNum, err := strconv.Atoi(ipLastOctet)
	if err != nil {
		return false
	}

	// Prüfen ob im Bereich (start und end können vertauscht sein)
	if start > end {
		start, end = end, start
	}

	return ipNum >= start && ipNum <= end
}

// MatchCIDR prüft ob eine IP in einem CIDR-Bereich liegt (z.B. 10.0.113.0/28)
func MatchCIDR(filter string, ipField string) bool {
	if ipField == "" {
		return false
	}

	// CIDR parsen
	_, network, err := net.ParseCIDR(filter)
	if err != nil {
		return false
	}

	// IP parsen
	ip := net.ParseIP(ipField)
	if ip == nil {
		return false
	}

	return network.Contains(ip)
}

// MatchWildcard prüft Wildcard-Pattern gegen Felder
// * = beliebige Zeichen (auch keine)
func MatchWildcard(pattern string, fields []string) bool {
	regexPattern := WildcardToRegex(pattern)

	for _, field := range fields {
		if field == "" {
			continue
		}
		matched, _ := regexp.MatchString(regexPattern, field)
		if matched {
			return true
		}
	}
	return false
}

// WildcardToRegex konvertiert ein Wildcard-Pattern zu Regex
func WildcardToRegex(pattern string) string {
	// Regex-Sonderzeichen escapen (außer *)
	escaped := regexp.QuoteMeta(pattern)
	// \* (escaped asterisk) zurück zu .* (regex any)
	result := strings.ReplaceAll(escaped, `\*`, `.*`)
	// Vollständiger Match (Anfang und Ende)
	return "^" + result + "$"
}
