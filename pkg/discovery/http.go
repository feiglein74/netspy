package discovery

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPBanner contains information extracted from HTTP headers
type HTTPBanner struct {
	Server     string // Server header (e.g., "nginx/1.18.0")
	PoweredBy  string // X-Powered-By header (e.g., "PHP/7.4")
	StatusCode int    // HTTP status code
	Port       int    // Port where banner was found
	Protocol   string // "http" or "https"
	Title      string // Page title (optional)
	Hostname   string // Hostname extracted from Location or other headers
}

// String returns a formatted string representation of the banner
func (b HTTPBanner) String() string {
	parts := []string{}

	if b.Server != "" {
		parts = append(parts, b.Server)
	}

	if b.PoweredBy != "" {
		parts = append(parts, b.PoweredBy)
	}

	if len(parts) == 0 {
		return fmt.Sprintf("%s:%d", b.Protocol, b.Port)
	}

	return strings.Join(parts, " | ")
}

// GrabHTTPBanner attempts to get HTTP banner from common web ports
func GrabHTTPBanner(ip string, timeout time.Duration) *HTTPBanner {
	// Try common web ports in order of likelihood
	ports := []struct {
		port     int
		protocol string
	}{
		{80, "http"},
		{443, "https"},
		{8080, "http"},
		{8443, "https"},
	}

	for _, p := range ports {
		if banner := grabBannerFromPort(ip, p.port, p.protocol, timeout); banner != nil {
			return banner
		}
	}

	return nil
}

// grabBannerFromPort attempts to grab banner from a specific port
func grabBannerFromPort(ip string, port int, protocol string, timeout time.Duration) *HTTPBanner {
	url := fmt.Sprintf("%s://%s:%d/", protocol, ip, port)

	// Create HTTP client with timeout and TLS config
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// #nosec G402 - Skip cert validation for local network scanning (self-signed certs)
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// CHANGED: Use GET directly to always get title for hostname detection
	// HEAD optimization was preventing title extraction for devices like Philips Hue
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	// Set a reasonable user agent
	req.Header.Set("User-Agent", "NetSpy/1.0")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }() // Ignore close error

	// Extract banner information
	banner := &HTTPBanner{
		StatusCode: resp.StatusCode,
		Port:       port,
		Protocol:   protocol,
	}

	// Extract Server header
	if server := resp.Header.Get("Server"); server != "" {
		banner.Server = cleanBanner(server)
	}

	// Extract X-Powered-By header
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		banner.PoweredBy = cleanBanner(poweredBy)
	}

	// Extract hostname from Location header (redirects often contain hostname)
	if location := resp.Header.Get("Location"); location != "" {
		if hostname := extractHostnameFromURL(location); hostname != "" {
			banner.Hostname = hostname
		}
	}

	// Try X-Forwarded-Host and X-Original-Host headers (proxy configs)
	if banner.Hostname == "" {
		if host := resp.Header.Get("X-Forwarded-Host"); host != "" {
			banner.Hostname = cleanHostname(host)
		} else if host := resp.Header.Get("X-Original-Host"); host != "" {
			banner.Hostname = cleanHostname(host)
		}
	}

	// Extract title from HTML (only for GET requests)
	if req.Method == "GET" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8192)) // Read max 8KB
		if err == nil {
			title := extractTitle(string(body))
			banner.Title = title

			// Try to extract hostname from title if we don't have one yet
			// Many devices have titles like "UniFi Dream Machine" or "iPhone (John)"
			if banner.Hostname == "" && title != "" {
				banner.Hostname = extractHostnameFromTitle(title)
			}
		}
	}

	return banner
}

// cleanBanner cleans and truncates banner strings
func cleanBanner(banner string) string {
	// Remove newlines and extra spaces
	banner = strings.TrimSpace(banner)
	banner = strings.ReplaceAll(banner, "\n", " ")
	banner = strings.ReplaceAll(banner, "\r", " ")

	// Truncate if too long
	if len(banner) > 50 {
		banner = banner[:47] + "..."
	}

	return banner
}

// extractTitle extracts the page title from HTML
func extractTitle(html string) string {
	// Simple title extraction (not using full HTML parser for performance)
	start := strings.Index(strings.ToLower(html), "<title>")
	if start == -1 {
		return ""
	}
	start += 7 // len("<title>")

	end := strings.Index(strings.ToLower(html[start:]), "</title>")
	if end == -1 {
		return ""
	}

	title := html[start : start+end]
	title = strings.TrimSpace(title)

	// Truncate if too long
	if len(title) > 40 {
		title = title[:37] + "..."
	}

	return title
}

// extractHostnameFromURL extracts hostname from a URL string
func extractHostnameFromURL(urlStr string) string {
	// Handle relative URLs
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return ""
	}

	// Find hostname part (between // and first /)
	start := strings.Index(urlStr, "//")
	if start == -1 {
		return ""
	}
	start += 2

	end := strings.Index(urlStr[start:], "/")
	if end == -1 {
		end = len(urlStr[start:])
	}

	hostname := urlStr[start : start+end]

	// Remove port if present
	if colonPos := strings.Index(hostname, ":"); colonPos != -1 {
		hostname = hostname[:colonPos]
	}

	// Don't return IP addresses, only real hostnames
	if net.ParseIP(hostname) != nil {
		return ""
	}

	return cleanHostname(hostname)
}

// extractHostnameFromTitle tries to extract a meaningful hostname from page title
func extractHostnameFromTitle(title string) string {
	// Remove common prefixes/suffixes
	title = strings.TrimSpace(title)

	// Skip if title is too generic or empty
	if title == "" || len(title) < 3 {
		return ""
	}

	lowerTitle := strings.ToLower(title)

	// Skip HTTP status codes (e.g., "401 Unauthorized", "403 Forbidden", "404 Not Found")
	httpStatusPrefixes := []string{
		"400 ", "401 ", "402 ", "403 ", "404 ", "405 ", "406 ", "407 ", "408 ", "409 ",
		"410 ", "500 ", "501 ", "502 ", "503 ", "504 ",
	}
	for _, prefix := range httpStatusPrefixes {
		if strings.HasPrefix(lowerTitle, prefix) {
			return ""
		}
	}

	// Common generic titles to skip (exact match)
	genericTitles := []string{
		"home", "index", "login", "admin", "dashboard",
		"welcome", "error", "forbidden", "unauthorized",
		"not found", "access denied", "bad request",
	}
	for _, generic := range genericTitles {
		if lowerTitle == generic {
			return ""
		}
	}

	// If title looks like a model/device name (e.g., "UniFi Dream Machine"), use it
	// But limit length and clean it up
	if len(title) > 40 {
		title = title[:37] + "..."
	}

	return title
}

// QueryHTTPHostname attempts to get hostname from HTTP headers/title
// This is a new resolution method specifically for IoT/web devices
func QueryHTTPHostname(ip string, timeout time.Duration) (string, error) {
	banner := GrabHTTPBanner(ip, timeout)
	if banner == nil {
		return "", fmt.Errorf("no HTTP response")
	}

	// banner.Hostname is already filtered (extractHostnameFromTitle was applied in grabBannerFromPort)
	if banner.Hostname != "" {
		return banner.Hostname, nil
	}

	// Note: banner.Title might contain unfiltered data, don't use it directly
	// All filtering happens in grabBannerFromPort -> banner.Hostname

	return "", fmt.Errorf("no hostname in HTTP response")
}

// GrabHTTPBannerFromPorts attempts to get HTTP banner from specific open ports
func GrabHTTPBannerFromPorts(ip string, openPorts []int, timeout time.Duration) *HTTPBanner {
	// Check if any web ports are open
	webPorts := make(map[int]string)
	webPorts[80] = "http"
	webPorts[443] = "https"
	webPorts[8080] = "http"
	webPorts[8443] = "https"
	webPorts[8000] = "http"
	webPorts[8888] = "http"

	for _, port := range openPorts {
		if protocol, ok := webPorts[port]; ok {
			if banner := grabBannerFromPort(ip, port, protocol, timeout); banner != nil {
				return banner
			}
		}
	}

	return nil
}
