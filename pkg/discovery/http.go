package discovery

import (
	"crypto/tls"
	"fmt"
	"io"
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

	// Create HEAD request (faster than GET)
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil
	}

	// Set a reasonable user agent
	req.Header.Set("User-Agent", "NetSpy/1.0")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		// Try GET if HEAD fails (some servers don't support HEAD)
		req, _ = http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "NetSpy/1.0")
		resp, err = client.Do(req)
		if err != nil {
			return nil
		}
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

	// Extract title from HTML (only for GET requests)
	if req.Method == "GET" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8192)) // Read max 8KB
		if err == nil {
			banner.Title = extractTitle(string(body))
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
