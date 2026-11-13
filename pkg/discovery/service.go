package discovery

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ServiceInfo beschreibt den auf einem offenen Port erkannten Dienst
type ServiceInfo struct {
	Name     string // z. B. "ssh", "http", "https", "ftp", "tls"
	Detected bool   // true = per Sonde erkannt, false = nur aus der Portnummer geschlossen
	TLS      bool   // Dienst spricht TLS
	Detail   string // Banner, Server-Header, Seitentitel, Zertifikatsname
}

// DetectService erkennt den Dienst auf einem offenen TCP-Port anhand seiner Antworten.
// Reihenfolge: passives Banner (SSH, FTP, SMTP, ...) → TLS-Handshake (ggf. HTTP darüber) → HTTP.
// Liefert ServiceInfo{Detected: false}, wenn keine Sonde anschlägt.
func DetectService(ip string, port int, timeout time.Duration) ServiceInfo {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	// 1. Passiv: Viele Protokolle melden sich unaufgefordert
	if banner := readGreeting(addr, timeout); banner != "" {
		if info, ok := classifyGreeting(banner); ok {
			return info
		}
		return ServiceInfo{Name: "unknown", Detected: true, Detail: firstLine(banner)}
	}

	// 2. TLS-Handshake, danach HTTP über TLS versuchen
	if info, ok := probeTLS(addr, timeout); ok {
		return info
	}

	// 3. Klartext-HTTP
	if info, ok := probeHTTP(addr, timeout); ok {
		return info
	}

	return ServiceInfo{}
}

// readGreeting liest, was der Server direkt nach dem Verbindungsaufbau sendet
func readGreeting(addr string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	// Kurzes Warten genügt: Protokolle mit Begrüßung senden sofort
	if err := conn.SetReadDeadline(time.Now().Add(timeout / 2)); err != nil {
		return ""
	}
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

// classifyGreeting ordnet ein unaufgefordert gesendetes Banner einem Protokoll zu
func classifyGreeting(banner string) (ServiceInfo, bool) {
	line := firstLine(banner)
	lower := strings.ToLower(line)

	switch {
	case strings.HasPrefix(line, "SSH-"):
		// "SSH-2.0-OpenSSH_9.6" → "OpenSSH_9.6"
		detail := line
		if parts := strings.SplitN(line, "-", 3); len(parts) == 3 {
			detail = parts[2]
		}
		return ServiceInfo{Name: "ssh", Detected: true, Detail: detail}, true
	case strings.HasPrefix(line, "RFB "):
		return ServiceInfo{Name: "vnc", Detected: true, Detail: line}, true
	case strings.HasPrefix(line, "+OK"):
		return ServiceInfo{Name: "pop3", Detected: true, Detail: strings.TrimSpace(line[3:])}, true
	case strings.HasPrefix(line, "* OK"):
		return ServiceInfo{Name: "imap", Detected: true, Detail: strings.TrimSpace(line[4:])}, true
	case strings.HasPrefix(line, "220"):
		// FTP und SMTP beginnen beide mit 220 - am Text unterscheiden
		detail := strings.TrimSpace(strings.TrimLeft(line[3:], " -"))
		if strings.Contains(lower, "smtp") || strings.Contains(lower, "mail") {
			return ServiceInfo{Name: "smtp", Detected: true, Detail: detail}, true
		}
		return ServiceInfo{Name: "ftp", Detected: true, Detail: detail}, true
	}
	return ServiceInfo{}, false
}

// probeTLS prüft per Handshake, ob der Port TLS spricht, und versucht danach HTTP
func probeTLS(addr string, timeout time.Duration) (ServiceInfo, bool) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		// #nosec G402 - Lokale Geräte nutzen meist selbstsignierte Zertifikate
		InsecureSkipVerify: true,
	})
	if err != nil {
		return ServiceInfo{}, false
	}
	defer func() { _ = conn.Close() }()

	certName := ""
	if certs := conn.ConnectionState().PeerCertificates; len(certs) > 0 {
		certName = certs[0].Subject.CommonName
		if certName == "" && len(certs[0].DNSNames) > 0 {
			certName = certs[0].DNSNames[0]
		}
	}

	info := ServiceInfo{Name: "tls", Detected: true, TLS: true}
	if detail, ok := httpRequest(conn, addr, timeout); ok {
		info.Name = "https"
		info.Detail = detail
	}
	if certName != "" {
		info.Detail = joinDetail(info.Detail, "cert: "+certName)
	}
	return info, true
}

// probeHTTP prüft, ob der Port unverschlüsseltes HTTP spricht
func probeHTTP(addr string, timeout time.Duration) (ServiceInfo, bool) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ServiceInfo{}, false
	}
	defer func() { _ = conn.Close() }()

	if detail, ok := httpRequest(conn, addr, timeout); ok {
		return ServiceInfo{Name: "http", Detected: true, Detail: detail}, true
	}
	return ServiceInfo{}, false
}

// httpRequest sendet ein GET über eine bestehende Verbindung und liefert Server-Header und Seitentitel
func httpRequest(conn net.Conn, addr string, timeout time.Duration) (string, bool) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", false
	}
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: NetSpy\r\nConnection: close\r\n\r\n", addr)
	if _, err := io.WriteString(conn, req); err != nil {
		return "", false
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()

	detail := ""
	if server := resp.Header.Get("Server"); server != "" {
		detail = strings.TrimSpace(server)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	if title := htmlTitle(body); title != "" {
		detail = joinDetail(detail, fmt.Sprintf("„%s“", title))
	}
	if detail == "" {
		detail = strings.TrimSpace(resp.Status)
	}
	return detail, true
}

// htmlTitle liefert den vollständigen Seitentitel (ohne Kürzung)
func htmlTitle(body []byte) string {
	lower := bytes.ToLower(body)
	start := bytes.Index(lower, []byte("<title"))
	if start == -1 {
		return ""
	}
	// Attribute im Start-Tag überspringen (<title id="x">)
	gt := bytes.IndexByte(lower[start:], '>')
	if gt == -1 {
		return ""
	}
	start += gt + 1
	end := bytes.Index(lower[start:], []byte("</title>"))
	if end == -1 {
		return ""
	}
	return strings.Join(strings.Fields(string(body[start:start+end])), " ")
}

// firstLine liefert die erste Zeile eines Banners
func firstLine(s string) string {
	if idx := strings.IndexAny(s, "\r\n"); idx >= 0 {
		return strings.TrimSpace(s[:idx])
	}
	return strings.TrimSpace(s)
}

// joinDetail verbindet zwei Detail-Angaben mit Trennzeichen
func joinDetail(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + " · " + b
}
