package discovery_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"netspy/pkg/discovery"
)

// startTCPServer startet einen lokalen Server, der jeder Verbindung handler übergibt
func startTCPServer(handler func(net.Conn)) (int, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				handler(conn)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

// portOf liefert den Port eines httptest-Servers
func portOf(srv *httptest.Server) int {
	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	Expect(err).NotTo(HaveOccurred())
	port, err := strconv.Atoi(portStr)
	Expect(err).NotTo(HaveOccurred())
	return port
}

var _ = Describe("DetectService", func() {
	const timeout = 2 * time.Second

	webHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25")
		_, _ = fmt.Fprint(w, "<html><head><title>FRITZ!Box  Heimnetz</title></head></html>")
	})

	It("erkennt SSH am Banner", func() {
		port, stop := startTCPServer(func(c net.Conn) {
			_, _ = fmt.Fprint(c, "SSH-2.0-OpenSSH_9.6\r\n")
			time.Sleep(200 * time.Millisecond)
		})
		defer stop()

		info := discovery.DetectService("127.0.0.1", port, timeout)
		Expect(info.Detected).To(BeTrue())
		Expect(info.Name).To(Equal("ssh"))
		Expect(info.Detail).To(Equal("OpenSSH_9.6"))
	})

	It("unterscheidet SMTP und FTP am 220-Banner", func() {
		smtpPort, stopSMTP := startTCPServer(func(c net.Conn) {
			_, _ = fmt.Fprint(c, "220 mail.example.org ESMTP Postfix\r\n")
			time.Sleep(200 * time.Millisecond)
		})
		defer stopSMTP()
		ftpPort, stopFTP := startTCPServer(func(c net.Conn) {
			_, _ = fmt.Fprint(c, "220 (vsFTPd 3.0.5)\r\n")
			time.Sleep(200 * time.Millisecond)
		})
		defer stopFTP()

		Expect(discovery.DetectService("127.0.0.1", smtpPort, timeout).Name).To(Equal("smtp"))
		Expect(discovery.DetectService("127.0.0.1", ftpPort, timeout).Name).To(Equal("ftp"))
	})

	It("erkennt HTTP mit Server-Header und vollständigem Titel", func() {
		srv := httptest.NewServer(webHandler)
		defer srv.Close()

		info := discovery.DetectService("127.0.0.1", portOf(srv), timeout)
		Expect(info.Detected).To(BeTrue())
		Expect(info.Name).To(Equal("http"))
		Expect(info.TLS).To(BeFalse())
		Expect(info.Detail).To(Equal("nginx/1.25 · „FRITZ!Box Heimnetz“"))
	})

	It("erkennt HTTPS unabhängig von der Portnummer", func() {
		srv := httptest.NewTLSServer(webHandler)
		defer srv.Close()

		info := discovery.DetectService("127.0.0.1", portOf(srv), timeout)
		Expect(info.Detected).To(BeTrue())
		Expect(info.Name).To(Equal("https"))
		Expect(info.TLS).To(BeTrue())
		Expect(info.Detail).To(ContainSubstring("nginx/1.25"))
		Expect(info.Detail).To(ContainSubstring("cert: "))
	})

	It("meldet nichts erkannt bei einem stummen Port", func() {
		port, stop := startTCPServer(func(c net.Conn) {
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 1024)
			for {
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
		})
		defer stop()

		info := discovery.DetectService("127.0.0.1", port, 500*time.Millisecond)
		Expect(info.Detected).To(BeFalse())
	})
})
