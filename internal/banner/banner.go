// Package banner performs a lightweight read on an already-open TCP
// connection, returning up to a few hundred bytes of service banner.
//
// This is intentionally passive — no HTTP GET, no TLS handshake, no
// protocol-specific probes. Many services (SSH, SMTP, FTP, Redis,
// MySQL, IRC, POP3, IMAP, VNC) advertise themselves on connect; HTTP
// does not. A richer, per-protocol probe belongs in the Phase 5
// scripting engine.
package banner

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// DefaultMaxBytes caps the banner read. Keeps noisy services (Cassandra,
// MongoDB) from dumping huge binary blobs into output.
const DefaultMaxBytes = 256

// Grab opens addr:port, reads up to maxBytes bytes within timeout, and
// returns whatever arrived as a sanitized single-line string. Returns ""
// when nothing arrived inside the window (common for HTTP).
//
// maxBytes<=0 uses DefaultMaxBytes; timeout<=0 uses 500ms.
func Grab(ctx context.Context, addr netip.Addr, port uint16, timeout time.Duration, maxBytes int) (string, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	d := net.Dialer{Timeout: timeout, KeepAlive: -1}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(int(port))))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, maxBytes)
	n, err := conn.Read(buf)
	if err != nil {
		// Timeouts and graceful close before any write are both expected
		// ("quiet" services). Squash into an empty banner.
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return "", nil
		}
		if errors.Is(err, io.EOF) {
			return sanitize(string(buf[:n])), nil
		}
		if n == 0 {
			return "", err
		}
	}
	return sanitize(string(buf[:n])), nil
}

// sanitize strips control characters, keeps only the first line, trims
// whitespace, and caps length. Output is safe to print in a single
// column of human output.
func sanitize(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0x7f || (unicode.IsControl(r) && r != '\t') {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
