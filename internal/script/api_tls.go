package script

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

func buildTLSTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "request", L.NewFunction(tlsRequest))
	L.SetField(t, "cert", L.NewFunction(tlsCert))
	return t
}

// tlsRequest: scry.tls.request(host, port, payload, opts?).
// opts.verify (bool, default false), opts.timeout (ms), opts.max_bytes (int).
func tlsRequest(L *lua.LState) int {
	host := L.CheckString(1)
	port := L.CheckInt(2)
	payload := L.OptString(3, "")
	opts := checkOptsTable(L, 4)

	timeout := time.Duration(optInt(opts, "timeout", defaultAPITimeoutMS)) * time.Millisecond
	maxBytes := optInt(opts, "max_bytes", defaultMaxBytes)
	verify := optBool(opts, "verify", false)

	body, err := doTLSRequest(L.Context(), host, port, []byte(payload), timeout, maxBytes, verify)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(body))
	L.Push(lua.LNil)
	return 2
}

// tlsCert: scry.tls.cert(host, port, opts?).
// Returns a table {subject, issuer, not_before, not_after, dns_names}, or nil+err.
func tlsCert(L *lua.LState) int {
	host := L.CheckString(1)
	port := L.CheckInt(2)
	opts := checkOptsTable(L, 3)
	timeout := time.Duration(optInt(opts, "timeout", defaultAPITimeoutMS)) * time.Millisecond
	verify := optBool(opts, "verify", false)

	tbl, err := doTLSCert(L.Context(), host, port, timeout, verify)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	// Convert to Lua table.
	lt := L.NewTable()
	L.SetField(lt, "subject", lua.LString(tbl.Subject))
	L.SetField(lt, "issuer", lua.LString(tbl.Issuer))
	L.SetField(lt, "not_before", lua.LString(tbl.NotBefore))
	L.SetField(lt, "not_after", lua.LString(tbl.NotAfter))
	names := L.NewTable()
	for i, n := range tbl.DNSNames {
		L.RawSetInt(names, i+1, lua.LString(n))
	}
	L.SetField(lt, "dns_names", names)
	L.Push(lt)
	L.Push(lua.LNil)
	return 2
}

type certInfo struct {
	Subject, Issuer, NotBefore, NotAfter string
	DNSNames                             []string
}

func doTLSRequest(ctx context.Context, host string, port int, payload []byte, timeout time.Duration, maxBytes int, verify bool) (string, error) {
	conn, err := dialTLS(ctx, host, port, timeout, verify)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return "", err
		}
	}
	buf := make([]byte, maxBytes)
	n, err := io.ReadFull(conn, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() || n == 0 {
			return "", err
		}
	}
	return string(buf[:n]), nil
}

func doTLSCert(ctx context.Context, host string, port int, timeout time.Duration, verify bool) (*certInfo, error) {
	conn, err := dialTLS(ctx, host, port, timeout, verify)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("no peer certificate")
	}
	leaf := chain[0]
	return &certInfo{
		Subject:   leaf.Subject.String(),
		Issuer:    leaf.Issuer.String(),
		NotBefore: leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  leaf.NotAfter.UTC().Format(time.RFC3339),
		DNSNames:  append([]string(nil), leaf.DNSNames...),
	}, nil
}

func dialTLS(ctx context.Context, host string, port int, timeout time.Duration, verify bool) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	serverName := host
	if strings.ContainsRune(host, ':') && !strings.Contains(host, "]") {
		// Bare IPv6 literal — TLS SNI expects a hostname, not an IP, so
		// leave ServerName empty to avoid an SNI with brackets.
		serverName = ""
	}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: !verify, //nolint:gosec // scanning untrusted targets
	}
	tconn := tls.Client(raw, cfg)
	_ = tconn.SetDeadline(time.Now().Add(timeout))
	if err := tconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tconn, nil
}
