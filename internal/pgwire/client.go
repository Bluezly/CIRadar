// Package pgwire implements the small PostgreSQL protocol surface CI Radar
// needs for its bundled PostgreSQL state backend. It intentionally supports
// simple queries only, but includes TLS, cleartext, MD5, and SCRAM-SHA-256
// authentication so deployments do not need a CGO client or downloaded driver.
package pgwire

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Host           string
	Port           int
	User           string
	Password       string
	Database       string
	SSLMode        string
	RootCert       string
	ConnectTimeout time.Duration
}

type Client struct {
	conn                    net.Conn
	r                       *bufio.Reader
	cfg                     Config
	expectedServerSignature []byte
}

type Rows struct {
	Columns []string
	Values  [][]*string
	Command string
}

func ParseDSN(dsn string) (Config, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return Config{}, errors.New("postgres dsn is empty")
	}
	cfg := Config{Port: 5432, SSLMode: "prefer", ConnectTimeout: 10 * time.Second}
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return cfg, err
		}
		cfg.Host = u.Hostname()
		if p := u.Port(); p != "" {
			n, e := strconv.Atoi(p)
			if e != nil {
				return cfg, e
			}
			cfg.Port = n
		}
		if u.User != nil {
			cfg.User = u.User.Username()
			cfg.Password, _ = u.User.Password()
		}
		cfg.Database = strings.TrimPrefix(u.Path, "/")
		q := u.Query()
		if v := q.Get("sslmode"); v != "" {
			cfg.SSLMode = v
		}
		cfg.RootCert = q.Get("sslrootcert")
		if v := q.Get("connect_timeout"); v != "" {
			n, e := strconv.Atoi(v)
			if e != nil {
				return cfg, e
			}
			cfg.ConnectTimeout = time.Duration(n) * time.Second
		}
	} else {
		fields, err := parseKV(dsn)
		if err != nil {
			return cfg, err
		}
		cfg.Host = fields["host"]
		cfg.User = fields["user"]
		cfg.Password = fields["password"]
		cfg.Database = fields["dbname"]
		if v := fields["port"]; v != "" {
			n, e := strconv.Atoi(v)
			if e != nil {
				return cfg, e
			}
			cfg.Port = n
		}
		if v := fields["sslmode"]; v != "" {
			cfg.SSLMode = v
		}
		cfg.RootCert = fields["sslrootcert"]
		if v := fields["connect_timeout"]; v != "" {
			n, e := strconv.Atoi(v)
			if e != nil {
				return cfg, e
			}
			cfg.ConnectTimeout = time.Duration(n) * time.Second
		}
	}
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if cfg.User == "" {
		return cfg, errors.New("postgres user is required")
	}
	if cfg.Database == "" {
		cfg.Database = cfg.User
	}
	switch cfg.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		return cfg, fmt.Errorf("unsupported sslmode %q", cfg.SSLMode)
	}
	return cfg, nil
}

func parseKV(s string) (map[string]string, error) {
	out := map[string]string{}
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n') {
			i++
		}
		if i >= len(s) {
			break
		}
		st := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			return nil, fmt.Errorf("invalid dsn near %q", s[st:])
		}
		key := s[st:i]
		i++
		var b strings.Builder
		if i < len(s) && s[i] == '\'' {
			i++
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					i++
					b.WriteByte(s[i])
					i++
					continue
				}
				if s[i] == '\'' {
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
		} else {
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\n' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				b.WriteByte(s[i])
				i++
			}
		}
		out[key] = b.String()
	}
	return out, nil
}

func Connect(ctx context.Context, dsn string) (*Client, error) {
	cfg, err := ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: cfg.ConnectTimeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, err
	}
	cl := &Client{conn: c, r: bufio.NewReader(c), cfg: cfg}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	} else if cfg.ConnectTimeout > 0 {
		_ = c.SetDeadline(time.Now().Add(cfg.ConnectTimeout))
	}
	if err = cl.negotiateTLS(); err != nil {
		c.Close()
		return nil, err
	}
	if err = cl.startup(); err != nil {
		cl.Close()
		return nil, err
	}
	_ = cl.conn.SetDeadline(time.Time{})
	return cl, nil
}

func (c *Client) negotiateTLS() error {
	if c.cfg.SSLMode == "disable" {
		return nil
	}
	var p [8]byte
	binary.BigEndian.PutUint32(p[0:4], 8)
	binary.BigEndian.PutUint32(p[4:8], 80877103)
	if _, err := c.conn.Write(p[:]); err != nil {
		return err
	}
	b := []byte{0}
	if _, err := io.ReadFull(c.r, b); err != nil {
		return err
	}
	if b[0] == 'N' {
		if c.cfg.SSLMode == "allow" || c.cfg.SSLMode == "prefer" {
			return nil
		}
		return errors.New("postgres server rejected TLS")
	}
	if b[0] != 'S' {
		return fmt.Errorf("unexpected TLS response %q", b[0])
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.cfg.Host}
	if c.cfg.SSLMode == "require" || c.cfg.SSLMode == "prefer" || c.cfg.SSLMode == "allow" {
		tc.InsecureSkipVerify = true
	}
	if c.cfg.RootCert != "" {
		pem, err := os.ReadFile(c.cfg.RootCert)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("invalid postgres root certificate")
		}
		tc.RootCAs = pool
	}
	if c.cfg.SSLMode == "verify-ca" {
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{Roots: tc.RootCAs, Intermediates: x509.NewCertPool()}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		}
	}
	t := tls.Client(c.conn, tc)
	if err := t.Handshake(); err != nil {
		return err
	}
	c.conn = t
	c.r = bufio.NewReader(t)
	return nil
}

func (c *Client) startup() error {
	var body []byte
	body = appendInt32(body, 196608)
	add := func(k, v string) {
		body = append(body, k...)
		body = append(body, 0)
		body = append(body, v...)
		body = append(body, 0)
	}
	add("user", c.cfg.User)
	add("database", c.cfg.Database)
	add("client_encoding", "UTF8")
	add("application_name", "ci-radar")
	body = append(body, 0)
	var packet []byte
	packet = appendInt32(packet, int32(len(body)+4))
	packet = append(packet, body...)
	if _, err := c.conn.Write(packet); err != nil {
		return err
	}
	var scr *scramState
	for {
		typ, p, err := c.readMessage()
		if err != nil {
			return err
		}
		switch typ {
		case 'R':
			if len(p) < 4 {
				return errors.New("short authentication message")
			}
			code := binary.BigEndian.Uint32(p[:4])
			switch code {
			case 0:
			case 3:
				if err := c.sendPassword(c.cfg.Password + "\x00"); err != nil {
					return err
				}
			case 5:
				if len(p) < 8 {
					return errors.New("short md5 auth")
				}
				h1 := md5.Sum([]byte(c.cfg.Password + c.cfg.User))
				h2 := md5.Sum(append([]byte(hex.EncodeToString(h1[:])), p[4:8]...))
				if err := c.sendPassword("md5" + hex.EncodeToString(h2[:]) + "\x00"); err != nil {
					return err
				}
			case 10:
				scr, err = newSCRAM(c.cfg.User, c.cfg.Password)
				if err != nil {
					return err
				}
				if err = scr.sendInitial(c); err != nil {
					return err
				}
			case 11:
				if scr == nil {
					return errors.New("unexpected sasl continue")
				}
				if err = scr.continueAuth(c, string(p[4:])); err != nil {
					return err
				}
			case 12:
				if scr == nil {
					return errors.New("unexpected sasl final")
				}
				if err = scr.verifyFinal(string(p[4:])); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported postgres authentication code %d", code)
			}
		case 'E':
			return parseError(p)
		case 'Z':
			return nil
		case 'S', 'K', 'N':
		default:
		}
	}
}

func (c *Client) sendPassword(s string) error { return c.sendMessage('p', []byte(s)) }
func (c *Client) sendMessage(t byte, p []byte) error {
	buf := []byte{t}
	buf = appendInt32(buf, int32(len(p)+4))
	buf = append(buf, p...)
	_, err := c.conn.Write(buf)
	return err
}
func (c *Client) readMessage() (byte, []byte, error) {
	t, err := c.r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var lb [4]byte
	if _, err = io.ReadFull(c.r, lb[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(lb[:])) - 4
	if n < 0 || n > 256<<20 {
		return 0, nil, fmt.Errorf("invalid postgres message length %d", n)
	}
	p := make([]byte, n)
	_, err = io.ReadFull(c.r, p)
	return t, p, err
}

func (c *Client) Query(ctx context.Context, q string) (Rows, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(deadline)
		defer c.conn.SetDeadline(time.Time{})
	}
	if err := c.sendMessage('Q', append([]byte(q), 0)); err != nil {
		return Rows{}, err
	}
	var out Rows
	for {
		t, p, err := c.readMessage()
		if err != nil {
			return out, err
		}
		switch t {
		case 'T':
			names, err := parseRowDescription(p)
			if err != nil {
				return out, err
			}
			out.Columns = names
		case 'D':
			vals, err := parseDataRow(p)
			if err != nil {
				return out, err
			}
			out.Values = append(out.Values, vals)
		case 'C':
			out.Command = strings.TrimRight(string(p), "\x00")
		case 'E':
			return out, parseError(p)
		case 'Z':
			return out, nil
		case 'I', 'N', 'S':
		}
	}
}
func (c *Client) Exec(ctx context.Context, q string) error { _, err := c.Query(ctx, q); return err }
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	_ = c.sendMessage('X', nil)
	return c.conn.Close()
}

func parseRowDescription(p []byte) ([]string, error) {
	if len(p) < 2 {
		return nil, errors.New("short row description")
	}
	n := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		z := bytesIndex(p, 0)
		if z < 0 {
			return nil, errors.New("bad row description")
		}
		out = append(out, string(p[:z]))
		p = p[z+1:]
		if len(p) < 18 {
			return nil, errors.New("short row field")
		}
		p = p[18:]
	}
	return out, nil
}
func parseDataRow(p []byte) ([]*string, error) {
	if len(p) < 2 {
		return nil, errors.New("short data row")
	}
	n := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	out := make([]*string, n)
	for i := 0; i < n; i++ {
		if len(p) < 4 {
			return nil, errors.New("short data value")
		}
		l := int(int32(binary.BigEndian.Uint32(p)))
		p = p[4:]
		if l < 0 {
			continue
		}
		if len(p) < l {
			return nil, errors.New("short data payload")
		}
		v := string(p[:l])
		out[i] = &v
		p = p[l:]
	}
	return out, nil
}
func parseError(p []byte) error {
	fields := map[byte]string{}
	for len(p) > 1 && p[0] != 0 {
		code := p[0]
		p = p[1:]
		z := bytesIndex(p, 0)
		if z < 0 {
			break
		}
		fields[code] = string(p[:z])
		p = p[z+1:]
	}
	return fmt.Errorf("postgres %s: %s", fields['C'], fields['M'])
}
func bytesIndex(b []byte, x byte) int {
	for i, v := range b {
		if v == x {
			return i
		}
	}
	return -1
}
func appendInt32(b []byte, v int32) []byte {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], uint32(v))
	return append(b, x[:]...)
}

type scramState struct {
	user, password, nonce, clientFirstBare, serverFirst, clientFinalWithout string
	serverSignature                                                         []byte
}

func newSCRAM(user, password string) (*scramState, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	u := strings.NewReplacer("=", "=3D", ",", "=2C").Replace(user)
	n := base64.RawStdEncoding.EncodeToString(b)
	return &scramState{user: u, password: password, nonce: n, clientFirstBare: "n=" + u + ",r=" + n}, nil
}
func (s *scramState) sendInitial(c *Client) error {
	resp := "n,," + s.clientFirstBare
	p := append([]byte("SCRAM-SHA-256\x00"), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(p[len(p)-4:], uint32(len(resp)))
	p = append(p, resp...)
	return c.sendMessage('p', p)
}
func (s *scramState) continueAuth(c *Client, server string) error {
	s.serverFirst = server
	m := parseSCRAMFields(server)
	r, sa, it := m["r"], m["s"], m["i"]
	if !strings.HasPrefix(r, s.nonce) {
		return errors.New("scram server nonce mismatch")
	}
	salt, err := base64.StdEncoding.DecodeString(sa)
	if err != nil {
		return err
	}
	iter, err := strconv.Atoi(it)
	if err != nil || iter < 4096 {
		return errors.New("invalid scram iteration count")
	}
	salted := pbkdf2SHA256([]byte(s.password), salt, iter, 32)
	s.clientFinalWithout = "c=biws,r=" + r
	auth := s.clientFirstBare + "," + server + "," + s.clientFinalWithout
	clientKey := hmacSHA(salted, []byte("Client Key"))
	stored := sha256.Sum256(clientKey)
	sig := hmacSHA(stored[:], []byte(auth))
	proof := make([]byte, len(clientKey))
	for i := range proof {
		proof[i] = clientKey[i] ^ sig[i]
	}
	serverKey := hmacSHA(salted, []byte("Server Key"))
	s.serverSignature = hmacSHA(serverKey, []byte(auth))
	final := s.clientFinalWithout + ",p=" + base64.StdEncoding.EncodeToString(proof)
	return c.sendMessage('p', []byte(final))
}
func (s *scramState) verifyFinal(final string) error {
	m := parseSCRAMFields(final)
	if e := m["e"]; e != "" {
		return fmt.Errorf("scram: %s", e)
	}
	v, err := base64.StdEncoding.DecodeString(m["v"])
	if err != nil {
		return err
	}
	if !hmac.Equal(v, s.serverSignature) {
		return errors.New("scram server signature mismatch")
	}
	return nil
}
func parseSCRAMFields(s string) map[string]string {
	m := map[string]string{}
	for _, p := range strings.Split(s, ",") {
		if len(p) > 2 && p[1] == '=' {
			m[p[:1]] = p[2:]
		}
	}
	return m
}
func hmacSHA(key, msg []byte) []byte { h := hmac.New(sha256.New, key); h.Write(msg); return h.Sum(nil) }
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	hLen := 32
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	for i := 1; i <= blocks; i++ {
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(i))
		u := hmacSHA(password, append(append([]byte{}, salt...), ib[:]...))
		t := append([]byte{}, u...)
		for j := 1; j < iter; j++ {
			u = hmacSHA(password, u)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
