package pgwire

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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

const maxProtocolMessageBytes = 256 << 20
const maxBoundParameterBytes = 64 << 20
const maxSCRAMMessageBytes = 16 << 10
const maxSCRAMAttributes = 32

type Config struct {
	Host             string
	Port             int
	User             string
	Password         string
	Database         string
	SSLMode          string
	RootCert         string
	ConnectTimeout   time.Duration
	OperationTimeout time.Duration
	PoolMaxConns     int
}

type Client struct {
	conn     net.Conn
	r        *bufio.Reader
	cfg      Config
	broken   bool
	txStatus byte
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
	cfg := Config{Port: 5432, SSLMode: "verify-full", ConnectTimeout: 10 * time.Second, OperationTimeout: 30 * time.Second, PoolMaxConns: 10}
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
		if v := q.Get("query_timeout"); v != "" {
			n, e := strconv.Atoi(v)
			if e != nil || n < 1 || n > 600 {
				return cfg, errors.New("query_timeout must be between 1 and 600 seconds")
			}
			cfg.OperationTimeout = time.Duration(n) * time.Second
		}
		if v := q.Get("pool_max_conns"); v != "" {
			n, e := strconv.Atoi(v)
			if e != nil || n < 1 || n > 200 {
				return cfg, errors.New("pool_max_conns must be between 1 and 200")
			}
			cfg.PoolMaxConns = n
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
		if v := fields["query_timeout"]; v != "" {
			n, e := strconv.Atoi(v)
			if e != nil || n < 1 || n > 600 {
				return cfg, errors.New("query_timeout must be between 1 and 600 seconds")
			}
			cfg.OperationTimeout = time.Duration(n) * time.Second
		}
		if v := fields["pool_max_conns"]; v != "" {
			n, e := strconv.Atoi(v)
			if e != nil || n < 1 || n > 200 {
				return cfg, errors.New("pool_max_conns must be between 1 and 200")
			}
			cfg.PoolMaxConns = n
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
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full", "insecure-require":
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
			closed := false
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					i++
					b.WriteByte(s[i])
					i++
					continue
				}
				if s[i] == '\'' {
					i++
					closed = true
					break
				}
				b.WriteByte(s[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated quoted dsn value for %q", key)
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
	if err := writeFull(c.conn, p[:]); err != nil {
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
	if c.cfg.SSLMode == "insecure-require" {
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
	if err := writeFull(c.conn, packet); err != nil {
		return err
	}
	var scr *scramState
	authenticated := false
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
			if len(p) > 64<<10 {
				return errors.New("postgres authentication message is too large")
			}
			code := binary.BigEndian.Uint32(p[:4])
			switch code {
			case 0:
				if scr != nil && !scr.verified {
					return errors.New("postgres authentication completed before SCRAM server verification")
				}
				authenticated = true
			case 3, 5:
				return errors.New("legacy PostgreSQL cleartext/MD5 password authentication is disabled; configure SCRAM-SHA-256")
			case 10:
				if scr != nil {
					return errors.New("duplicate postgres SASL authentication start")
				}
				if !saslMechanismOffered(p[4:], "SCRAM-SHA-256") {
					return errors.New("postgres server did not offer SCRAM-SHA-256")
				}
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
			if !authenticated {
				return errors.New("postgres became ready before authentication completed")
			}
			if err := c.setReadyStatus(p); err != nil {
				return err
			}
			return nil
		case 'S', 'K', 'N':
		default:
			return fmt.Errorf("unexpected postgres startup message %q", typ)
		}
	}
}

func (c *Client) sendMessage(t byte, p []byte) error {
	if len(p) > maxProtocolMessageBytes-4 {
		return errors.New("postgres protocol message is too large")
	}
	buf := make([]byte, 0, len(p)+5)
	buf = append(buf, t)
	buf = appendInt32(buf, int32(len(p)+4))
	buf = append(buf, p...)
	return writeFull(c.conn, buf)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
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
	if n < 0 || n > maxProtocolMessageBytes {
		return 0, nil, fmt.Errorf("invalid postgres message length %d", n)
	}
	p := make([]byte, n)
	_, err = io.ReadFull(c.r, p)
	return t, p, err
}

func validateQueryText(q string) error {
	if strings.IndexByte(q, 0) >= 0 {
		return errors.New("postgres query contains NUL")
	}
	if len(q) > 64<<20 {
		return errors.New("postgres query is too large")
	}
	return nil
}

func (c *Client) operationDeadline(ctx context.Context) (time.Time, bool) {
	deadline, hasDeadline := ctx.Deadline()
	if c.cfg.OperationTimeout <= 0 {
		return deadline, hasDeadline
	}
	operationDeadline := time.Now().Add(c.cfg.OperationTimeout)
	if !hasDeadline || operationDeadline.Before(deadline) {
		return operationDeadline, true
	}
	return deadline, true
}

func (c *Client) Query(ctx context.Context, q string) (Rows, error) {
	if err := validateQueryText(q); err != nil {
		return Rows{}, err
	}
	if err := ctx.Err(); err != nil {
		return Rows{}, err
	}
	if deadline, ok := c.operationDeadline(ctx); ok {
		_ = c.conn.SetDeadline(deadline)
	}
	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		_ = c.conn.SetDeadline(time.Now())
		close(cancelDone)
	})
	defer func() {
		if !stopCancel() {
			<-cancelDone
		}
		_ = c.conn.SetDeadline(time.Time{})
	}()
	if err := c.sendMessage('Q', append([]byte(q), 0)); err != nil {
		c.broken = true
		return Rows{}, err
	}
	var out Rows
	var queryErr error
	for {
		t, p, err := c.readMessage()
		if err != nil {
			c.broken = true
			if ctxErr := ctx.Err(); ctxErr != nil {
				return out, ctxErr
			}
			return out, err
		}
		switch t {
		case 'T':
			names, err := parseRowDescription(p)
			if err != nil {
				c.broken = true
				return out, err
			}
			out.Columns = names
		case 'D':
			vals, err := parseDataRow(p)
			if err != nil {
				c.broken = true
				return out, err
			}
			out.Values = append(out.Values, vals)
		case 'C':
			out.Command = strings.TrimRight(string(p), "\x00")
		case 'E':
			queryErr = parseError(p)
		case 'Z':
			if err := c.setReadyStatus(p); err != nil {
				c.broken = true
				return out, err
			}
			return out, queryErr
		case 'I', 'N', 'S', 'A':
		default:
			c.broken = true
			return out, fmt.Errorf("unexpected postgres query message %q", t)
		}
	}
}
func (c *Client) Exec(ctx context.Context, q string) error { _, err := c.Query(ctx, q); return err }
func (c *Client) QueryParams(ctx context.Context, q string, args ...any) (Rows, error) {
	if err := validateQueryText(q); err != nil {
		return Rows{}, err
	}
	if len(args) == 0 {
		return c.Query(ctx, q)
	}
	if len(args) > 32767 {
		return Rows{}, errors.New("too many postgres parameters")
	}
	encodedArgs := make([][]byte, len(args))
	nullArgs := make([]bool, len(args))
	totalParameterBytes := 0
	for i, arg := range args {
		value, isNull, err := encodeTextParameter(arg)
		if err != nil {
			return Rows{}, err
		}
		if len(value) > maxBoundParameterBytes {
			return Rows{}, errors.New("postgres parameter is too large")
		}
		if !isNull {
			if totalParameterBytes > maxBoundParameterBytes-len(value) {
				return Rows{}, errors.New("postgres bound parameters are too large")
			}
			totalParameterBytes += len(value)
		}
		encodedArgs[i] = value
		nullArgs[i] = isNull
	}
	if err := ctx.Err(); err != nil {
		return Rows{}, err
	}
	if deadline, ok := c.operationDeadline(ctx); ok {
		_ = c.conn.SetDeadline(deadline)
	}
	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		_ = c.conn.SetDeadline(time.Now())
		close(cancelDone)
	})
	defer func() {
		if !stopCancel() {
			<-cancelDone
		}
		_ = c.conn.SetDeadline(time.Time{})
	}()

	parse := []byte{0}
	parse = append(parse, q...)
	parse = append(parse, 0)
	parse = appendInt16(parse, 0)
	if err := c.sendMessage('P', parse); err != nil {
		c.broken = true
		return Rows{}, err
	}

	bind := []byte{0, 0}
	bind = appendInt16(bind, 0)
	bind = appendInt16(bind, int16(len(encodedArgs)))
	for i, value := range encodedArgs {
		if nullArgs[i] {
			bind = appendInt32(bind, -1)
			continue
		}
		bind = appendInt32(bind, int32(len(value)))
		bind = append(bind, value...)
	}
	bind = appendInt16(bind, 0)
	if err := c.sendMessage('B', bind); err != nil {
		c.broken = true
		return Rows{}, err
	}
	if err := c.sendMessage('D', []byte{'P', 0}); err != nil {
		c.broken = true
		return Rows{}, err
	}
	execute := []byte{0}
	execute = appendInt32(execute, 0)
	if err := c.sendMessage('E', execute); err != nil {
		c.broken = true
		return Rows{}, err
	}
	if err := c.sendMessage('S', nil); err != nil {
		c.broken = true
		return Rows{}, err
	}

	var out Rows
	var queryErr error
	for {
		t, payload, err := c.readMessage()
		if err != nil {
			c.broken = true
			if ctxErr := ctx.Err(); ctxErr != nil {
				return out, ctxErr
			}
			return out, err
		}
		switch t {
		case 'T':
			names, err := parseRowDescription(payload)
			if err != nil {
				c.broken = true
				return out, err
			}
			out.Columns = names
		case 'D':
			values, err := parseDataRow(payload)
			if err != nil {
				c.broken = true
				return out, err
			}
			out.Values = append(out.Values, values)
		case 'C':
			out.Command = strings.TrimRight(string(payload), "\x00")
		case 'E':
			queryErr = parseError(payload)
		case 'Z':
			if err := c.setReadyStatus(payload); err != nil {
				c.broken = true
				return out, err
			}
			return out, queryErr
		case '1', '2', '3', 'I', 'N', 'S', 'n', 's', 't', 'A':
		default:
			c.broken = true
			return out, fmt.Errorf("unexpected postgres extended-query message %q", t)
		}
	}
}

func (c *Client) ExecParams(ctx context.Context, q string, args ...any) error {
	_, err := c.QueryParams(ctx, q, args...)
	return err
}

func encodeTextParameter(value any) ([]byte, bool, error) {
	if value == nil {
		return nil, true, nil
	}
	var encoded string
	switch v := value.(type) {
	case string:
		encoded = v
	case []byte:
		encoded = string(v)
	case bool:
		encoded = strconv.FormatBool(v)
	case int:
		encoded = strconv.Itoa(v)
	case int8:
		encoded = strconv.FormatInt(int64(v), 10)
	case int16:
		encoded = strconv.FormatInt(int64(v), 10)
	case int32:
		encoded = strconv.FormatInt(int64(v), 10)
	case int64:
		encoded = strconv.FormatInt(v, 10)
	case uint:
		encoded = strconv.FormatUint(uint64(v), 10)
	case uint8:
		encoded = strconv.FormatUint(uint64(v), 10)
	case uint16:
		encoded = strconv.FormatUint(uint64(v), 10)
	case uint32:
		encoded = strconv.FormatUint(uint64(v), 10)
	case uint64:
		encoded = strconv.FormatUint(v, 10)
	case float32:
		encoded = strconv.FormatFloat(float64(v), 'g', -1, 32)
	case float64:
		encoded = strconv.FormatFloat(v, 'g', -1, 64)
	case time.Time:
		if v.IsZero() {
			return nil, true, nil
		}
		encoded = v.UTC().Format(time.RFC3339Nano)
	case json.RawMessage:
		encoded = string(v)
	default:
		return nil, false, fmt.Errorf("unsupported postgres parameter type %T", value)
	}
	if strings.IndexByte(encoded, 0) >= 0 {
		return nil, false, errors.New("postgres text parameter contains NUL")
	}
	return []byte(encoded), false, nil
}

func (c *Client) setReadyStatus(payload []byte) error {
	if len(payload) != 1 {
		return errors.New("invalid postgres ReadyForQuery payload")
	}
	switch payload[0] {
	case 'I', 'T', 'E':
		c.txStatus = payload[0]
		return nil
	default:
		return fmt.Errorf("invalid postgres transaction status %q", payload[0])
	}
}

func (c *Client) TransactionStatus() byte {
	if c == nil {
		return 0
	}
	return c.txStatus
}

func (c *Client) Reset(ctx context.Context) error {
	if c == nil || c.broken {
		return errors.New("postgres connection is not reusable")
	}
	switch c.txStatus {
	case 'I':
		return nil
	case 'T', 'E':
		if err := c.Exec(ctx, "ROLLBACK"); err != nil {
			c.broken = true
			return err
		}
		if c.txStatus != 'I' {
			c.broken = true
			return errors.New("postgres connection did not return to idle state")
		}
		return nil
	default:
		c.broken = true
		return errors.New("postgres connection has unknown transaction state")
	}
}

func (c *Client) Broken() bool { return c == nil || c.broken }

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	wasBroken := c.broken
	c.broken = true
	if c.conn == nil {
		return nil
	}
	conn := c.conn
	c.conn = nil
	if !wasBroken {
		_ = conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
		buf := []byte{'X', 0, 0, 0, 4}
		_ = writeFull(conn, buf)
	}
	return conn.Close()
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
		rawLength := binary.BigEndian.Uint32(p)
		p = p[4:]
		if rawLength == ^uint32(0) {
			continue
		}
		if uint64(rawLength) > uint64(len(p)) {
			return nil, errors.New("short data payload")
		}
		l := int(rawLength)
		v := string(p[:l])
		out[i] = &v
		p = p[l:]
	}
	if len(p) != 0 {
		return nil, errors.New("trailing data row payload")
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
func appendInt16(b []byte, v int16) []byte {
	var x [2]byte
	binary.BigEndian.PutUint16(x[:], uint16(v))
	return append(b, x[:]...)
}
func appendInt32(b []byte, v int32) []byte {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], uint32(v))
	return append(b, x[:]...)
}

type scramState struct {
	user, password, nonce, clientFirstBare, serverFirst, clientFinalWithout string
	serverSignature                                                         []byte
	continued                                                               bool
	verified                                                                bool
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
	if s.continued {
		return errors.New("duplicate scram server-first message")
	}
	s.serverFirst = server
	m, err := parseSCRAMFields(server)
	if err != nil {
		return err
	}
	if m["m"] != "" {
		return errors.New("unsupported mandatory scram extension")
	}
	r, sa, it := m["r"], m["s"], m["i"]
	if r == "" || sa == "" || it == "" {
		return errors.New("incomplete scram server-first message")
	}
	if !strings.HasPrefix(r, s.nonce) || len(r) <= len(s.nonce) {
		return errors.New("scram server nonce mismatch")
	}
	salt, err := base64.StdEncoding.DecodeString(sa)
	if err != nil {
		return err
	}
	if len(salt) == 0 || len(salt) > 1024 {
		return errors.New("invalid scram salt size")
	}
	iter, err := strconv.Atoi(it)
	if err != nil || !validSCRAMIterationCount(iter) {
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
	if err := c.sendMessage('p', []byte(final)); err != nil {
		return err
	}
	s.continued = true
	return nil
}
func validSCRAMIterationCount(iter int) bool {
	return iter >= 4096 && iter <= 1_000_000
}

func (s *scramState) verifyFinal(final string) error {
	if !s.continued {
		return errors.New("scram server-final message arrived before server-first verification")
	}
	if s.verified {
		return errors.New("duplicate scram server-final message")
	}
	m, err := parseSCRAMFields(final)
	if err != nil {
		return err
	}
	if e := m["e"]; e != "" {
		if m["v"] != "" {
			return errors.New("scram final message contains both error and verifier")
		}
		return fmt.Errorf("scram: %s", e)
	}
	encodedVerifier := m["v"]
	if encodedVerifier == "" {
		return errors.New("scram final message is missing verifier")
	}
	v, err := base64.StdEncoding.DecodeString(encodedVerifier)
	if err != nil {
		return err
	}
	if !hmac.Equal(v, s.serverSignature) {
		return errors.New("scram server signature mismatch")
	}
	s.verified = true
	return nil
}

func parseSCRAMFields(value string) (map[string]string, error) {
	if value == "" {
		return nil, errors.New("malformed scram attribute")
	}
	if len(value) > maxSCRAMMessageBytes {
		return nil, errors.New("scram message is too large")
	}
	parts := strings.Split(value, ",")
	if len(parts) > maxSCRAMAttributes {
		return nil, errors.New("scram message has too many attributes")
	}
	fields := map[string]string{}
	for _, part := range parts {
		if len(part) < 2 || part[1] != '=' {
			return nil, errors.New("malformed scram attribute")
		}
		key := part[:1]
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("duplicate scram attribute %q", key)
		}
		fields[key] = part[2:]
	}
	return fields, nil
}

func saslMechanismOffered(payload []byte, wanted string) bool {
	if wanted == "" || len(payload) == 0 || payload[len(payload)-1] != 0 {
		return false
	}
	found := false
	for len(payload) > 0 {
		end := bytesIndex(payload, 0)
		if end < 0 {
			return false
		}
		if end == 0 {
			return found && len(payload) == 1
		}
		if string(payload[:end]) == wanted {
			found = true
		}
		payload = payload[end+1:]
	}
	return false
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
