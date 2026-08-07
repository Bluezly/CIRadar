package pgwire

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseDSN(t *testing.T) {
	c, err := ParseDSN("postgres://user:pass@db.example:5433/ciradar?sslmode=require&connect_timeout=4")
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "db.example" || c.Port != 5433 || c.User != "user" || c.Password != "pass" || c.Database != "ciradar" || c.SSLMode != "require" || c.PoolMaxConns != 10 {
		t.Fatalf("config=%#v", c)
	}
	c, err = ParseDSN("host=localhost user='ci radar' password='s e c' dbname=radar sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if c.User != "ci radar" || c.Password != "s e c" {
		t.Fatalf("kv=%#v", c)
	}
}
func TestSimpleQueryProtocol(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() { done <- servePG(ln) }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := Connect(ctx, "postgres://user:pass@"+ln.Addr().String()+"/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rows, err := c.Query(ctx, "SELECT 42 AS answer")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Columns) != 1 || rows.Columns[0] != "answer" || len(rows.Values) != 1 || *rows.Values[0][0] != "42" {
		t.Fatalf("rows=%#v", rows)
	}
	if err := c.Exec(ctx, "UPDATE x SET y=1"); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func servePG(ln net.Listener) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	var lenb [4]byte
	if _, err = io.ReadFull(r, lenb[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint32(lenb[:])) - 4
	if n < 0 {
		return io.ErrUnexpectedEOF
	}
	if _, err = io.CopyN(io.Discard, r, int64(n)); err != nil {
		return err
	}
	writePG(conn, 'R', u32(0))
	writePG(conn, 'Z', []byte{'I'})
	for {
		typ, err := r.ReadByte()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err = io.ReadFull(r, lenb[:]); err != nil {
			return err
		}
		n = int(binary.BigEndian.Uint32(lenb[:])) - 4
		p := make([]byte, n)
		if _, err = io.ReadFull(r, p); err != nil {
			return err
		}
		if typ == 'X' {
			return nil
		}
		if typ != 'Q' {
			continue
		}
		q := strings.TrimRight(string(p), "\x00")
		if strings.HasPrefix(q, "SELECT") {
			writePG(conn, 'T', rowDesc("answer"))
			writePG(conn, 'D', dataRow("42"))
			writePG(conn, 'C', append([]byte("SELECT 1"), 0))
		} else {
			writePG(conn, 'C', append([]byte("UPDATE 1"), 0))
		}
		writePG(conn, 'Z', []byte{'I'})
	}
}
func writePG(w io.Writer, t byte, p []byte) {
	_, _ = w.Write([]byte{t})
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(len(p)+4))
	_, _ = w.Write(b[:])
	_, _ = w.Write(p)
}
func u32(v uint32) []byte { var b [4]byte; binary.BigEndian.PutUint32(b[:], v); return b[:] }
func rowDesc(name string) []byte {
	p := []byte{0, 1}
	p = append(p, []byte(name)...)
	p = append(p, 0)
	p = append(p, make([]byte, 18)...)
	return p
}
func dataRow(v string) []byte {
	p := []byte{0, 1}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(len(v)))
	p = append(p, b[:]...)
	p = append(p, []byte(v)...)
	return p
}

func TestParseDSNDefaultsToVerifyFull(t *testing.T) {
	c, err := ParseDSN("postgres://user:pass@db.example/ciradar")
	if err != nil {
		t.Fatal(err)
	}
	if c.SSLMode != "verify-full" {
		t.Fatalf("unexpected sslmode %q", c.SSLMode)
	}
}

func TestParseDSNExplicitInsecureMode(t *testing.T) {
	c, err := ParseDSN("postgres://user:pass@db.example/ciradar?sslmode=insecure-require")
	if err != nil {
		t.Fatal(err)
	}
	if c.SSLMode != "insecure-require" {
		t.Fatalf("unexpected sslmode %q", c.SSLMode)
	}
}

func TestParseDSNPoolMaxConnections(t *testing.T) {
	c, err := ParseDSN("postgres://user:pass@db.example/ciradar?pool_max_conns=24")
	if err != nil {
		t.Fatal(err)
	}
	if c.PoolMaxConns != 24 {
		t.Fatalf("pool max connections=%d", c.PoolMaxConns)
	}
	if _, err := ParseDSN("postgres://user:pass@db.example/ciradar?pool_max_conns=0"); err == nil {
		t.Fatal("expected invalid pool size to fail")
	}
}

func TestQueryConsumesReadyForQueryAfterError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() { done <- servePGErrorThenSuccess(ln) }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := Connect(ctx, "postgres://user:pass@"+ln.Addr().String()+"/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Exec(ctx, "BAD SQL"); err == nil || !strings.Contains(err.Error(), "syntax error") {
		t.Fatalf("expected postgres syntax error, got %v", err)
	}
	rows, err := c.Query(ctx, "SELECT 42 AS answer")
	if err != nil {
		t.Fatalf("connection was desynchronized after error: %v", err)
	}
	if len(rows.Values) != 1 || rows.Values[0][0] == nil || *rows.Values[0][0] != "42" {
		t.Fatalf("unexpected rows after recovery: %#v", rows)
	}
	_ = c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func servePGErrorThenSuccess(ln net.Listener) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	var lenb [4]byte
	if _, err = io.ReadFull(r, lenb[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint32(lenb[:])) - 4
	if _, err = io.CopyN(io.Discard, r, int64(n)); err != nil {
		return err
	}
	writePG(conn, 'R', u32(0))
	writePG(conn, 'Z', []byte{'I'})
	for {
		typ, err := r.ReadByte()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err = io.ReadFull(r, lenb[:]); err != nil {
			return err
		}
		n = int(binary.BigEndian.Uint32(lenb[:])) - 4
		payload := make([]byte, n)
		if _, err = io.ReadFull(r, payload); err != nil {
			return err
		}
		if typ == 'X' {
			return nil
		}
		if typ != 'Q' {
			continue
		}
		q := strings.TrimRight(string(payload), "\x00")
		if strings.HasPrefix(q, "BAD") {
			writePG(conn, 'E', pgError("42601", "syntax error"))
			writePG(conn, 'Z', []byte{'I'})
			continue
		}
		writePG(conn, 'T', rowDesc("answer"))
		writePG(conn, 'D', dataRow("42"))
		writePG(conn, 'C', append([]byte("SELECT 1"), 0))
		writePG(conn, 'Z', []byte{'I'})
	}
}

func pgError(code, message string) []byte {
	p := []byte{'S'}
	p = append(p, []byte("ERROR")...)
	p = append(p, 0, 'C')
	p = append(p, []byte(code)...)
	p = append(p, 0, 'M')
	p = append(p, []byte(message)...)
	p = append(p, 0, 0)
	return p
}

func TestCancelledQueryMarksConnectionBroken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		var lenb [4]byte
		if _, err = io.ReadFull(r, lenb[:]); err != nil {
			done <- err
			return
		}
		n := int(binary.BigEndian.Uint32(lenb[:])) - 4
		if _, err = io.CopyN(io.Discard, r, int64(n)); err != nil {
			done <- err
			return
		}
		writePG(conn, 'R', u32(0))
		writePG(conn, 'Z', []byte{'I'})
		if _, err = r.ReadByte(); err != nil {
			done <- err
			return
		}
		if _, err = io.ReadFull(r, lenb[:]); err != nil {
			done <- err
			return
		}
		n = int(binary.BigEndian.Uint32(lenb[:])) - 4
		_, err = io.CopyN(io.Discard, r, int64(n))
		if err == nil {
			time.Sleep(250 * time.Millisecond)
		}
		done <- err
	}()
	connectCtx, cancelConnect := context.WithTimeout(context.Background(), time.Second)
	defer cancelConnect()
	c, err := Connect(connectCtx, "postgres://user:pass@"+ln.Addr().String()+"/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	queryCtx, cancelQuery := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancelQuery()
	if _, err := c.Query(queryCtx, "SELECT pg_sleep(5)"); err == nil {
		t.Fatal("expected cancelled query to fail")
	}
	if !c.Broken() {
		t.Fatal("cancelled query connection was considered reusable")
	}
	_ = c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestParseDSNRejectsUnterminatedQuotedValue(t *testing.T) {
	if _, err := ParseDSN("host=localhost user='ci radar dbname=radar sslmode=disable"); err == nil {
		t.Fatal("unterminated quoted DSN value was accepted")
	}
}

func TestSCRAMIterationBounds(t *testing.T) {
	for _, tc := range []struct {
		iterations int
		valid      bool
	}{
		{4095, false},
		{4096, true},
		{1_000_000, true},
		{1_000_001, false},
	} {
		if got := validSCRAMIterationCount(tc.iterations); got != tc.valid {
			t.Fatalf("iterations=%d valid=%v, want %v", tc.iterations, got, tc.valid)
		}
	}
}

func TestExtendedQueryProtocolKeepsParametersOutOfSQL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	injection := "x'); DROP TABLE ciradar_objects;--"
	multiline := "line one\nline 'two'\\tail"
	done := make(chan error, 1)
	go func() { done <- servePGExtended(ln, injection, multiline) }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := Connect(ctx, "postgres://user:pass@"+ln.Addr().String()+"/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.QueryParams(ctx, "SELECT $1::text AS first, $2::text AS second, $3::text AS third", injection, multiline, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Values) != 1 || len(rows.Values[0]) != 3 || rows.Values[0][0] == nil || *rows.Values[0][0] != injection || rows.Values[0][1] == nil || *rows.Values[0][1] != multiline || rows.Values[0][2] != nil {
		t.Fatalf("rows=%#v", rows)
	}
	_ = c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestQueryParamsRejectsInvalidParameterBeforeWriting(t *testing.T) {
	c := &Client{}
	if _, err := c.QueryParams(context.Background(), "SELECT $1", "bad\x00value"); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("expected NUL error, got %v", err)
	}
	if _, err := c.QueryParams(context.Background(), "SELECT $1", struct{}{}); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported type error, got %v", err)
	}
}

func servePGExtended(ln net.Listener, wantFirst, wantSecond string) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	if err := readStartupPacket(r); err != nil {
		return err
	}
	writePG(conn, 'R', u32(0))
	writePG(conn, 'Z', []byte{'I'})

	var query string
	var params []*string
	for {
		typ, payload, err := readFrontendMessage(r)
		if err != nil {
			return err
		}
		switch typ {
		case 'P':
			query, err = parseTestParseMessage(payload)
			if err != nil {
				return err
			}
			if strings.Contains(query, wantFirst) || strings.Contains(query, wantSecond) {
				return fmt.Errorf("parameter leaked into SQL text: %q", query)
			}
		case 'B':
			params, err = parseTestBindMessage(payload)
			if err != nil {
				return err
			}
		case 'S':
			if query != "SELECT $1::text AS first, $2::text AS second, $3::text AS third" {
				return fmt.Errorf("query=%q", query)
			}
			if len(params) != 3 || params[0] == nil || *params[0] != wantFirst || params[1] == nil || *params[1] != wantSecond || params[2] != nil {
				return fmt.Errorf("params=%#v", params)
			}
			writePG(conn, '1', nil)
			writePG(conn, '2', nil)
			writePG(conn, 'T', rowDesc3("first", "second", "third"))
			writePG(conn, 'D', dataRow3(params))
			writePG(conn, 'C', append([]byte("SELECT 1"), 0))
			writePG(conn, 'Z', []byte{'I'})
		case 'X':
			return nil
		}
	}
}

func readStartupPacket(r *bufio.Reader) error {
	var lenb [4]byte
	if _, err := io.ReadFull(r, lenb[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint32(lenb[:])) - 4
	if n < 0 {
		return io.ErrUnexpectedEOF
	}
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}

func readFrontendMessage(r *bufio.Reader) (byte, []byte, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var lenb [4]byte
	if _, err := io.ReadFull(r, lenb[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(lenb[:])) - 4
	if n < 0 {
		return 0, nil, io.ErrUnexpectedEOF
	}
	payload := make([]byte, n)
	_, err = io.ReadFull(r, payload)
	return typ, payload, err
}

func parseTestParseMessage(payload []byte) (string, error) {
	statementEnd := bytesIndex(payload, 0)
	if statementEnd < 0 {
		return "", io.ErrUnexpectedEOF
	}
	payload = payload[statementEnd+1:]
	queryEnd := bytesIndex(payload, 0)
	if queryEnd < 0 || len(payload) < queryEnd+3 {
		return "", io.ErrUnexpectedEOF
	}
	return string(payload[:queryEnd]), nil
}

func parseTestBindMessage(payload []byte) ([]*string, error) {
	for i := 0; i < 2; i++ {
		end := bytesIndex(payload, 0)
		if end < 0 {
			return nil, io.ErrUnexpectedEOF
		}
		payload = payload[end+1:]
	}
	if len(payload) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	formatCount := int(binary.BigEndian.Uint16(payload[:2]))
	payload = payload[2:]
	if len(payload) < formatCount*2+2 {
		return nil, io.ErrUnexpectedEOF
	}
	payload = payload[formatCount*2:]
	count := int(binary.BigEndian.Uint16(payload[:2]))
	payload = payload[2:]
	params := make([]*string, count)
	for i := range params {
		if len(payload) < 4 {
			return nil, io.ErrUnexpectedEOF
		}
		length := int(int32(binary.BigEndian.Uint32(payload[:4])))
		payload = payload[4:]
		if length < 0 {
			continue
		}
		if len(payload) < length {
			return nil, io.ErrUnexpectedEOF
		}
		value := string(payload[:length])
		params[i] = &value
		payload = payload[length:]
	}
	return params, nil
}

func rowDesc3(names ...string) []byte {
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(len(names)))
	for _, name := range names {
		p = append(p, []byte(name)...)
		p = append(p, 0)
		p = append(p, make([]byte, 18)...)
	}
	return p
}

func dataRow3(values []*string) []byte {
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(len(values)))
	for _, value := range values {
		if value == nil {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], ^uint32(0))
			p = append(p, b[:]...)
			continue
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(len(*value)))
		p = append(p, b[:]...)
		p = append(p, []byte(*value)...)
	}
	return p
}

func TestQueriesRejectNULBeforeWriting(t *testing.T) {
	c := &Client{}
	if _, err := c.Query(context.Background(), "SELECT 1\x00DROP TABLE x"); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("simple query NUL error=%v", err)
	}
	if _, err := c.QueryParams(context.Background(), "SELECT $1\x00DROP TABLE x", "safe"); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("parameterized query NUL error=%v", err)
	}
}

type chunkWriter struct {
	max int
	buf []byte
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := len(p)
	if n > w.max {
		n = w.max
	}
	w.buf = append(w.buf, p[:n]...)
	return n, nil
}

func TestWriteFullHandlesShortSuccessfulWrites(t *testing.T) {
	writer := &chunkWriter{max: 3}
	payload := []byte("postgres-protocol-message")
	if err := writeFull(writer, payload); err != nil {
		t.Fatal(err)
	}
	if string(writer.buf) != string(payload) {
		t.Fatalf("written=%q want=%q", writer.buf, payload)
	}
}

func TestResetIdleConnectionDoesNotTouchNetwork(t *testing.T) {
	c := &Client{txStatus: 'I'}
	if err := c.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.Broken() {
		t.Fatal("idle connection was marked broken")
	}
}

func TestResetRollsBackOpenTransaction(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	c := &Client{conn: clientConn, r: bufio.NewReader(clientConn), txStatus: 'T'}
	done := make(chan error, 1)
	go func() {
		r := bufio.NewReader(serverConn)
		typ, payload, err := readFrontendMessage(r)
		if err != nil {
			done <- err
			return
		}
		if typ != 'Q' || strings.TrimRight(string(payload), "\x00") != "ROLLBACK" {
			done <- fmt.Errorf("unexpected reset query type=%q payload=%q", typ, payload)
			return
		}
		writePG(serverConn, 'C', append([]byte("ROLLBACK"), 0))
		writePG(serverConn, 'Z', []byte{'I'})
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if got := c.TransactionStatus(); got != 'I' {
		t.Fatalf("transaction status=%q", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReadyForQueryRejectsInvalidStatus(t *testing.T) {
	c := &Client{}
	if err := c.setReadyStatus(nil); err == nil {
		t.Fatal("empty ReadyForQuery payload was accepted")
	}
	if err := c.setReadyStatus([]byte{'X'}); err == nil {
		t.Fatal("invalid transaction state was accepted")
	}
}

func TestQueryParamsRejectsProtocolParameterCountOverflow(t *testing.T) {
	args := make([]any, 32768)
	_, err := (&Client{}).QueryParams(context.Background(), "SELECT 1", args...)
	if err == nil || !strings.Contains(err.Error(), "too many postgres parameters") {
		t.Fatalf("expected parameter-count error, got %v", err)
	}
}

func TestParseDataRowRejectsInvalidNegativeLengthEncoding(t *testing.T) {
	payload := []byte{0, 1, 0xff, 0xff, 0xff, 0xfe}
	if _, err := parseDataRow(payload); err == nil {
		t.Fatal("invalid negative data length was accepted")
	}
}

func TestParseDataRowRejectsTrailingPayload(t *testing.T) {
	payload := []byte{0, 1, 0, 0, 0, 1, 'x', 'y'}
	if _, err := parseDataRow(payload); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected trailing payload error, got %v", err)
	}
}

func TestSCRAMFieldsRejectDuplicatesAndMalformedAttributes(t *testing.T) {
	for _, value := range []string{"r=one,r=two", "r=one,bad", ""} {
		if _, err := parseSCRAMFields(value); err == nil {
			t.Fatalf("invalid SCRAM attributes accepted: %q", value)
		}
	}
	fields, err := parseSCRAMFields("r=nonce,s=c2FsdA==,i=4096")
	if err != nil || fields["r"] != "nonce" || fields["i"] != "4096" {
		t.Fatalf("valid SCRAM attributes rejected: %#v %v", fields, err)
	}
}

func TestSCRAMFieldsRejectOversizedAndAttributeFlood(t *testing.T) {
	if _, err := parseSCRAMFields("r=" + strings.Repeat("x", maxSCRAMMessageBytes)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized SCRAM message accepted: %v", err)
	}
	parts := make([]string, maxSCRAMAttributes+1)
	for i := range parts {
		parts[i] = fmt.Sprintf("%c=x", 'a'+rune(i%26))
	}
	if _, err := parseSCRAMFields(strings.Join(parts, ",")); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("SCRAM attribute flood accepted: %v", err)
	}
}

func TestSCRAMStateRejectsOutOfOrderMessages(t *testing.T) {
	state := &scramState{nonce: "clientnonce", password: "secret", clientFirstBare: "n=user,r=clientnonce"}
	if err := state.verifyFinal("v=c2ln"); err == nil || !strings.Contains(err.Error(), "before server-first") {
		t.Fatalf("server-final before server-first was accepted: %v", err)
	}
	state.continued = true
	state.verified = true
	if err := state.verifyFinal("v=c2ln"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate server-final was accepted: %v", err)
	}
	if err := state.continueAuth(&Client{}, "r=clientnonce-server,s=c2FsdA==,i=4096"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate server-first was accepted: %v", err)
	}
}

func TestSASLMechanismOfferMustBeWellFormed(t *testing.T) {
	if !saslMechanismOffered([]byte("SCRAM-SHA-256\x00SCRAM-SHA-256-PLUS\x00\x00"), "SCRAM-SHA-256") {
		t.Fatal("SCRAM-SHA-256 offer was not recognized")
	}
	for _, payload := range [][]byte{
		[]byte("SCRAM-SHA-256-PLUS\x00\x00"),
		[]byte("SCRAM-SHA-256"),
		[]byte("SCRAM-SHA-256\x00"),
		[]byte("SCRAM-SHA-256\x00\x00garbage\x00"),
		[]byte("\x00"),
	} {
		if saslMechanismOffered(payload, "SCRAM-SHA-256") {
			t.Fatalf("invalid or missing mechanism was accepted: %q", payload)
		}
	}
}

func TestSCRAMRequiresServerNonceContribution(t *testing.T) {
	state := &scramState{nonce: "clientnonce", password: "secret", clientFirstBare: "n=user,r=clientnonce"}
	server := "r=clientnonce,s=c2FsdA==,i=4096"
	if err := state.continueAuth(&Client{}, server); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("server nonce without server contribution was accepted: %v", err)
	}
}

func TestCloseIsBoundedWhenPeerStopsReading(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	c := &Client{conn: clientConn, r: bufio.NewReader(clientConn), txStatus: 'I'}
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- c.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("close took too long: %s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("close blocked on PostgreSQL Terminate write")
	}
}

func FuzzParseDSN(f *testing.F) {
	for _, seed := range []string{
		"postgres://user:pass@localhost/db?sslmode=verify-full",
		"host=localhost user='ci radar' password='secret' dbname=radar sslmode=disable",
		"host='unterminated",
		"postgres://%00@localhost/db",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, dsn string) {
		_, _ = ParseDSN(dsn)
	})
}

func FuzzParseDataRow(f *testing.F) {
	for _, seed := range [][]byte{
		{0, 0},
		{0, 1, 0xff, 0xff, 0xff, 0xff},
		{0, 1, 0, 0, 0, 1, 'x'},
		{0xff, 0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = parseDataRow(payload)
	})
}

func FuzzParseSCRAMFields(f *testing.F) {
	for _, seed := range []string{"r=nonce,s=c2FsdA==,i=4096", "r=one,r=two", "", "m=ext,r=x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = parseSCRAMFields(value)
	})
}

func TestClosedClientIsNotReusable(t *testing.T) {
	client := &Client{}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if !client.Broken() {
		t.Fatal("closed postgres client remained reusable")
	}
}

func TestConnectRejectsReadyBeforeAuthentication(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		var length [4]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			done <- err
			return
		}
		n := int(binary.BigEndian.Uint32(length[:])) - 4
		if n < 0 {
			done <- errors.New("invalid startup length")
			return
		}
		if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
			done <- err
			return
		}
		writePG(conn, 'Z', []byte{'I'})
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := Connect(ctx, "postgres://user:pass@"+ln.Addr().String()+"/db?sslmode=disable")
	if client != nil {
		_ = client.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "before authentication completed") {
		t.Fatalf("ReadyForQuery before authentication was accepted: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConnectRejectsLegacyPasswordAuthentication(t *testing.T) {
	for _, authCode := range []uint32{3, 5} {
		t.Run(fmt.Sprintf("auth-%d", authCode), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				var length [4]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					done <- err
					return
				}
				n := int(binary.BigEndian.Uint32(length[:])) - 4
				if n < 0 {
					done <- errors.New("invalid startup length")
					return
				}
				if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
					done <- err
					return
				}
				payload := u32(authCode)
				if authCode == 5 {
					payload = append(payload, []byte{1, 2, 3, 4}...)
				}
				writePG(conn, 'R', payload)
				done <- nil
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client, err := Connect(ctx, "postgres://user:pass@"+ln.Addr().String()+"/db?sslmode=disable")
			if client != nil {
				_ = client.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "SCRAM-SHA-256") {
				t.Fatalf("legacy authentication code %d was accepted: %v", authCode, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParseDSNQueryTimeout(t *testing.T) {
	cfg, err := ParseDSN("postgres://user:pass@db.example/ciradar?query_timeout=45")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OperationTimeout != 45*time.Second {
		t.Fatalf("operation timeout=%s", cfg.OperationTimeout)
	}
	for _, raw := range []string{
		"postgres://user:pass@db.example/ciradar?query_timeout=0",
		"postgres://user:pass@db.example/ciradar?query_timeout=601",
		"host=db.example user=user query_timeout=nope",
	} {
		if _, err := ParseDSN(raw); err == nil {
			t.Fatalf("invalid query timeout accepted: %s", raw)
		}
	}
}

func TestOperationDeadlineUsesShorterBound(t *testing.T) {
	client := &Client{cfg: Config{OperationTimeout: 30 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deadline, ok := client.operationDeadline(ctx)
	if !ok {
		t.Fatal("deadline missing")
	}
	ctxDeadline, _ := ctx.Deadline()
	if deadline.Sub(ctxDeadline) > time.Millisecond || ctxDeadline.Sub(deadline) > time.Millisecond {
		t.Fatalf("deadline=%s context=%s", deadline, ctxDeadline)
	}
}
