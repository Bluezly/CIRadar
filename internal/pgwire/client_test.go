package pgwire

import (
	"bufio"
	"context"
	"encoding/binary"
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
