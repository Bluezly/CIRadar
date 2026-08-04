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
	if c.Host != "db.example" || c.Port != 5433 || c.User != "user" || c.Password != "pass" || c.Database != "ciradar" || c.SSLMode != "require" {
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
