package db

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPostgresSourceDoesNotUseManualSQLLiteralEscaping(t *testing.T) {
	names, err := filepath.Glob("postgres*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		for _, forbidden := range []string{"sqlLiteral(", "sqlTime(", "jsonExpr("} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s still contains manual SQL literal helper %q", name, forbidden)
			}
		}
	}
}

func TestPostgresSimpleQueryDynamicSQLIsExplicitlyReviewed(t *testing.T) {
	files, err := filepath.Glob("postgres*.go")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]map[string]map[string]bool{
		"postgres_relational.go": {
			"migrateRelational": {
				"statement": true,
			},
			"ensureObservationPartitions": {
				"statement": true,
			},
			"dropExpiredObservationPartitions": {
				"`DROP TABLE IF EXISTS ` + name": true,
			},
			"backfillNativeTestObservations": {
				"query": true,
			},
		},
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || len(call.Args) < 2 {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (selector.Sel.Name != "Query" && selector.Sel.Name != "Exec") {
					return true
				}
				if literal, ok := call.Args[1].(*ast.BasicLit); ok && literal.Kind == token.STRING {
					return true
				}
				var rendered bytes.Buffer
				if err := format.Node(&rendered, set, call.Args[1]); err != nil {
					t.Errorf("render SQL expression in %s: %v", name, err)
					return true
				}
				expression := rendered.String()
				if allowed[name] != nil && allowed[name][function.Name.Name] != nil && allowed[name][function.Name.Name][expression] {
					return true
				}
				t.Errorf("%s:%d %s uses a dynamic Simple Query SQL expression %q; use QueryParams/ExecParams for values or explicitly review and allowlist identifier-only DDL", name, set.Position(call.Pos()).Line, function.Name.Name, expression)
				return true
			})
		}
	}
}

func TestObservationPartitionDDLRejectsUntrustedIdentifier(t *testing.T) {
	from := time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
	if _, err := observationPartitionDDL("ciradar_test_observations_202608;DROP TABLE ciradar_objects", from, from.AddDate(0, 1, 0)); err == nil {
		t.Fatal("unsafe partition identifier was accepted")
	}
	statement, err := observationPartitionDDL("ciradar_test_observations_202608", from, from.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statement, "ciradar_test_observations_202608") || strings.Contains(statement, ";DROP") {
		t.Fatalf("unexpected partition statement: %s", statement)
	}
}

func TestAuthFailureDelayIsBounded(t *testing.T) {
	threshold := 3
	base := 5 * time.Second
	max := 40 * time.Second
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{1, 0},
		{2, 0},
		{3, 5 * time.Second},
		{4, 10 * time.Second},
		{5, 20 * time.Second},
		{6, 40 * time.Second},
		{1000, 40 * time.Second},
	}
	for _, tc := range cases {
		if got := authFailureDelay(tc.failures, threshold, base, max); got != tc.want {
			t.Fatalf("failures=%d delay=%s want=%s", tc.failures, got, tc.want)
		}
	}
}

func TestRateLimitInputValidation(t *testing.T) {
	if err := validateRateLimitInput("http", strings.Repeat("a", 64), 600, time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		scope  string
		key    string
		limit  int
		window time.Duration
	}{
		{"", "key", 1, time.Minute},
		{"http", "", 1, time.Minute},
		{"http", "key", 0, time.Minute},
		{"http", "key", 1, 0},
		{"http", strings.Repeat("a", 129), 1, time.Minute},
	} {
		if err := validateRateLimitInput(tc.scope, tc.key, tc.limit, tc.window); err == nil {
			t.Fatalf("invalid input accepted: %#v", tc)
		}
	}
}

func TestAdvisoryLockKeyIsStableAndUsesWideHash(t *testing.T) {
	a := advisoryLockKey("ciradar:tenant:a")
	b := advisoryLockKey("ciradar:tenant:b")
	if a != advisoryLockKey("ciradar:tenant:a") {
		t.Fatal("advisory lock key is not stable")
	}
	if a == b {
		t.Fatal("distinct advisory lock names unexpectedly collided")
	}
	if a < 0 || b < 0 {
		t.Fatal("advisory lock key exceeded the signed PostgreSQL bigint range")
	}
}

func TestAuthFailureKeyHashValidationAndLockKey(t *testing.T) {
	key := strings.Repeat("ab", 32)
	normalized, err := normalizeAuthFailureKeyHash(strings.ToUpper(key))
	if err != nil {
		t.Fatal(err)
	}
	if normalized != key {
		t.Fatalf("normalized key=%q", normalized)
	}
	if got := authFailureAdvisoryLockKey(normalized); got != authFailureAdvisoryLockKey(key) {
		t.Fatal("auth advisory lock key is not stable")
	}
	if got := authFailureAdvisoryLockKey(strings.Repeat("f", 64)); got < 0 {
		t.Fatal("auth advisory lock key exceeded the signed PostgreSQL bigint range")
	}
	for _, invalid := range []string{"", "abc", strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		if _, err := normalizeAuthFailureKeyHash(invalid); err == nil {
			t.Fatalf("invalid auth key hash %q was accepted", invalid)
		}
	}
}
