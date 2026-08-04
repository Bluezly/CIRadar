package repair

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildAndApplyRepairPlan(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "src", "app.js")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	original := "const retries = 1;\nconsole.log(retries);\n"
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	patch := `diff --git a/src/app.js b/src/app.js
--- a/src/app.js
+++ b/src/app.js
@@ -1,2 +1,2 @@
-const retries = 1;
+const retries = 2;
 console.log(retries);
`
	plan, err := BuildPlan("analysis-1", patch, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Files) != 1 || plan.ChangedLines != 2 || plan.Confirmation == "" {
		t.Fatalf("plan=%#v", plan)
	}
	if err := Apply(plan, root, plan.Confirmation, true); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != original {
		t.Fatal("dry run changed file")
	}
	if err := Apply(plan, root, plan.Confirmation, false); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if string(raw) != "const retries = 2;\nconsole.log(retries);\n" {
		t.Fatalf("content=%q", string(raw))
	}
	backup, err := os.ReadFile(filepath.Join(root, ".ciradar-repair-backup", plan.ID, "src", "app.js"))
	if err != nil || string(backup) != original {
		t.Fatalf("backup=%q err=%v", string(backup), err)
	}
}

func TestRepairRejectsUnsafePatch(t *testing.T) {
	root := t.TempDir()
	cases := []string{
		"--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n-a\n+b\n",
		"--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-a\n+b\n",
		"--- a/file.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n",
	}
	for _, patch := range cases {
		if _, err := BuildPlan("analysis", patch, root); err == nil {
			t.Fatalf("expected rejection for %q", patch)
		}
	}
}

func TestRepairDetectsConcurrentFileChange(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	_ = os.WriteFile(path, []byte("old\n"), 0644)
	plan, err := BuildPlan("analysis", "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n+new\n", root)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(path, []byte("other\n"), 0644)
	if err := Apply(plan, root, plan.Confirmation, false); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("err=%v", err)
	}
}
