package repair

import (
	"errors"
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

func TestRepairRejectsParentSymlinkTraversal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim.txt")
	if err := os.WriteFile(victim, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	patch := "--- a/link/victim.txt\n+++ b/link/victim.txt\n@@ -1 +1 @@\n-old\n+owned\n"
	if _, err := BuildPlan("analysis", patch, root); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("err=%v", err)
	}
	raw, err := os.ReadFile(victim)
	if err != nil || string(raw) != "old\n" {
		t.Fatalf("outside file changed: content=%q err=%v", string(raw), err)
	}
}

func TestRepairRejectsSymlinkedBackupDirectory(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	if err := os.WriteFile(path, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan("analysis", "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n+new\n", root)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".ciradar-repair-backup")); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	if err := Apply(plan, root, plan.Confirmation, false); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("err=%v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "old\n" {
		t.Fatalf("repository file changed despite rejected backup path: content=%q err=%v", string(raw), err)
	}
}

func TestRepairBacksUpExistingEmptyFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "empty.txt")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan("analysis", "--- a/empty.txt\n+++ b/empty.txt\n@@ -0,0 +1 @@\n+content\n", root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(plan, root, plan.Confirmation, false); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(root, ".ciradar-repair-backup", plan.ID, "empty.txt")
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read empty-file backup: %v", err)
	}
	if len(backup) != 0 {
		t.Fatalf("backup=%q, want empty", string(backup))
	}
}

func TestRepairRejectsDuplicateCanonicalPath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	patch := "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n+one\n" +
		"--- a/dir/../a.txt\n+++ b/dir/../a.txt\n@@ -1 +1 @@\n-old\n+two\n"
	if _, err := BuildPlan("analysis", patch, root); err == nil || !strings.Contains(err.Error(), "duplicate path") {
		t.Fatalf("err=%v", err)
	}
	if _, err := RequiredFiles(patch); err == nil || !strings.Contains(err.Error(), "duplicate path") {
		t.Fatalf("required files err=%v", err)
	}
}

func TestRepairDoesNotOverwriteNewFileCreatedAfterPlanning(t *testing.T) {
	root := t.TempDir()
	patch := "--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+planned\n"
	plan, err := BuildPlan("analysis", patch, root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "new.txt")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := Apply(plan, root, plan.Confirmation, false); err == nil || !strings.Contains(err.Error(), "was created") {
		t.Fatalf("err=%v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) != 0 {
		t.Fatalf("new file was overwritten: body=%q err=%v", string(body), err)
	}
}

func TestRepairRollsBackEarlierFilesWhenLaterCommitFails(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("old\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	patch := "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n+new-a\n" +
		"--- a/b.txt\n+++ b/b.txt\n@@ -1 +1 @@\n-old\n+new-b\n"
	plan, err := BuildPlan("analysis", patch, root)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	sentinel := errors.New("injected rename failure")
	rename := func(oldPath, newPath string) error {
		calls++
		if calls == 4 {
			return sentinel
		}
		return os.Rename(oldPath, newPath)
	}
	err = applyChanges(plan, root, false, rename, os.Link)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
	for _, name := range []string{"a.txt", "b.txt"} {
		body, readErr := os.ReadFile(filepath.Join(root, name))
		if readErr != nil || string(body) != "old\n" {
			t.Fatalf("%s was not rolled back: body=%q err=%v", name, string(body), readErr)
		}
	}
}

func TestRepairRejectsFabricatedPlanID(t *testing.T) {
	plan := Plan{ID: "../../outside", Confirmation: "confirm"}
	if err := Apply(plan, t.TempDir(), "confirm", false); err == nil || !strings.Contains(err.Error(), "plan ID") {
		t.Fatalf("err=%v", err)
	}
}

func TestRepairNewFileCommitDoesNotReplaceRacingFile(t *testing.T) {
	root := t.TempDir()
	patch := "--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+planned\n"
	plan, err := BuildPlan("analysis", patch, root)
	if err != nil {
		t.Fatal(err)
	}
	racingBody := []byte("created concurrently\n")
	link := func(oldPath, newPath string) error {
		if err := os.WriteFile(newPath, racingBody, 0644); err != nil {
			return err
		}
		return os.Link(oldPath, newPath)
	}
	if err := applyChanges(plan, root, false, os.Rename, link); err == nil {
		t.Fatal("expected atomic no-replace failure")
	}
	body, err := os.ReadFile(filepath.Join(root, "new.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(racingBody) {
		t.Fatalf("racing file was overwritten: %q", string(body))
	}
}

func TestRepairRejectsMissingDiffHeaderPathWithoutPanicking(t *testing.T) {
	patch := "--- \n+++ b/a.txt\n@@ -0,0 +1 @@\n+x\n"
	if _, err := RequiredFiles(patch); err == nil || !strings.Contains(err.Error(), "no path") {
		t.Fatalf("err=%v", err)
	}
}

func TestRepairParsesRemovedLineThatLooksLikeFileHeader(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "flags.txt")
	if err := os.WriteFile(path, []byte("-- old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	patch := "--- a/flags.txt\n+++ b/flags.txt\n@@ -1 +1 @@\n--- old\n+++ new\n"
	plan, err := BuildPlan("analysis", patch, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(plan, root, plan.Confirmation, false); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "++ new\n" {
		t.Fatalf("body=%q err=%v", string(body), err)
	}
}

func TestRepairPreservesTrailingWhitespaceInPatch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "spaces.txt")
	if err := os.WriteFile(path, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	patch := "--- a/spaces.txt\n+++ b/spaces.txt\n@@ -1 +1 @@\n-old\n+   \n"
	plan, err := BuildPlan("analysis", patch, root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Files[0].NewContent != "   \n" {
		t.Fatalf("new content lost whitespace: %q", plan.Files[0].NewContent)
	}
}

func TestRepairRejectsOversizedAndOverflowingPatchMetadata(t *testing.T) {
	oversized := strings.Repeat("x", maxRepairPatchBytes+1)
	if _, err := RequiredFiles(oversized); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized err=%v", err)
	}
	overflow := "--- a/a.txt\n+++ b/a.txt\n@@ -999999999999999999999999 +1 @@\n-old\n+new\n"
	if _, err := RequiredFiles(overflow); err == nil || !strings.Contains(err.Error(), "invalid old start") {
		t.Fatalf("overflow err=%v", err)
	}
}

func FuzzParseUnifiedDiffDoesNotPanic(f *testing.F) {
	for _, seed := range []string{
		"",
		"--- ",
		"--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n+new\n",
		"--- a/flags.txt\n+++ b/flags.txt\n@@ -1 +1 @@\n--- old\n+++ new\n",
		"@@ -999999999999999999 +1 @@\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, patch string) {
		_, _ = RequiredFiles(patch)
	})
}
