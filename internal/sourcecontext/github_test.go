package sourcecontext

import (
	"reflect"
	"testing"
)

func TestExtractSourcePathsFromCommonStackTraces(t *testing.T) {
	log := `/home/runner/work/ciradar/ciradar/internal/worker/worker.go:131:17
Traceback (most recent call last):
  File "/github/workspace/pkg/checks/parser.py", line 42, in parse
    raise ValueError()
Error at /workspace/web/src/index.ts:8:2`
	got := extractSourcePaths("acme/ciradar", log)
	want := []string{"internal/worker/worker.go", "pkg/checks/parser.py", "web/src/index.ts"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
}

func TestMergePathsPrioritizesStackTraceCandidates(t *testing.T) {
	got := mergePaths([]string{"src/root.go"}, []string{"changed.go", "src/root.go"})
	want := []string{"src/root.go", "changed.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
}
