package version

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceContainsNoLineComments(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			file, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if parseErr != nil {
				return parseErr
			}
			for _, group := range file.Comments {
				for _, item := range group.List {
					if strings.HasPrefix(item.Text, "//") {
						pos := fset.Position(item.Pos())
						t.Errorf("line comment at %s:%d", path, pos.Line)
					}
				}
			}
			return nil
		}
		if strings.HasSuffix(path, ".js") {
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			for index, line := range strings.Split(string(body), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "//") {
					t.Errorf("line comment at %s:%d", path, index+1)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
