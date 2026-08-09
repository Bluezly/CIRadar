package testselection

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
	"github.com/Bluezly/CIRadar/internal/version"
)

var jsImportPattern = regexp.MustCompile(`(?m)(?:import\s+(?:[^'\"]+?\s+from\s+)?|export\s+[^'\"]*?\s+from\s+|require\s*\(|import\s*\()\s*['\"]([^'\"]+)['\"]`)
var pyFromPattern = regexp.MustCompile(`(?m)^\s*from\s+([\.\w]+)\s+import\s+`)
var pyImportPattern = regexp.MustCompile(`(?m)^\s*import\s+([\w\.]+)`)

func BuildGraph(root, repository string) (model.ImpactGraph, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return model.ImpactGraph{}, err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return model.ImpactGraph{}, errors.New("repository root is not a directory")
	}
	files := []string{}
	languages := map[string]string{}
	byDir := map[string][]string{}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && ignoredDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		lang := sourceLanguage(path)
		if lang == "" {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = norm(rel)
		files = append(files, rel)
		languages[rel] = lang
		dir := norm(filepath.Dir(rel))
		byDir[dir] = append(byDir[dir], rel)
		return nil
	})
	if err != nil {
		return model.ImpactGraph{}, err
	}
	sort.Strings(files)
	moduleName := readGoModule(filepath.Join(root, "go.mod"))
	deps := map[string][]string{}
	tests := map[string]string{}
	fileSet := map[string]bool{}
	for _, file := range files {
		fileSet[file] = true
		if isTestFile(file) {
			tests[file] = languages[file]
		}
	}
	for _, file := range files {
		absolute := filepath.Join(root, filepath.FromSlash(file))
		imports := []string{}
		if isTestFile(file) {
			for _, sibling := range byDir[norm(filepath.Dir(file))] {
				if sibling != file && !isTestFile(sibling) {
					imports = append(imports, sibling)
				}
			}
		}
		switch languages[file] {
		case "go":
			imports = append(imports, goDependencies(absolute, moduleName, byDir)...)
		case "javascript", "typescript":
			imports = append(imports, scriptDependencies(absolute, file, fileSet)...)
		case "python":
			imports = append(imports, pythonDependencies(absolute, file, fileSet)...)
		}
		if len(imports) > 0 {
			deps[file] = uniqueSorted(imports)
		}
	}
	return model.ImpactGraph{Repository: strings.TrimSpace(repository), Root: filepath.ToSlash(root), LanguageFiles: languages, Dependencies: deps, TestFiles: tests, TestCoverage: map[string][]string{}, GeneratedAt: time.Now().UTC(), Generator: "ciradar-impact-index", GeneratorBuild: version.Version}, nil
}

func SaveGraph(ctx context.Context, store db.Backend, tenant string, graph model.ImpactGraph) error {
	graph.TenantID = strings.ToLower(strings.TrimSpace(tenant))
	graph.Repository = strings.TrimSpace(graph.Repository)
	if graph.Repository == "" {
		return errors.New("repository is required")
	}
	if graph.Dependencies == nil {
		graph.Dependencies = map[string][]string{}
	}
	if graph.TestCoverage == nil {
		graph.TestCoverage = map[string][]string{}
	}
	graph.GeneratedAt = time.Now().UTC()
	return store.PutObject(ctx, graph.TenantID, "test_impact_graph", strings.ToLower(graph.Repository), graph)
}

func LoadGraph(ctx context.Context, store db.Backend, tenant, repository string) (model.ImpactGraph, bool, error) {
	var graph model.ImpactGraph
	ok, err := store.GetObject(ctx, tenant, "test_impact_graph", strings.ToLower(strings.TrimSpace(repository)), &graph)
	return graph, ok, err
}

func MergeCoverage(ctx context.Context, store db.Backend, tenant string, input model.TestCoverageInput) (model.ImpactGraph, error) {
	graph, ok, err := LoadGraph(ctx, store, tenant, input.Repository)
	if err != nil {
		return model.ImpactGraph{}, err
	}
	if !ok {
		graph = model.ImpactGraph{TenantID: tenant, Repository: input.Repository, Dependencies: map[string][]string{}, TestFiles: map[string]string{}, LanguageFiles: map[string]string{}, TestCoverage: map[string][]string{}, Generator: "coverage-only"}
	}
	if graph.TestCoverage == nil {
		graph.TestCoverage = map[string][]string{}
	}
	for key, covered := range input.Coverage {
		key = normalizeTestIdentity(key)
		if key == "" {
			continue
		}
		normalized := normalize(covered)
		if len(normalized) > 0 {
			graph.TestCoverage[key] = uniqueSorted(append(graph.TestCoverage[key], normalized...))
		}
	}
	if err := SaveGraph(ctx, store, tenant, graph); err != nil {
		return model.ImpactGraph{}, err
	}
	return graph, nil
}

func ParseCoverageJSON(data []byte) (model.TestCoverageInput, error) {
	var input model.TestCoverageInput
	if err := json.Unmarshal(data, &input); err == nil && input.Repository != "" && len(input.Coverage) > 0 {
		return input, nil
	}
	var simple map[string][]string
	if err := json.Unmarshal(data, &simple); err != nil {
		return model.TestCoverageInput{}, err
	}
	return model.TestCoverageInput{Coverage: simple}, nil
}

func ignoredDirectory(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".idea", ".vscode", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv", "__pycache__", "coverage", ".next", ".terraform":
		return true
	default:
		return false
	}
}

func sourceLanguage(path string) string {
	lower := strings.ToLower(path)
	switch filepath.Ext(lower) {
	case ".go":
		return "go"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx", ".mts", ".cts":
		return "typescript"
	case ".py":
		return "python"
	default:
		return ""
	}
}

func isTestFile(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(lower)
	return strings.HasSuffix(base, "_test.go") || strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py") || strings.HasSuffix(base, "_test.py") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || strings.Contains(lower, "/tests/") || strings.Contains(lower, "/test/") || strings.Contains(lower, "/__tests__/")
}

func readGoModule(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func goDependencies(path, moduleName string, byDir map[string][]string) []string {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, item := range f.Imports {
		value, err := strconv.Unquote(item.Path.Value)
		if err != nil || moduleName == "" || value != moduleName && !strings.HasPrefix(value, moduleName+"/") {
			continue
		}
		dir := strings.TrimPrefix(value, moduleName)
		dir = strings.TrimPrefix(dir, "/")
		if dir == "" {
			dir = "."
		}
		for _, dep := range byDir[norm(dir)] {
			if !strings.HasSuffix(dep, "_test.go") {
				out = append(out, dep)
			}
		}
	}
	return out
}

func scriptDependencies(path, rel string, files map[string]bool) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, match := range jsImportPattern.FindAllSubmatch(data, -1) {
		if len(match) < 2 {
			continue
		}
		value := string(match[1])
		if !strings.HasPrefix(value, ".") {
			continue
		}
		base := norm(filepath.Join(filepath.Dir(rel), value))
		for _, candidate := range scriptCandidates(base) {
			if files[candidate] {
				out = append(out, candidate)
				break
			}
		}
	}
	return out
}

func scriptCandidates(base string) []string {
	extensions := []string{"", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"}
	out := make([]string, 0, len(extensions))
	for _, ext := range extensions {
		out = append(out, norm(base+ext))
	}
	return out
}

func pythonDependencies(path, rel string, files map[string]bool) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	modules := []string{}
	for _, match := range pyFromPattern.FindAllSubmatch(data, -1) {
		if len(match) > 1 {
			modules = append(modules, string(match[1]))
		}
	}
	for _, match := range pyImportPattern.FindAllSubmatch(data, -1) {
		if len(match) > 1 {
			modules = append(modules, string(match[1]))
		}
	}
	out := []string{}
	for _, module := range modules {
		leading := len(module) - len(strings.TrimLeft(module, "."))
		clean := strings.TrimLeft(module, ".")
		baseDir := filepath.Dir(rel)
		for i := 1; i < leading; i++ {
			baseDir = filepath.Dir(baseDir)
		}
		base := norm(filepath.Join(baseDir, strings.ReplaceAll(clean, ".", "/")))
		for _, candidate := range []string{base + ".py", base + "/__init__.py"} {
			if files[candidate] {
				out = append(out, candidate)
				break
			}
		}
	}
	return out
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = norm(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
