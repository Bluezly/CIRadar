package repair

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Plan struct {
	ID           string       `json:"id"`
	AnalysisID   string       `json:"analysis_id"`
	Confirmation string       `json:"confirmation"`
	Files        []FileChange `json:"files"`
	ChangedLines int          `json:"changed_lines"`
	Risk         string       `json:"risk"`
	CreatedAt    time.Time    `json:"created_at"`
}

type FileChange struct {
	Path       string `json:"path"`
	OldContent string `json:"-"`
	NewContent string `json:"-"`
	Added      int    `json:"added"`
	Removed    int    `json:"removed"`
	NewFile    bool   `json:"new_file"`
}

type hunk struct {
	OldStart int
	OldCount int
	NewStart int
	NewCount int
	Lines    []string
}

type patchFile struct {
	OldPath string
	NewPath string
	Hunks   []hunk
}

var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

func RequiredFiles(patch string) ([]string, error) {
	files, err := parseUnifiedDiff(patch)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(files))
	for _, file := range files {
		if file.NewPath == "/dev/null" || file.NewPath == "" {
			return nil, errors.New("file deletion is not supported")
		}
		if _, err := safePath(string(filepath.Separator), file.NewPath); err != nil {
			return nil, err
		}
		out = append(out, file.NewPath)
	}
	return out, nil
}

func BuildPlanFromFiles(analysisID, patch string, contents map[string]string) (Plan, error) {
	analysisID = strings.TrimSpace(analysisID)
	if analysisID == "" {
		return Plan{}, errors.New("analysis ID is required")
	}
	files, err := parseUnifiedDiff(patch)
	if err != nil {
		return Plan{}, err
	}
	if len(files) == 0 || len(files) > 10 {
		return Plan{}, errors.New("repair patch must change between one and ten files")
	}
	plan := Plan{AnalysisID: analysisID, Risk: "review_required", CreatedAt: time.Now().UTC()}
	for _, file := range files {
		path := file.NewPath
		if path == "/dev/null" || path == "" {
			return Plan{}, errors.New("file deletion is not supported by repair apply")
		}
		if _, err := safePath(string(filepath.Separator), path); err != nil {
			return Plan{}, err
		}
		old, exists := contents[path]
		newFile := file.OldPath == "/dev/null"
		if !exists && !newFile {
			return Plan{}, fmt.Errorf("missing remote content for %s", path)
		}
		if exists && newFile {
			return Plan{}, fmt.Errorf("new file %s already exists", path)
		}
		updated, added, removed, err := applyHunks(old, file.Hunks)
		if err != nil {
			return Plan{}, fmt.Errorf("apply %s: %w", path, err)
		}
		plan.ChangedLines += added + removed
		plan.Files = append(plan.Files, FileChange{Path: path, OldContent: old, NewContent: updated, Added: added, Removed: removed, NewFile: newFile})
	}
	if plan.ChangedLines > 1000 {
		return Plan{}, errors.New("repair patch changes more than 1000 lines")
	}
	digest := sha256.Sum256([]byte(analysisID + "\x00" + normalizePatch(patch)))
	plan.ID = "repair_" + hex.EncodeToString(digest[:12])
	confirmation := sha256.Sum256([]byte(plan.ID + "\x00confirm"))
	plan.Confirmation = hex.EncodeToString(confirmation[:8])
	return plan, nil
}

func BuildPlan(analysisID, patch, root string) (Plan, error) {
	analysisID = strings.TrimSpace(analysisID)
	if analysisID == "" {
		return Plan{}, errors.New("analysis ID is required")
	}
	files, err := parseUnifiedDiff(patch)
	if err != nil {
		return Plan{}, err
	}
	if len(files) == 0 || len(files) > 10 {
		return Plan{}, errors.New("repair patch must change between one and ten files")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{AnalysisID: analysisID, Risk: "review_required", CreatedAt: time.Now().UTC()}
	for _, file := range files {
		change, err := prepareFile(root, file)
		if err != nil {
			return Plan{}, err
		}
		plan.ChangedLines += change.Added + change.Removed
		plan.Files = append(plan.Files, change)
	}
	if plan.ChangedLines > 1000 {
		return Plan{}, errors.New("repair patch changes more than 1000 lines")
	}
	digest := sha256.Sum256([]byte(analysisID + "\x00" + normalizePatch(patch)))
	plan.ID = "repair_" + hex.EncodeToString(digest[:12])
	confirmation := sha256.Sum256([]byte(plan.ID + "\x00confirm"))
	plan.Confirmation = hex.EncodeToString(confirmation[:8])
	return plan, nil
}

func Apply(plan Plan, root, confirmation string, dryRun bool) error {
	if !constantText(plan.Confirmation, strings.TrimSpace(confirmation)) {
		return errors.New("repair confirmation does not match")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	for _, change := range plan.Files {
		path, err := safePath(root, change.Path)
		if err != nil {
			return err
		}
		current := ""
		if raw, err := os.ReadFile(path); err == nil {
			current = string(raw)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if current != change.OldContent {
			return fmt.Errorf("%s changed after the repair plan was created", change.Path)
		}
	}
	if dryRun {
		return nil
	}
	backupRoot := filepath.Join(root, ".ciradar-repair-backup", plan.ID)
	for _, change := range plan.Files {
		path, _ := safePath(root, change.Path)
		if change.OldContent != "" {
			backupPath := filepath.Join(backupRoot, filepath.FromSlash(change.Path))
			if err := os.MkdirAll(filepath.Dir(backupPath), 0700); err != nil {
				return err
			}
			if err := os.WriteFile(backupPath, []byte(change.OldContent), 0600); err != nil {
				return err
			}
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		temp, err := os.CreateTemp(filepath.Dir(path), ".ciradar-repair-*")
		if err != nil {
			return err
		}
		tempName := temp.Name()
		if _, err := temp.WriteString(change.NewContent); err != nil {
			_ = temp.Close()
			_ = os.Remove(tempName)
			return err
		}
		if err := temp.Sync(); err != nil {
			_ = temp.Close()
			_ = os.Remove(tempName)
			return err
		}
		if err := temp.Close(); err != nil {
			_ = os.Remove(tempName)
			return err
		}
		mode := os.FileMode(0644)
		if info, err := os.Stat(path); err == nil {
			mode = info.Mode().Perm()
		}
		if err := os.Chmod(tempName, mode); err != nil {
			_ = os.Remove(tempName)
			return err
		}
		if err := os.Rename(tempName, path); err != nil {
			_ = os.Remove(tempName)
			return err
		}
	}
	return nil
}

func prepareFile(root string, file patchFile) (FileChange, error) {
	path := file.NewPath
	if path == "/dev/null" || path == "" {
		return FileChange{}, errors.New("file deletion is not supported by repair apply")
	}
	resolved, err := safePath(root, path)
	if err != nil {
		return FileChange{}, err
	}
	old := ""
	newFile := file.OldPath == "/dev/null"
	if !newFile {
		info, err := os.Lstat(resolved)
		if err != nil {
			return FileChange{}, fmt.Errorf("read %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return FileChange{}, fmt.Errorf("%s is not a regular file", path)
		}
		raw, err := os.ReadFile(resolved)
		if err != nil {
			return FileChange{}, err
		}
		if bytesContainZero(raw) {
			return FileChange{}, fmt.Errorf("%s is binary", path)
		}
		old = string(raw)
	} else if _, err := os.Lstat(resolved); err == nil {
		return FileChange{}, fmt.Errorf("new file %s already exists", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return FileChange{}, err
	}
	updated, added, removed, err := applyHunks(old, file.Hunks)
	if err != nil {
		return FileChange{}, fmt.Errorf("apply %s: %w", path, err)
	}
	return FileChange{Path: path, OldContent: old, NewContent: updated, Added: added, Removed: removed, NewFile: newFile}, nil
}

func parseUnifiedDiff(raw string) ([]patchFile, error) {
	scanner := bufio.NewScanner(strings.NewReader(normalizePatch(raw)))
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	files := []patchFile{}
	var current *patchFile
	var currentHunk *hunk
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "diff --git "):
			currentHunk = nil
		case strings.HasPrefix(line, "--- "):
			oldPath := cleanDiffPath(strings.Fields(strings.TrimPrefix(line, "--- "))[0])
			if !scanner.Scan() {
				return nil, errors.New("missing +++ file header")
			}
			next := scanner.Text()
			if !strings.HasPrefix(next, "+++ ") {
				return nil, errors.New("missing +++ file header")
			}
			newPath := cleanDiffPath(strings.Fields(strings.TrimPrefix(next, "+++ "))[0])
			files = append(files, patchFile{OldPath: oldPath, NewPath: newPath})
			current = &files[len(files)-1]
			currentHunk = nil
		case strings.HasPrefix(line, "@@ "):
			if current == nil {
				return nil, errors.New("hunk appears before file header")
			}
			match := hunkHeader.FindStringSubmatch(line)
			if match == nil {
				return nil, fmt.Errorf("invalid hunk header %q", line)
			}
			h := hunk{OldStart: parseNumber(match[1]), OldCount: countOrOne(match[2]), NewStart: parseNumber(match[3]), NewCount: countOrOne(match[4])}
			current.Hunks = append(current.Hunks, h)
			currentHunk = &current.Hunks[len(current.Hunks)-1]
		case currentHunk != nil && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") || line == "\\ No newline at end of file"):
			if line != "\\ No newline at end of file" {
				currentHunk.Lines = append(currentHunk.Lines, line)
			}
		case strings.TrimSpace(line) == "" || strings.HasPrefix(line, "index ") || strings.HasPrefix(line, "new file mode ") || strings.HasPrefix(line, "old mode ") || strings.HasPrefix(line, "new mode "):
		default:
			if currentHunk != nil {
				return nil, fmt.Errorf("unsupported patch line %q", line)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for _, file := range files {
		if len(file.Hunks) == 0 {
			return nil, fmt.Errorf("%s has no hunks", file.NewPath)
		}
	}
	return files, nil
}

func applyHunks(old string, hunks []hunk) (string, int, int, error) {
	oldLines, newline := splitLines(old)
	output := []string{}
	oldIndex := 0
	added, removed := 0, 0
	for _, h := range hunks {
		target := h.OldStart - 1
		if h.OldStart == 0 {
			target = 0
		}
		if target < oldIndex || target > len(oldLines) {
			return "", 0, 0, errors.New("hunk position is outside the file")
		}
		output = append(output, oldLines[oldIndex:target]...)
		cursor := target
		oldSeen, newSeen := 0, 0
		for _, line := range h.Lines {
			if line == "" {
				return "", 0, 0, errors.New("empty hunk line has no prefix")
			}
			text := line[1:]
			switch line[0] {
			case ' ':
				if cursor >= len(oldLines) || oldLines[cursor] != text {
					return "", 0, 0, fmt.Errorf("context mismatch at line %d", cursor+1)
				}
				output = append(output, text)
				cursor++
				oldSeen++
				newSeen++
			case '-':
				if cursor >= len(oldLines) || oldLines[cursor] != text {
					return "", 0, 0, fmt.Errorf("removal mismatch at line %d", cursor+1)
				}
				cursor++
				oldSeen++
				removed++
			case '+':
				output = append(output, text)
				newSeen++
				added++
			default:
				return "", 0, 0, errors.New("unsupported hunk prefix")
			}
		}
		if oldSeen != h.OldCount || newSeen != h.NewCount {
			return "", 0, 0, errors.New("hunk line counts do not match header")
		}
		oldIndex = cursor
	}
	output = append(output, oldLines[oldIndex:]...)
	result := strings.Join(output, "\n")
	if newline && (len(output) > 0 || old != "") {
		result += "\n"
	}
	return result, added, removed, nil
}

func safePath(root, raw string) (string, error) {
	raw = filepath.ToSlash(strings.TrimSpace(raw))
	if raw == "" || strings.HasPrefix(raw, "/") || strings.Contains(raw, "\x00") {
		return "", errors.New("unsafe repair path")
	}
	clean := filepath.Clean(filepath.FromSlash(raw))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("repair path escapes repository")
	}
	lower := strings.ToLower(filepath.ToSlash(clean))
	for _, blocked := range []string{".git/", ".ssh/", ".env", "id_rsa", "id_ed25519", "private_key", "credentials"} {
		if lower == strings.TrimSuffix(blocked, "/") || strings.Contains(lower, blocked) {
			return "", fmt.Errorf("repair path %s is blocked", raw)
		}
	}
	resolved := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("repair path escapes repository")
	}
	return resolved, nil
}

func cleanDiffPath(raw string) string {
	if raw == "/dev/null" {
		return raw
	}
	raw = strings.TrimPrefix(raw, "a/")
	raw = strings.TrimPrefix(raw, "b/")
	return filepath.ToSlash(filepath.Clean(raw))
}

func normalizePatch(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	return strings.TrimSpace(raw) + "\n"
}

func parseNumber(raw string) int {
	value, _ := strconv.Atoi(raw)
	return value
}

func countOrOne(raw string) int {
	if raw == "" {
		return 1
	}
	return parseNumber(raw)
}

func splitLines(value string) ([]string, bool) {
	newline := strings.HasSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\n")
	if value == "" {
		return []string{}, newline
	}
	return strings.Split(value, "\n"), newline
}

func bytesContainZero(value []byte) bool {
	for _, item := range value {
		if item == 0 {
			return true
		}
	}
	return false
}

func constantText(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var difference byte
	for index := range a {
		difference |= a[index] ^ b[index]
	}
	return difference == 0
}
