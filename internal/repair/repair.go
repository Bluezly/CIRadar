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

const (
	maxRepairPatchBytes = 4 << 20
	maxRepairFiles      = 10
)

var (
	hunkHeader   = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)
	repairIDForm = regexp.MustCompile(`^repair_[0-9a-f]{24}$`)
)

func RequiredFiles(patch string) ([]string, error) {
	files, err := parseUnifiedDiff(patch)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(files))
	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		if file.NewPath == "/dev/null" || file.NewPath == "" {
			return nil, errors.New("file deletion is not supported")
		}
		path, err := canonicalRepairPath(file.NewPath)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[path]; exists {
			return nil, fmt.Errorf("repair patch contains duplicate path %s", path)
		}
		seen[path] = struct{}{}
		out = append(out, path)
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
	if len(files) == 0 || len(files) > maxRepairFiles {
		return Plan{}, errors.New("repair patch must change between one and ten files")
	}
	plan := Plan{AnalysisID: analysisID, Risk: "review_required", CreatedAt: time.Now().UTC()}
	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		if file.NewPath == "/dev/null" || file.NewPath == "" {
			return Plan{}, errors.New("file deletion is not supported by repair apply")
		}
		path, err := canonicalRepairPath(file.NewPath)
		if err != nil {
			return Plan{}, err
		}
		if _, exists := seen[path]; exists {
			return Plan{}, fmt.Errorf("repair patch contains duplicate path %s", path)
		}
		seen[path] = struct{}{}
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
	if len(files) == 0 || len(files) > maxRepairFiles {
		return Plan{}, errors.New("repair patch must change between one and ten files")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{AnalysisID: analysisID, Risk: "review_required", CreatedAt: time.Now().UTC()}
	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		path, err := canonicalRepairPath(file.NewPath)
		if err != nil {
			return Plan{}, err
		}
		if _, exists := seen[path]; exists {
			return Plan{}, fmt.Errorf("repair patch contains duplicate path %s", path)
		}
		seen[path] = struct{}{}
		file.NewPath = path
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
	if !repairIDForm.MatchString(strings.TrimSpace(plan.ID)) {
		return errors.New("invalid repair plan ID")
	}
	if !constantText(plan.Confirmation, strings.TrimSpace(confirmation)) {
		return errors.New("repair confirmation does not match")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	return applyChanges(plan, root, dryRun, os.Rename, os.Link)
}

type stagedRepairChange struct {
	change    FileChange
	target    string
	backup    string
	temp      string
	rollback  string
	committed bool
}

func applyChanges(plan Plan, root string, dryRun bool, rename, link func(string, string) error) error {
	if rename == nil {
		return errors.New("repair rename operation is unavailable")
	}
	if link == nil {
		return errors.New("repair link operation is unavailable")
	}
	for _, change := range plan.Files {
		if err := verifyRepairTarget(root, change); err != nil {
			return err
		}
	}
	if dryRun {
		return nil
	}

	staged := make([]stagedRepairChange, 0, len(plan.Files))
	cleanupStaged := func(removeBackups bool) {
		for i := range staged {
			if staged[i].temp != "" {
				_ = os.Remove(staged[i].temp)
			}
			if removeBackups && staged[i].backup != "" {
				_ = os.Remove(staged[i].backup)
			}
		}
	}
	for _, change := range plan.Files {
		target, err := safePath(root, change.Path)
		if err != nil {
			cleanupStaged(true)
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			cleanupStaged(true)
			return err
		}
		target, err = safePath(root, change.Path)
		if err != nil {
			cleanupStaged(true)
			return err
		}
		item := stagedRepairChange{change: change, target: target}
		mode := os.FileMode(0644)
		if !change.NewFile {
			info, err := os.Lstat(target)
			if err != nil {
				cleanupStaged(true)
				return err
			}
			mode = info.Mode().Perm()
			backupRelative := filepath.Join(".ciradar-repair-backup", plan.ID, filepath.FromSlash(change.Path))
			item.backup, err = safePath(root, backupRelative)
			if err != nil {
				cleanupStaged(true)
				return err
			}
			if err := os.MkdirAll(filepath.Dir(item.backup), 0700); err != nil {
				cleanupStaged(true)
				return err
			}
			item.backup, err = safePath(root, backupRelative)
			if err != nil {
				cleanupStaged(true)
				return err
			}
			if err := writeExclusiveSynced(item.backup, []byte(change.OldContent), 0600); err != nil {
				cleanupStaged(true)
				return fmt.Errorf("create repair backup %s: %w", filepath.ToSlash(item.backup), err)
			}
			item.rollback = filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".ciradar-old-"+plan.ID)
			if _, err := os.Lstat(item.rollback); err == nil {
				cleanupStaged(true)
				_ = os.Remove(item.backup)
				return fmt.Errorf("repair rollback path already exists: %s", filepath.ToSlash(item.rollback))
			} else if !errors.Is(err, os.ErrNotExist) {
				cleanupStaged(true)
				_ = os.Remove(item.backup)
				return err
			}
		}
		temp, err := os.CreateTemp(filepath.Dir(target), ".ciradar-repair-*")
		if err != nil {
			if item.backup != "" {
				_ = os.Remove(item.backup)
			}
			cleanupStaged(true)
			return err
		}
		item.temp = temp.Name()
		if _, err := temp.WriteString(change.NewContent); err != nil {
			_ = temp.Close()
			_ = os.Remove(item.temp)
			if item.backup != "" {
				_ = os.Remove(item.backup)
			}
			cleanupStaged(true)
			return err
		}
		if err := temp.Sync(); err != nil {
			_ = temp.Close()
			_ = os.Remove(item.temp)
			if item.backup != "" {
				_ = os.Remove(item.backup)
			}
			cleanupStaged(true)
			return err
		}
		if err := temp.Close(); err != nil {
			_ = os.Remove(item.temp)
			if item.backup != "" {
				_ = os.Remove(item.backup)
			}
			cleanupStaged(true)
			return err
		}
		if err := os.Chmod(item.temp, mode); err != nil {
			_ = os.Remove(item.temp)
			if item.backup != "" {
				_ = os.Remove(item.backup)
			}
			cleanupStaged(true)
			return err
		}
		staged = append(staged, item)
	}

	rollbackCommitted := func(last int) error {
		var rollbackErr error
		for i := last; i >= 0; i-- {
			item := &staged[i]
			if !item.committed {
				continue
			}
			if item.change.NewFile {
				if err := os.Remove(item.target); err != nil && !errors.Is(err, os.ErrNotExist) {
					rollbackErr = errors.Join(rollbackErr, err)
				}
			} else {
				if err := os.Remove(item.target); err != nil && !errors.Is(err, os.ErrNotExist) {
					rollbackErr = errors.Join(rollbackErr, err)
					continue
				}
				if err := rename(item.rollback, item.target); err != nil {
					rollbackErr = errors.Join(rollbackErr, err)
				}
			}
			item.committed = false
		}
		return rollbackErr
	}

	for i := range staged {
		item := &staged[i]
		if err := verifyRepairTarget(root, item.change); err != nil {
			rollbackErr := rollbackCommitted(i - 1)
			cleanupStaged(false)
			return errors.Join(err, rollbackErr)
		}
		if item.change.NewFile {
			if err := link(item.temp, item.target); err != nil {
				rollbackErr := rollbackCommitted(i - 1)
				cleanupStaged(false)
				return errors.Join(err, rollbackErr)
			}
			item.committed = true
			if err := os.Remove(item.temp); err != nil {
				removeTargetErr := os.Remove(item.target)
				item.committed = false
				rollbackErr := rollbackCommitted(i - 1)
				cleanupStaged(false)
				return errors.Join(fmt.Errorf("remove staged repair file: %w", err), removeTargetErr, rollbackErr)
			}
			item.temp = ""
			continue
		}
		if err := rename(item.target, item.rollback); err != nil {
			rollbackErr := rollbackCommitted(i - 1)
			cleanupStaged(false)
			return errors.Join(err, rollbackErr)
		}
		if err := rename(item.temp, item.target); err != nil {
			restoreErr := rename(item.rollback, item.target)
			rollbackErr := rollbackCommitted(i - 1)
			cleanupStaged(false)
			return errors.Join(err, restoreErr, rollbackErr)
		}
		item.temp = ""
		item.committed = true
	}

	for i := range staged {
		if staged[i].rollback != "" {
			if err := os.Remove(staged[i].rollback); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("repair applied, but temporary rollback cleanup failed: %w", err)
			}
		}
	}
	return nil
}

func verifyRepairTarget(root string, change FileChange) error {
	path, err := safePath(root, change.Path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if change.NewFile {
		if err == nil {
			return fmt.Errorf("new file %s was created after the repair plan was built", change.Path)
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", change.Path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", change.Path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if string(raw) != change.OldContent {
		return fmt.Errorf("%s changed after the repair plan was created", change.Path)
	}
	return nil
}

func writeExclusiveSynced(path string, body []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
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
	if len(raw) > maxRepairPatchBytes {
		return nil, fmt.Errorf("repair patch exceeds %d bytes", maxRepairPatchBytes)
	}
	scanner := bufio.NewScanner(strings.NewReader(normalizePatch(raw)))
	scanner.Buffer(make([]byte, 64<<10), maxRepairPatchBytes)
	files := []patchFile{}
	var current *patchFile
	var currentHunk *hunk
	for scanner.Scan() {
		line := scanner.Text()
		if currentHunk != nil && !hunkComplete(currentHunk) && isHunkLine(line) {
			if line != "\\ No newline at end of file" {
				currentHunk.Lines = append(currentHunk.Lines, line)
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "diff --git "):
			if currentHunk != nil && !hunkComplete(currentHunk) {
				return nil, errors.New("diff header appears before the current hunk is complete")
			}
			currentHunk = nil
		case strings.HasPrefix(line, "---"):
			if currentHunk != nil && !hunkComplete(currentHunk) {
				return nil, errors.New("file header appears before the current hunk is complete")
			}
			oldPath, err := parseDiffHeaderPath(line, "---")
			if err != nil {
				return nil, err
			}
			if !scanner.Scan() {
				return nil, errors.New("missing +++ file header")
			}
			next := scanner.Text()
			newPath, err := parseDiffHeaderPath(next, "+++")
			if err != nil {
				return nil, err
			}
			files = append(files, patchFile{OldPath: oldPath, NewPath: newPath})
			if len(files) > maxRepairFiles {
				return nil, fmt.Errorf("repair patch changes more than %d files", maxRepairFiles)
			}
			current = &files[len(files)-1]
			currentHunk = nil
		case strings.HasPrefix(line, "@@ "):
			if current == nil {
				return nil, errors.New("hunk appears before file header")
			}
			if currentHunk != nil && !hunkComplete(currentHunk) {
				return nil, errors.New("new hunk appears before the current hunk is complete")
			}
			match := hunkHeader.FindStringSubmatch(line)
			if match == nil {
				return nil, fmt.Errorf("invalid hunk header %q", line)
			}
			oldStart, err := parseHunkNumber("old start", match[1], false)
			if err != nil {
				return nil, err
			}
			oldCount, err := parseHunkCount(match[2])
			if err != nil {
				return nil, err
			}
			newStart, err := parseHunkNumber("new start", match[3], false)
			if err != nil {
				return nil, err
			}
			newCount, err := parseHunkCount(match[4])
			if err != nil {
				return nil, err
			}
			h := hunk{OldStart: oldStart, OldCount: oldCount, NewStart: newStart, NewCount: newCount}
			current.Hunks = append(current.Hunks, h)
			currentHunk = &current.Hunks[len(current.Hunks)-1]
		case currentHunk != nil && isHunkLine(line):
			return nil, fmt.Errorf("hunk contains more lines than its header declares: %q", line)
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
	if currentHunk != nil && !hunkComplete(currentHunk) {
		return nil, errors.New("patch ended before the current hunk was complete")
	}
	for _, file := range files {
		if len(file.Hunks) == 0 {
			return nil, fmt.Errorf("%s has no hunks", file.NewPath)
		}
	}
	return files, nil
}

func parseDiffHeaderPath(line, marker string) (string, error) {
	if !strings.HasPrefix(line, marker+" ") && !strings.HasPrefix(line, marker+"\t") {
		return "", fmt.Errorf("missing %s file header", marker)
	}
	remainder := strings.TrimSpace(strings.TrimPrefix(line, marker))
	fields := strings.Fields(remainder)
	if len(fields) == 0 {
		return "", fmt.Errorf("%s file header has no path", marker)
	}
	return cleanDiffPath(fields[0]), nil
}

func isHunkLine(line string) bool {
	return strings.HasPrefix(line, " ") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") || line == "\\ No newline at end of file"
}

func hunkComplete(value *hunk) bool {
	if value == nil {
		return true
	}
	oldSeen, newSeen := 0, 0
	for _, line := range value.Lines {
		if line == "" {
			continue
		}
		switch line[0] {
		case ' ':
			oldSeen++
			newSeen++
		case '-':
			oldSeen++
		case '+':
			newSeen++
		}
	}
	return oldSeen == value.OldCount && newSeen == value.NewCount
}

func parseHunkNumber(name, raw string, allowEmpty bool) (int, error) {
	if raw == "" {
		if allowEmpty {
			return 1, nil
		}
		return 0, fmt.Errorf("%s is missing", name)
	}
	value, err := strconv.ParseUint(raw, 10, 31)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", name, raw, err)
	}
	return int(value), nil
}

func parseHunkCount(raw string) (int, error) {
	return parseHunkNumber("hunk count", raw, true)
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
	clean, err := validateRepairPath(raw)
	if err != nil {
		return "", err
	}
	resolved := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("repair path escapes repository")
	}
	if err := rejectSymlinkComponents(root, clean); err != nil {
		return "", err
	}
	return resolved, nil
}

func validateRepairPath(raw string) (string, error) {
	raw = filepath.ToSlash(strings.TrimSpace(raw))
	if raw == "" || strings.HasPrefix(raw, "/") || strings.Contains(raw, "\x00") {
		return "", errors.New("unsafe repair path")
	}
	clean := filepath.Clean(filepath.FromSlash(raw))
	if clean == "." || clean == ".." || filepath.IsAbs(clean) || filepath.VolumeName(clean) != "" || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("repair path escapes repository")
	}
	lower := strings.ToLower(filepath.ToSlash(clean))
	for _, blocked := range []string{".git/", ".ssh/", ".env", "id_rsa", "id_ed25519", "private_key", "credentials"} {
		if lower == strings.TrimSuffix(blocked, "/") || strings.Contains(lower, blocked) {
			return "", fmt.Errorf("repair path %s is blocked", raw)
		}
	}
	return clean, nil
}

func canonicalRepairPath(raw string) (string, error) {
	clean, err := validateRepairPath(raw)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(clean), nil
}

func rejectSymlinkComponents(root, clean string) error {
	current := filepath.Clean(root)
	parts := strings.Split(clean, string(filepath.Separator))
	for index, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect repair path %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("repair path traverses symbolic link: %s", filepath.ToSlash(current))
		}
		if index < len(parts)-1 && !info.IsDir() {
			return fmt.Errorf("repair path component is not a directory: %s", filepath.ToSlash(current))
		}
	}
	return nil
}

func cleanDiffPath(raw string) string {
	if raw == "/dev/null" {
		return raw
	}
	if strings.HasPrefix(raw, "a/") {
		raw = strings.TrimPrefix(raw, "a/")
	} else if strings.HasPrefix(raw, "b/") {
		raw = strings.TrimPrefix(raw, "b/")
	}
	return filepath.ToSlash(filepath.Clean(raw))
}

func normalizePatch(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	return strings.TrimRight(raw, "\n") + "\n"
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
