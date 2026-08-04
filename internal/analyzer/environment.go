package analyzer

import (
	"regexp"
	"sort"
	"strings"

	"ciradar/internal/model"
)

var (
	imageOSRe      = regexp.MustCompile(`(?im)^Image:\s*([^\r\n]+)`)
	imageVersionRe = regexp.MustCompile(`(?im)^Version:\s*([^\r\n]+)|^Image Version:\s*([^\r\n]+)`)
	archRe         = regexp.MustCompile(`(?im)^(?:Architecture|Runner Architecture):\s*([^\r\n]+)`)
	toolPatterns   = map[string]*regexp.Regexp{
		"go":        regexp.MustCompile(`(?im)\bgo version go([0-9][^\s]*)`),
		"node":      regexp.MustCompile(`(?im)^(?:node|Node\.js)\s*(?:version)?\s*[:=]?\s*v?([0-9]+\.[0-9]+\.[0-9]+)`),
		"python":    regexp.MustCompile(`(?im)^Python\s+([0-9]+\.[0-9]+\.[0-9]+)`),
		"pip":       regexp.MustCompile(`(?im)^pip\s+([0-9]+(?:\.[0-9]+)+)`),
		"docker":    regexp.MustCompile(`(?im)Docker version\s+([0-9]+(?:\.[0-9]+)+)`),
		"cargo":     regexp.MustCompile(`(?im)^cargo\s+([0-9]+(?:\.[0-9]+)+)`),
		"rustc":     regexp.MustCompile(`(?im)^rustc\s+([0-9]+(?:\.[0-9]+)+)`),
		"terraform": regexp.MustCompile(`(?im)Terraform v([0-9]+(?:\.[0-9]+)+)`),
		"java":      regexp.MustCompile(`(?im)(?:openjdk|java) version ["']?([0-9]+(?:\.[0-9._]+)*)`),
		"dotnet":    regexp.MustCompile(`(?im)^\.NET SDK:\s*Version:\s*([0-9]+(?:\.[0-9]+)+)|^([0-9]+\.[0-9]+\.[0-9]+)\s*$`),
	}
	actionRe    = regexp.MustCompile(`(?im)(?:uses:|Download action repository)\s*['"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[^\s'"]+)`)
	containerRe = regexp.MustCompile(`(?im)(?:docker pull|image:\s*)\s*([a-z0-9./_-]+(?::[A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64}))`)
)

func ExtractEnvironment(log string) model.Environment {
	log = timestampRe.ReplaceAllString(log, "")
	env := model.Environment{ToolVersions: map[string]string{}}
	if m := imageOSRe.FindStringSubmatch(log); len(m) > 1 {
		env.RunnerOS = strings.TrimSpace(m[1])
	}
	if m := imageVersionRe.FindStringSubmatch(log); len(m) > 1 {
		if strings.TrimSpace(m[1]) != "" {
			env.RunnerImage = strings.TrimSpace(m[1])
		} else if len(m) > 2 {
			env.RunnerImage = strings.TrimSpace(m[2])
		}
	}
	if m := archRe.FindStringSubmatch(log); len(m) > 1 {
		env.RunnerArch = strings.TrimSpace(m[1])
	}
	for name, pattern := range toolPatterns {
		if m := pattern.FindStringSubmatch(log); len(m) > 1 {
			for _, v := range m[1:] {
				if strings.TrimSpace(v) != "" {
					env.ToolVersions[name] = strings.TrimSpace(v)
					break
				}
			}
		}
	}
	for _, m := range actionRe.FindAllStringSubmatch(log, -1) {
		if len(m) > 1 {
			env.ActionVersions = appendUnique(env.ActionVersions, strings.TrimSpace(m[1]))
		}
	}
	for _, m := range containerRe.FindAllStringSubmatch(log, -1) {
		if len(m) > 1 {
			env.ContainerRefs = appendUnique(env.ContainerRefs, strings.TrimSpace(m[1]))
		}
	}
	sort.Strings(env.ActionVersions)
	sort.Strings(env.ContainerRefs)
	return env
}

func CompareEnvironment(previous, current model.Environment) []string {
	var changes []string
	if previous.RunnerOS != "" && current.RunnerOS != "" && previous.RunnerOS != current.RunnerOS {
		changes = append(changes, "runner OS: "+previous.RunnerOS+" -> "+current.RunnerOS)
	}
	if previous.RunnerImage != "" && current.RunnerImage != "" && previous.RunnerImage != current.RunnerImage {
		changes = append(changes, "runner image: "+previous.RunnerImage+" -> "+current.RunnerImage)
	}
	if previous.RunnerArch != "" && current.RunnerArch != "" && previous.RunnerArch != current.RunnerArch {
		changes = append(changes, "runner architecture: "+previous.RunnerArch+" -> "+current.RunnerArch)
	}
	for k, old := range previous.ToolVersions {
		if now, ok := current.ToolVersions[k]; ok && old != now {
			changes = append(changes, k+": "+old+" -> "+now)
		}
	}
	if len(previous.ActionVersions) > 0 && len(current.ActionVersions) > 0 && !equalStrings(previous.ActionVersions, current.ActionVersions) {
		changes = append(changes, "actions: "+strings.Join(previous.ActionVersions, ", ")+" -> "+strings.Join(current.ActionVersions, ", "))
	}
	if len(previous.ContainerRefs) > 0 && len(current.ContainerRefs) > 0 && !equalStrings(previous.ContainerRefs, current.ContainerRefs) {
		changes = append(changes, "containers: "+strings.Join(previous.ContainerRefs, ", ")+" -> "+strings.Join(current.ContainerRefs, ", "))
	}
	sort.Strings(changes)
	return changes
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func appendUnique(xs []string, x string) []string {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}
