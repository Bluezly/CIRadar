package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"ciradar/internal/analyzer"
	"ciradar/internal/config"
	"ciradar/internal/db"
	gh "ciradar/internal/github"
	"ciradar/internal/model"
	"ciradar/internal/providers"
	"ciradar/internal/server"
	"ciradar/internal/version"
	"ciradar/internal/worker"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "analyze":
		err = cmdAnalyze(os.Args[2:])
	case "baseline":
		err = cmdBaseline(os.Args[2:])
	case "incidents":
		err = cmdIncidents(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "simulate":
		err = cmdSimulate(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "rules":
		err = cmdRules(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Printf("CI Radar %s (%s, %s) %s/%s\n", version.Version, version.Commit, version.BuildDate, runtime.GOOS, runtime.GOARCH)
		return
	case "help", "--help", "-h":
		usage()
		return
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`CI Radar - CI failure intelligence for GitHub Actions

Usage:
  ciradar init [--config ciradar.json]
  ciradar analyze [--config ciradar.json] [--json] <log-file|->
  ciradar baseline [--config ciradar.json] --repo OWNER/REPO <successful-log>
  ciradar incidents [--config ciradar.json] [--json]
  ciradar status [--config ciradar.json] [--json]
  ciradar export [--config ciradar.json] --output report.json
  ciradar inspect <log-file|->
  ciradar simulate [--config ciradar.json] <log-file> [count]
  ciradar serve [--config ciradar.json]
  ciradar doctor [--config ciradar.json]
  ciradar rules
  ciradar version

Fast local test:
  ciradar init
  ciradar analyze samples/npm-econnreset.log
  ciradar serve
`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*path); err == nil {
		return fmt.Errorf("%s already exists", *path)
	}
	if err := config.SaveDefault(*path); err != nil {
		return err
	}
	fmt.Println("Created", *path)
	fmt.Println("Edit GitHub settings later; local analysis works immediately.")
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	a, err := buildAnalyzer(cfg)
	if err != nil {
		return err
	}
	var githubClient *gh.Client
	if cfg.GitHubConfigured() {
		githubClient, err = gh.New(cfg.GitHubAppID, cfg.GitHubPrivateKeyPath, cfg.GitHubAPIURL)
		if err != nil {
			return err
		}
	} else {
		log.Warn("GitHub App is not configured; webhook processing will be unavailable, local API remains active")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if cfg.ProviderPolling {
		poller := providers.NewPoller(store, log)
		go poller.Run(ctx, cfg.ProviderPollInterval)
	}
	if githubClient != nil {
		w := worker.New(cfg, store, a, githubClient, log)
		go w.Run(ctx)
	}
	go maintenanceLoop(ctx, store, cfg, log)
	srv := server.New(cfg, store, a, log)
	return srv.Run(ctx)
}

func cmdAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	jsonOut := fs.Bool("json", false, "print JSON")
	repo := fs.String("repo", "local/test", "repository name")
	workflow := fs.String("workflow", "local-analysis", "workflow name")
	job := fs.String("job", "local-job", "job name")
	previous := fs.Bool("previous-success", false, "mark that an earlier run succeeded")
	workflowChanged := fs.Bool("workflow-changed", false, "mark workflow files changed")
	dependencyChanged := fs.Bool("dependency-changed", false, "mark dependency files changed")
	changeInfo := fs.Bool("change-info", false, "confirm that workflow/dependency change information is known")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("provide a log file path or - for stdin")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	b, err := readInput(fs.Arg(0), cfg.MaxLogBytes)
	if err != nil {
		return err
	}
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	a, err := buildAnalyzer(cfg)
	if err != nil {
		return err
	}
	org := strings.SplitN(*repo, "/", 2)[0]
	in := model.AnalysisInput{Repository: *repo, Organization: org, Workflow: *workflow, Job: *job, PreviousSuccess: *previous, WorkflowChanged: *workflowChanged, DependencyChanged: *dependencyChanged, ChangeInfoAvailable: *changeInfo, Log: string(b), OccurredAt: time.Now().UTC()}
	initial := a.Analyze(in, analyzer.Context{})
	corr, _ := store.Correlation(context.Background(), initial.Fingerprint, time.Now().UTC().Add(-cfg.IncidentWindow))
	prev, _ := store.LastSuccessfulEnvironment(context.Background(), in.Repository, in.Workflow, in.Job)
	providerIncident := providerIncident(context.Background(), store, initial.Provider)
	result := a.Analyze(in, analyzer.Context{CrossRepoCount: corr.Repositories + 1, CrossOrgCount: corr.Organizations + 1, RecentOccurrences: corr.Occurrences + 1, ProviderIncident: providerIncident, PreviousEnvironment: prev})
	if err := store.RecordAnalysis(context.Background(), in, result, cfg.StoreRedactedExcerpts, cfg.StoreRawLogs); err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	printHuman(result)
	return nil
}

func cmdBaseline(args []string) error {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	repo := fs.String("repo", "", "repository OWNER/REPO")
	workflow := fs.String("workflow", "CI", "workflow name")
	job := fs.String("job", "test", "job name")
	sha := fs.String("sha", "manual-baseline", "commit SHA or label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || strings.TrimSpace(*repo) == "" {
		return errors.New("provide --repo OWNER/REPO and a successful log file")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	b, err := readInput(fs.Arg(0), cfg.MaxLogBytes)
	if err != nil {
		return err
	}
	env := analyzer.ExtractEnvironment(analyzer.NewRedactor().Redact(string(b)))
	if env.RunnerOS == "" && env.RunnerImage == "" && len(env.ToolVersions) == 0 && len(env.ActionVersions) == 0 && len(env.ContainerRefs) == 0 {
		return errors.New("no environment information could be extracted from the log")
	}
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.RecordSuccessfulEnvironment(context.Background(), *repo, *workflow, *job, *sha, env, time.Now().UTC()); err != nil {
		return err
	}
	fmt.Printf("Saved successful baseline for %s / %s / %s\n", *repo, *workflow, *job)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

func cmdIncidents(args []string) error {
	fs := flag.NewFlagSet("incidents", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	jsonOut := fs.Bool("json", false, "print JSON")
	stateFilter := fs.String("state", "", "filter by open or resolved")
	limit := fs.Int("limit", 100, "maximum incidents")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	items, err := store.ListIncidents(context.Background(), *limit, *stateFilter)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(items)
	}
	if len(items) == 0 {
		fmt.Println("No incidents found.")
		return nil
	}
	for _, item := range items {
		fmt.Printf("%-9s %-8s repos=%-4d orgs=%-3d occurrences=%-5d %s\n", item.State, item.Severity, item.RepositoryCount, item.OrganizationCount, item.OccurrenceCount, item.Title)
	}
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	jsonOut := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	stats, err := store.Stats(context.Background())
	if err != nil {
		return err
	}
	providerList, err := store.ListProviderStatuses(context.Background())
	if err != nil {
		return err
	}
	result := map[string]any{"version": version.Version, "github_configured": cfg.GitHubConfigured(), "stats": stats, "providers": providerList}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	fmt.Printf("CI Radar %s\n", version.Version)
	fmt.Printf("Analyses: %d | Repositories: %d | Incidents: %d open / %d total | Queued jobs: %d\n", stats.Analyses, stats.Repositories, stats.OpenIncidents, stats.Incidents, stats.QueuedJobs)
	fmt.Println("GitHub configured:", cfg.GitHubConfigured())
	for _, p := range providerList {
		fmt.Printf("Provider %-15s %-18s %s\n", p.Provider, p.Indicator, p.Description)
	}
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	output := fs.String("output", "ciradar-report.json", "output JSON file")
	limit := fs.Int("limit", 500, "maximum analyses")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	stats, err := store.Stats(context.Background())
	if err != nil {
		return err
	}
	incidents, err := store.ListIncidents(context.Background(), 500, "")
	if err != nil {
		return err
	}
	analyses, err := store.ListAnalyses(context.Background(), *limit)
	if err != nil {
		return err
	}
	providerList, err := store.ListProviderStatuses(context.Background())
	if err != nil {
		return err
	}
	report := map[string]any{"generated_at": time.Now().UTC(), "version": version.Version, "stats": stats, "providers": providerList, "incidents": incidents, "analyses": analyses}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Clean(*output), append(b, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Println("Exported", *output)
	return nil
}

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("provide a log file path or - for stdin")
	}
	b, err := readInput(fs.Arg(0), 32<<20)
	if err != nil {
		return err
	}
	r := analyzer.NewRedactor()
	redacted := r.Redact(string(b))
	env := analyzer.ExtractEnvironment(redacted)
	payload := map[string]any{"redacted_log": redacted, "environment": env, "raw_log_retained": false}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func cmdSimulate(args []string) error {
	fs := flag.NewFlagSet("simulate", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("provide a log file")
	}
	count := 5
	if fs.NArg() > 1 {
		fmt.Sscanf(fs.Arg(1), "%d", &count)
	}
	if count < 1 || count > 1000 {
		return errors.New("count must be between 1 and 1000")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	b, err := readInput(fs.Arg(0), cfg.MaxLogBytes)
	if err != nil {
		return err
	}
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	a, err := buildAnalyzer(cfg)
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		repo := fmt.Sprintf("simulation-org-%d/repo-%d", i%3, i)
		in := model.AnalysisInput{Repository: repo, Organization: strings.SplitN(repo, "/", 2)[0], Workflow: "ci", Job: "test", Log: string(b), OccurredAt: time.Now().UTC().Add(time.Duration(i) * time.Millisecond)}
		initial := a.Analyze(in, analyzer.Context{})
		corr, _ := store.Correlation(context.Background(), initial.Fingerprint, time.Now().UTC().Add(-cfg.IncidentWindow))
		r := a.Analyze(in, analyzer.Context{CrossRepoCount: corr.Repositories + 1, CrossOrgCount: corr.Organizations + 1, RecentOccurrences: corr.Occurrences + 1})
		if err := store.RecordAnalysis(context.Background(), in, r, cfg.StoreRedactedExcerpts, cfg.StoreRawLogs); err != nil {
			return err
		}
		if r.CrossRepoCount >= cfg.IncidentRepoThreshold || r.CrossOrgCount >= cfg.IncidentOrgThreshold {
			now := time.Now().UTC()
			_ = store.UpsertIncident(context.Background(), model.Incident{ID: "inc_" + r.Fingerprint, Fingerprint: r.Fingerprint, Provider: r.Provider, ErrorFamily: r.ErrorFamily, State: "open", Severity: "major", RepositoryCount: r.CrossRepoCount, OrganizationCount: r.CrossOrgCount, OccurrenceCount: r.CrossRepoCount, FirstSeenAt: now, LastSeenAt: now, Title: r.Provider + ": " + r.Summary})
		}
	}
	st, _ := store.Stats(context.Background())
	fmt.Printf("Inserted %d simulated failures. Analyses=%d incidents=%d open=%d\n", count, st.Analyses, st.Incidents, st.OpenIncidents)
	return nil
}

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	fmt.Println("CI Radar doctor")
	fmt.Println("  Version:", version.Version)
	fmt.Println("  OS/Arch:", runtime.GOOS+"/"+runtime.GOARCH)
	fmt.Println("  Config:", *path)
	fmt.Println("  Database:", cfg.DatabasePath)
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		fmt.Println("  Database check: FAILED -", err)
		return err
	}
	defer store.Close()
	fmt.Println("  Database check: OK")
	fmt.Println("  Raw log storage:", cfg.StoreRawLogs, "(recommended: false)")
	fmt.Println("  Cross-repository sharing:", cfg.CrossRepositorySharing)
	fmt.Println("  Automatic retry:", cfg.AutomaticRetryEnabled)
	extra, err := analyzer.LoadCustomRules(cfg.RulesDirectory)
	if err != nil {
		fmt.Println("  Custom rules: FAILED -", err)
		return err
	}
	fmt.Printf("  Rules: %d built-in + %d custom\n", len(analyzer.BuiltinRules()), len(extra))
	if cfg.GitHubConfigured() {
		fmt.Println("  GitHub App config: PRESENT")
		if _, err := gh.New(cfg.GitHubAppID, cfg.GitHubPrivateKeyPath, cfg.GitHubAPIURL); err != nil {
			fmt.Println("  GitHub key check: FAILED -", err)
			return err
		}
		fmt.Println("  GitHub key check: OK")
	} else {
		fmt.Println("  GitHub App config: NOT SET (local mode only)")
	}
	fmt.Println("Doctor completed.")
	return nil
}

func cmdRules(args []string) error {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	rules := analyzer.BuiltinRules()
	extra, err := analyzer.LoadCustomRules(cfg.RulesDirectory)
	if err != nil {
		return err
	}
	rules = append(rules, extra...)
	for _, r := range rules {
		fmt.Printf("%-28s %-22s %-20s %+d\n", r.ID, r.Category, r.Provider, r.Weight)
	}
	return nil
}

func buildAnalyzer(cfg config.Config) (*analyzer.Analyzer, error) {
	extra, err := analyzer.LoadCustomRules(cfg.RulesDirectory)
	if err != nil {
		return nil, fmt.Errorf("load custom rules: %w", err)
	}
	return analyzer.New(cfg.FingerprintHMACKey, extra...), nil
}

func printHuman(r model.AnalysisResult) {
	fmt.Println("\nCI Radar diagnosis")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Confidence : %s\nCategory   : %s\nProvider   : %s\nOperation  : %s\nScore      : %d/100\nFingerprint: %s\n\n", r.Confidence, r.Category, r.Provider, r.Operation, r.Score, r.Fingerprint)
	fmt.Println("Summary:")
	fmt.Println(" ", r.Summary)
	fmt.Println("\nEvidence:")
	if len(r.Evidence) == 0 {
		fmt.Println("  - Insufficient structured evidence")
	} else {
		for _, e := range r.Evidence {
			fmt.Printf("  - [%+d] %s\n", e.Weight, e.Description)
		}
	}
	if len(r.EnvironmentChanges) > 0 {
		fmt.Println("\nEnvironment changes:")
		for _, x := range r.EnvironmentChanges {
			fmt.Println("  -", x)
		}
	}
	fmt.Println("\nRecommendation:")
	fmt.Println(" ", r.Recommendation)
	fmt.Println()
}

func readInput(path string, max int64) ([]byte, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(filepath.Clean(path))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("input exceeds %d bytes", max)
	}
	return b, nil
}
func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}
func providerIncident(ctx context.Context, store *db.Store, provider string) bool {
	statuses, _ := store.ListProviderStatuses(ctx)
	for _, s := range statuses {
		if s.Incident && providers.MatchesStatusProvider(provider, s.Provider) {
			return true
		}
	}
	return false
}
func maintenanceLoop(ctx context.Context, store *db.Store, cfg config.Config, log *slog.Logger) {
	incidentTicker := time.NewTicker(time.Minute)
	cleanupTicker := time.NewTicker(12 * time.Hour)
	defer incidentTicker.Stop()
	defer cleanupTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-incidentTicker.C:
			resolved, err := store.ResolveStaleIncidents(ctx, time.Now().UTC().Add(-2*cfg.IncidentWindow))
			if err != nil {
				log.Warn("incident maintenance failed", "error", err)
			} else if resolved > 0 {
				log.Info("stale incidents resolved", "count", resolved)
			}
		case <-cleanupTicker.C:
			if err := store.Cleanup(ctx, cfg.RetentionDays); err != nil {
				log.Warn("cleanup failed", "error", err)
			}
		}
	}
}
