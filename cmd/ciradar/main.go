package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Bluezly/CIRadar/internal/analyzer"
	"github.com/Bluezly/CIRadar/internal/benchmark"
	"github.com/Bluezly/CIRadar/internal/config"
	"github.com/Bluezly/CIRadar/internal/db"
	gh "github.com/Bluezly/CIRadar/internal/github"
	"github.com/Bluezly/CIRadar/internal/insights"
	mcpserver "github.com/Bluezly/CIRadar/internal/mcp"
	"github.com/Bluezly/CIRadar/internal/model"
	"github.com/Bluezly/CIRadar/internal/notifications"
	"github.com/Bluezly/CIRadar/internal/providers"
	"github.com/Bluezly/CIRadar/internal/repair"
	"github.com/Bluezly/CIRadar/internal/secrets"
	"github.com/Bluezly/CIRadar/internal/server"
	"github.com/Bluezly/CIRadar/internal/similarity"
	"github.com/Bluezly/CIRadar/internal/testintelligence"
	"github.com/Bluezly/CIRadar/internal/testselection"
	"github.com/Bluezly/CIRadar/internal/version"
	"github.com/Bluezly/CIRadar/internal/worker"
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
	case "demo":
		err = cmdDemo(os.Args[2:])
	case "baseline":
		err = cmdBaseline(os.Args[2:])
	case "benchmark":
		err = cmdBenchmark(os.Args[2:])
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
	case "notify":
		err = cmdNotify(os.Args[2:])
	case "tenant":
		err = cmdTenant(os.Args[2:])
	case "apikey":
		err = cmdAPIKey(os.Args[2:])
	case "github-installation":
		err = cmdGitHubInstallation(os.Args[2:])
	case "repository":
		err = cmdRepository(os.Args[2:])
	case "incident":
		err = cmdIncidentAction(os.Args[2:])
	case "secret":
		err = cmdSecret(os.Args[2:])
	case "tests":
		err = cmdTests(os.Args[2:])
	case "mcp":
		err = cmdMCP(os.Args[2:])
	case "database":
		err = cmdDatabase(os.Args[2:])
	case "deployment":
		err = cmdDeployment(os.Args[2:])
	case "metrics":
		err = cmdMetrics(os.Args[2:])
	case "similar":
		err = cmdSimilar(os.Args[2:])
	case "repair":
		err = cmdRepair(os.Args[2:])
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
	fmt.Print(`CI Radar - multi-CI failure intelligence and test reliability

Usage:
  ciradar init [--config ciradar.json]
  ciradar analyze [--config ciradar.json] [--json] [--correlate] <log-file|->
  ciradar demo [--json] [--config ciradar.json] npm-econnreset|go-test-failure
  ciradar baseline [--config ciradar.json] --repo OWNER/REPO <successful-log>
  ciradar benchmark --dataset PATH [--config ciradar.json] [--json] [thresholds]
  ciradar incidents [--config ciradar.json] [--json]
  ciradar status [--config ciradar.json] [--json]
  ciradar export [--config ciradar.json] --output report.json
  ciradar inspect <log-file|->
  ciradar simulate [--config ciradar.json] <log-file> [count]
  ciradar serve [--config ciradar.json]
  ciradar doctor [--config ciradar.json]
  ciradar rules
  ciradar notify test [--config ciradar.json] [--channel NAME]
  ciradar notify list [--config ciradar.json]
  ciradar tenant create|list [options]
  ciradar apikey create|list|revoke [options]
  ciradar github-installation bind|unbind|list [options]
  ciradar repository set|list [options]
  ciradar incident acknowledge|resolve|reopen [options]
  ciradar secret key|encrypt [value]
  ciradar tests ingest|list|gate|select|index|coverage|quarantine|unquarantine|critical|noncritical [options]
  ciradar deployment record [options]
  ciradar metrics dora|usage [options]
  ciradar similar --analysis ID [options]
  ciradar repair plan|apply --analysis ID --repo-dir PATH [options]
  ciradar mcp [--config ciradar.json] [--tenant default]
  ciradar database check|migrate [--config ciradar.json]
  ciradar version

Fast local test:
  ciradar init
  ciradar demo npm-econnreset
  ciradar serve
`)
}

func cmdBenchmark(args []string) error {
	fs := flag.NewFlagSet("benchmark", flag.ContinueOnError)
	datasetPath := fs.String("dataset", "", "labeled benchmark dataset JSON")
	split := fs.String("split", "", "evaluate only train, dev, or test cases")
	configPath := fs.String("config", "", "optional CI Radar configuration for custom rules and redaction")
	jsonOutput := fs.Bool("json", false, "print the full benchmark report as JSON")
	output := fs.String("output", "", "write the JSON report to a file")
	minimumCases := fs.Int("min-cases", 0, "fail if the benchmark contains fewer labeled cases")
	minimumAccuracy := fs.Float64("min-category-accuracy", 0, "fail if category accuracy is below this 0..1 threshold")
	minimumMacroF1 := fs.Float64("min-macro-f1", 0, "fail if macro F1 is below this 0..1 threshold")
	minimumCoverage := fs.Float64("min-coverage", 0, "fail if non-UNKNOWN coverage is below this 0..1 threshold")
	maximumUnknown := fs.Float64("max-unknown-rate", 0, "fail if UNKNOWN rate exceeds this 0..1 threshold")
	if err := fs.Parse(args); err != nil {
		return err
	}
	maximumUnknownSet := false
	fs.Visit(func(value *flag.Flag) {
		if value.Name == "max-unknown-rate" {
			maximumUnknownSet = true
		}
	})
	if strings.TrimSpace(*datasetPath) == "" {
		return errors.New("--dataset is required")
	}
	if *minimumCases < 0 {
		return errors.New("--min-cases must be zero or greater")
	}
	for name, value := range map[string]float64{
		"--min-category-accuracy": *minimumAccuracy,
		"--min-macro-f1":          *minimumMacroF1,
		"--min-coverage":          *minimumCoverage,
		"--max-unknown-rate":      *maximumUnknown,
	} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
			return fmt.Errorf("%s must be a finite value between 0 and 1", name)
		}
	}

	dataset, err := benchmark.Load(*datasetPath)
	if err != nil {
		return err
	}
	dataset, err = benchmark.Select(dataset, *split)
	if err != nil {
		return err
	}
	var engine *analyzer.Analyzer
	if strings.TrimSpace(*configPath) == "" {
		engine = analyzer.New("ciradar-public-benchmark-v1")
	} else {
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		engine, err = buildAnalyzer(cfg)
		if err != nil {
			return err
		}
	}
	report := benchmark.Evaluate(engine, dataset)
	if strings.TrimSpace(*output) != "" {
		body, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		body = append(body, '\n')
		if err := os.WriteFile(filepath.Clean(*output), body, 0o600); err != nil {
			return err
		}
	}
	if *jsonOutput {
		if err := printJSON(report); err != nil {
			return err
		}
	} else {
		printBenchmarkReport(report)
	}
	return benchmark.CheckThresholds(report, benchmark.Thresholds{
		MinimumCases:              *minimumCases,
		MinimumCategoryAccuracy:   *minimumAccuracy,
		MinimumMacroF1:            *minimumMacroF1,
		MinimumCoverage:           *minimumCoverage,
		MaximumUnknownRate:        *maximumUnknown,
		MaximumUnknownRateEnabled: maximumUnknownSet,
	})
}

func printBenchmarkReport(report benchmark.Report) {
	fmt.Printf("CI Radar benchmark: %s", report.Dataset)
	if report.DatasetVersion != "" {
		fmt.Printf(" %s", report.DatasetVersion)
	}
	if report.Split != "" {
		fmt.Printf(" [%s]", report.Split)
	}
	fmt.Println()
	fmt.Printf("Cases              : %d\n", report.Cases)
	fmt.Printf("Dataset SHA-256    : %s\n", report.DatasetDigestSHA256)
	fmt.Printf("Analyzer SHA-256   : %s\n", report.AnalyzerDigestSHA256)
	fmt.Printf("Category accuracy  : %.2f%% (95%% CI %.2f%%..%.2f%%)\n", report.CategoryAccuracy*100, report.CategoryAccuracyCI95Low*100, report.CategoryAccuracyCI95High*100)
	fmt.Printf("Macro precision    : %.2f%%\n", report.MacroPrecision*100)
	fmt.Printf("Macro recall       : %.2f%%\n", report.MacroRecall*100)
	fmt.Printf("Macro F1           : %.2f%%\n", report.MacroF1*100)
	fmt.Printf("Coverage           : %.2f%% (95%% CI %.2f%%..%.2f%%)\n", report.Coverage*100, report.CoverageCI95Low*100, report.CoverageCI95High*100)
	fmt.Printf("UNKNOWN rate       : %.2f%%\n", report.UnknownRate*100)
	fmt.Printf("Covered accuracy   : %.2f%%\n", report.CoveredAccuracy*100)
	fmt.Printf("Rule match coverage: %.2f%% (%d cases)\n", report.RuleMatchCoverage*100, report.CasesWithMatchedRules)
	fmt.Printf("Rule utilization   : %.2f%% (%d/%d rules matched)\n", report.RuleUtilization*100, report.DistinctRulesMatched, report.RulesAvailable)
	if report.AttributionCases > 0 {
		fmt.Printf("Attribution accuracy: %.2f%% (%d labeled cases)\n", report.AttributionAccuracy*100, report.AttributionCases)
	}
	if report.ProviderCases > 0 {
		fmt.Printf("Provider accuracy  : %.2f%% (%d labeled cases)\n", report.ProviderAccuracy*100, report.ProviderCases)
	}
	if report.ErrorFamilyCases > 0 {
		fmt.Printf("Error-family accuracy: %.2f%% (%d labeled cases)\n", report.ErrorFamilyAccuracy*100, report.ErrorFamilyCases)
	}
	if len(report.ByCategory) > 0 {
		fmt.Println("\nPer-category precision / recall / F1:")
		for _, metric := range report.ByCategory {
			fmt.Printf("  %-24s p=%6.2f%% r=%6.2f%% f1=%6.2f%% n=%d\n", metric.Label, metric.Precision*100, metric.Recall*100, metric.F1*100, metric.Support)
		}
	}
	if len(report.Misclassified) > 0 {
		fmt.Printf("\nMisclassified or secondary-label mismatches: %d\n", len(report.Misclassified))
		limit := len(report.Misclassified)
		if limit > 20 {
			limit = 20
		}
		for _, failure := range report.Misclassified[:limit] {
			fmt.Printf("  %s: category %s -> %s", failure.ID, failure.ExpectedCategory, failure.PredictedCategory)
			if failure.ExpectedAttribution != "" && failure.ExpectedAttribution != failure.PredictedAttribution {
				fmt.Printf(", attribution %s -> %s", failure.ExpectedAttribution, failure.PredictedAttribution)
			}
			fmt.Println()
		}
		if len(report.Misclassified) > limit {
			fmt.Printf("  ... %d more; use --json or --output for the full list\n", len(report.Misclassified)-limit)
		}
	}
}

func cmdRepair(args []string) error {
	if len(args) < 1 || (args[0] != "plan" && args[0] != "apply") {
		return errors.New("usage: ciradar repair plan|apply --analysis ID --repo-dir PATH")
	}
	operation := args[0]
	fs := flag.NewFlagSet("repair "+operation, flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration")
	tenant := fs.String("tenant", "", "tenant")
	analysisID := fs.String("analysis", "", "analysis ID")
	repoDir := fs.String("repo-dir", ".", "repository working directory")
	patchFile := fs.String("patch", "", "unified diff file override")
	confirmation := fs.String("confirm", "", "repair confirmation token")
	dryRun := fs.Bool("dry-run", false, "validate without writing")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if strings.TrimSpace(*analysisID) == "" {
		return errors.New("--analysis is required")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	tid := chooseTenant(*tenant, cfg.DefaultTenantID)
	patch := ""
	if strings.TrimSpace(*patchFile) != "" {
		raw, err := os.ReadFile(*patchFile)
		if err != nil {
			return err
		}
		patch = string(raw)
	} else {
		var enhancement model.LLMEnhancement
		found, err := store.GetObject(context.Background(), tid, "llm_enhancement", *analysisID, &enhancement)
		if err != nil {
			return err
		}
		if !found || strings.TrimSpace(enhancement.Patch) == "" {
			return errors.New("analysis has no stored repair patch; run LLM enhancement or pass --patch")
		}
		patch = enhancement.Patch
	}
	plan, err := repair.BuildPlan(*analysisID, patch, *repoDir)
	if err != nil {
		return err
	}
	if operation == "plan" {
		return printJSON(plan)
	}
	if strings.TrimSpace(*confirmation) == "" {
		return fmt.Errorf("--confirm is required; run `ciradar repair plan` and use %s", plan.Confirmation)
	}
	if err := repair.Apply(plan, *repoDir, *confirmation, *dryRun); err != nil {
		return err
	}
	status := "applied"
	if *dryRun {
		status = "validated"
	}
	files := make([]string, 0, len(plan.Files))
	for _, file := range plan.Files {
		files = append(files, file.Path)
	}
	if err := store.RecordAudit(context.Background(), model.AuditEvent{TenantID: tid, Actor: "cli", Role: model.RoleOperator, Action: "repair." + status, Resource: "analysis", ResourceID: *analysisID, Metadata: map[string]string{"plan_id": plan.ID, "files": strings.Join(files, ",")}}); err != nil {
		return fmt.Errorf("repair %s, but recording its audit event failed: %w", status, err)
	}
	return printJSON(map[string]any{"status": status, "plan_id": plan.ID, "analysis_id": *analysisID, "files": files})
}

func cmdDeployment(args []string) error {
	if len(args) < 1 || args[0] != "record" {
		return errors.New("usage: ciradar deployment record --repo OWNER/REPO --environment production --sha COMMIT")
	}
	fs := flag.NewFlagSet("deployment record", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration")
	tenant := fs.String("tenant", "", "tenant")
	repo := fs.String("repo", "", "repository")
	env := fs.String("environment", "production", "environment")
	sha := fs.String("sha", "", "commit")
	status := fs.String("status", "success", "status")
	firstCommit := fs.String("first-commit-at", "", "RFC3339 first commit time")
	started := fs.String("started-at", "", "RFC3339 started time")
	completed := fs.String("completed-at", "", "RFC3339 completed time")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	cfg, e := config.Load(*path)
	if e != nil {
		return e
	}
	store, e := openBackend(context.Background(), cfg)
	if e != nil {
		return e
	}
	defer store.Close()
	if *repo == "" || *sha == "" {
		return errors.New("--repo and --sha are required")
	}
	now := time.Now().UTC()
	fc, err := parseOptionalRFC3339("first-commit-at", *firstCommit)
	if err != nil {
		return err
	}
	st, err := parseOptionalRFC3339("started-at", *started)
	if err != nil {
		return err
	}
	co, err := parseOptionalRFC3339("completed-at", *completed)
	if err != nil {
		return err
	}
	if co.IsZero() {
		co = now
	}
	if st.IsZero() {
		st = co
	}
	out, e := insights.RecordDeployment(context.Background(), store, model.DeploymentEvent{TenantID: chooseTenant(*tenant, cfg.DefaultTenantID), Repository: *repo, Environment: *env, CommitSHA: *sha, Status: *status, FirstCommitAt: fc, StartedAt: st, CompletedAt: co, CreatedAt: now, SourceProvider: "cli"})
	if e != nil {
		return e
	}
	return printJSON(out)
}
func cmdMetrics(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: ciradar metrics dora|usage")
	}
	fs := flag.NewFlagSet("metrics "+args[0], flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration")
	tenant := fs.String("tenant", "", "tenant")
	days := fs.Int("days", 30, "days")
	environment := fs.String("environment", "", "environment")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	cfg, e := config.Load(*path)
	if e != nil {
		return e
	}
	store, e := openBackend(context.Background(), cfg)
	if e != nil {
		return e
	}
	defer store.Close()
	until := time.Now().UTC()
	since := until.Add(-time.Duration(*days) * 24 * time.Hour)
	tid := chooseTenant(*tenant, cfg.DefaultTenantID)
	switch args[0] {
	case "dora":
		v, e := insights.DORA(context.Background(), store, tid, *environment, since, until)
		if e != nil {
			return e
		}
		return printJSON(v)
	case "usage":
		v, e := insights.Usage(context.Background(), store, tid, since, until)
		if e != nil {
			return e
		}
		return printJSON(v)
	default:
		return fmt.Errorf("unknown metrics command %q", args[0])
	}
}
func cmdSimilar(args []string) error {
	fs := flag.NewFlagSet("similar", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration")
	tenant := fs.String("tenant", "", "tenant")
	id := fs.String("analysis", "", "analysis id")
	limit := fs.Int("limit", 10, "limit")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if *id == "" {
		return errors.New("--analysis is required")
	}
	cfg, e := config.Load(*path)
	if e != nil {
		return e
	}
	store, e := openBackend(context.Background(), cfg)
	if e != nil {
		return e
	}
	defer store.Close()
	v, e := similarity.FindConfigured(context.Background(), store, chooseTenant(*tenant, cfg.DefaultTenantID), *id, *limit, cfg.Semantic, cfg.LLM)
	if e != nil {
		return e
	}
	return printJSON(v)
}
func parseOptionalRFC3339(name, value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("--%s must be RFC3339: %w", name, err)
	}
	return parsed, nil
}

func cmdDatabase(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: ciradar database check|migrate [--config ciradar.json]")
	}
	sub := strings.ToLower(strings.TrimSpace(args[0]))
	fs := flag.NewFlagSet("database "+sub, flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	jsonOut := fs.Bool("json", false, "print JSON health report")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := openBackend(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	stats, err := store.Stats(ctx)
	if err != nil {
		return err
	}
	switch sub {
	case "check", "migrate":
		result := map[string]any{"operation": sub, "driver": cfg.DatabaseDriver, "stats": stats}
		if postgres, ok := store.(*db.PostgresBackend); ok {
			health, healthErr := postgres.Health(ctx)
			if healthErr != nil {
				return healthErr
			}
			result["postgres"] = health
		}
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		}
		fmt.Printf("Database %s OK: driver=%s analyses=%d incidents=%d queued_jobs=%d\n", sub, cfg.DatabaseDriver, stats.Analyses, stats.Incidents, stats.QueuedJobs)
		if health, ok := result["postgres"].(db.PostgresHealthReport); ok {
			fmt.Printf("PostgreSQL %s schema=%d partitions=%d default_rows=%d pool=%d/%d database_bytes=%d telemetry_bytes=%d recovery=%t\n", health.ServerVersion, health.SchemaVersion, health.ObservationPartitions, health.DefaultPartitionRows, health.PoolOpenConnections, health.PoolMaximumConnections, health.DatabaseSizeBytes, health.ObservationTableBytes, health.InRecovery)
			for _, warning := range health.Warnings {
				fmt.Println("WARNING:", warning)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown database command %q", sub)
	}
}

func cmdSecret(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: ciradar secret key|encrypt [value]")
	}
	switch args[0] {
	case "key":
		k, err := secrets.GenerateMasterKey()
		if err != nil {
			return err
		}
		fmt.Println(k)
		return nil
	case "encrypt":
		fs := flag.NewFlagSet("secret encrypt", flag.ContinueOnError)
		key := fs.String("key", os.Getenv("CIRADAR_MASTER_KEY"), "32-byte base64url master key from 'ciradar secret key' (defaults to CIRADAR_MASTER_KEY)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var value string
		if fs.NArg() > 0 {
			value = strings.Join(fs.Args(), " ")
		} else {
			b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
			if err != nil {
				return err
			}
			value = strings.TrimRight(string(b), "\r\n")
		}
		enc, err := secrets.Encrypt(*key, value)
		if err != nil {
			return err
		}
		fmt.Println(enc)
		return nil
	default:
		return fmt.Errorf("unknown secret command %q", args[0])
	}
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
	fmt.Println("This file contains bootstrap secrets. It is created with owner-only permissions on POSIX systems; restrict its ACL on Windows.")
	fmt.Println("For production, move secrets to environment variables or an external secret manager. Local analysis works immediately.")
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
	if strings.TrimSpace(cfg.AdminToken) == "" && !cfg.AllowUnauthenticatedLocalhost {
		return errors.New("admin_token is empty; run `ciradar init` or set CIRADAR_ADMIN_TOKEN before serving")
	}
	log := newLogger(cfg.LogLevel)
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	skipStoreClose := false
	defer func() {
		if !skipStoreClose {
			_ = store.Close()
		}
	}()
	if tenant, err := store.GetTenant(context.Background(), cfg.DefaultTenantID); err != nil {
		return err
	} else if tenant == nil {
		name := "Tenant " + cfg.DefaultTenantID
		if _, err := store.CreateTenant(context.Background(), cfg.DefaultTenantID, name); err != nil {
			return err
		}
	}
	a, err := buildAnalyzer(cfg)
	if err != nil {
		return err
	}
	var githubClient *gh.Client
	if cfg.SSO.Enabled && cfg.SSO.Mode == "saml" {
		fmt.Println("  Native SAML profile:", cfg.SSO.SAMLSecurityProfile)
		fmt.Println("  Native SAML warning: xmlsec1 verifies signatures, but protocol parsing remains project-maintained and needs independent security review")
	}
	if cfg.GitHubConfigured() {
		githubClient, err = gh.New(cfg.GitHubAppID, cfg.GitHubPrivateKeyPath, cfg.GitHubAPIURL, cfg.GitHubAllowPrivateNetwork)
		if err != nil {
			return err
		}
	} else {
		log.Warn("GitHub App is not configured; webhook processing will be unavailable, local API remains active")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var background sync.WaitGroup
	if cfg.ProviderPolling {
		poller := providers.NewPoller(store, log)
		background.Add(1)
		go func() {
			defer background.Done()
			poller.Run(ctx, cfg.ProviderPollInterval)
		}()
	}
	notifier := notifications.New(cfg.Notifications, store, log)
	w := worker.New(cfg, store, a, githubClient, notifier, log)
	background.Add(1)
	go func() {
		defer background.Done()
		w.Run(ctx)
	}()
	background.Add(1)
	go func() {
		defer background.Done()
		maintenanceLoop(ctx, store, cfg, log)
	}()
	srv := server.New(cfg, store, a, log)
	runErr := srv.Run(ctx)
	cancel()
	backgroundDone := make(chan struct{})
	go func() {
		background.Wait()
		close(backgroundDone)
	}()
	select {
	case <-backgroundDone:
	case <-time.After(30 * time.Second):
		skipStoreClose = true
		shutdownErr := errors.New("background services did not stop within 30 seconds; storage was left open for process shutdown")
		if runErr != nil {
			return fmt.Errorf("server stopped: %v; %w", runErr, shutdownErr)
		}
		return shutdownErr
	}
	if closeErr := store.Close(); closeErr != nil {
		skipStoreClose = true
		if runErr != nil {
			return fmt.Errorf("server stopped: %v; close storage: %w", runErr, closeErr)
		}
		return fmt.Errorf("close storage: %w", closeErr)
	}
	skipStoreClose = true
	return runErr
}

func cmdAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	jsonOut := fs.Bool("json", false, "print JSON")
	correlate := fs.Bool("correlate", false, "include stored cross-run correlation in the score")
	repo := fs.String("repo", "local/test", "repository name")
	workflow := fs.String("workflow", "local-analysis", "workflow name")
	job := fs.String("job", "local-job", "job name")
	previous := fs.Bool("previous-success", false, "mark that an earlier run succeeded")
	workflowChanged := fs.Bool("workflow-changed", false, "mark workflow files changed")
	dependencyChanged := fs.Bool("dependency-changed", false, "mark dependency files changed")
	changeInfo := fs.Bool("change-info", false, "confirm that workflow/dependency change information is known")
	tenant := fs.String("tenant", "", "tenant id")
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
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	a, err := buildAnalyzer(cfg)
	if err != nil {
		return err
	}
	tenantID := chooseTenant(*tenant, cfg.DefaultTenantID)
	org := strings.SplitN(*repo, "/", 2)[0]
	in := model.AnalysisInput{TenantID: tenantID, Repository: *repo, Organization: org, Workflow: *workflow, Job: *job, PreviousSuccess: *previous, WorkflowChanged: *workflowChanged, DependencyChanged: *dependencyChanged, ChangeInfoAvailable: *changeInfo, Log: string(b), OccurredAt: time.Now().UTC()}
	initial := a.Analyze(in, analyzer.Context{})
	prev, err := store.LastSuccessfulEnvironmentForTenant(context.Background(), tenantID, in.Repository, in.Workflow, in.Job)
	if err != nil {
		return fmt.Errorf("load previous successful environment: %w", err)
	}
	providerDown, err := providerIncident(context.Background(), store, initial.Provider)
	if err != nil {
		return fmt.Errorf("load provider status: %w", err)
	}
	analysisContext := analyzer.Context{ProviderIncident: providerDown, PreviousEnvironment: prev}
	if *correlate {
		corr, corrErr := store.CorrelationForTenant(context.Background(), tenantID, initial.Fingerprint, in.Repository, in.Organization, time.Now().UTC().Add(-cfg.IncidentWindow), cfg.CrossTenantCorrelation)
		if corrErr != nil {
			return corrErr
		}
		analysisContext.CrossRepoCount = corr.Repositories
		analysisContext.CrossOrgCount = corr.Organizations
		analysisContext.RecentOccurrences = corr.Occurrences
	}
	result := a.Analyze(in, analysisContext)
	if err := store.RecordAnalysisForTenant(context.Background(), tenantID, in, result, cfg.StoreRedactedExcerpts, cfg.StoreRawLogs); err != nil {
		return err
	}
	if cfg.Notifications.Enabled {
		n := notifications.New(cfg.Notifications, store, newLogger(cfg.LogLevel))
		if err := n.Dispatch(context.Background(), notifications.AnalysisEvent(in, result, cfg.PublicBaseURL)); err != nil {
			fmt.Fprintln(os.Stderr, "Notification warning:", err)
		}
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	printHuman(result)
	return nil
}

func cmdDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	path := fs.String("config", "", "optional configuration file for custom rules and redaction")
	jsonOut := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ciradar demo [--json] [--config ciradar.json] npm-econnreset|go-test-failure")
	}
	samples := map[string]string{
		"npm-econnreset":  "npm ERR! code ECONNRESET\nnpm ERR! network request to https://registry.npmjs.org/react failed, reason: socket hang up\n",
		"go-test-failure": "--- FAIL: TestCalculateDiscount (0.00s)\n    discount_test.go:42: expected: 90, actual: 100\nFAIL\nFAIL\texample.com/shop\t0.013s\n",
	}
	logText, ok := samples[strings.ToLower(strings.TrimSpace(fs.Arg(0)))]
	if !ok {
		return fmt.Errorf("unknown demo %q; choose npm-econnreset or go-test-failure", fs.Arg(0))
	}
	tenantID := "demo"
	a := analyzer.New("ciradar-demo-v1")
	if strings.TrimSpace(*path) != "" {
		cfg, err := config.Load(*path)
		if err != nil {
			return err
		}
		a, err = buildAnalyzer(cfg)
		if err != nil {
			return err
		}
		tenantID = cfg.DefaultTenantID
	}
	in := model.AnalysisInput{TenantID: tenantID, Repository: "demo/local", Organization: "demo", Workflow: "demo", Job: "demo", Log: logText, OccurredAt: time.Now().UTC()}
	result := a.Analyze(in, analyzer.Context{})
	if *jsonOut {
		return printJSON(result)
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
	tenant := fs.String("tenant", "", "tenant id")
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
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.RecordSuccessfulEnvironmentForTenant(context.Background(), chooseTenant(*tenant, cfg.DefaultTenantID), *repo, *workflow, *job, *sha, env, time.Now().UTC()); err != nil {
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
	tenant := fs.String("tenant", "", "tenant id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	items, err := store.ListIncidentsForTenant(context.Background(), chooseTenant(*tenant, cfg.DefaultTenantID), *limit, *stateFilter)
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
	tenant := fs.String("tenant", "", "tenant id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	stats, err := store.StatsForTenant(context.Background(), chooseTenant(*tenant, cfg.DefaultTenantID))
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
	tenant := fs.String("tenant", "", "tenant id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	tenantID := chooseTenant(*tenant, cfg.DefaultTenantID)
	stats, err := store.StatsForTenant(context.Background(), tenantID)
	if err != nil {
		return err
	}
	incidents, err := store.ListIncidentsForTenant(context.Background(), tenantID, 500, "")
	if err != nil {
		return err
	}
	analyses, err := store.ListAnalysesForTenant(context.Background(), tenantID, *limit)
	if err != nil {
		return err
	}
	providerList, err := store.ListProviderStatuses(context.Background())
	if err != nil {
		return err
	}
	report := map[string]any{"generated_at": time.Now().UTC(), "version": version.Version, "tenant_id": tenantID, "stats": stats, "providers": providerList, "incidents": incidents, "analyses": analyses}
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
	tenant := fs.String("tenant", "", "tenant id")
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
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	a, err := buildAnalyzer(cfg)
	if err != nil {
		return err
	}
	tenantID := chooseTenant(*tenant, cfg.DefaultTenantID)
	for i := 0; i < count; i++ {
		repo := fmt.Sprintf("simulation-org-%d/repo-%d", i%3, i)
		in := model.AnalysisInput{TenantID: tenantID, Repository: repo, Organization: strings.SplitN(repo, "/", 2)[0], Workflow: "ci", Job: "test", Log: string(b), OccurredAt: time.Now().UTC().Add(time.Duration(i) * time.Millisecond)}
		initial := a.Analyze(in, analyzer.Context{})
		corr, err := store.CorrelationForTenant(context.Background(), tenantID, initial.Fingerprint, in.Repository, in.Organization, time.Now().UTC().Add(-cfg.IncidentWindow), cfg.CrossTenantCorrelation)
		if err != nil {
			return fmt.Errorf("correlate simulated failure %d: %w", i+1, err)
		}
		r := a.Analyze(in, analyzer.Context{CrossRepoCount: corr.Repositories, CrossOrgCount: corr.Organizations, RecentOccurrences: corr.Occurrences})
		if err := store.RecordAnalysisForTenant(context.Background(), tenantID, in, r, cfg.StoreRedactedExcerpts, cfg.StoreRawLogs); err != nil {
			return err
		}
		if r.CrossRepoCount >= cfg.IncidentRepoThreshold || r.CrossOrgCount >= cfg.IncidentOrgThreshold {
			now := time.Now().UTC()
			if err := store.UpsertIncidentForTenant(context.Background(), tenantID, model.Incident{ID: "inc_" + tenantID + "_" + r.Fingerprint, TenantID: tenantID, Fingerprint: r.Fingerprint, Provider: r.Provider, ErrorFamily: r.ErrorFamily, State: "open", Severity: "major", RepositoryCount: r.CrossRepoCount, OrganizationCount: r.CrossOrgCount, OccurrenceCount: corr.Occurrences, FirstSeenAt: now, LastSeenAt: now, Title: r.Provider + ": " + r.Summary}); err != nil {
				return fmt.Errorf("upsert simulated incident: %w", err)
			}
		}
	}
	st, err := store.StatsForTenant(context.Background(), tenantID)
	if err != nil {
		return fmt.Errorf("load simulation stats: %w", err)
	}
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
	if info, statErr := os.Stat(*path); statErr == nil && runtime.GOOS != "windows" {
		mode := info.Mode().Perm()
		fmt.Printf("  Config permissions: %04o\n", mode)
		if mode&0o077 != 0 {
			fmt.Println("  Config warning: bootstrap secrets are readable by group or other users; use chmod 600")
		}
	}
	if cfg.DatabaseDriver == "postgres" {
		fmt.Println("  Database: PostgreSQL")
		fmt.Println("  PostgreSQL driver warning: built-in pgwire remains custom; use independent security review before high-risk production")
	} else {
		fmt.Println("  Database:", cfg.DatabasePath)
	}
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		fmt.Println("  Database check: FAILED -", err)
		return err
	}
	defer store.Close()
	fmt.Println("  Database check: OK")
	fmt.Println("  Raw log storage:", cfg.StoreRawLogs, "(recommended: false)")
	if strings.TrimSpace(cfg.FingerprintHMACKey) == "" {
		fmt.Println("  Fingerprint HMAC key: MISSING (fingerprints use unsalted SHA-256)")
	} else {
		fmt.Println("  Fingerprint HMAC key: PRESENT")
	}
	fmt.Println("  Cross-repository correlation within tenant: enabled")
	fmt.Println("  Cross-tenant correlation:", cfg.CrossTenantCorrelation)
	fmt.Println("  Require GitHub installation binding:", cfg.RequireInstallationBinding)
	fmt.Println("  Local unauthenticated API:", cfg.AllowUnauthenticatedLocalhost)
	if strings.TrimSpace(cfg.AdminToken) == "" {
		fmt.Println("  Root admin token: MISSING")
	} else {
		fmt.Println("  Root admin token: PRESENT")
	}
	if cfg.DatabaseDriver != "postgres" {
		if info, err := os.Stat(cfg.DatabasePath); err == nil {
			fmt.Printf("  State file size: %.2f MiB\n", float64(info.Size())/(1024*1024))
			if info.Size() > 250<<20 {
				fmt.Println("  State warning: embedded storage is large; archive old data or migrate to PostgreSQL")
			}
		}
	}
	fmt.Println("  Automatic retry:", cfg.AutomaticRetryEnabled)
	fmt.Println("  Notifications enabled:", cfg.Notifications.Enabled)
	for _, ch := range cfg.Notifications.Channels {
		fmt.Printf("    - %s (%s): enabled=%v events=%d min_evidence=%d\n", ch.Name, ch.Type, ch.Enabled, len(ch.Events), ch.MinimumScore)
	}
	extra, err := analyzer.LoadCustomRules(cfg.RulesDirectory)
	if err != nil {
		fmt.Println("  Custom rules: FAILED -", err)
		return err
	}
	fmt.Printf("  Rules: %d built-in + %d custom\n", len(analyzer.BuiltinRules()), len(extra))
	if cfg.GitHubConfigured() {
		fmt.Println("  GitHub App config: PRESENT")
		if _, err := gh.New(cfg.GitHubAppID, cfg.GitHubPrivateKeyPath, cfg.GitHubAPIURL, cfg.GitHubAllowPrivateNetwork); err != nil {
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
	rulesDirectory := config.Default().RulesDirectory
	if _, err := os.Stat(*path); err == nil {
		cfg, loadErr := config.Load(*path)
		if loadErr != nil {
			return loadErr
		}
		rulesDirectory = cfg.RulesDirectory
	} else if !errors.Is(err, os.ErrNotExist) || *path != "ciradar.json" {
		return err
	}
	rules := analyzer.BuiltinRules()
	extra, err := analyzer.LoadCustomRules(rulesDirectory)
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
	return analyzer.NewConfigured(cfg.FingerprintHMACKey, cfg.RedactionPatterns, cfg.RedactionEntropyDetection, extra...), nil
}

func printHuman(r model.AnalysisResult) {
	fmt.Println("\nCI Radar diagnosis")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Attribution      : %s\nConfidence       : %s\nCategory         : %s\nProvider         : %s\nOperation        : %s\nEvidence strength: %d/100\nExternality score: %+d (-100 code, +100 external)\nEvidence split   : external %d, code %d\nFingerprint      : %s\n\n", r.Attribution, r.Confidence, r.Category, r.Provider, r.Operation, model.EvidenceStrengthOf(r), model.ExternalityScoreOf(r), model.ExternalEvidenceScoreOf(r), model.CodeEvidenceScoreOf(r), r.Fingerprint)
	if r.DecisionReason != "" {
		fmt.Println("Decision:", r.DecisionReason)
	}
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

func openBackend(ctx context.Context, cfg config.Config) (db.Backend, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.DatabaseDriver)) {
	case "", "embedded":
		return db.Open(cfg.DatabasePath)
	case "postgres":
		return db.OpenPostgres(ctx, cfg.DatabaseURL)
	default:
		return nil, fmt.Errorf("unsupported database driver %q", cfg.DatabaseDriver)
	}
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
func providerIncident(ctx context.Context, store db.Backend, provider string) (bool, error) {
	statuses, err := store.ListProviderStatuses(ctx)
	if err != nil {
		return false, err
	}
	for _, status := range statuses {
		if status.Incident && providers.MatchesStatusProvider(provider, status.Provider) {
			return true, nil
		}
	}
	return false, nil
}
func cmdNotify(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: ciradar notify test|list")
	}
	sub := args[0]
	fs := flag.NewFlagSet("notify "+sub, flag.ContinueOnError)
	configPath := fs.String("config", "ciradar.json", "configuration file path")
	channel := fs.String("channel", "", "send only to this channel")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	switch sub {
	case "test":
		if *channel != "" {
			found := false
			for i := range cfg.Notifications.Channels {
				cfg.Notifications.Channels[i].Enabled = cfg.Notifications.Channels[i].Name == *channel
				if cfg.Notifications.Channels[i].Enabled {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("notification channel %q not found", *channel)
			}
		}
		cfg.Notifications.Enabled = true
		n := notifications.New(cfg.Notifications, store, newLogger(cfg.LogLevel))
		ev := notifications.TestEvent()
		if err := n.Dispatch(context.Background(), ev); err != nil {
			return err
		}
		deliveries, err := store.ListNotificationDeliveriesForTenant(context.Background(), cfg.DefaultTenantID, 100)
		if err != nil {
			return err
		}
		sent := 0
		var failures []string
		for _, d := range deliveries {
			if d.EventID != ev.ID {
				continue
			}
			if d.Status == "sent" {
				sent++
			} else if d.Status == "failed" {
				failures = append(failures, d.Channel+": "+d.LastError)
			}
		}
		if sent == 0 {
			if len(failures) > 0 {
				return fmt.Errorf("notification test failed: %s", strings.Join(failures, "; "))
			}
			return errors.New("notification test did not match any enabled channel")
		}
		if len(failures) > 0 {
			return fmt.Errorf("sent to %d channel(s), but some failed: %s", sent, strings.Join(failures, "; "))
		}
		fmt.Printf("Notification test sent successfully to %d channel(s).\n", sent)
		return nil
	case "list":
		items, err := store.ListNotificationDeliveriesForTenant(context.Background(), cfg.DefaultTenantID, 100)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			fmt.Println("No notification deliveries found.")
			return nil
		}
		for _, d := range items {
			fmt.Printf("%-12s %-12s attempts=%d http=%d %s\n", d.Status, d.Channel, d.Attempts, d.HTTPStatus, d.LastError)
		}
		return nil
	default:
		return fmt.Errorf("unknown notify command %q", sub)
	}
}

type testGateResult struct {
	TotalTests            int      `json:"total_tests"`
	FailedTests           int      `json:"failed_tests"`
	QuarantinedFailures   []string `json:"quarantined_failures"`
	UnquarantinedFailures []string `json:"unquarantined_failures"`
}

func evaluateTestGate(observations []model.TestObservation, quarantines []model.TestQuarantine) testGateResult {
	now := time.Now().UTC()
	active := map[string]bool{}
	for _, q := range quarantines {
		if q.Active && q.ExpiresAt.After(now) {
			active[q.TestKey] = true
		}
	}
	r := testGateResult{TotalTests: len(observations)}
	for _, o := range observations {
		if o.Status != "failed" && o.Status != "error" {
			continue
		}
		r.FailedTests++
		label := strings.Trim(strings.Join([]string{o.Suite, o.ClassName, o.Name + o.Parameters}, "/"), "/")
		if active[db.TestKey(o)] {
			r.QuarantinedFailures = append(r.QuarantinedFailures, label)
		} else {
			r.UnquarantinedFailures = append(r.UnquarantinedFailures, label)
		}
	}
	return r
}

func cmdTests(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: ciradar tests ingest|list|gate|select|index|coverage|quarantine|unquarantine|critical|noncritical")
	}
	sub := args[0]
	fs := flag.NewFlagSet("tests "+sub, flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	tenant := fs.String("tenant", "", "tenant id")
	repo := fs.String("repo", "", "repository")
	workflow := fs.String("workflow", "", "workflow")
	job := fs.String("job", "", "job")
	framework := fs.String("framework", "", "test framework label")
	format := fs.String("format", "junit", "report format: junit, playwright, jest, pytest, cypress, mocha")
	runID := fs.Int64("run-id", 0, "run id")
	sha := fs.String("sha", "", "commit SHA")
	branch := fs.String("branch", "", "branch")
	pullRequestNumber := fs.Int("pr", 0, "pull request number")
	runURL := fs.String("run-url", "", "CI run URL")
	variant := fs.String("variant", "", "execution variant such as operating system or runtime")
	classification := fs.String("classification", "", "classification filter")
	key := fs.String("key", "", "test key")
	testSelector := fs.String("test", "", "readable test identity")
	owner := fs.String("owner", "", "test owner")
	reason := fs.String("reason", "", "quarantine reason")
	duration := fs.Duration("duration", 7*24*time.Hour, "quarantine duration")
	limit := fs.Int("limit", 200, "result limit")
	changed := fs.String("changed", "", "comma-separated changed files")
	root := fs.String("root", ".", "repository source root")
	minimumScore := fs.Float64("minimum-score", 0, "minimum test selection score")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	tenantID := chooseTenant(*tenant, cfg.DefaultTenantID)
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	switch sub {
	case "ingest":
		if fs.NArg() < 1 || strings.TrimSpace(*repo) == "" {
			return errors.New("usage: ciradar tests ingest --repo OWNER/REPO <junit.xml|->")
		}
		b, err := readInput(fs.Arg(0), 128<<20)
		if err != nil {
			return err
		}
		obs, err := testintelligence.ParseReport(*format, strings.NewReader(string(b)), testintelligence.Metadata{TenantID: tenantID, Repository: *repo, Workflow: *workflow, Job: *job, RunID: *runID, CommitSHA: *sha, Branch: *branch, PullRequestNumber: *pullRequestNumber, RunURL: *runURL, Variant: *variant, Framework: firstNonEmptyCLI(*framework, *format), OccurredAt: time.Now().UTC()})
		if err != nil {
			return err
		}
		stats, err := store.RecordTestObservations(context.Background(), tenantID, obs)
		if err != nil {
			return err
		}
		enrichTestStats(stats)
		fmt.Printf("Ingested %d test observations; %d test cases updated.\n", len(obs), len(stats))
		return printJSON(stats)
	case "list":
		items, err := store.ListTestCaseStats(context.Background(), tenantID, *repo, *classification, *limit)
		if err != nil {
			return err
		}
		enrichTestStats(items)
		return printJSON(items)
	case "gate":
		if fs.NArg() < 1 || strings.TrimSpace(*repo) == "" {
			return errors.New("usage: ciradar tests gate --repo OWNER/REPO <junit.xml|->")
		}
		b, err := readInput(fs.Arg(0), 128<<20)
		if err != nil {
			return err
		}
		obs, err := testintelligence.ParseReport(*format, strings.NewReader(string(b)), testintelligence.Metadata{TenantID: tenantID, Repository: *repo, Workflow: *workflow, Job: *job, RunID: *runID, CommitSHA: *sha, Branch: *branch, PullRequestNumber: *pullRequestNumber, RunURL: *runURL, Variant: *variant, Framework: firstNonEmptyCLI(*framework, *format), OccurredAt: time.Now().UTC()})
		if err != nil {
			return err
		}
		quarantines, err := store.ListTestQuarantines(context.Background(), tenantID)
		if err != nil {
			return err
		}
		result := evaluateTestGate(obs, quarantines)
		if err := printJSON(result); err != nil {
			return err
		}
		if len(result.UnquarantinedFailures) > 0 {
			return fmt.Errorf("test gate failed: %d unquarantined failure(s)", len(result.UnquarantinedFailures))
		}
		fmt.Printf("Test gate passed: %d quarantined failure(s), no blocking failures.\n", len(result.QuarantinedFailures))
		return nil
	case "select":
		if strings.TrimSpace(*repo) == "" {
			return errors.New("--repo is required")
		}
		files := []string{}
		for _, x := range strings.Split(*changed, ",") {
			if strings.TrimSpace(x) != "" {
				files = append(files, strings.TrimSpace(x))
			}
		}
		out, err := testselection.Select(context.Background(), store, tenantID, model.TestSelectionRequest{Repository: *repo, ChangedFiles: files, Framework: *framework, Limit: *limit, IncludeFlaky: cfg.PredictiveTests.AlwaysRunFlaky, MinimumScore: firstPositiveFloat(*minimumScore, cfg.PredictiveTests.MinimumScore)})
		if err != nil {
			return err
		}
		return printJSON(out)
	case "index":
		if strings.TrimSpace(*repo) == "" {
			return errors.New("--repo is required")
		}
		graph, err := testselection.BuildGraph(*root, *repo)
		if err != nil {
			return err
		}
		if err := testselection.SaveGraph(context.Background(), store, tenantID, graph); err != nil {
			return err
		}
		fmt.Printf("Indexed %d source files, %d dependency roots, and %d test files.\n", len(graph.LanguageFiles), len(graph.Dependencies), len(graph.TestFiles))
		return printJSON(graph)
	case "coverage":
		if strings.TrimSpace(*repo) == "" || fs.NArg() < 1 {
			return errors.New("usage: ciradar tests coverage --repo OWNER/REPO <coverage-map.json>")
		}
		b, err := readInput(fs.Arg(0), 128<<20)
		if err != nil {
			return err
		}
		input, err := testselection.ParseCoverageJSON(b)
		if err != nil {
			return err
		}
		input.Repository = *repo
		graph, err := testselection.MergeCoverage(context.Background(), store, tenantID, input)
		if err != nil {
			return err
		}
		fmt.Printf("Stored coverage links for %d test identities.\n", len(graph.TestCoverage))
		return printJSON(graph)
	case "quarantine":
		resolvedKey, err := resolveTestKey(context.Background(), store, tenantID, *repo, *key, *testSelector)
		if err != nil {
			return err
		}
		if *owner == "" || *reason == "" {
			return errors.New("--owner and --reason are required")
		}
		q, err := store.SetTestQuarantine(context.Background(), model.TestQuarantine{TenantID: tenantID, TestKey: resolvedKey, Owner: *owner, Reason: *reason, CreatedBy: "cli", ExpiresAt: time.Now().UTC().Add(*duration)})
		if err != nil {
			return err
		}
		return printJSON(q)
	case "unquarantine":
		resolvedKey, err := resolveTestKey(context.Background(), store, tenantID, *repo, *key, *testSelector)
		if err != nil {
			return err
		}
		return store.RemoveTestQuarantine(context.Background(), tenantID, resolvedKey)
	case "critical", "noncritical":
		resolvedKey, err := resolveTestKey(context.Background(), store, tenantID, *repo, *key, *testSelector)
		if err != nil {
			return err
		}
		stats, err := store.SetTestCritical(context.Background(), tenantID, resolvedKey, sub == "critical")
		if err != nil {
			return err
		}
		if stats == nil {
			return errors.New("test case not found")
		}
		stats.DisplayName = testselection.DisplayName(*stats)
		stats.Aliases = testselection.TestAliases(*stats)
		return printJSON(stats)
	default:
		return fmt.Errorf("unknown tests command %q", sub)
	}
}

func enrichTestStats(items []model.TestCaseStats) {
	for i := range items {
		items[i].DisplayName = testselection.DisplayName(items[i])
		items[i].Aliases = testselection.TestAliases(items[i])
	}
}

func resolveTestKey(ctx context.Context, store db.Backend, tenantID, repository, key, selector string) (string, error) {
	key = strings.TrimSpace(key)
	selector = strings.TrimSpace(selector)
	if key != "" && selector != "" {
		return "", errors.New("use either --key or --test, not both")
	}
	if key != "" {
		return key, nil
	}
	if selector == "" {
		return "", errors.New("--key or --test is required")
	}
	if strings.TrimSpace(repository) == "" {
		return "", errors.New("--repo is required when using --test")
	}
	items, err := store.ListTestCaseStats(ctx, tenantID, repository, "", 5000)
	if err != nil {
		return "", err
	}
	match, err := testselection.ResolveTest(items, selector)
	if err != nil {
		return "", err
	}
	return match.TestKey, nil
}

func firstPositiveFloat(a, b float64) float64 {
	if a > 0 {
		return a
	}
	return b
}

func firstNonEmptyCLI(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func cmdMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	tenant := fs.String("tenant", "", "tenant id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	srv := &mcpserver.Server{Store: store, Semantic: cfg.Semantic, LLM: cfg.LLM}
	tenantID := chooseTenant(*tenant, cfg.DefaultTenantID)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	enc := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req mcpserver.Request
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&req); err != nil {
			if encodeErr := enc.Encode(mcpserver.Response{JSONRPC: "2.0", Error: &mcpserver.RPCError{Code: -32700, Message: "parse error"}}); encodeErr != nil {
				return encodeErr
			}
			continue
		}
		if err := enc.Encode(srv.Handle(context.Background(), tenantID, req)); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func chooseTenant(v, fallback string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		v = strings.ToLower(strings.TrimSpace(fallback))
	}
	if v == "" {
		return model.DefaultTenantID
	}
	return v
}

func cmdTenant(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: ciradar tenant create|list|enable|disable")
	}
	sub := args[0]
	fs := flag.NewFlagSet("tenant "+sub, flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	id := fs.String("id", "", "tenant id")
	name := fs.String("name", "", "tenant name")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	switch sub {
	case "create":
		t, err := store.CreateTenant(context.Background(), *id, *name)
		if err != nil {
			return err
		}
		return printJSON(t)
	case "list":
		items, err := store.ListTenants(context.Background())
		if err != nil {
			return err
		}
		return printJSON(items)
	case "enable", "disable":
		if strings.TrimSpace(*id) == "" {
			return errors.New("--id is required")
		}
		return store.SetTenantEnabled(context.Background(), *id, sub == "enable")
	default:
		return fmt.Errorf("unknown tenant command %q", sub)
	}
}
func cmdAPIKey(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: ciradar apikey create|list|revoke")
	}
	sub := args[0]
	fs := flag.NewFlagSet("apikey "+sub, flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	tenant := fs.String("tenant", "", "tenant id")
	name := fs.String("name", "", "key name")
	role := fs.String("role", "viewer", "viewer, operator, or admin")
	id := fs.String("id", "", "api key id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	tenantID := chooseTenant(*tenant, cfg.DefaultTenantID)
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	switch sub {
	case "create":
		key, token, err := store.CreateAPIKey(context.Background(), tenantID, *name, model.Role(strings.ToLower(*role)))
		if err != nil {
			return err
		}
		fmt.Println("API key created. This token is shown once:")
		fmt.Println(token)
		return printJSON(key)
	case "list":
		items, err := store.ListAPIKeys(context.Background(), tenantID)
		if err != nil {
			return err
		}
		return printJSON(items)
	case "revoke":
		if *id == "" {
			return errors.New("--id is required")
		}
		return store.RevokeAPIKey(context.Background(), tenantID, *id)
	default:
		return fmt.Errorf("unknown apikey command %q", sub)
	}
}
func cmdGitHubInstallation(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: ciradar github-installation bind|unbind|list")
	}
	sub := args[0]
	fs := flag.NewFlagSet("github-installation "+sub, flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	tenant := fs.String("tenant", "", "tenant id")
	id := fs.Int64("id", 0, "GitHub installation id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	switch sub {
	case "bind":
		if *id < 1 {
			return errors.New("--id is required")
		}
		return store.BindInstallation(context.Background(), chooseTenant(*tenant, cfg.DefaultTenantID), *id)
	case "unbind":
		if *id < 1 {
			return errors.New("--id is required")
		}
		return store.UnbindInstallation(context.Background(), *id)
	case "list":
		return printJSON(store.ListInstallationBindings(context.Background()))
	default:
		return fmt.Errorf("unknown github-installation command %q", sub)
	}
}
func cmdRepository(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: ciradar repository set|list")
	}
	sub := args[0]
	fs := flag.NewFlagSet("repository "+sub, flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	tenant := fs.String("tenant", "", "tenant id")
	repo := fs.String("repo", "", "repository in owner/name form")
	team := fs.String("team", "", "team name")
	owner := fs.String("owner", "", "responsible owner")
	criticality := fs.String("criticality", "normal", "low, normal, high, or critical")
	channels := fs.String("channels", "", "comma-separated notification channel names")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	tenantID := chooseTenant(*tenant, cfg.DefaultTenantID)
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	switch sub {
	case "list":
		items, err := store.ListRepositoryProfiles(context.Background(), tenantID)
		if err != nil {
			return err
		}
		return printJSON(items)
	case "set":
		if strings.TrimSpace(*repo) == "" {
			return errors.New("--repo is required")
		}
		channelList := splitCSV(*channels)
		known := map[string]struct{}{}
		for _, channel := range cfg.Notifications.Channels {
			known[strings.ToLower(channel.Name)] = struct{}{}
		}
		for _, channel := range channelList {
			if _, ok := known[strings.ToLower(channel)]; !ok {
				return fmt.Errorf("notification channel %q is not configured", channel)
			}
		}
		profile, err := store.UpsertRepositoryProfile(context.Background(), model.RepositoryProfile{TenantID: tenantID, Repository: *repo, Team: *team, Owner: *owner, Criticality: *criticality, NotificationChannels: channelList})
		if err != nil {
			return err
		}
		return printJSON(profile)
	default:
		return fmt.Errorf("unknown repository command %q", sub)
	}
}

func cmdIncidentAction(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: ciradar incident acknowledge|resolve|reopen")
	}
	sub := strings.ToLower(args[0])
	fs := flag.NewFlagSet("incident "+sub, flag.ContinueOnError)
	path := fs.String("config", "ciradar.json", "configuration file path")
	tenant := fs.String("tenant", "", "tenant id")
	fingerprint := fs.String("fingerprint", "", "incident fingerprint")
	actor := fs.String("actor", "cli", "actor name")
	note := fs.String("note", "", "resolution or acknowledgement note")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	state := ""
	switch sub {
	case "acknowledge":
		state = "acknowledged"
	case "resolve":
		state = "resolved"
	case "reopen":
		state = "open"
	default:
		return fmt.Errorf("unknown incident command %q", sub)
	}
	if strings.TrimSpace(*fingerprint) == "" {
		return errors.New("--fingerprint is required")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	tenantID := chooseTenant(*tenant, cfg.DefaultTenantID)
	store, err := openBackend(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	incident, err := store.UpdateIncidentState(context.Background(), tenantID, *fingerprint, state, *actor, *note)
	if err != nil {
		return err
	}
	if incident == nil {
		return errors.New("incident not found")
	}
	if err := store.RecordAudit(context.Background(), model.AuditEvent{TenantID: tenantID, Actor: *actor, Role: model.RoleOperator, Action: "incident." + state, Resource: "incident", ResourceID: incident.ID, Metadata: map[string]string{"note": *note}}); err != nil {
		return fmt.Errorf("incident state changed to %s, but recording its audit event failed: %w", state, err)
	}
	return printJSON(incident)
}

func splitCSV(v string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func maintenanceLoop(ctx context.Context, store db.Backend, cfg config.Config, log *slog.Logger) {
	incidentTicker := time.NewTicker(time.Minute)
	cleanupTicker := time.NewTicker(12 * time.Hour)
	defer incidentTicker.Stop()
	defer cleanupTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-incidentTicker.C:
			resolvedItems, err := store.ResolveStaleIncidentsDetailed(ctx, time.Now().UTC().Add(-cfg.IncidentResolveAfter))
			resolved := len(resolvedItems)
			if err != nil {
				log.Warn("incident maintenance failed", "error", err)
			} else if resolved > 0 {
				log.Info("stale incidents resolved", "count", resolved)
				if cfg.Notifications.Enabled {
					for _, i := range resolvedItems {
						if err := store.EnqueueForTenant(ctx, i.TenantID, "notify.event", notifications.IncidentEvent("incident_resolved", i, cfg.PublicBaseURL), time.Now().UTC()); err != nil {
							log.Error("enqueue incident resolution notification failed", "tenant", i.TenantID, "incident_id", i.ID, "error", err)
						}
					}
				}
			}
		case <-cleanupTicker.C:
			if err := store.Cleanup(ctx, cfg.RetentionDays); err != nil {
				log.Warn("cleanup failed", "error", err)
			}
		}
	}
}
