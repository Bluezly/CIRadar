package model

import "time"

type LLMEnhancement struct {
	AnalysisID       string            `json:"analysis_id"`
	TenantID         string            `json:"tenant_id"`
	Provider         string            `json:"provider"`
	Model            string            `json:"model"`
	Explanation      string            `json:"explanation"`
	SuggestedFix     string            `json:"suggested_fix,omitempty"`
	Patch            string            `json:"patch,omitempty"`
	Warnings         []string          `json:"warnings,omitempty"`
	InputFingerprint string            `json:"input_fingerprint"`
	Usage            map[string]int    `json:"usage,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
}

type DeploymentEvent struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Repository     string    `json:"repository"`
	Environment    string    `json:"environment"`
	CommitSHA      string    `json:"commit_sha"`
	PreviousSHA    string    `json:"previous_sha,omitempty"`
	Status         string    `json:"status"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	FirstCommitAt  time.Time `json:"first_commit_at,omitempty"`
	IncidentID     string    `json:"incident_id,omitempty"`
	SourceProvider string    `json:"source_provider,omitempty"`
	SourceURL      string    `json:"source_url,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type DORAMetrics struct {
	TenantID                  string    `json:"tenant_id"`
	Environment               string    `json:"environment,omitempty"`
	Since                     time.Time `json:"since"`
	Until                     time.Time `json:"until"`
	Deployments               int       `json:"deployments"`
	SuccessfulDeployments     int       `json:"successful_deployments"`
	FailedDeployments         int       `json:"failed_deployments"`
	DeploymentFrequencyPerDay float64   `json:"deployment_frequency_per_day"`
	LeadTimeForChangesMinutes float64   `json:"lead_time_for_changes_minutes"`
	MeanTimeToRestoreMinutes  float64   `json:"mean_time_to_restore_minutes"`
	ChangeFailureRatePercent  float64   `json:"change_failure_rate_percent"`
	GeneratedAt               time.Time `json:"generated_at"`
}

type CIUsageRecord struct {
	ID              string            `json:"id"`
	TenantID        string            `json:"tenant_id"`
	Provider        string            `json:"provider"`
	Repository      string            `json:"repository"`
	Workflow        string            `json:"workflow,omitempty"`
	Job             string            `json:"job,omitempty"`
	RunID           int64             `json:"run_id,omitempty"`
	RunnerClass     string            `json:"runner_class,omitempty"`
	RunnerLabels    []string          `json:"runner_labels,omitempty"`
	DurationSeconds int64             `json:"duration_seconds"`
	BillableMinutes float64           `json:"billable_minutes"`
	EstimatedCost   float64           `json:"estimated_cost"`
	Currency        string            `json:"currency"`
	StartedAt       time.Time         `json:"started_at"`
	CompletedAt     time.Time         `json:"completed_at"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type CIUsageSummary struct {
	TenantID        string             `json:"tenant_id"`
	Since           time.Time          `json:"since"`
	Until           time.Time          `json:"until"`
	Runs            int                `json:"runs"`
	DurationHours   float64            `json:"duration_hours"`
	BillableMinutes float64            `json:"billable_minutes"`
	EstimatedCost   float64            `json:"estimated_cost"`
	Currency        string             `json:"currency"`
	ByRepository    map[string]float64 `json:"by_repository"`
	MinutesByRepo   map[string]float64 `json:"minutes_by_repository"`
	RunsByProvider  map[string]int     `json:"runs_by_provider"`
	GeneratedAt     time.Time          `json:"generated_at"`
}

type SimilarAnalysis struct {
	AnalysisID  string      `json:"analysis_id"`
	Repository  string      `json:"repository"`
	Summary     string      `json:"summary"`
	Category    Category    `json:"category"`
	Attribution Attribution `json:"attribution"`
	Score       float64     `json:"similarity_score"`
	Engine      string      `json:"similarity_engine"`
	CreatedAt   time.Time   `json:"created_at"`
}

type TestSelectionRequest struct {
	Repository   string   `json:"repository"`
	ChangedFiles []string `json:"changed_files"`
	Framework    string   `json:"framework,omitempty"`
	Limit        int      `json:"limit,omitempty"`
	IncludeFlaky bool     `json:"include_flaky,omitempty"`
	MinimumScore float64  `json:"minimum_score,omitempty"`
}

type ImpactGraph struct {
	TenantID       string              `json:"tenant_id"`
	Repository     string              `json:"repository"`
	Root           string              `json:"root,omitempty"`
	LanguageFiles  map[string]string   `json:"language_files,omitempty"`
	Dependencies   map[string][]string `json:"dependencies"`
	TestFiles      map[string]string   `json:"test_files,omitempty"`
	TestCoverage   map[string][]string `json:"test_coverage,omitempty"`
	GeneratedAt    time.Time           `json:"generated_at"`
	Generator      string              `json:"generator,omitempty"`
	GeneratorBuild string              `json:"generator_build,omitempty"`
}

type TestCoverageInput struct {
	Repository  string              `json:"repository"`
	Coverage    map[string][]string `json:"coverage"`
	GeneratedAt time.Time           `json:"generated_at,omitempty"`
}

type SelectedTest struct {
	TestKey       string   `json:"test_key"`
	Name          string   `json:"name"`
	Suite         string   `json:"suite,omitempty"`
	ClassName     string   `json:"class_name,omitempty"`
	File          string   `json:"file,omitempty"`
	Framework     string   `json:"framework,omitempty"`
	PriorityScore float64  `json:"priority_score"`
	Confidence    float64  `json:"confidence"`
	Strategy      string   `json:"strategy"`
	Reason        string   `json:"reason"`
	ImpactPath    []string `json:"impact_path,omitempty"`
	Quarantined   bool     `json:"quarantined"`
}

type TestSelection struct {
	Repository   string         `json:"repository"`
	ChangedFiles []string       `json:"changed_files"`
	Selected     []SelectedTest `json:"selected"`
	Skipped      int            `json:"skipped"`
	GeneratedAt  time.Time      `json:"generated_at"`
}

type SSOIdentity struct {
	Subject  string   `json:"subject"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	TenantID string   `json:"tenant_id"`
	Role     Role     `json:"role"`
	Groups   []string `json:"groups,omitempty"`
	Issuer   string   `json:"issuer,omitempty"`
}

type RepairSource struct {
	TenantID          string `json:"tenant_id"`
	Provider          string `json:"provider"`
	Repository        string `json:"repository"`
	InstallationID    int64  `json:"installation_id,omitempty"`
	CommitSHA         string `json:"commit_sha,omitempty"`
	BaseBranch        string `json:"base_branch,omitempty"`
	RunURL            string `json:"run_url,omitempty"`
	PullRequestNumber int    `json:"pull_request_number,omitempty"`
}

type RepairResult struct {
	TenantID          string    `json:"tenant_id"`
	AnalysisID        string    `json:"analysis_id"`
	PlanID            string    `json:"plan_id"`
	Provider          string    `json:"provider"`
	Branch            string    `json:"branch,omitempty"`
	PullRequestNumber int       `json:"pull_request_number,omitempty"`
	PullRequestURL    string    `json:"pull_request_url,omitempty"`
	Status            string    `json:"status"`
	Error             string    `json:"error,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}
