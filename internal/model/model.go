package model

import "time"

const DefaultTenantID = "default"

type Category string

const (
	CategoryCodeFailure         Category = "CODE_FAILURE"
	CategoryTestFlake           Category = "TEST_FLAKE"
	CategoryDependencyRegistry  Category = "DEPENDENCY_REGISTRY"
	CategoryNetworkFailure      Category = "NETWORK_FAILURE"
	CategoryRunnerFailure       Category = "RUNNER_FAILURE"
	CategoryRunnerImageDrift    Category = "RUNNER_IMAGE_DRIFT"
	CategoryCacheFailure        Category = "CACHE_FAILURE"
	CategoryResourceExhaustion  Category = "RESOURCE_EXHAUSTION"
	CategoryProviderIncident    Category = "PROVIDER_INCIDENT"
	CategoryConcurrencyConflict Category = "CONCURRENCY_CONFLICT"
	CategoryToolchainFailure    Category = "TOOLCHAIN_FAILURE"
	CategoryUnknown             Category = "UNKNOWN"
)

type Confidence string

const (
	ConfidenceStrong       Confidence = "STRONG"
	ConfidenceModerate     Confidence = "MODERATE"
	ConfidenceMixed        Confidence = "MIXED"
	ConfidenceLikelyCode   Confidence = "LIKELY_CODE_RELATED"
	ConfidenceInsufficient Confidence = "INSUFFICIENT_EVIDENCE"
)

type Attribution string

const (
	AttributionExternal  Attribution = "EXTERNAL"
	AttributionCode      Attribution = "CODE"
	AttributionMixed     Attribution = "MIXED"
	AttributionToolchain Attribution = "TOOLCHAIN"
	AttributionUnknown   Attribution = "UNKNOWN"
)

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

type Evidence struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Weight      int    `json:"weight"`
}

type Environment struct {
	RunnerOS       string            `json:"runner_os,omitempty"`
	RunnerImage    string            `json:"runner_image,omitempty"`
	RunnerArch     string            `json:"runner_arch,omitempty"`
	ToolVersions   map[string]string `json:"tool_versions,omitempty"`
	ContainerRefs  []string          `json:"container_refs,omitempty"`
	ActionVersions []string          `json:"action_versions,omitempty"`
}

type AnalysisInput struct {
	SourceProvider      string    `json:"source_provider,omitempty"`
	SourceRunURL        string    `json:"source_run_url,omitempty"`
	PullRequestNumber   int       `json:"pull_request_number,omitempty"`
	MergeRequestNumber  int       `json:"merge_request_number,omitempty"`
	TenantID            string    `json:"tenant_id,omitempty"`
	Repository          string    `json:"repository,omitempty"`
	Organization        string    `json:"organization,omitempty"`
	Workflow            string    `json:"workflow,omitempty"`
	Job                 string    `json:"job,omitempty"`
	RunID               int64     `json:"run_id,omitempty"`
	JobID               int64     `json:"job_id,omitempty"`
	CommitSHA           string    `json:"commit_sha,omitempty"`
	PreviousSuccess     bool      `json:"previous_success,omitempty"`
	ChangeInfoAvailable bool      `json:"change_info_available,omitempty"`
	WorkflowChanged     bool      `json:"workflow_changed,omitempty"`
	DependencyChanged   bool      `json:"dependency_changed,omitempty"`
	Log                 string    `json:"log"`
	OccurredAt          time.Time `json:"occurred_at,omitempty"`
}

type AnalysisResult struct {
	ID                    string            `json:"id"`
	TenantID              string            `json:"tenant_id,omitempty"`
	Repository            string            `json:"repository,omitempty"`
	Organization          string            `json:"organization,omitempty"`
	Workflow              string            `json:"workflow,omitempty"`
	Job                   string            `json:"job,omitempty"`
	RunID                 int64             `json:"run_id,omitempty"`
	CommitSHA             string            `json:"commit_sha,omitempty"`
	SourceProvider        string            `json:"source_provider,omitempty"`
	SourceRunURL          string            `json:"source_run_url,omitempty"`
	PullRequestNumber     int               `json:"pull_request_number,omitempty"`
	MergeRequestNumber    int               `json:"merge_request_number,omitempty"`
	Category              Category          `json:"category"`
	Provider              string            `json:"provider,omitempty"`
	Operation             string            `json:"operation,omitempty"`
	ErrorFamily           string            `json:"error_family,omitempty"`
	Attribution           Attribution       `json:"attribution"`
	Confidence            Confidence        `json:"confidence"`
	Score                 int               `json:"score"`
	ExternalityScore      int               `json:"externality_score"`
	EvidenceStrength      int               `json:"evidence_strength"`
	ExternalEvidenceScore int               `json:"external_evidence_score"`
	CodeEvidenceScore     int               `json:"code_evidence_score"`
	RawScore              int               `json:"raw_score"`
	PositiveScore         int               `json:"positive_score"`
	NegativeScore         int               `json:"negative_score"`
	CompetingSignals      bool              `json:"competing_signals,omitempty"`
	DecisionReason        string            `json:"decision_reason,omitempty"`
	Fingerprint           string            `json:"fingerprint"`
	PrivateFingerprint    string            `json:"private_fingerprint,omitempty"`
	Summary               string            `json:"summary"`
	Recommendation        string            `json:"recommendation"`
	Evidence              []Evidence        `json:"evidence"`
	RedactedExcerpt       string            `json:"redacted_excerpt,omitempty"`
	Environment           Environment       `json:"environment"`
	MatchedRules          []string          `json:"matched_rules,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	CrossRepoCount        int               `json:"cross_repo_count,omitempty"`
	CrossOrgCount         int               `json:"cross_org_count,omitempty"`
	ProviderIncident      bool              `json:"provider_incident,omitempty"`
	EnvironmentDrift      bool              `json:"environment_drift,omitempty"`
	EnvironmentChanges    []string          `json:"environment_changes,omitempty"`
	SuggestedActions      []SuggestedAction `json:"suggested_actions,omitempty"`
	FeedbackSummary       FeedbackSummary   `json:"feedback_summary,omitempty"`
}

type Incident struct {
	ID                string            `json:"id"`
	TenantID          string            `json:"tenant_id,omitempty"`
	Fingerprint       string            `json:"fingerprint"`
	Provider          string            `json:"provider,omitempty"`
	ErrorFamily       string            `json:"error_family,omitempty"`
	Category          Category          `json:"category,omitempty"`
	Attribution       Attribution       `json:"attribution,omitempty"`
	State             string            `json:"state"`
	Severity          string            `json:"severity"`
	RepositoryCount   int               `json:"repository_count"`
	OrganizationCount int               `json:"organization_count"`
	OccurrenceCount   int               `json:"occurrence_count"`
	FirstSeenAt       time.Time         `json:"first_seen_at"`
	LastSeenAt        time.Time         `json:"last_seen_at"`
	AcknowledgedAt    time.Time         `json:"acknowledged_at,omitempty"`
	AcknowledgedBy    string            `json:"acknowledged_by,omitempty"`
	ResolvedAt        time.Time         `json:"resolved_at,omitempty"`
	ResolvedBy        string            `json:"resolved_by,omitempty"`
	ResolutionNote    string            `json:"resolution_note,omitempty"`
	Title             string            `json:"title"`
	SuggestedActions  []SuggestedAction `json:"suggested_actions,omitempty"`
}

type ProviderStatus struct {
	Provider    string    `json:"provider"`
	Indicator   string    `json:"indicator"`
	Description string    `json:"description"`
	Incident    bool      `json:"incident"`
	CheckedAt   time.Time `json:"checked_at"`
	Source      string    `json:"source"`
}

type GitHubWorkflowRunEvent struct {
	TenantID     string `json:"tenant_id,omitempty"`
	DeliveryID   string `json:"delivery_id,omitempty"`
	Action       string `json:"action"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
	Repository struct {
		FullName string `json:"full_name"`
		Owner    struct {
			Login string `json:"login"`
		} `json:"owner"`
		Name string `json:"name"`
	} `json:"repository"`
	WorkflowRun struct {
		ID           int64  `json:"id"`
		Name         string `json:"name"`
		HeadSHA      string `json:"head_sha"`
		Conclusion   string `json:"conclusion"`
		Status       string `json:"status"`
		HTMLURL      string `json:"html_url"`
		RunAttempt   int    `json:"run_attempt"`
		Event        string `json:"event"`
		HeadBranch   string `json:"head_branch"`
		PullRequests []struct {
			Number int `json:"number"`
		} `json:"pull_requests"`
	} `json:"workflow_run"`
}

type NotificationEvent struct {
	ID                    string      `json:"id"`
	TenantID              string      `json:"tenant_id,omitempty"`
	Type                  string      `json:"type"`
	DedupeKey             string      `json:"dedupe_key"`
	OccurredAt            time.Time   `json:"occurred_at"`
	Severity              string      `json:"severity,omitempty"`
	Title                 string      `json:"title"`
	Summary               string      `json:"summary"`
	Repository            string      `json:"repository,omitempty"`
	Organization          string      `json:"organization,omitempty"`
	Workflow              string      `json:"workflow,omitempty"`
	Job                   string      `json:"job,omitempty"`
	RunID                 int64       `json:"run_id,omitempty"`
	CommitSHA             string      `json:"commit_sha,omitempty"`
	DetailsURL            string      `json:"details_url,omitempty"`
	Category              Category    `json:"category,omitempty"`
	Confidence            Confidence  `json:"confidence,omitempty"`
	Attribution           Attribution `json:"attribution,omitempty"`
	Score                 int         `json:"score,omitempty"`
	ExternalityScore      int         `json:"externality_score,omitempty"`
	EvidenceStrength      int         `json:"evidence_strength,omitempty"`
	ExternalEvidenceScore int         `json:"external_evidence_score,omitempty"`
	CodeEvidenceScore     int         `json:"code_evidence_score,omitempty"`
	Provider              string      `json:"provider,omitempty"`
	Operation             string      `json:"operation,omitempty"`
	Fingerprint           string      `json:"fingerprint,omitempty"`
	Recommendation        string      `json:"recommendation,omitempty"`
	Evidence              []Evidence  `json:"evidence,omitempty"`
	Incident              *Incident   `json:"incident,omitempty"`
	TargetChannels        []string    `json:"target_channels,omitempty"`
}

type NotificationDelivery struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id,omitempty"`
	EventID          string    `json:"event_id"`
	DedupeKey        string    `json:"dedupe_key"`
	Channel          string    `json:"channel"`
	ChannelType      string    `json:"channel_type"`
	Status           string    `json:"status"`
	Attempts         int       `json:"attempts"`
	HTTPStatus       int       `json:"http_status,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
	SuppressedReason string    `json:"suppressed_reason,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	SentAt           time.Time `json:"sent_at,omitempty"`
}

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type APIKey struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"name"`
	Prefix     string    `json:"prefix"`
	Role       Role      `json:"role"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
}

type Principal struct {
	TenantID string   `json:"tenant_id"`
	Name     string   `json:"name"`
	Role     Role     `json:"role"`
	APIKeyID string   `json:"api_key_id,omitempty"`
	Root     bool     `json:"root,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
}

type AuditEvent struct {
	ID         string            `json:"id"`
	TenantID   string            `json:"tenant_id"`
	Actor      string            `json:"actor"`
	Role       Role              `json:"role"`
	Action     string            `json:"action"`
	Resource   string            `json:"resource"`
	ResourceID string            `json:"resource_id,omitempty"`
	RemoteIP   string            `json:"remote_ip,omitempty"`
	RequestID  string            `json:"request_id,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

type RepositoryProfile struct {
	TenantID             string    `json:"tenant_id"`
	Repository           string    `json:"repository"`
	Team                 string    `json:"team,omitempty"`
	Owner                string    `json:"owner,omitempty"`
	Criticality          string    `json:"criticality,omitempty"`
	NotificationChannels []string  `json:"notification_channels,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type DashboardSummary struct {
	TenantID              string             `json:"tenant_id"`
	Since                 time.Time          `json:"since"`
	GeneratedAt           time.Time          `json:"generated_at"`
	TotalAnalyses         int                `json:"total_analyses"`
	ExternalAnalyses      int                `json:"external_analyses"`
	CodeAnalyses          int                `json:"code_analyses"`
	MixedAnalyses         int                `json:"mixed_analyses"`
	ToolchainAnalyses     int                `json:"toolchain_analyses"`
	UnknownAnalyses       int                `json:"unknown_analyses"`
	OpenIncidents         int                `json:"open_incidents"`
	AcknowledgedIncidents int                `json:"acknowledged_incidents"`
	CriticalIncidents     int                `json:"critical_incidents"`
	Repositories          int                `json:"repositories"`
	NotificationFailures  int                `json:"notification_failures"`
	Categories            map[string]int     `json:"categories"`
	Providers             map[string]int     `json:"providers"`
	RepositoryFailures    map[string]int     `json:"repository_failures"`
	DailyAnalyses         map[string]int     `json:"daily_analyses"`
	RecentIncidents       []Incident         `json:"recent_incidents"`
	RecentAnalyses        []AnalysisResult   `json:"recent_analyses"`
	DiagnosisFeedback     FeedbackMetrics    `json:"diagnosis_feedback"`
	FlakyTests            int                `json:"flaky_tests"`
	QuarantinedTests      int                `json:"quarantined_tests"`
	TestCasesTracked      int                `json:"test_cases_tracked"`
	DORA                  DORAMetrics        `json:"dora"`
	Usage                 CIUsageSummary     `json:"usage"`
	DailyIncidents        map[string]int     `json:"daily_incidents"`
	DailyTestFailures     map[string]int     `json:"daily_test_failures"`
	DailyCost             map[string]float64 `json:"daily_cost"`
}

type SuggestedAction struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Risk        string   `json:"risk"`
	Automatic   bool     `json:"automatic,omitempty"`
	Commands    []string `json:"commands,omitempty"`
	References  []string `json:"references,omitempty"`
}

type DiagnosisFeedback struct {
	ID          string      `json:"id"`
	TenantID    string      `json:"tenant_id"`
	AnalysisID  string      `json:"analysis_id"`
	Verdict     string      `json:"verdict"`
	ActualCause Attribution `json:"actual_cause,omitempty"`
	Comment     string      `json:"comment,omitempty"`
	Actor       string      `json:"actor,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

type FeedbackSummary struct {
	Correct   int `json:"correct"`
	Partial   int `json:"partial"`
	Incorrect int `json:"incorrect"`
}

type FeedbackMetrics struct {
	Total             int     `json:"total"`
	Correct           int     `json:"correct"`
	Partial           int     `json:"partial"`
	Incorrect         int     `json:"incorrect"`
	PrecisionPercent  float64 `json:"precision_percent"`
	ExternalPrecision float64 `json:"external_precision_percent"`
}

type TestObservation struct {
	ID          string      `json:"id"`
	TenantID    string      `json:"tenant_id"`
	Repository  string      `json:"repository"`
	Workflow    string      `json:"workflow,omitempty"`
	Job         string      `json:"job,omitempty"`
	RunID       int64       `json:"run_id,omitempty"`
	CommitSHA   string      `json:"commit_sha,omitempty"`
	Branch      string      `json:"branch,omitempty"`
	Framework   string      `json:"framework,omitempty"`
	Suite       string      `json:"suite,omitempty"`
	ClassName   string      `json:"class_name,omitempty"`
	Name        string      `json:"name"`
	Parameters  string      `json:"parameters,omitempty"`
	File        string      `json:"file,omitempty"`
	Status      string      `json:"status"`
	DurationMS  int64       `json:"duration_ms,omitempty"`
	Message     string      `json:"message,omitempty"`
	Details     string      `json:"details,omitempty"`
	Environment Environment `json:"environment,omitempty"`
	OccurredAt  time.Time   `json:"occurred_at"`
}

type TestCaseStats struct {
	TenantID                        string         `json:"tenant_id"`
	TestKey                         string         `json:"test_key"`
	Repository                      string         `json:"repository"`
	Framework                       string         `json:"framework,omitempty"`
	Suite                           string         `json:"suite,omitempty"`
	ClassName                       string         `json:"class_name,omitempty"`
	Name                            string         `json:"name"`
	Parameters                      string         `json:"parameters,omitempty"`
	File                            string         `json:"file,omitempty"`
	TotalRuns                       int            `json:"total_runs"`
	ExecutedRuns                    int            `json:"executed_runs"`
	Passes                          int            `json:"passes"`
	Failures                        int            `json:"failures"`
	Skipped                         int            `json:"skipped"`
	Transitions                     int            `json:"transitions"`
	RerunRecoveries                 int            `json:"rerun_recoveries"`
	FailureRate                     float64        `json:"failure_rate"`
	FailureRateLow                  float64        `json:"failure_rate_low"`
	FailureRateHigh                 float64        `json:"failure_rate_high"`
	TransitionRate                  float64        `json:"transition_rate"`
	HistoryConfidence               float64        `json:"history_confidence"`
	FlakeProbability                float64        `json:"flake_probability"`
	FlakeScore                      float64        `json:"flake_score"`
	ColdStart                       bool           `json:"cold_start"`
	TotalDurationMS                 int64          `json:"total_duration_ms"`
	AverageDurationMS               int64          `json:"average_duration_ms"`
	EstimatedComputeMinutesLost     float64        `json:"estimated_compute_minutes_lost"`
	EstimatedEngineeringMinutesLost float64        `json:"estimated_engineering_minutes_lost"`
	LastCommitSHA                   string         `json:"last_commit_sha,omitempty"`
	LastRunID                       int64          `json:"last_run_id,omitempty"`
	LastDurationMS                  int64          `json:"last_duration_ms,omitempty"`
	Classification                  string         `json:"classification"`
	PrimaryFlakeCause               string         `json:"primary_flake_cause,omitempty"`
	CauseConfidence                 float64        `json:"cause_confidence,omitempty"`
	CauseCounts                     map[string]int `json:"cause_counts,omitempty"`
	FirstSeenAt                     time.Time      `json:"first_seen_at"`
	LastSeenAt                      time.Time      `json:"last_seen_at"`
	LastStatus                      string         `json:"last_status"`
	Quarantined                     bool           `json:"quarantined"`
	QuarantineUntil                 time.Time      `json:"quarantine_until,omitempty"`
	Owner                           string         `json:"owner,omitempty"`
	DisplayName                     string         `json:"display_name,omitempty"`
	Aliases                         []string       `json:"aliases,omitempty"`
}

type TestQuarantine struct {
	TenantID  string    `json:"tenant_id"`
	TestKey   string    `json:"test_key"`
	Reason    string    `json:"reason"`
	Owner     string    `json:"owner"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Active    bool      `json:"active"`
}

type CIEvent struct {
	TenantID          string            `json:"tenant_id,omitempty"`
	Provider          string            `json:"provider"`
	DeliveryID        string            `json:"delivery_id,omitempty"`
	Repository        string            `json:"repository"`
	Organization      string            `json:"organization,omitempty"`
	Workflow          string            `json:"workflow,omitempty"`
	Job               string            `json:"job,omitempty"`
	RunID             int64             `json:"run_id,omitempty"`
	JobID             string            `json:"job_id,omitempty"`
	CommitSHA         string            `json:"commit_sha,omitempty"`
	Branch            string            `json:"branch,omitempty"`
	Conclusion        string            `json:"conclusion,omitempty"`
	Status            string            `json:"status,omitempty"`
	RunURL            string            `json:"run_url,omitempty"`
	PullRequestNumber int               `json:"pull_request_number,omitempty"`
	MergeRequestIID   int               `json:"merge_request_iid,omitempty"`
	InstallationID    int64             `json:"installation_id,omitempty"`
	ProjectID         string            `json:"project_id,omitempty"`
	PipelineID        string            `json:"pipeline_id,omitempty"`
	LogURL            string            `json:"log_url,omitempty"`
	StartedAt         time.Time         `json:"started_at,omitempty"`
	CompletedAt       time.Time         `json:"completed_at,omitempty"`
	DurationSeconds   int64             `json:"duration_seconds,omitempty"`
	RunnerClass       string            `json:"runner_class,omitempty"`
	RunnerLabels      []string          `json:"runner_labels,omitempty"`
	EstimatedCost     float64           `json:"estimated_cost,omitempty"`
	Currency          string            `json:"currency,omitempty"`
	InlineLog         string            `json:"inline_log,omitempty"`
	OccurredAt        time.Time         `json:"occurred_at,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}
