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
	ID                 string      `json:"id"`
	TenantID           string      `json:"tenant_id,omitempty"`
	Category           Category    `json:"category"`
	Provider           string      `json:"provider,omitempty"`
	Operation          string      `json:"operation,omitempty"`
	ErrorFamily        string      `json:"error_family,omitempty"`
	Attribution        Attribution `json:"attribution"`
	Confidence         Confidence  `json:"confidence"`
	Score              int         `json:"score"`
	RawScore           int         `json:"raw_score"`
	PositiveScore      int         `json:"positive_score"`
	NegativeScore      int         `json:"negative_score"`
	CompetingSignals   bool        `json:"competing_signals,omitempty"`
	DecisionReason     string      `json:"decision_reason,omitempty"`
	Fingerprint        string      `json:"fingerprint"`
	PrivateFingerprint string      `json:"private_fingerprint,omitempty"`
	Summary            string      `json:"summary"`
	Recommendation     string      `json:"recommendation"`
	Evidence           []Evidence  `json:"evidence"`
	RedactedExcerpt    string      `json:"redacted_excerpt,omitempty"`
	Environment        Environment `json:"environment"`
	MatchedRules       []string    `json:"matched_rules,omitempty"`
	CreatedAt          time.Time   `json:"created_at"`
	CrossRepoCount     int         `json:"cross_repo_count,omitempty"`
	CrossOrgCount      int         `json:"cross_org_count,omitempty"`
	ProviderIncident   bool        `json:"provider_incident,omitempty"`
	EnvironmentDrift   bool        `json:"environment_drift,omitempty"`
	EnvironmentChanges []string    `json:"environment_changes,omitempty"`
}

type Incident struct {
	ID                string      `json:"id"`
	TenantID          string      `json:"tenant_id,omitempty"`
	Fingerprint       string      `json:"fingerprint"`
	Provider          string      `json:"provider,omitempty"`
	ErrorFamily       string      `json:"error_family,omitempty"`
	Category          Category    `json:"category,omitempty"`
	Attribution       Attribution `json:"attribution,omitempty"`
	State             string      `json:"state"`
	Severity          string      `json:"severity"`
	RepositoryCount   int         `json:"repository_count"`
	OrganizationCount int         `json:"organization_count"`
	OccurrenceCount   int         `json:"occurrence_count"`
	FirstSeenAt       time.Time   `json:"first_seen_at"`
	LastSeenAt        time.Time   `json:"last_seen_at"`
	AcknowledgedAt    time.Time   `json:"acknowledged_at,omitempty"`
	AcknowledgedBy    string      `json:"acknowledged_by,omitempty"`
	ResolvedAt        time.Time   `json:"resolved_at,omitempty"`
	ResolvedBy        string      `json:"resolved_by,omitempty"`
	ResolutionNote    string      `json:"resolution_note,omitempty"`
	Title             string      `json:"title"`
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
	ID             string      `json:"id"`
	TenantID       string      `json:"tenant_id,omitempty"`
	Type           string      `json:"type"`
	DedupeKey      string      `json:"dedupe_key"`
	OccurredAt     time.Time   `json:"occurred_at"`
	Severity       string      `json:"severity,omitempty"`
	Title          string      `json:"title"`
	Summary        string      `json:"summary"`
	Repository     string      `json:"repository,omitempty"`
	Organization   string      `json:"organization,omitempty"`
	Workflow       string      `json:"workflow,omitempty"`
	Job            string      `json:"job,omitempty"`
	RunID          int64       `json:"run_id,omitempty"`
	CommitSHA      string      `json:"commit_sha,omitempty"`
	DetailsURL     string      `json:"details_url,omitempty"`
	Category       Category    `json:"category,omitempty"`
	Confidence     Confidence  `json:"confidence,omitempty"`
	Attribution    Attribution `json:"attribution,omitempty"`
	Score          int         `json:"score,omitempty"`
	Provider       string      `json:"provider,omitempty"`
	Operation      string      `json:"operation,omitempty"`
	Fingerprint    string      `json:"fingerprint,omitempty"`
	Recommendation string      `json:"recommendation,omitempty"`
	Evidence       []Evidence  `json:"evidence,omitempty"`
	Incident       *Incident   `json:"incident,omitempty"`
	TargetChannels []string    `json:"target_channels,omitempty"`
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
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Role     Role   `json:"role"`
	APIKeyID string `json:"api_key_id,omitempty"`
	Root     bool   `json:"root,omitempty"`
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
	TenantID              string           `json:"tenant_id"`
	Since                 time.Time        `json:"since"`
	GeneratedAt           time.Time        `json:"generated_at"`
	TotalAnalyses         int              `json:"total_analyses"`
	ExternalAnalyses      int              `json:"external_analyses"`
	CodeAnalyses          int              `json:"code_analyses"`
	MixedAnalyses         int              `json:"mixed_analyses"`
	ToolchainAnalyses     int              `json:"toolchain_analyses"`
	UnknownAnalyses       int              `json:"unknown_analyses"`
	OpenIncidents         int              `json:"open_incidents"`
	AcknowledgedIncidents int              `json:"acknowledged_incidents"`
	CriticalIncidents     int              `json:"critical_incidents"`
	Repositories          int              `json:"repositories"`
	NotificationFailures  int              `json:"notification_failures"`
	Categories            map[string]int   `json:"categories"`
	Providers             map[string]int   `json:"providers"`
	RepositoryFailures    map[string]int   `json:"repository_failures"`
	DailyAnalyses         map[string]int   `json:"daily_analyses"`
	RecentIncidents       []Incident       `json:"recent_incidents"`
	RecentAnalyses        []AnalysisResult `json:"recent_analyses"`
}
