package model

import "time"

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
	Category           Category    `json:"category"`
	Provider           string      `json:"provider,omitempty"`
	Operation          string      `json:"operation,omitempty"`
	ErrorFamily        string      `json:"error_family,omitempty"`
	Confidence         Confidence  `json:"confidence"`
	Score              int         `json:"score"`
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
	ID                string    `json:"id"`
	Fingerprint       string    `json:"fingerprint"`
	Provider          string    `json:"provider,omitempty"`
	ErrorFamily       string    `json:"error_family,omitempty"`
	State             string    `json:"state"`
	Severity          string    `json:"severity"`
	RepositoryCount   int       `json:"repository_count"`
	OrganizationCount int       `json:"organization_count"`
	OccurrenceCount   int       `json:"occurrence_count"`
	FirstSeenAt       time.Time `json:"first_seen_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	Title             string    `json:"title"`
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
	ID             string     `json:"id"`
	Type           string     `json:"type"`
	DedupeKey      string     `json:"dedupe_key"`
	OccurredAt     time.Time  `json:"occurred_at"`
	Severity       string     `json:"severity,omitempty"`
	Title          string     `json:"title"`
	Summary        string     `json:"summary"`
	Repository     string     `json:"repository,omitempty"`
	Organization   string     `json:"organization,omitempty"`
	Workflow       string     `json:"workflow,omitempty"`
	Job            string     `json:"job,omitempty"`
	RunID          int64      `json:"run_id,omitempty"`
	CommitSHA      string     `json:"commit_sha,omitempty"`
	DetailsURL     string     `json:"details_url,omitempty"`
	Category       Category   `json:"category,omitempty"`
	Confidence     Confidence `json:"confidence,omitempty"`
	Score          int        `json:"score,omitempty"`
	Provider       string     `json:"provider,omitempty"`
	Operation      string     `json:"operation,omitempty"`
	Fingerprint    string     `json:"fingerprint,omitempty"`
	Recommendation string     `json:"recommendation,omitempty"`
	Evidence       []Evidence `json:"evidence,omitempty"`
	Incident       *Incident  `json:"incident,omitempty"`
}

type NotificationDelivery struct {
	ID               string    `json:"id"`
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
