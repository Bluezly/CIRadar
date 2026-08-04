package db

import (
	"context"
	"time"

	"ciradar/internal/model"
)

// Backend is the persistence contract used by the server, workers, notification
// dispatcher, and provider poller. The bundled Store is the portable single-node
// implementation. A PostgreSQL backend can implement this contract without
// changing the analysis or delivery layers.
type Backend interface {
	Close() error
	Migrate(context.Context) error
	ClaimJob(context.Context, string) (*Job, error)
	CompleteJob(context.Context, int64) error
	FailJob(context.Context, int64, int, string) error
	RequeueStaleJobs(context.Context, time.Duration) error
	Enqueue(context.Context, string, any, time.Time) error
	EnqueueForTenant(context.Context, string, string, any, time.Time) error

	RecordDelivery(context.Context, string, string) (bool, error)
	UpdateDelivery(context.Context, string, string, string) error

	RecordAnalysisForTenant(context.Context, string, model.AnalysisInput, model.AnalysisResult, bool, bool) error
	GetAnalysisForTenant(context.Context, string, string) (*model.AnalysisResult, error)
	ListAnalysesForTenant(context.Context, string, int) ([]model.AnalysisResult, error)
	CorrelationForTenant(context.Context, string, string, time.Time, bool) (CorrelationStats, error)

	RecordSuccessfulEnvironmentForTenant(context.Context, string, string, string, string, string, model.Environment, time.Time) error
	LastSuccessfulEnvironmentForTenant(context.Context, string, string, string, string) (*model.Environment, error)

	GetIncidentForTenant(context.Context, string, string) (*model.Incident, error)
	ListIncidentsForTenant(context.Context, string, int, string) ([]model.Incident, error)
	UpsertIncidentForTenant(context.Context, string, model.Incident) error
	UpdateIncidentState(context.Context, string, string, string, string, string) (*model.Incident, error)
	ResolveStaleIncidentsDetailed(context.Context, time.Time) ([]model.Incident, error)

	RecordProviderStatus(context.Context, model.ProviderStatus) error
	ListProviderStatuses(context.Context) ([]model.ProviderStatus, error)

	BeginNotificationDeliveryForTenant(context.Context, string, string, string, string, string, time.Duration, int) (string, model.NotificationDelivery, error)
	GetNotificationDeliveryForTenant(context.Context, string, string, string) (*model.NotificationDelivery, error)
	RecordNotificationDelivery(context.Context, model.NotificationDelivery) error
	ListNotificationDeliveriesForTenant(context.Context, string, int) ([]model.NotificationDelivery, error)

	CreateTenant(context.Context, string, string) (model.Tenant, error)
	GetTenant(context.Context, string) (*model.Tenant, error)
	ListTenants(context.Context) ([]model.Tenant, error)
	SetTenantEnabled(context.Context, string, bool) error
	CreateAPIKey(context.Context, string, string, model.Role) (model.APIKey, string, error)
	AuthenticateAPIKey(context.Context, string) (*model.Principal, error)
	ListAPIKeys(context.Context, string) ([]model.APIKey, error)
	RevokeAPIKey(context.Context, string, string) error
	RecordAudit(context.Context, model.AuditEvent) error
	ListAudit(context.Context, string, int) ([]model.AuditEvent, error)

	BindInstallation(context.Context, string, int64) error
	UnbindInstallation(context.Context, int64) error
	ResolveInstallationTenant(context.Context, int64) (string, bool)
	ListInstallationBindings(context.Context) map[string]string

	UpsertRepositoryProfile(context.Context, model.RepositoryProfile) (model.RepositoryProfile, error)
	GetRepositoryProfile(context.Context, string, string) (*model.RepositoryProfile, error)
	ListRepositoryProfiles(context.Context, string) ([]model.RepositoryProfile, error)

	Stats(context.Context) (Stats, error)
	StatsForTenant(context.Context, string) (Stats, error)
	Dashboard(context.Context, string, time.Time) (model.DashboardSummary, error)
	UpsertDiagnosisFeedback(context.Context, model.DiagnosisFeedback) (model.DiagnosisFeedback, error)
	ListDiagnosisFeedback(context.Context, string, int) ([]model.DiagnosisFeedback, error)
	FeedbackMetrics(context.Context, string) (model.FeedbackMetrics, error)
	RecordTestObservations(context.Context, string, []model.TestObservation) ([]model.TestCaseStats, error)
	ListTestCaseStats(context.Context, string, string, string, int) ([]model.TestCaseStats, error)
	SetTestQuarantine(context.Context, model.TestQuarantine) (model.TestQuarantine, error)
	RemoveTestQuarantine(context.Context, string, string) error
	ListTestQuarantines(context.Context, string) ([]model.TestQuarantine, error)
	Cleanup(context.Context, int) error
}

var _ Backend = (*Store)(nil)
