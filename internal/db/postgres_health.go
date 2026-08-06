package db

import (
	"context"
	"fmt"
	"strconv"
)

// PostgresHealthReport exposes operational facts that an operator can verify
// before trusting a deployment. Counts are intentionally limited to small
// metadata/default-partition queries; large telemetry tables use PostgreSQL's
// estimates instead of a blocking COUNT(*).
type PostgresHealthReport struct {
	ServerVersion            string   `json:"server_version"`
	SchemaVersion            int64    `json:"schema_version"`
	DatabaseSizeBytes        int64    `json:"database_size_bytes"`
	ObservationTableBytes    int64    `json:"observation_table_bytes"`
	ObservationEstimatedRows int64    `json:"observation_estimated_rows"`
	ObservationPartitions    int      `json:"observation_partitions"`
	DefaultPartitionRows     int64    `json:"default_partition_rows"`
	InRecovery               bool     `json:"in_recovery"`
	PoolMaximumConnections   int      `json:"pool_maximum_connections"`
	PoolOpenConnections      int      `json:"pool_open_connections"`
	PoolIdleConnections      int      `json:"pool_idle_connections"`
	Warnings                 []string `json:"warnings,omitempty"`
}

func (p *PostgresBackend) Health(ctx context.Context) (PostgresHealthReport, error) {
	var report PostgresHealthReport
	c, err := p.connect(ctx)
	if err != nil {
		return report, err
	}
	defer p.release(c)
	rows, err := c.Query(ctx, `SELECT
  current_setting('server_version'),
  coalesce((SELECT max(version) FROM ciradar_schema_migrations),0)::text,
  pg_database_size(current_database())::text,
  pg_total_relation_size('ciradar_test_observations'::regclass)::text,
  coalesce((SELECT sum(greatest(child.reltuples,0))::bigint
    FROM pg_inherits JOIN pg_class parent ON pg_inherits.inhparent=parent.oid
    JOIN pg_class child ON pg_inherits.inhrelid=child.oid
    WHERE parent.relname='ciradar_test_observations'),0)::text,
  (SELECT count(*) FROM pg_inherits
    JOIN pg_class parent ON pg_inherits.inhparent=parent.oid
    JOIN pg_class child ON pg_inherits.inhrelid=child.oid
    WHERE parent.relname='ciradar_test_observations'
      AND child.relname<>'ciradar_test_observations_default')::text,
  (SELECT count(*) FROM ciradar_test_observations_default)::text,
  pg_is_in_recovery()::text`)
	if err != nil {
		return report, err
	}
	row, err := requireRow(rows, 8)
	if err != nil {
		return report, err
	}
	report.ServerVersion = valueOf(row[0])
	if report.SchemaVersion, err = parseInt64Health(row[1], "schema version"); err != nil {
		return report, err
	}
	if report.DatabaseSizeBytes, err = parseInt64Health(row[2], "database size"); err != nil {
		return report, err
	}
	if report.ObservationTableBytes, err = parseInt64Health(row[3], "observation table size"); err != nil {
		return report, err
	}
	if report.ObservationEstimatedRows, err = parseInt64Health(row[4], "observation estimated rows"); err != nil {
		return report, err
	}
	partitions, err := parsePostgresInt(row[5], "observation partition count")
	if err != nil {
		return report, err
	}
	report.ObservationPartitions = partitions
	if report.DefaultPartitionRows, err = parseInt64Health(row[6], "default partition rows"); err != nil {
		return report, err
	}
	report.InRecovery = pgBool(row[7])
	if p.pool != nil {
		report.PoolMaximumConnections = cap(p.pool.slots)
		report.PoolOpenConnections = len(p.pool.slots)
		report.PoolIdleConnections = len(p.pool.idle)
	}
	if report.SchemaVersion != postgresSchemaVersion {
		report.Warnings = append(report.Warnings, fmt.Sprintf("schema version is %d; this binary expects %d", report.SchemaVersion, postgresSchemaVersion))
	}
	if report.ObservationPartitions < 4 {
		report.Warnings = append(report.Warnings, "fewer than four monthly telemetry partitions are attached")
	}
	if report.DefaultPartitionRows > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("default telemetry partition contains %d rows; run database migrate/maintenance to route current months", report.DefaultPartitionRows))
	}
	if report.PoolMaximumConnections == 0 {
		report.Warnings = append(report.Warnings, "PostgreSQL connection pool is unavailable")
	}
	return report, nil
}

func parseInt64Health(value *string, field string) (int64, error) {
	raw := valueOf(value)
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse postgres %s %q: %w", field, raw, err)
	}
	return n, nil
}
