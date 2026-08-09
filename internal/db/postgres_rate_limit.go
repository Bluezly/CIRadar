package db

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func validateRateLimitInput(scope, keyHash string, limit int, window time.Duration) error {
	if strings.TrimSpace(scope) == "" || len(scope) > 64 {
		return errors.New("rate limit scope is invalid")
	}
	if strings.TrimSpace(keyHash) == "" || len(keyHash) > 128 {
		return errors.New("rate limit key hash is invalid")
	}
	if limit < 1 || limit > 10_000_000 {
		return errors.New("rate limit must be between 1 and 10000000")
	}
	if window < time.Second || window > 24*time.Hour {
		return errors.New("rate limit window must be between one second and 24 hours")
	}
	return nil
}

func durationSeconds(value time.Duration) int64 {
	seconds := int64((value + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func (p *PostgresBackend) TakeRateLimit(ctx context.Context, scope, keyHash string, limit int, window time.Duration, now time.Time) (bool, time.Duration, error) {
	if err := validateRateLimitInput(scope, keyHash, limit, window); err != nil {
		return false, 0, err
	}
	_ = now
	c, err := p.connect(ctx)
	if err != nil {
		return false, 0, err
	}
	defer p.release(c)
	seconds := durationSeconds(window)
	query := `INSERT INTO ciradar_rate_limits(scope,key_hash,window_start,count,updated_at)
VALUES ($1,$2,CURRENT_TIMESTAMP,1,CURRENT_TIMESTAMP)
ON CONFLICT(scope,key_hash) DO UPDATE SET
  window_start=CASE WHEN ciradar_rate_limits.window_start <= CURRENT_TIMESTAMP-($3::bigint * interval '1 second') THEN CURRENT_TIMESTAMP ELSE ciradar_rate_limits.window_start END,
  count=CASE WHEN ciradar_rate_limits.window_start <= CURRENT_TIMESTAMP-($3::bigint * interval '1 second') THEN 1 ELSE ciradar_rate_limits.count+1 END,
  updated_at=CURRENT_TIMESTAMP
RETURNING count::text,window_start::text,CURRENT_TIMESTAMP::text`
	rows, err := c.QueryParams(ctx, query, strings.TrimSpace(scope), strings.TrimSpace(keyHash), seconds)
	if err != nil {
		return false, 0, err
	}
	row, err := requireRow(rows, 3)
	if err != nil {
		return false, 0, err
	}
	count, err := strconv.ParseInt(strings.TrimSpace(valueOf(row[0])), 10, 64)
	if err != nil {
		return false, 0, fmt.Errorf("parse postgres rate limit count: %w", err)
	}
	windowStart := parsePGTime(valueOf(row[1]))
	serverNow := parsePGTime(valueOf(row[2]))
	if windowStart.IsZero() || serverNow.IsZero() {
		return false, 0, errors.New("postgres rate limit returned invalid timestamps")
	}
	if count <= int64(limit) {
		return true, 0, nil
	}
	retry := windowStart.Add(time.Duration(seconds) * time.Second).Sub(serverNow)
	if retry < time.Second {
		retry = time.Second
	}
	return false, retry, nil
}

func (p *PostgresBackend) AuthFailureRetryAfter(ctx context.Context, keyHash string, now time.Time) (time.Duration, error) {
	keyHash, err := normalizeAuthFailureKeyHash(keyHash)
	if err != nil {
		return 0, err
	}
	_ = now
	c, err := p.connect(ctx)
	if err != nil {
		return 0, err
	}
	defer p.release(c)
	rows, err := c.QueryParams(ctx, `SELECT coalesce(blocked_until::text,''),CURRENT_TIMESTAMP::text FROM ciradar_auth_failures WHERE key_hash=$1`, strings.TrimSpace(keyHash))
	if err != nil {
		return 0, err
	}
	if len(rows.Values) == 0 {
		return 0, nil
	}
	row, err := requireRow(rows, 2)
	if err != nil {
		return 0, err
	}
	blockedUntil := parsePGTime(valueOf(row[0]))
	serverNow := parsePGTime(valueOf(row[1]))
	if serverNow.IsZero() {
		return 0, errors.New("postgres authentication limiter returned invalid server time")
	}
	if blockedUntil.After(serverNow) {
		return blockedUntil.Sub(serverNow), nil
	}
	return 0, nil
}

func advisoryLockKey(value string) int64 {
	sum := sha256.Sum256([]byte(value))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

func normalizeAuthFailureKeyHash(keyHash string) (string, error) {
	keyHash = strings.ToLower(strings.TrimSpace(keyHash))
	if len(keyHash) != sha256.Size*2 {
		return "", errors.New("auth failure key hash is invalid")
	}
	for _, c := range keyHash {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return "", errors.New("auth failure key hash is invalid")
	}
	return keyHash, nil
}

func authFailureAdvisoryLockKey(keyHash string) int64 {
	value, _ := strconv.ParseUint(keyHash[:16], 16, 64)
	return int64(value)
}

func authFailureDelay(failures, threshold int, baseDelay, maxDelay time.Duration) time.Duration {
	if failures < threshold {
		return 0
	}
	delay := baseDelay
	for i := threshold; i < failures && delay < maxDelay; i++ {
		if delay > maxDelay/2 {
			return maxDelay
		}
		delay *= 2
	}
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

func (p *PostgresBackend) RecordAuthFailure(ctx context.Context, keyHash string, threshold int, window, baseDelay, maxDelay time.Duration, now time.Time) (delay time.Duration, err error) {
	keyHash, err = normalizeAuthFailureKeyHash(keyHash)
	if err != nil {
		return 0, err
	}
	if threshold < 1 || threshold > 1_000_000 {
		return 0, errors.New("auth failure threshold is invalid")
	}
	if window < time.Second || window > 24*time.Hour || baseDelay < time.Second || maxDelay < baseDelay || maxDelay > 24*time.Hour {
		return 0, errors.New("auth failure timing configuration is invalid")
	}
	_ = now
	c, err := p.connect(ctx)
	if err != nil {
		return 0, err
	}
	defer p.release(c)
	if err = c.Exec(ctx, "BEGIN"); err != nil {
		return 0, err
	}
	clockRows, clockErr := c.Query(ctx, `SELECT CURRENT_TIMESTAMP::text`)
	if clockErr != nil {
		rollbackPostgres(c)
		return 0, clockErr
	}
	clockRow, clockErr := requireRow(clockRows, 1)
	if clockErr != nil {
		rollbackPostgres(c)
		return 0, clockErr
	}
	now = parsePGTime(valueOf(clockRow[0]))
	if now.IsZero() {
		rollbackPostgres(c)
		return 0, errors.New("postgres authentication limiter returned invalid server time")
	}
	defer func() {
		if err != nil {
			rollbackPostgres(c)
		}
	}()
	if err = c.ExecParams(ctx, `SELECT pg_advisory_xact_lock($1::bigint)`, authFailureAdvisoryLockKey(keyHash)); err != nil {
		return 0, err
	}
	rows, err := c.QueryParams(ctx, `SELECT window_start::text,failures::text,coalesce(blocked_until::text,'') FROM ciradar_auth_failures WHERE key_hash=$1 FOR UPDATE`, keyHash)
	if err != nil {
		return 0, err
	}
	windowStart := now
	failures := 0
	if len(rows.Values) > 0 {
		row, rowErr := requireRow(rows, 3)
		if rowErr != nil {
			return 0, rowErr
		}
		windowStart = parsePGTime(valueOf(row[0]))
		if windowStart.IsZero() {
			return 0, errors.New("postgres auth failure returned invalid window start")
		}
		failures, err = parsePostgresInt(row[1], "auth failure count")
		if err != nil {
			return 0, err
		}
		if now.Sub(windowStart) >= window {
			windowStart = now
			failures = 0
		}
	}
	failures++
	delay = authFailureDelay(failures, threshold, baseDelay, maxDelay)
	var blockedUntil any
	if delay > 0 {
		blockedUntil = now.Add(delay)
	}
	query := `INSERT INTO ciradar_auth_failures(key_hash,window_start,failures,blocked_until,updated_at)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT(key_hash) DO UPDATE SET window_start=excluded.window_start,failures=excluded.failures,blocked_until=excluded.blocked_until,updated_at=excluded.updated_at`
	if err = c.ExecParams(ctx, query, keyHash, windowStart, failures, blockedUntil, now); err != nil {
		return 0, err
	}
	if err = c.Exec(ctx, "COMMIT"); err != nil {
		return 0, err
	}
	return delay, nil
}
