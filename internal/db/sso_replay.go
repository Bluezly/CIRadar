package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const ssoReplayExtensionKind = "sso_replay"

type ssoReplayRecord struct {
	ExpiresAt time.Time `json:"expires_at"`
}

func validateSSOReplay(key string, expiresAt, now time.Time) error {
	if strings.TrimSpace(key) == "" || len(key) > 128 {
		return errors.New("SSO replay key is invalid")
	}
	if expiresAt.IsZero() || !expiresAt.After(now) || expiresAt.Sub(now) > 24*time.Hour {
		return errors.New("SSO replay expiration is invalid")
	}
	return nil
}

func (s *Store) ClaimSSOReplay(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	now := time.Now().UTC()
	key = strings.TrimSpace(key)
	expiresAt = expiresAt.UTC()
	if err := validateSSOReplay(key, expiresAt, now); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, errors.New("store is closed")
	}
	extensionKeyValue := extensionKey("__system__", ssoReplayExtensionKind, key)
	previous, existed := s.state.Extensions[extensionKeyValue]
	if existed {
		var record ssoReplayRecord
		if json.Unmarshal(previous.Value, &record) == nil && record.ExpiresAt.After(now) {
			return false, nil
		}
	}
	removed := map[string]ExtensionObject{}
	replayCount := 0
	for candidateKey, candidate := range s.state.Extensions {
		if candidate.TenantID != "__system__" || candidate.Kind != ssoReplayExtensionKind || candidateKey == extensionKeyValue {
			continue
		}
		var record ssoReplayRecord
		if json.Unmarshal(candidate.Value, &record) != nil || !record.ExpiresAt.After(now) {
			removed[candidateKey] = candidate
			delete(s.state.Extensions, candidateKey)
			continue
		}
		replayCount++
	}
	if replayCount >= 100000 {
		for candidateKey, candidate := range removed {
			s.state.Extensions[candidateKey] = candidate
		}
		return false, errors.New("SSO replay store capacity exceeded")
	}
	payload, err := json.Marshal(ssoReplayRecord{ExpiresAt: expiresAt})
	if err != nil {
		return false, err
	}
	s.state.Extensions[extensionKeyValue] = ExtensionObject{TenantID: "__system__", Kind: ssoReplayExtensionKind, ID: key, Value: payload, CreatedAt: now, UpdatedAt: now}
	if existed {
		current := s.state.Extensions[extensionKeyValue]
		current.CreatedAt = previous.CreatedAt
		s.state.Extensions[extensionKeyValue] = current
	}
	if err := s.persistLocked(); err != nil {
		if existed {
			s.state.Extensions[extensionKeyValue] = previous
		} else {
			delete(s.state.Extensions, extensionKeyValue)
		}
		for candidateKey, candidate := range removed {
			s.state.Extensions[candidateKey] = candidate
		}
		return false, err
	}
	return true, nil
}

func (p *PostgresBackend) ClaimSSOReplay(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	key = strings.TrimSpace(key)
	expiresAt = expiresAt.UTC()
	if key == "" || len(key) > 128 || expiresAt.IsZero() {
		return false, errors.New("SSO replay claim is invalid")
	}
	c, err := p.connect(ctx)
	if err != nil {
		return false, err
	}
	defer p.release(c)
	query := `WITH clock AS (
  SELECT CURRENT_TIMESTAMP AS now
), valid AS (
  SELECT $2::timestamptz AS expires_at, now FROM clock
  WHERE $2::timestamptz>now AND $2::timestamptz<=now+interval '24 hours'
), claimed AS (
  INSERT INTO ciradar_sso_replays(key_hash,expires_at,created_at)
  SELECT $1,valid.expires_at,valid.now FROM valid
  ON CONFLICT(key_hash) DO UPDATE SET expires_at=excluded.expires_at,created_at=excluded.created_at
  WHERE ciradar_sso_replays.expires_at<=(SELECT now FROM clock)
  RETURNING key_hash
)
SELECT EXISTS(SELECT 1 FROM valid)::text,EXISTS(SELECT 1 FROM claimed)::text`
	rows, err := c.QueryParams(ctx, query, key, expiresAt)
	if err != nil {
		return false, err
	}
	row, err := requireRow(rows, 2)
	if err != nil {
		return false, err
	}
	if valueOf(row[0]) != "true" && valueOf(row[0]) != "t" {
		return false, errors.New("SSO replay expiration is invalid relative to PostgreSQL server time")
	}
	return valueOf(row[1]) == "true" || valueOf(row[1]) == "t", nil
}
