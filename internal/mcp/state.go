package mcp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/Bluezly/CIRadar/internal/model"
)

type session struct {
	ID        string
	TenantID  string
	Actor     string
	Role      model.Role
	ExpiresAt time.Time
	Events    chan []byte
}

type confirmation struct {
	Token     string
	TenantID  string
	Actor     string
	Action    string
	Target    string
	Reason    string
	ExpiresAt time.Time
}

type Runtime struct {
	mu            sync.Mutex
	sessions      map[string]*session
	confirmations map[string]confirmation
}

func NewRuntime() *Runtime {
	return &Runtime{sessions: map[string]*session{}, confirmations: map[string]confirmation{}}
}

func (r *Runtime) CreateSession(principal model.Principal) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupLocked()
	id, err := randomToken(24)
	if err != nil {
		return "", err
	}
	r.sessions[id] = &session{ID: id, TenantID: principal.TenantID, Actor: principal.Name, Role: principal.Role, ExpiresAt: time.Now().Add(8 * time.Hour), Events: make(chan []byte, 32)}
	return id, nil
}

func (r *Runtime) Session(id string, principal model.Principal) (*session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupLocked()
	value, ok := r.sessions[id]
	if !ok || value.TenantID != principal.TenantID || value.Role != principal.Role {
		return nil, false
	}
	value.ExpiresAt = time.Now().Add(8 * time.Hour)
	return value, true
}

func (r *Runtime) CloseSession(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if value := r.sessions[id]; value != nil {
		close(value.Events)
		delete(r.sessions, id)
	}
}

func (r *Runtime) NotifyTenant(tenant string, payload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupLocked()
	for _, value := range r.sessions {
		if value.TenantID != tenant {
			continue
		}
		select {
		case value.Events <- payload:
		default:
		}
	}
}

func (r *Runtime) Prepare(principal model.Principal, action, target, reason string) (string, time.Time, error) {
	if !operatorOrHigher(principal) {
		return "", time.Time{}, errors.New("operator permission is required")
	}
	if action == "" || target == "" {
		return "", time.Time{}, errors.New("action and target are required")
	}
	if !allowedAction(action) {
		return "", time.Time{}, errors.New("unsupported write action")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupLocked()
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expires := time.Now().Add(5 * time.Minute)
	r.confirmations[token] = confirmation{Token: token, TenantID: principal.TenantID, Actor: principal.Name, Action: action, Target: target, Reason: reason, ExpiresAt: expires}
	return token, expires, nil
}

func (r *Runtime) Consume(principal model.Principal, token, action, target string) (confirmation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupLocked()
	value, ok := r.confirmations[token]
	if !ok || value.TenantID != principal.TenantID || value.Actor != principal.Name || value.Action != action || value.Target != target {
		return confirmation{}, errors.New("invalid or expired confirmation token")
	}
	delete(r.confirmations, token)
	return value, nil
}

func (r *Runtime) cleanupLocked() {
	now := time.Now()
	for id, value := range r.sessions {
		if now.After(value.ExpiresAt) {
			close(value.Events)
			delete(r.sessions, id)
		}
	}
	for token, value := range r.confirmations {
		if now.After(value.ExpiresAt) {
			delete(r.confirmations, token)
		}
	}
}

func allowedAction(action string) bool {
	switch action {
	case "acknowledge_incident", "resolve_incident", "quarantine_test", "unquarantine_test", "create_draft_repair_pr":
		return true
	default:
		return false
	}
}

func operatorOrHigher(principal model.Principal) bool {
	return principal.Root || principal.Role == model.RoleOperator || principal.Role == model.RoleAdmin
}

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func WaitEvent(ctx context.Context, value *session) ([]byte, bool) {
	select {
	case event, ok := <-value.Events:
		return event, ok
	case <-ctx.Done():
		return nil, false
	}
}
