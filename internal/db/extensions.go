package db

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type ExtensionObject struct {
	TenantID  string          `json:"tenant_id"`
	Kind      string          `json:"kind"`
	ID        string          `json:"id"`
	Value     json.RawMessage `json:"value"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

func extensionKey(tenant, kind, id string) string {
	return normalizeTenant(tenant) + "|" + strings.ToLower(strings.TrimSpace(kind)) + "|" + strings.TrimSpace(id)
}

func (s *Store) PutObject(ctx context.Context, tenant, kind, id string, value any) error {
	_ = ctx
	tenant = normalizeTenant(tenant)
	kind = strings.ToLower(strings.TrimSpace(kind))
	id = strings.TrimSpace(id)
	if kind == "" || id == "" {
		return fmt.Errorf("kind and id are required")
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	key := extensionKey(tenant, kind, id)
	old, existed := s.state.Extensions[key]
	obj := old
	if !existed {
		obj = ExtensionObject{TenantID: tenant, Kind: kind, ID: id, CreatedAt: now}
	}
	obj.Value = append(json.RawMessage(nil), b...)
	obj.UpdatedAt = now
	s.state.Extensions[key] = obj
	if err := s.persistLocked(); err != nil {
		if existed {
			s.state.Extensions[key] = old
		} else {
			delete(s.state.Extensions, key)
		}
		return err
	}
	return nil
}

func (s *Store) PutObjectIfKindBelowLimit(ctx context.Context, tenant, kind, id string, value any, limit int) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	tenant = normalizeTenant(tenant)
	kind = strings.ToLower(strings.TrimSpace(kind))
	id = strings.TrimSpace(id)
	if kind == "" || id == "" || limit < 1 {
		return false, fmt.Errorf("kind, id, and a positive limit are required")
	}
	b, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	key := extensionKey(tenant, kind, id)
	old, existed := s.state.Extensions[key]
	if !existed {
		count := 0
		for _, object := range s.state.Extensions {
			if object.TenantID == tenant && object.Kind == kind {
				count++
			}
		}
		if count >= limit {
			return false, nil
		}
	}
	object := old
	if !existed {
		object = ExtensionObject{TenantID: tenant, Kind: kind, ID: id, CreatedAt: now}
	}
	object.Value = append(json.RawMessage(nil), b...)
	object.UpdatedAt = now
	s.state.Extensions[key] = object
	if err := s.persistLocked(); err != nil {
		if existed {
			s.state.Extensions[key] = old
		} else {
			delete(s.state.Extensions, key)
		}
		return false, err
	}
	return true, nil
}

func (s *Store) GetObject(ctx context.Context, tenant, kind, id string, out any) (bool, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.state.Extensions[extensionKey(tenant, kind, id)]
	if !ok {
		return false, nil
	}
	if out == nil {
		return true, nil
	}
	return true, json.Unmarshal(obj.Value, out)
}

func (s *Store) ListObjects(ctx context.Context, tenant, kind string, limit int) ([]ExtensionObject, error) {
	_ = ctx
	tenant = normalizeTenant(tenant)
	kind = strings.ToLower(strings.TrimSpace(kind))
	if limit < 1 || limit > 10000 {
		limit = 500
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ExtensionObject, 0)
	for _, obj := range s.state.Extensions {
		if obj.TenantID == tenant && obj.Kind == kind {
			copyObj := obj
			copyObj.Value = append(json.RawMessage(nil), obj.Value...)
			out = append(out, copyObj)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) DeleteObject(ctx context.Context, tenant, kind, id string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	key := extensionKey(tenant, kind, id)
	old, existed := s.state.Extensions[key]
	delete(s.state.Extensions, key)
	if err := s.persistLocked(); err != nil {
		if existed {
			s.state.Extensions[key] = old
		}
		return err
	}
	return nil
}
