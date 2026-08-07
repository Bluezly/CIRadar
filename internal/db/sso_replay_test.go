package db

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupRemovesOnlyExpiredSSOReplayRecords(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UTC()
	expired, _ := json.Marshal(ssoReplayRecord{ExpiresAt: now.Add(-time.Minute)})
	valid, _ := json.Marshal(ssoReplayRecord{ExpiresAt: now.Add(time.Hour)})
	store.mu.Lock()
	store.state.Extensions[extensionKey("__system__", ssoReplayExtensionKind, "expired")] = ExtensionObject{TenantID: "__system__", Kind: ssoReplayExtensionKind, ID: "expired", Value: expired, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour)}
	store.state.Extensions[extensionKey("__system__", ssoReplayExtensionKind, "valid")] = ExtensionObject{TenantID: "__system__", Kind: ssoReplayExtensionKind, ID: "valid", Value: valid, CreatedAt: now, UpdatedAt: now}
	store.state.Extensions[extensionKey("default", "custom", "keep")] = ExtensionObject{TenantID: "default", Kind: "custom", ID: "keep", Value: []byte(`{"ok":true}`), CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour)}
	if err := store.persistLocked(); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()

	if err := store.Cleanup(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.state.Extensions[extensionKey("__system__", ssoReplayExtensionKind, "expired")]; ok {
		t.Fatal("expired SSO replay record survived cleanup")
	}
	if _, ok := store.state.Extensions[extensionKey("__system__", ssoReplayExtensionKind, "valid")]; !ok {
		t.Fatal("valid SSO replay record was removed")
	}
	if _, ok := store.state.Extensions[extensionKey("default", "custom", "keep")]; !ok {
		t.Fatal("unrelated extension was removed")
	}
}

func TestStoreSSOReplayClaimRejectsDuplicate(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	expires := time.Now().UTC().Add(5 * time.Minute)
	claimed, err := store.ClaimSSOReplay(context.Background(), "same-response", expires)
	if err != nil || !claimed {
		t.Fatalf("first claim claimed=%v err=%v", claimed, err)
	}
	claimed, err = store.ClaimSSOReplay(context.Background(), "same-response", expires)
	if err != nil || claimed {
		t.Fatalf("duplicate claim claimed=%v err=%v", claimed, err)
	}
}
