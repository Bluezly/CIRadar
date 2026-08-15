package server

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestMarketplaceSetupStateRoundTrip(t *testing.T) {
	secret := strings.Repeat("s", 32)
	input := marketplaceSetupState{InstallationID: 4242, IssuedAt: time.Now().UTC().Truncate(time.Second)}
	sealed, err := sealMarketplaceSetupState(secret, input)
	if err != nil {
		t.Fatalf("seal state: %v", err)
	}
	got, err := openMarketplaceSetupState(secret, sealed)
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	if got.InstallationID != input.InstallationID || !got.IssuedAt.Equal(input.IssuedAt) {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, input)
	}
}

func TestMarketplaceSetupStateRejectsTampering(t *testing.T) {
	secret := strings.Repeat("s", 32)
	sealed, err := sealMarketplaceSetupState(secret, marketplaceSetupState{InstallationID: 7, IssuedAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("seal state: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("decode state: %v", err)
	}
	raw[0] ^= 1
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := openMarketplaceSetupState(secret, tampered); err == nil {
		t.Fatal("expected tampered state to be rejected")
	}
}

func TestMarketplaceSetupStateRejectsWrongSecret(t *testing.T) {
	sealed, err := sealMarketplaceSetupState(strings.Repeat("a", 32), marketplaceSetupState{InstallationID: 9, IssuedAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("seal state: %v", err)
	}
	if _, err := openMarketplaceSetupState(strings.Repeat("b", 32), sealed); err == nil {
		t.Fatal("expected state signed with another secret to be rejected")
	}
}

func TestNextGitHubLinkOnlyAcceptsGitHubAPI(t *testing.T) {
	header := `<https://api.github.com/user/installations?per_page=100&page=2>; rel="next", <https://api.github.com/user/installations?per_page=100&page=4>; rel="last"`
	got := nextGitHubLink(header)
	if !strings.Contains(got, "api.github.com/user/installations") || !strings.Contains(got, "page=2") {
		t.Fatalf("unexpected next link: %q", got)
	}
	malicious := `<https://example.com/steal>; rel="next"`
	if got := nextGitHubLink(malicious); got != "" {
		t.Fatalf("expected non-GitHub link to be rejected, got %q", got)
	}
}
