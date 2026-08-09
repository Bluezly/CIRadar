package analyzer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFingerprintWithoutConfiguredKeyStillUsesHMAC(t *testing.T) {
	material := []byte("credential-shaped-material")
	got := fingerprintValue(nil, material)
	mac := hmac.New(sha256.New, nil)
	_, _ = mac.Write(material)
	want := hex.EncodeToString(mac.Sum(nil)[:16])
	if got != want {
		t.Fatalf("fingerprint=%q want=%q", got, want)
	}
	raw := sha256.Sum256(material)
	if got == hex.EncodeToString(raw[:16]) {
		t.Fatal("fingerprint fell back to an unkeyed raw digest")
	}
}
