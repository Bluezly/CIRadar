package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"testing"
)

func TestEncryptRoundTrip(t *testing.T) {
	k, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := Encrypt(k, "secret-value")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(k, v)
	if err != nil {
		t.Fatal(err)
	}
	if got != "secret-value" {
		t.Fatalf("got %q", got)
	}
}
func TestResolveEnv(t *testing.T) {
	t.Setenv("CI_RADAR_TEST_SECRET", "hello")
	v, err := Resolve("", "env:CI_RADAR_TEST_SECRET")
	if err != nil || v != "hello" {
		t.Fatalf("%q %v", v, err)
	}
}

func TestResolveRejectsMalformedEnvReferences(t *testing.T) {
	for _, value := range []string{"env:", "env:   ", "${ENV:}", "${ENV:   }", "${ENV:MISSING"} {
		if got, err := Resolve("", value); err == nil {
			t.Fatalf("Resolve(%q)=%q, expected error", value, got)
		}
	}
}

func TestMasterKeyRejectsPassphrasesAndWrongLength(t *testing.T) {
	for _, key := range []string{"correct horse battery staple", "c2hvcnQ"} {
		if err := ValidateMasterKey(key); err == nil {
			t.Fatalf("weak master key %q was accepted", key)
		}
		if _, err := Encrypt(key, "secret"); err == nil {
			t.Fatalf("encryption accepted weak master key %q", key)
		}
	}
}

func TestDerivedEncryptionRoundTrip(t *testing.T) {
	value, err := EncryptDerived("0123456789abcdef0123456789abcdef|oauth|access", "payload")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptDerived("0123456789abcdef0123456789abcdef|oauth|access", value)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "payload" {
		t.Fatalf("got %q", plain)
	}
}

func TestGeneratedMasterKeyRemainsCompatibleWithLegacyCiphertext(t *testing.T) {
	master, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := legacyEncryptGeneratedKey(master, "legacy-secret")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(master, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "legacy-secret" {
		t.Fatalf("got %q", plain)
	}
}

func legacyEncryptGeneratedKey(master, plain string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(master)
	if err != nil {
		return "", err
	}
	key := sha256.Sum256(raw)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := g.Seal(nil, nonce, []byte(plain), []byte("ci-radar-secret-v1"))
	return prefix + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func TestDerivedEncryptionRejectsWeakMaterial(t *testing.T) {
	if _, err := EncryptDerived("short", "payload"); err == nil {
		t.Fatal("derived encryption accepted weak key material")
	}
}

func TestDerivedDecryptionRejectsPlaintextFallback(t *testing.T) {
	if _, err := DecryptDerived("0123456789abcdef0123456789abcdef|oauth|access", `{"id":"forged"}`); err == nil {
		t.Fatal("derived decryption accepted unsigned plaintext")
	}
}
