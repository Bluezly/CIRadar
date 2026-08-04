package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const prefix = "enc:v1:"

func deriveKey(master string) ([]byte, error) {
	master = strings.TrimSpace(master)
	if master == "" {
		return nil, errors.New("CIRADAR_MASTER_KEY is required for encrypted secrets")
	}
	if raw, err := base64.RawURLEncoding.DecodeString(master); err == nil && len(raw) >= 32 {
		h := sha256.Sum256(raw)
		return h[:], nil
	}
	h := sha256.Sum256([]byte(master))
	return h[:], nil
}
func Encrypt(master, plain string) (string, error) {
	key, err := deriveKey(master)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := g.Seal(nil, nonce, []byte(plain), []byte("ci-radar-secret-v1"))
	payload := append(nonce, sealed...)
	return prefix + base64.RawURLEncoding.EncodeToString(payload), nil
}
func Decrypt(master, value string) (string, error) {
	if !strings.HasPrefix(value, prefix) {
		return value, nil
	}
	key, err := deriveKey(master)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted secret: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < g.NonceSize() {
		return "", errors.New("encrypted secret is truncated")
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte("ci-radar-secret-v1"))
	if err != nil {
		return "", errors.New("decrypt secret: invalid master key or ciphertext")
	}
	return string(plain), nil
}
func Resolve(master, value string) (string, error) {
	value = strings.TrimSpace(value)
	var name string
	if strings.HasPrefix(value, "env:") {
		name = strings.TrimSpace(strings.TrimPrefix(value, "env:"))
	}
	if strings.HasPrefix(value, "${ENV:") && strings.HasSuffix(value, "}") {
		name = strings.TrimSuffix(strings.TrimPrefix(value, "${ENV:"), "}")
	}
	if name != "" {
		v, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("environment secret %s is not set", name)
		}
		return v, nil
	}
	return Decrypt(master, value)
}
func GenerateMasterKey() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
