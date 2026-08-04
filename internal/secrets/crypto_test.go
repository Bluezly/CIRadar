package secrets

import "testing"

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
