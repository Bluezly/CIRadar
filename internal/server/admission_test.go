package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestAdmissionGateRejectsWhenSaturatedAndRecovers(t *testing.T) {
	gate := newAdmissionGate(1)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	h := gate.wrap(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusNoContent)
	})

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodPost, "http://example.test/webhook", nil))
		firstDone <- rr
	}()
	<-entered

	busy := httptest.NewRecorder()
	h(busy, httptest.NewRequest(http.MethodPost, "http://example.test/webhook", nil))
	if busy.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated status=%d body=%s", busy.Code, busy.Body.String())
	}
	if busy.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After=%q", busy.Header().Get("Retry-After"))
	}
	if calls.Load() != 1 {
		t.Fatalf("saturated request entered protected handler; calls=%d", calls.Load())
	}

	close(release)
	first := <-firstDone
	if first.Code != http.StatusNoContent {
		t.Fatalf("first status=%d", first.Code)
	}

	second := httptest.NewRecorder()
	h2 := gate.wrap(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	h2(second, httptest.NewRequest(http.MethodPost, "http://example.test/webhook", nil))
	if second.Code != http.StatusNoContent || calls.Load() != 2 {
		t.Fatalf("gate did not recover: status=%d calls=%d", second.Code, calls.Load())
	}
}
