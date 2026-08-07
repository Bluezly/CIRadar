package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func TestRefreshStreamWriteDeadlineExtendsStreamingWindow(t *testing.T) {
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	before := time.Now().Add(29 * time.Second)
	if err := refreshStreamWriteDeadline(w); err != nil {
		t.Fatalf("refreshStreamWriteDeadline: %v", err)
	}
	if len(w.deadlines) != 1 {
		t.Fatalf("got %d deadlines, want 1", len(w.deadlines))
	}
	if !w.deadlines[0].After(before) {
		t.Fatalf("deadline %v was not extended far enough", w.deadlines[0])
	}
}

func TestRefreshStreamWriteDeadlineToleratesUnsupportedWriter(t *testing.T) {
	w := struct{ http.ResponseWriter }{ResponseWriter: httptest.NewRecorder()}
	if err := refreshStreamWriteDeadline(w); err != nil {
		t.Fatalf("unsupported writer should not fail stream: %v", err)
	}
}
