package server

import (
	"net/http"
	"strconv"
)

type admissionGate struct {
	slots chan struct{}
}

func newAdmissionGate(limit int) *admissionGate {
	if limit < 1 {
		limit = 1
	}
	return &admissionGate{slots: make(chan struct{}, limit)}
}

func (g *admissionGate) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case g.slots <- struct{}{}:
			defer func() { <-g.slots }()
			next(w, r)
		default:
			w.Header().Set("Retry-After", strconv.Itoa(1))
			writeError(w, http.StatusServiceUnavailable, "server is busy processing this request")
		}
	}
}
