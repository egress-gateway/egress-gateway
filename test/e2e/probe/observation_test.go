package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestObservePolicyRecordsRealResponses(t *testing.T) {
	for _, unexpected := range []bool{false, true} {
		t.Run(map[bool]string{false: "transition", true: "unexpected-response"}[unexpected], func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.Header.Get("X-Request-Id") == "" {
					t.Error("missing attributable operation")
				}
				n := calls.Add(1)
				if unexpected {
					w.WriteHeader(503)
					return
				}
				if n == 1 {
					w.WriteHeader(200)
				} else {
					w.WriteHeader(403)
				}
				_, _ = w.Write([]byte("response"))
			}))
			defer server.Close()
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			observations, err := observePolicy(t.Context(), server.URL, "update", ca, `{"action":"safe"}`, 403, time.Millisecond, time.Second)
			if unexpected {
				if err == nil || len(observations.Attempts) != 1 {
					t.Fatalf("unexpected response: %+v %v", observations, err)
				}
				return
			}
			if err != nil || len(observations.Attempts) != 2 {
				t.Fatalf("transition: %+v %v", observations, err)
			}
			old, next := observations.Attempts[0], observations.Attempts[1]
			if old.Status != 200 || next.Status != 403 || old.ID == next.ID || old.ObservedAt.Before(old.StartedAt) || next.StartedAt.Before(old.ObservedAt) || next.ObservedAt.Before(next.StartedAt) || next.Body != "response" {
				t.Fatalf("invalid timing/response: %+v", observations)
			}
		})
	}
}
