package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type publication struct {
	Role        string    `json:"role"`
	Revision    string    `json:"revision"`
	PublishedAt time.Time `json:"publishedAt"`
	Digest      string    `json:"digest"`
	Status      int       `json:"status"`
	body        []byte
}

type policyPublisher struct {
	mu      sync.RWMutex
	bundles map[string]publication
}

func (p *policyPublisher) publish(role, revision string, body []byte, status int) publication {
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	p.mu.Lock()
	defer p.mu.Unlock()
	value := publication{Role: role, Revision: revision, PublishedAt: time.Now().UTC(), Digest: digest, Status: status, body: body}
	p.bundles[role] = value
	return value
}

func (p *policyPublisher) reader(w http.ResponseWriter, r *http.Request) {
	role := r.PathValue("role")
	p.mu.RLock()
	value, ok := p.bundles[role]
	p.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if value.Status != http.StatusOK {
		w.WriteHeader(value.Status)
		return
	}
	etag := strconv.Quote(value.Revision)
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	_, _ = w.Write(value.body)
}

func (p *policyPublisher) admin(w http.ResponseWriter, r *http.Request) {
	role := r.PathValue("role")
	if role != "workload" && role != "egress" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		p.mu.RLock()
		value := p.bundles[role]
		p.mu.RUnlock()
		_ = json.NewEncoder(w).Encode(value)
		return
	}
	revision := r.URL.Query().Get("revision")
	if revision == "" {
		http.Error(w, "revision required", http.StatusBadRequest)
		return
	}
	status := http.StatusOK
	if raw := r.URL.Query().Get("status"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 400 || parsed > 599 {
			http.Error(w, "invalid failure status", http.StatusBadRequest)
			return
		}
		status = parsed
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	value := p.publish(role, revision, body, status)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

// The fixture exposes read-only bundle delivery. Only the loopback listener
// accepts publication, through the test runner's authenticated kubectl access.
func servePolicies(ctx context.Context, dir string) error {
	p := &policyPublisher{bundles: map[string]publication{}}
	for _, role := range []string{"workload", "egress"} {
		body, err := os.ReadFile(filepath.Join(dir, role, "workload.tar.gz"))
		if err != nil {
			return err
		}
		p.publish(role, "fixture-"+role, body, http.StatusOK)
	}
	read := http.NewServeMux()
	read.HandleFunc("GET /bundles/{role}", p.reader)
	admin := http.NewServeMux()
	admin.HandleFunc("PUT /bundles/{role}", p.admin)
	admin.HandleFunc("GET /bundles/{role}", p.admin)
	servers := []*http.Server{{Addr: ":8085", Handler: read, ReadHeaderTimeout: 5 * time.Second}, {Addr: "127.0.0.1:8086", Handler: admin, ReadHeaderTimeout: 5 * time.Second}}
	errs := make(chan error, len(servers))
	for _, server := range servers {
		defer server.Close()
		go func() { errs <- server.ListenAndServe() }()
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
