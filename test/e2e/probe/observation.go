package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type policyObservation struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"startedAt"`
	ObservedAt time.Time `json:"observedAt"`
	Status     int       `json:"status"`
	Body       string    `json:"body"`
}

type policyObservations struct {
	Interval time.Duration       `json:"intervalNs"`
	Attempts []policyObservation `json:"attempts"`
}

// Times are recorded by the application-side probe in the same kind VM clock
// domain as the publisher and OPA. kubectl round trips are outside this interval.
func observePolicy(ctx context.Context, target, id, ca, payload string, want int, interval, timeout time.Duration) (policyObservations, error) {
	result := policyObservations{Interval: interval}
	roots := x509.NewCertPool()
	raw, err := os.ReadFile(ca)
	if err != nil {
		return result, err
	}
	if !roots.AppendCertsFromPEM(raw) {
		return result, fmt.Errorf("invalid policy probe trust bundle")
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for i := 0; ; i++ {
		sample := policyObservation{ID: fmt.Sprintf("%s-%d", id, i), StartedAt: time.Now().UTC()}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(payload))
		if err != nil {
			return result, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", sample.ID)
		response, err := client.Do(req)
		if err != nil {
			return result, err
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		closeErr := response.Body.Close()
		sample.Status, sample.Body, sample.ObservedAt = response.StatusCode, string(body), time.Now().UTC()
		result.Attempts = append(result.Attempts, sample)
		if readErr != nil {
			return result, readErr
		}
		if closeErr != nil {
			return result, closeErr
		}
		if sample.Status == want {
			return result, nil
		}
		if sample.Status != http.StatusOK && sample.Status != http.StatusForbidden {
			return result, fmt.Errorf("unexpected policy probe response: %d", sample.Status)
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(interval):
		}
	}
}
