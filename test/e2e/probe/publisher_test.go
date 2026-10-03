package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPublisherSeparatesDeliveryAndPublication(t *testing.T) {
	p := &policyPublisher{bundles: map[string]publication{}}
	read := http.NewServeMux()
	read.HandleFunc("GET /bundles/{role}", p.reader)
	admin := http.NewServeMux()
	admin.HandleFunc("PUT /bundles/{role}", p.admin)
	before := time.Now().UTC()
	req := httptest.NewRequest(http.MethodPut, "/bundles/workload?revision=r1", bytes.NewBufferString("one"))
	response := httptest.NewRecorder()
	admin.ServeHTTP(response, req)
	var published publication
	if err := json.Unmarshal(response.Body.Bytes(), &published); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || published.Revision != "r1" || published.PublishedAt.Before(before) || published.PublishedAt.After(time.Now().UTC()) {
		t.Fatalf("invalid publication receipt: %+v", published)
	}
	response = httptest.NewRecorder()
	read.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/bundles/workload", nil))
	if response.Body.String() != "one" || response.Header().Get("ETag") != `"r1"` {
		t.Fatal("published bytes not immediately available")
	}
	req = httptest.NewRequest(http.MethodGet, "/bundles/workload", nil)
	req.Header.Set("If-None-Match", `"r1"`)
	response = httptest.NewRecorder()
	read.ServeHTTP(response, req)
	if response.Code != 304 {
		t.Fatal("conditional bundle request not honored")
	}
	response = httptest.NewRecorder()
	read.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/bundles/workload?revision=evil", bytes.NewBufferString("changed")))
	if response.Code != 405 {
		t.Fatal("delivery listener permitted publication")
	}
	p.publish("workload", "failure", nil, 503)
	response = httptest.NewRecorder()
	read.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/bundles/workload", nil))
	if response.Code != 503 {
		t.Fatal("controlled failure not delivered")
	}
	p.publish("workload", "r2", []byte("two"), 200)
	response = httptest.NewRecorder()
	read.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/bundles/workload", nil))
	if response.Body.String() != "two" {
		t.Fatal("publication did not recover")
	}
}
