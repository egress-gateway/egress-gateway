//go:build image

package https_test

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egress-gateway/egress-gateway/test/telemetry"
	"github.com/google/uuid"
)

func TestTracing(t *testing.T) {
	for _, mode := range []string{"disabled", "grpc", "http/protobuf"} {
		t.Run(strings.ReplaceAll(mode, "/", "-"), func(t *testing.T) { runHTTPS(t, mode) })
	}
}

func startTracingCollector(t *testing.T, state string, start func(string, ...string) string) string {
	t.Helper()
	ca := makeCA(t, state, "collector-ca")
	issue(t, state, ca, "collector", []string{"collector"}, "")
	issue(t, state, ca, "collector-client", nil, "")
	// These credentials belong only to this disposable fixture.
	sum := sha1.Sum([]byte("fixture-password"))
	config := fmt.Sprintf(`extensions:
  basicauth:
    htpasswd:
      inline: "fixture:{SHA}%s"
receivers:
  otlp/opa:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        tls: &tls
          cert_file: /certs/collector.pem
          key_file: /certs/collector-key.pem
          client_ca_file: /certs/collector-ca.pem
        auth:
          authenticator: basicauth
      http:
        endpoint: 0.0.0.0:4318
        tls: *tls
        auth:
          authenticator: basicauth
  otlp/envoy:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4319
exporters:
  file/opa:
    path: /data/opa.json
    flush_interval: 100ms
  file/envoy:
    path: /data/envoy.json
    flush_interval: 100ms
service:
  extensions: [basicauth]
  pipelines:
    traces/opa:
      receivers: [otlp/opa]
      exporters: [file/opa]
    traces/envoy:
      receivers: [otlp/envoy]
      exporters: [file/envoy]
`, base64.StdEncoding.EncodeToString(sum[:]))
	writeFixture(t, filepath.Join(state, "collector.yaml"), []byte(config))
	data := filepath.Join(state, "collected")
	if err := os.Mkdir(data, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(data, 0777); err != nil {
		t.Fatal(err)
	}
	args := []string{"-p", "127.0.0.1::4318", "-v", filepath.Join(state, "collector.yaml") + ":/etc/otelcol-contrib/config.yaml:ro", "-v", data + ":/data"}
	for _, name := range []string{"collector.pem", "collector-key.pem", "collector-ca.pem"} {
		args = append(args, "-v", filepath.Join(state, name)+":/certs/"+name+":ro")
	}
	id := start("collector", append(args, telemetry.CollectorImage)...)
	verifyCollectorTrust(t, state, id)
	return id
}

func tracingEnvironment(state, role, mode string) []string {
	if mode == "disabled" {
		return []string{"-e", "OTEL_TRACES_EXPORTER=none"}
	}
	port := "4317"
	endpointSuffix := ""
	if mode == "http/protobuf" {
		port = "4318"
		endpointSuffix = "/v1/traces"
	}
	args := []string{"-e", "OTEL_SERVICE_NAME=" + role + "-opa", "-e", "OTEL_TRACES_SAMPLER=parentbased_always_on",
		"-e", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=" + mode,
		"-e", "OTEL_EXPORTER_OTLP_ENDPOINT=http://must-not-be-used:9999",
		"-e", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://collector:" + port + endpointSuffix,
		"-e", "OTEL_EXPORTER_OTLP_HEADERS=authorization=wrong-general-token",
		"-e", "OTEL_EXPORTER_OTLP_TRACES_HEADERS=authorization=Basic%20" + base64.StdEncoding.EncodeToString([]byte("fixture:fixture-password")),
		"-e", "OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE=/certs/collector-ca.pem",
		"-e", "OTEL_EXPORTER_OTLP_TRACES_CLIENT_CERTIFICATE=/certs/collector-client.pem",
		"-e", "OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY=/certs/collector-client-key.pem",
		"-e", "OTEL_BSP_SCHEDULE_DELAY=100", "-e", "OTEL_BSP_EXPORT_TIMEOUT=1000",
		"-e", "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT=1000", "-e", "OTEL_BSP_MAX_QUEUE_SIZE=64", "-e", "OTEL_BSP_MAX_EXPORT_BATCH_SIZE=16",
		"-e", "OTEL_RESOURCE_ATTRIBUTES=service.namespace=component,service.version=fixture"}
	for _, name := range []string{"collector-ca.pem", "collector-client.pem", "collector-client-key.pem"} {
		args = append(args, "-v", filepath.Join(state, name)+":/certs/"+name+":ro")
	}
	return args
}

func tracingBootstrap(t *testing.T, state, source, role string, enabled bool) string {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	var bootstrap map[string]any
	if err := json.Unmarshal(raw, &bootstrap); err != nil {
		t.Fatal(err)
	}
	if enabled {
		resources := bootstrap["static_resources"].(map[string]any)
		cluster := map[string]any{"name": "collector", "connect_timeout": "1s", "type": "STRICT_DNS", "http2_protocol_options": map[string]any{},
			"load_assignment": map[string]any{"cluster_name": "collector", "endpoints": []any{map[string]any{"lb_endpoints": []any{map[string]any{"endpoint": map[string]any{"address": map[string]any{"socket_address": map[string]any{"address": "collector", "port_value": 4319}}}}}}}}}
		resources["clusters"] = append(resources["clusters"].([]any), cluster)
		for _, l := range resources["listeners"].([]any) {
			for _, ch := range l.(map[string]any)["filter_chains"].([]any) {
				for _, f := range ch.(map[string]any)["filters"].([]any) {
					filter := f.(map[string]any)
					if filter["name"] != "envoy.filters.network.http_connection_manager" {
						continue
					}
					hcm := filter["typed_config"].(map[string]any)
					hcm["request_id_extension"] = map[string]any{"typed_config": map[string]any{"@type": "type.googleapis.com/envoy.extensions.request_id.uuid.v3.UuidRequestIdConfig", "pack_trace_reason": false, "use_request_id_for_trace_sampling": false}}
					hcm["tracing"] = map[string]any{"random_sampling": map[string]any{"value": 100}, "provider": map[string]any{"name": "envoy.tracers.opentelemetry", "typed_config": map[string]any{
						"@type": "type.googleapis.com/envoy.config.trace.v3.OpenTelemetryConfig", "service_name": role + "-envoy", "grpc_service": map[string]any{"envoy_grpc": map[string]any{"cluster_name": "collector"}, "timeout": "1s"}}}}
				}
			}
		}
	}
	raw, err = json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, role+"-tracing.json")
	writeFixture(t, path, raw)
	return path
}

func writeFixture(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
}

func verifyTracing(t *testing.T, state, mode, collector, workload, egress, host string, send func(*testing.T, string, string, map[string]string) (int, string, *tls.ConnectionState)) {
	t.Helper()
	read := func() ([]telemetry.Span, int) {
		t.Helper()
		var spans []telemetry.Span
		size := 0
		for _, file := range []string{"envoy.json", "opa.json"} {
			raw, err := os.ReadFile(filepath.Join(state, "collected", file))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			list, err := telemetry.Read(raw)
			if err != nil {
				t.Fatal(err)
			}
			size += len(raw)
			for _, span := range list {
				suffix := "-envoy"
				if file == "opa.json" {
					suffix = "-opa"
				}
				if !strings.HasSuffix(span.Service, suffix) {
					t.Fatalf("exporter ownership crossed: %s in %s", span.Service, file)
				}
			}
			spans = append(spans, list...)
		}
		return spans, size
	}
	var latency time.Duration
	for i := range 12 {
		started := time.Now()
		code, _, _ := send(t, host, `{"action":"safe"}`, map[string]string{"X-Request-Id": fmt.Sprintf("measurement-%d", i)})
		latency += time.Since(started)
		if code != 200 {
			t.Fatalf("measurement response: %d", code)
		}
	}
	if mode == "disabled" {
		time.Sleep(2 * time.Second)
		spans, bytes := read()
		if len(spans) != 0 || bytes != 0 {
			t.Fatalf("disabled exporter sent spans=%d bytes=%d", len(spans), bytes)
		}
		t.Logf("tracing disabled: requests=12 mean_latency=%s collected_spans=0 collected_bytes=0", latency/12)
		return
	}
	for _, parent := range []bool{true, false} {
		id := uuid.NewString()
		traceID := strings.ReplaceAll(id, "-", "")
		headers := map[string]string{"X-Request-Id": id}
		if parent {
			headers["traceparent"] = "00-" + traceID + "-0123456789abcdef-01"
		}
		code, _, _ := send(t, host, `{"action":"safe"}`, headers)
		if code != 200 {
			t.Fatalf("traced response: %d", code)
		}
		var reason string
		t.Cleanup(func() {
			if t.Failed() && reason != "" {
				spans, _ := read()
				t.Logf("last correlation failure: %s; spans=%+v", reason, spans)
			}
		})
		until(t, 20*time.Second, func() bool {
			spans, _ := read()
			var w, e telemetry.Span
			for _, s := range spans {
				if s.Service == "workload-envoy" && (parent && s.TraceID == traceID || !parent && s.Attributes["guid:x-request-id"] == id) && s.Attributes["http.method"] == "POST" {
					w = s
				}
			}
			if w.ID == "" {
				reason = "workload span missing"
				return false
			}
			if parent && !telemetry.Descends(spans, w, "0123456789abcdef") {
				reason = "incoming parent missing"
				return false
			}
			if !parent && w.ParentID != "" {
				reason = "generated root has unexpected parent"
				return false
			}
			for _, s := range spans {
				if s.Service == "egress-envoy" && s.Attributes["http.method"] == "POST" && s.TraceID == w.TraceID && telemetry.Descends(spans, s, w.ID) {
					e = s
					break
				}
			}
			if e.ID == "" {
				reason = "egress descendant missing"
				return false
			}
			for _, role := range []string{"workload", "egress"} {
				ancestor := w.ID
				if role == "egress" {
					ancestor = e.ID
				}
				found := false
				for _, s := range spans {
					if s.Service == role+"-opa" && s.TraceID == w.TraceID && strings.Contains(s.Name, "Authorization/Check") && telemetry.Descends(spans, s, ancestor) {
						found = true
					}
				}
				if !found {
					reason = role + " OPA authorization descendant missing"
					return false
				}
			}
			reason = ""
			t.Logf("context=%t trace=%s: both Envoy and OPA roles have linked spans", parent, w.TraceID)
			return true
		})
		if reason != "" {
			t.Fatal(reason)
		}
	}
	spans, size := read()
	t.Logf("tracing %s: requests=12 mean_latency=%s collected_spans=%d collected_bytes=%d", mode, latency/12, len(spans), size)
	run(t, "docker", "stop", "-t", "2", collector)
	spans, size = read()
	var faultLatency time.Duration
	for i := range 80 {
		action, expected := "safe", 200
		if i%3 == 1 {
			action, expected = "local-deny", 403
		}
		if i%3 == 2 {
			action, expected = "egress-deny", 403
		}
		started := time.Now()
		code, _, _ := send(t, host, `{"action":"`+action+`"}`, map[string]string{"X-Request-Id": fmt.Sprintf("collector-down-%d", i)})
		faultLatency += time.Since(started)
		if code != expected {
			t.Fatalf("Collector failure changed authorization: %d != %d", code, expected)
		}
	}
	for _, proxy := range []string{workload, egress} {
		run(t, "docker", "exec", proxy, "gateway-daemon", "ready")
	}
	after, afterSize := read()
	if len(after) != len(spans) || afterSize != size {
		t.Fatal("unexpected export after Collector stopped")
	}
	t.Logf("Collector unavailable: requests=80 mean_latency=%s collected_delta=0; both proxies ready", faultLatency/80)
}

// Negative handshakes prove the fixture actually enforces client trust and
// authorization; successful exports alone would not distinguish an open receiver.
func verifyCollectorTrust(t *testing.T, state, id string) {
	t.Helper()
	target := strings.TrimSpace(run(t, "docker", "port", id, "4318/tcp"))
	roots := x509.NewCertPool()
	raw, err := os.ReadFile(filepath.Join(state, "collector-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots.AppendCertsFromPEM(raw)
	cert, err := tls.LoadX509KeyPair(filepath.Join(state, "collector-client.pem"), filepath.Join(state, "collector-client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	check := func(c *tls.Config, auth string) (int, error) {
		tr := &http.Transport{TLSClientConfig: c, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", target)
		}}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "https://collector/v1/traces", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set("Authorization", auth)
		response, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer response.Body.Close()
		io.Copy(io.Discard, response.Body)
		return response.StatusCode, nil
	}
	good := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("fixture:fixture-password"))
	until(t, 10*time.Second, func() bool { code, err := check(good, auth); return err == nil && code == 200 })
	if code, err := check(good, "Basic wrong"); err != nil || code != 401 {
		t.Fatalf("Collector did not reject bad authentication: status=%d err=%v", code, err)
	}
	if _, err := check(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, auth); err == nil {
		t.Fatal("Collector accepted missing client certificate")
	}
	if _, err := check(&tls.Config{RootCAs: x509.NewCertPool(), Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, auth); err == nil {
		t.Fatal("untrusted Collector certificate accepted")
	}
}
