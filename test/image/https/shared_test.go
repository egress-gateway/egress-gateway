//go:build image

package https_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/extension"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/request"
	opabundle "github.com/open-policy-agent/opa/v1/bundle"
	opastatus "github.com/open-policy-agent/opa/v1/plugins/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestSharedPolicyInspection(t *testing.T) { runHTTPSMode(t, "", true) }

func stageSharedPolicy(t *testing.T, state, role string) *imagePolicySource {
	t.Helper()
	dir := filepath.Join(state, role+"-policy")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{protodesc.ToFileDescriptorProto(health.File_grpc_health_v1_health_proto)}}
	descriptor, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	ref := workload.ArtifactRef{URL: "https://fixture.example/health.pb", Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(descriptor))}
	hosts := []workload.HostMatcher{{Type: workload.DomainSuffix, Value: "origin.test"}}
	values := []string{"safe", "egress-deny"}
	if role == "egress" {
		values = []string{"safe"}
	}
	p := workload.Policy{RequestConstraints: []workload.Constraint{
		{Name: "http-body", Match: workload.Match{Hosts: hosts, HTTP: &workload.HTTPMatch{Paths: []string{"/body"}}}, Decode: &workload.Decoder{Format: workload.JSON}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/action"), Operator: workload.In, Values: values}}},
		{Name: "rpc-body", Match: workload.Match{Hosts: hosts, GRPC: &workload.GRPCMatch{Service: "grpc.health.v1.Health", Methods: []string{"Check"}}}, Decode: &workload.Decoder{Format: workload.Protobuf, DescriptorSet: &ref}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/service"), Operator: workload.In, Values: values}}},
		{Name: "rpc-metadata", Match: workload.Match{Hosts: hosts, GRPC: &workload.GRPCMatch{Service: "grpc.health.v1.Health"}}, Require: []workload.Requirement{{Source: workload.GRPCMetadata, Name: new("x-role"), Operator: workload.In, Values: []string{"reader"}}}},
		{Name: "http-carrier", Match: workload.Match{Hosts: hosts, HTTP: &workload.HTTPMatch{Paths: []string{"/grpc.health.v1.Health/Check"}}}, Require: []workload.Requirement{{Source: workload.Header, Name: new("x-carrier"), Operator: workload.NotIn, Values: []string{"blocked"}}}},
	}}
	archive, err := policybundle.BuildExecution(p, "image-"+role)
	if err != nil {
		t.Fatal(err)
	}
	cfg := extension.Config{Role: role, Descriptors: []extension.DescriptorFile{{URL: ref.URL, Digest: ref.Digest, Path: "/policy/health.pb"}}}
	if role == "egress" {
		cfg.AllowedPeers = []string{"spiffe://fixture.test/ns/gateway/sa/workload"}
	}
	source := &imagePolicySource{raw: archive, status: 503}
	server := httptest.NewUnstartedServer(source)
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	port := listener.Addr().(*net.TCPAddr).Port
	raw, err := json.Marshal(map[string]any{
		"services": map[string]any{"publisher": map[string]any{"url": fmt.Sprintf("http://host.docker.internal:%d", port)}},
		"status":   map[string]any{"console": true},
		"plugins":  map[string]any{extension.PluginName: cfg, "envoy_ext_authz_grpc": map[string]any{"path": extension.DecisionPath, "skip-request-body-parse": true}},
		"bundles":  map[string]any{"workload": map[string]any{"service": "publisher", "resource": "bundle", "polling": map[string]any{"min_delay_seconds": 1, "max_delay_seconds": 1}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"opa.json": raw, "workload.tar.gz": archive, "health.pb": descriptor} {
		writeFixture(t, filepath.Join(dir, name), b)
	}
	return source
}

func sharedBootstrap(t *testing.T, state, path, role string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var bootstrap map[string]any
	if err := json.Unmarshal(raw, &bootstrap); err != nil {
		t.Fatal(err)
	}
	static := bootstrap["static_resources"].(map[string]any)
	for _, item := range static["listeners"].([]any) {
		listener := item.(map[string]any)
		for _, item := range listener["filter_chains"].([]any) {
			chain := item.(map[string]any)
			if socket, ok := chain["transport_socket"].(map[string]any); ok {
				socket["typed_config"].(map[string]any)["common_tls_context"].(map[string]any)["alpn_protocols"] = []string{"h2", "http/1.1"}
			}
		}
	}
	for _, item := range static["clusters"].([]any) {
		cluster := item.(map[string]any)
		if cluster["name"] != "next_hop" {
			continue
		}
		cluster["typed_extension_protocol_options"] = map[string]any{"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]any{"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions", "auto_config": map[string]any{"http_protocol_options": map[string]any{}, "http2_protocol_options": map[string]any{}}}}
		cluster["transport_socket"].(map[string]any)["typed_config"].(map[string]any)["common_tls_context"].(map[string]any)["alpn_protocols"] = []string{"h2", "http/1.1"}
		if role == "egress" {
			cluster["typed_extension_protocol_options"].(map[string]any)["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].(map[string]any)["upstream_http_protocol_options"] = map[string]any{"auto_sni": true, "auto_san_validation": true}
		}
	}
	addSharedHTTPListener(t, static, role)
	raw, err = json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(state, role+"-shared-envoy.json")
	writeFixture(t, path, raw)
	return path
}

func runSharedTraffic(t *testing.T, state, host, workloadID, egressID, originID string, roots *x509.CertPool, httpClient *http.Client) {
	t.Helper()
	authority := host + ":8443"
	var observations []sharedDelivery
	record := func(id string, allowed bool, denier string) {
		observations = append(observations, sharedDelivery{id, allowed, denier})
	}
	target := published(t, workloadID)
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
	}
	conn, err := grpc.NewClient("passthrough:///"+authority, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})), grpc.WithContextDialer(dial), grpc.WithAuthority(authority))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rpc := health.NewHealthClient(conn)
	for _, tc := range []struct {
		name, service, role, carrier string
		allow                        bool
		denier                       string
	}{
		{"safe", "safe", "reader", "open", true, ""},
		{"workload-payload", "local-deny", "reader", "open", false, "workload"},
		{"egress-payload", "egress-deny", "reader", "open", false, "egress"},
		{"metadata", "safe", "writer", "open", false, "workload"},
		{"carrier", "safe", "reader", "blocked", false, "workload"},
		{"repeated-metadata", "safe", "reader", "open", false, "workload"},
	} {
		t.Run("grpc-"+tc.name, func(t *testing.T) {
			id := "shared-grpc-" + tc.name
			md := metadata.Pairs("x-request-id", id, "x-role", tc.role, "x-carrier", tc.carrier)
			if tc.name == "repeated-metadata" {
				md.Append("x-role", "writer")
			}
			ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(t.Context(), md), 10*time.Second)
			defer cancel()
			started := time.Now()
			response, err := rpc.Check(ctx, &health.HealthCheckRequest{Service: tc.service})
			t.Logf("RPC elapsed=%s allowed=%v", time.Since(started), err == nil)
			if tc.allow {
				if err != nil || response.Status != health.HealthCheckResponse_SERVING {
					t.Fatalf("allowed RPC: %v %v", response, err)
				}
			} else if err == nil {
				t.Fatal("denied RPC reached origin")
			}
			record(id, tc.allow, tc.denier)
		})
	}
	for _, tc := range []struct {
		name, body, denier string
		status             int
	}{
		{"safe", `{"action":"safe"}`, "", 200},
		{"egress", `{"action":"egress-deny"}`, "egress", 403},
		{"invalid", `{"action":`, "workload", 403},
		{"duplicate", `{"action":"safe","action":"local-deny"}`, "workload", 403},
		{"trailing", `{"action":"safe"} {}`, "workload", 403},
	} {
		t.Run("json-"+tc.name, func(t *testing.T) {
			id := "shared-http-" + tc.name
			req, err := http.NewRequestWithContext(t.Context(), "POST", "https://"+authority+"/body", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Request-Id", id)
			started := time.Now()
			response, err := httpClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			t.Logf("HTTP elapsed=%s status=%d", time.Since(started), response.StatusCode)
			if response.StatusCode != tc.status {
				t.Fatalf("status=%d", response.StatusCode)
			}
			record(id, tc.status == 200, tc.denier)
		})
	}
	// HTTP/2 raw requests exercise malformed wire envelopes without asking a gRPC
	// client library to emit a valid frame on their behalf.
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, "") }}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	body, err := proto.Marshal(&health.HealthCheckRequest{Service: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 5)
	binary.BigEndian.PutUint32(frame[1:], uint32(len(body)))
	frame = append(frame, body...)
	compressed := append([]byte(nil), frame...)
	compressed[0] = 1
	for _, tc := range []struct {
		name, contentType string
		body              []byte
	}{{"spoof-type", "application/json", frame}, {"unsupported-codec", "application/grpc+json", frame}, {"short", "application/grpc", []byte{0, 0}}, {"extra", "application/grpc", append(append([]byte(nil), frame...), frame...)}, {"compressed", "application/grpc", compressed}} {
		t.Run("wire-"+tc.name, func(t *testing.T) {
			id := "shared-wire-" + tc.name
			req, err := http.NewRequestWithContext(t.Context(), "POST", "https://"+authority+"/grpc.health.v1.Health/Check", strings.NewReader(string(tc.body)))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", tc.contentType)
			req.Header.Set("X-Role", "reader")
			req.Header.Set("X-Carrier", "open")
			req.Header.Set("X-Request-Id", id)
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			grpcDenied := response.StatusCode == 200 && (response.Header.Get("Grpc-Status") == "7" || response.Trailer.Get("Grpc-Status") == "7")
			if response.ProtoMajor != 2 || (response.StatusCode != 403 && !grpcDenied) {
				t.Fatalf("wire rejection protocol=%s status=%d", response.Proto, response.StatusCode)
			}
			record(id, false, "workload")
		})
	}
	verifySharedHTTP(t, host, workloadID, record)
	for _, observation := range observations {
		assertSharedDelivery(t, observation.id, observation.allowed, observation.denier, workloadID, egressID, originID)
	}
	verifySharedPeer(t, state, authority, egressID, originID)
}

func assertSharedDelivery(t *testing.T, id string, allowed bool, denier, workloadID, egressID, originID string) {
	t.Helper()
	// Access logs are flushed asynchronously; wait only for the responsible hop.
	gateway := workloadID
	if denier == "egress" || allowed {
		gateway = egressID
	}
	until(t, 15*time.Second, func() bool { return strings.Contains(run(t, "docker", "logs", gateway), "request_id="+id+" ") })
	origin := run(t, "docker", "logs", originID)
	if (strings.Contains(origin, "request_id="+id+" ") || strings.Contains(origin, "request_id="+id+"\n")) != allowed {
		t.Fatalf("upstream delivery for %s allowed=%v logs=%s", id, allowed, origin)
	}
	if !allowed {
		logs := run(t, "docker", "logs", gateway)
		for line := range strings.SplitSeq(logs, "\n") {
			if strings.Contains(line, "request_id="+id+" ") && strings.Contains(line, "details=ext_authz_denied") {
				return
			}
		}
		t.Fatalf("missing responsible rejection for %s", id)
	}
}

func verifySharedPeer(t *testing.T, state, authority, egressID, originID string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(state, "mesh-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(raw)
	identity, err := tls.LoadX509KeyPair(filepath.Join(state, "egress.pem"), filepath.Join(state, "egress-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	address := published(t, egressID)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "egress", Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	}}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://"+authority+"/body", strings.NewReader(`{"action":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "shared-peer")
	req.Header.Set("X-Gateway-Allowed", "true")
	req.Header.Set("X-Forwarded-Client-Cert", "URI=spiffe://fixture.test/ns/gateway/sa/workload")
	response, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatalf("unbound mesh peer allowed: %d", response.StatusCode)
	}
	assertSharedDelivery(t, "shared-peer", false, "egress", "", egressID, originID)
}

func addSharedHTTPListener(t *testing.T, static map[string]any, role string) {
	t.Helper()
	clone := func(value any) map[string]any {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	listener := clone(static["listeners"].([]any)[0])
	listener["name"] = role + "-http"
	listener["address"].(map[string]any)["socket_address"].(map[string]any)["port_value"] = 8080
	chain := listener["filter_chains"].([]any)[0].(map[string]any)
	if role == "workload" {
		delete(listener, "listener_filters")
		delete(chain, "transport_socket")
		delete(chain, "transport_socket_connect_timeout")
	}
	hcm := chain["filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
	hcm["stat_prefix"] = role + "-http"
	for _, vhost := range hcm["route_config"].(map[string]any)["virtual_hosts"].([]any) {
		for _, route := range vhost.(map[string]any)["routes"].([]any) {
			route.(map[string]any)["route"].(map[string]any)["cluster"] = "next_hop_http"
		}
	}
	for _, item := range hcm["http_filters"].([]any) {
		filter := item.(map[string]any)
		if filter["name"] == "gateway.request" || filter["name"] == "gateway.dispatch" {
			filter["name"] = fmt.Sprint(filter["name"]) + "-http"
			filter["typed_config"] = map[string]any{"@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua", "default_source_code": map[string]any{"inline_string": request.HTTPSource(config.Role(role))}}
		}
	}
	static["listeners"] = append(static["listeners"].([]any), listener)
	for _, item := range static["clusters"].([]any) {
		original := item.(map[string]any)
		if original["name"] != "next_hop" {
			continue
		}
		cluster := clone(original)
		cluster["name"] = "next_hop_http"
		if role == "egress" {
			delete(cluster, "transport_socket")
			cluster["typed_extension_protocol_options"] = map[string]any{"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]any{"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions", "upstream_http_protocol_options": map[string]any{"auto_sni": true, "auto_san_validation": true}, "explicit_http_config": map[string]any{"http_protocol_options": map[string]any{}}}}
		} else {
			assignment := cluster["load_assignment"].(map[string]any)
			assignment["cluster_name"] = "next_hop_http"
			for _, endpoint := range assignment["endpoints"].([]any) {
				for _, lb := range endpoint.(map[string]any)["lb_endpoints"].([]any) {
					lb.(map[string]any)["endpoint"].(map[string]any)["address"].(map[string]any)["socket_address"].(map[string]any)["port_value"] = 8080
				}
			}
		}
		static["clusters"] = append(static["clusters"].([]any), cluster)
		break
	}
}

func verifySharedHTTP(t *testing.T, host, workloadID string, record func(string, bool, string)) {
	t.Helper()
	address := strings.TrimSpace(run(t, "docker", "port", workloadID, "8080/tcp"))
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	for _, tc := range []struct {
		action, denier string
		status         int
	}{{"safe", "", 200}, {"local-deny", "workload", 403}, {"egress-deny", "egress", 403}} {
		id := "shared-plain-" + tc.action
		req, err := http.NewRequestWithContext(t.Context(), "POST", "http://"+host+":8080/body", strings.NewReader(fmt.Sprintf(`{"action":%q}`, tc.action)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", id)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("plain HTTP %s status=%d", tc.action, response.StatusCode)
		}
		record(id, tc.status == 200, tc.denier)
	}
}

type sharedDelivery struct {
	id      string
	allowed bool
	denier  string
}

type imagePolicySource struct {
	mu       sync.Mutex
	raw      []byte
	status   int
	requests int
}

func (s *imagePolicySource) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	if s.status != 0 {
		w.WriteHeader(s.status)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	_, _ = w.Write(s.raw)
}
func (s *imagePolicySource) initialAvailable(t *testing.T, id string) {
	t.Helper()
	until(t, 10*time.Second, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.requests > 0 })
	if exec.Command("docker", "exec", id, "gateway-daemon", "ready").Run() == nil {
		t.Fatal("image became ready before first usable native bundle")
	}
	s.mu.Lock()
	s.status = 0
	s.mu.Unlock()
}

func (s *imagePolicySource) replace(raw []byte, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.raw, s.status = raw, status
}

func runImageNativeUpdates(t *testing.T, sources map[string]*imagePolicySource, workloadID, egressID, host string, client *http.Client) {
	t.Helper()
	containers := map[string]string{"workload": workloadID, "egress": egressID}
	identities := map[string]string{}
	for role, id := range containers {
		identities[role] = run(t, "docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}} {{.RestartCount}}", id)
	}
	publish := func(role, revision string, p workload.Policy) {
		t.Helper()
		raw, err := policybundle.BuildExecution(p, revision)
		if err != nil {
			t.Fatal(err)
		}
		sources[role].replace(raw, 0)
	}
	native := func(role, revision string, failed bool) {
		t.Helper()
		until(t, 20*time.Second, func() bool {
			raw := run(t, "docker", "logs", containers[role])
			var latest opastatus.UpdateRequestV1
			for line := range strings.SplitSeq(raw, "\n") {
				var row struct {
					Type string `json:"type"`
					opastatus.UpdateRequestV1
				}
				if json.Unmarshal([]byte(line), &row) == nil && row.Type == "openpolicyagent.org/status" {
					latest = row.UpdateRequestV1
				}
			}
			status := latest.Bundles["workload"]
			return status != nil && status.ActiveRevision == revision && (status.Code != "") == failed
		})
	}
	request := func(want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), "POST", "https://"+host+":8443/body", strings.NewReader(`{"action":"safe"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != want || (want == 200 && !strings.Contains(string(raw), "upstream reached")) {
			t.Fatalf("native update traffic: status=%d body=%s err=%v", response.StatusCode, raw, err)
		}
	}
	for role := range sources {
		publish(role, "image-empty-"+role, workload.Policy{})
		native(role, "image-empty-"+role, false)
	}
	for _, role := range []string{"workload", "egress"} {
		t.Run("native-updates-"+role, func(t *testing.T) {
			request(200)
			deny := workload.Policy{RequestConstraints: []workload.Constraint{{Name: "updated-body", Match: workload.Match{Hosts: []workload.HostMatcher{{Type: workload.DomainSuffix, Value: "origin.test"}}, HTTP: &workload.HTTPMatch{Paths: []string{"/body"}}}, Decode: &workload.Decoder{Format: workload.JSON}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/action"), Operator: workload.In, Values: []string{"deny-safe"}}}}}}
			good := "image-deny-" + role
			publish(role, good, deny)
			native(role, good, false)
			request(403)
			for _, failure := range []string{"unavailable", "invalid", "compile"} {
				body := []byte("invalid archive")
				status := 0
				if failure == "unavailable" {
					status = 503
				}
				if failure == "compile" {
					raw, err := policybundle.BuildExecution(workload.Policy{}, "must-not-activate")
					if err != nil {
						t.Fatal(err)
					}
					b, err := opabundle.NewReader(bytes.NewReader(raw)).Read()
					if err != nil {
						t.Fatal(err)
					}
					b.Modules = append(b.Modules, opabundle.ModuleFile{URL: "bad.rego", Path: "bad.rego", Raw: []byte("package egress_gateway.workload.bad\nvalue := missing_function()")})
					var out bytes.Buffer
					if err := opabundle.NewWriter(&out).Write(b); err != nil {
						t.Fatal(err)
					}
					body = out.Bytes()
				}
				sources[role].replace(body, status)
				native(role, good, true)
				request(403)
				publish(role, "image-recovered-"+role+"-"+failure, workload.Policy{})
				native(role, "image-recovered-"+role+"-"+failure, false)
				request(200)
				publish(role, good, deny)
				native(role, good, false)
				request(403)
			}
			publish(role, "image-final-"+role, workload.Policy{})
			native(role, "image-final-"+role, false)
			request(200)
		})
	}
	for role, id := range containers {
		if got := run(t, "docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}} {{.RestartCount}}", id); got != identities[role] {
			t.Fatalf("runtime restarted: %s", role)
		}
	}
}
