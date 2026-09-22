//go:build image

package https_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func TestHTTPSInspection(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(root, "test/image/https")
	state := t.TempDir()
	if err := os.Chmod(state, 0755); err != nil {
		t.Fatal(err)
	}
	image := os.Getenv("GATEWAY_IMAGE")
	if image == "" {
		image = "egress-gateway:dev"
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	network := "gateway-https-" + suffix
	run(t, "docker", "network", "create", network)
	t.Cleanup(func() { run(t, "docker", "network", "rm", network) })
	mesh := makeCA(t, state, "mesh-ca")
	origins := makeCA(t, state, "origin-ca")
	other := makeCA(t, state, "untrusted-ca")
	issue(t, state, mesh, "egress", nil, "spiffe://fixture.test/ns/gateway/sa/egress")
	issue(t, state, mesh, "workload", nil, "spiffe://fixture.test/ns/gateway/sa/workload")
	issue(t, state, origins, "origin", []string{"*.origin.test"}, "")
	issue(t, state, other, "untrusted", []string{"*.origin.test"}, "")
	// Each role receives only its own key and the independent trust roots.
	mountCerts := func(names ...string) []string {
		var args []string
		for _, name := range names {
			args = append(args, "-v", filepath.Join(state, name)+":/certs/"+name+":ro")
		}
		return args
	}
	start := func(name string, args ...string) string {
		t.Helper()
		fullName := "gateway-https-" + name + "-" + suffix
		command := append([]string{"run", "-d", "--name", fullName, "--network", network, "--network-alias", name, "--memory", "256m"}, args...)
		id := strings.TrimSpace(run(t, "docker", command...))
		t.Cleanup(func() {
			if t.Failed() {
				output, _ := exec.Command("docker", "logs", id).CombinedOutput()
				t.Logf("%s logs:\n%s", name, output)
			}
			run(t, "docker", "rm", "-f", id)
		})
		return id
	}
	startProxy := func(role string) string {
		args := []string{"-p", "127.0.0.1::8443", "-e", "GATEWAY_ROLE=" + role, "-e", "GATEWAY_PROXY_MODE=standalone", "-e", "ENVOY_CONFIG=/fixture/envoy.json", "-e", "OPA_CONFIG=/fixture/opa.yaml",
			"-v", filepath.Join(fixture, role+"-envoy.json") + ":/fixture/envoy.json:ro",
			"-v", filepath.Join(fixture, role+".rego") + ":/fixture/policy.rego:ro",
			"-v", filepath.Join(root, "examples/local", role+"-opa.yaml") + ":/fixture/opa.yaml:ro"}
		args = append(args, mountCerts(role+".pem", role+"-key.pem", "mesh-ca.pem", "origin-ca.pem")...)
		args = append(args, image, "--policy", "/fixture/policy.rego")
		id := start(role, args...)
		until(t, 30*time.Second, func() bool { return exec.Command("docker", "exec", id, "gateway-daemon", "ready").Run() == nil })
		return id
	}
	egress := startProxy("egress")
	workload := startProxy("workload")
	// Pick the first target only after both proxies are ready. Origin wildcard
	// credentials do not pre-issue any inspection leaf certificate.
	host := "first-" + suffix + ".origin.test"
	wrongHost := "wrong-" + suffix + ".invalid.test"
	untrustedHost := "untrusted-" + suffix + ".origin.test"
	originImage := "gateway-https-origin:" + suffix
	run(t, "docker", "build", "-q", "-f", filepath.Join(root, "examples/local/upstream/Dockerfile"), "-t", originImage, root)
	t.Cleanup(func() { run(t, "docker", "image", "rm", originImage) })
	origin := start("origin", append(append([]string{"--network-alias", host, "--network-alias", wrongHost, "-p", "127.0.0.1::8443", "-e", "ORIGIN_TLS_CERT=/certs/origin.pem", "-e", "ORIGIN_TLS_KEY=/certs/origin-key.pem"}, mountCerts("origin.pem", "origin-key.pem")...), originImage)...)
	start("untrusted", append(append([]string{"--network-alias", untrustedHost, "-e", "ORIGIN_TLS_CERT=/certs/untrusted.pem", "-e", "ORIGIN_TLS_KEY=/certs/untrusted-key.pem"}, mountCerts("untrusted.pem", "untrusted-key.pem")...), originImage)...)
	until(t, 10*time.Second, func() bool {
		conn, err := net.DialTimeout("tcp", published(t, origin), time.Second)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	})
	run(t, "docker", "exec", workload, "gateway-daemon", "trust-init", "--base", "/etc/ssl/certs/ca-certificates.crt", "--ca", "/run/gateway/trust/inspection-ca.pem", "--output", "/run/gateway/trust/ca-bundle.pem")
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(run(t, "docker", "exec", workload, "cat", "/run/gateway/trust/ca-bundle.pem"))) {
		t.Fatal("startup trust bundle invalid")
	}
	target := published(t, workload)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
	}}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	send := func(t *testing.T, name, body string, headers map[string]string) (int, string, *tls.ConnectionState) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), "POST", "https://"+name+":8443/body", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", headers["X-Request-Id"])
		for k, v := range headers {
			if k == "Host" {
				req.Host = v
			} else {
				req.Header.Set(k, v)
			}
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(data), response.TLS
	}
	var coldSerial string
	t.Run("first-unseen-host-and-warm-reuse", func(t *testing.T) {
		started := time.Now()
		code, body, state := send(t, host, `{"action":"safe"}`, map[string]string{"X-Request-Id": "https-cold"})
		if code != 200 || !strings.Contains(body, "upstream reached") {
			t.Fatalf("cold request: %d %s", code, body)
		}
		coldSerial = state.PeerCertificates[0].SerialNumber.String()
		t.Logf("cold first request: %s, serial=%s", time.Since(started), coldSerial)
		tr.CloseIdleConnections()
		started = time.Now()
		code, _, state = send(t, host, `{"action":"safe"}`, map[string]string{"X-Request-Id": "https-warm"})
		if code != 200 || state.PeerCertificates[0].SerialNumber.String() != coldSerial {
			t.Fatal("warm leaf was not reused")
		}
		t.Logf("warm new connection: %s", time.Since(started))
	})
	for _, tc := range []struct {
		name, body string
		headers    map[string]string
		code       int
		message    string
	}{
		{"local-deny", `{"action":"local-deny"}`, nil, 403, "workload denied"},
		{"local-target-mutation", `{"action":"workload-mutate"}`, nil, 403, "authorization changed request target"},
		{"egress-target-mutation", `{"action":"egress-mutate"}`, nil, 403, "authorization changed request target"},
		{"egress-deny", `{"action":"egress-deny"}`, nil, 403, "egress denied"},
		{"spoof-prior-allow", `{"action":"egress-deny"}`, map[string]string{"X-Gateway-Identity": "spiffe://fixture.test/ns/gateway/sa/admin", "X-Gateway-Allowed": "true", "X-Forwarded-Client-Cert": "URI=spiffe://fixture.test/ns/gateway/sa/admin"}, 403, "egress denied"},
		{"target-conflict", `{"action":"safe"}`, map[string]string{"Host": "other.origin.test:8443"}, 400, "conflicts"},
		{"invalid-body", `{"action":`, nil, 400, "request_parse_error"},
		{"missing-input", `{}`, nil, 403, "workload denied"},
		{"unsupported-encoding", `{"action":"safe"}`, map[string]string{"Content-Encoding": "gzip"}, 415, "unsupported content encoding"},
		{"oversized", strings.Repeat("a", 65537), nil, 413, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := tc.headers
			if headers == nil {
				headers = make(map[string]string)
			}
			headers["X-Request-Id"] = "https-denied-" + tc.name
			code, body, _ := send(t, host, tc.body, headers)
			if code != tc.code || !strings.Contains(body, tc.message) {
				t.Fatalf("got %d %q", code, body)
			}
		})
	}
	for _, name := range []string{wrongHost, untrustedHost} {
		t.Run(name, func(t *testing.T) {
			code, _, _ := send(t, name, `{"action":"safe"}`, map[string]string{"X-Request-Id": "https-denied-origin"})
			if code != 503 {
				t.Fatalf("invalid origin accepted/status=%d", code)
			}
		})
	}
	t.Run("no-client-identity", func(t *testing.T) {
		meshRoots := x509.NewCertPool()
		raw, err := os.ReadFile(filepath.Join(state, "mesh-ca.pem"))
		if err != nil {
			t.Fatal(err)
		}
		meshRoots.AppendCertsFromPEM(raw)
		address := published(t, egress)
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: meshRoots, ServerName: "egress", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", address)
		}}
		defer transport.CloseIdleConnections()
		response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get("https://egress/body")
		if err == nil {
			response.Body.Close()
			t.Fatalf("unauthenticated peer reached HTTP: %d", response.StatusCode)
		}
	})

	t.Run("verified-other-principal-cannot-spoof-workload", func(t *testing.T) {
		meshRoots := x509.NewCertPool()
		raw, err := os.ReadFile(filepath.Join(state, "mesh-ca.pem"))
		if err != nil {
			t.Fatal(err)
		}
		meshRoots.AppendCertsFromPEM(raw)
		identity, err := tls.LoadX509KeyPair(filepath.Join(state, "egress.pem"), filepath.Join(state, "egress-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		address := published(t, egress)
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: meshRoots, ServerName: "egress", Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", address)
		}}
		defer transport.CloseIdleConnections()
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "https://"+host+":8443/body", strings.NewReader(`{"action":"safe"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", "https-denied-spoofed-identity")
		req.Header.Set("X-Forwarded-Client-Cert", "URI=spiffe://fixture.test/ns/gateway/sa/workload")
		req.Header.Set("X-Gateway-Identity", "spiffe://fixture.test/ns/gateway/sa/workload")
		response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatalf("spoofed principal authorized: %d", response.StatusCode)
		}
	})

	t.Run("egress-complete-body-boundary", func(t *testing.T) {
		meshRoots := x509.NewCertPool()
		raw, err := os.ReadFile(filepath.Join(state, "mesh-ca.pem"))
		if err != nil {
			t.Fatal(err)
		}
		meshRoots.AppendCertsFromPEM(raw)
		identity, err := tls.LoadX509KeyPair(filepath.Join(state, "workload.pem"), filepath.Join(state, "workload-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		address := published(t, egress)
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: meshRoots, ServerName: "egress", Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", address)
		}}
		defer transport.CloseIdleConnections()
		direct := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		for _, tc := range []struct {
			name, body, encoding string
			status               int
		}{{"oversized", strings.Repeat("a", 65537), "", 413}, {"invalid-json", `{"action":`, "", 400}, {"missing", "{}", "", 403}, {"unsupported-encoding", `{"action":"safe"}`, "gzip", 415}} {
			t.Run(tc.name, func(t *testing.T) {
				req, _ := http.NewRequestWithContext(t.Context(), "POST", "https://"+host+":8443/body", strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Content-Encoding", tc.encoding)
				req.Header.Set("X-Request-Id", "https-denied-egress-"+tc.name)
				response, err := direct.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.StatusCode != tc.status {
					t.Fatalf("egress invalid body status=%d", response.StatusCode)
				}
			})
		}
	})
	logs := run(t, "docker", "logs", origin)
	if !strings.Contains(logs, "request_id=https-cold") || !strings.Contains(logs, "request_id=https-warm") || strings.Contains(logs, "request_id=https-denied-") {
		t.Fatalf("origin authorization evidence: %s", logs)
	}
	egressLogs := run(t, "docker", "logs", egress)
	if !strings.Contains(egressLogs, "peer=spiffe://fixture.test/ns/gateway/sa/workload") {
		t.Fatal("missing verified peer evidence")
	}

	for role, id := range map[string]string{"workload": workload, "egress": egress} {
		t.Run(role+"-OPA-unavailable", func(t *testing.T) {
			run(t, "docker", "kill", "--signal=STOP", id)
			defer run(t, "docker", "kill", "--signal=CONT", id)
			code, _, _ := send(t, host, `{"action":"safe"}`, map[string]string{"X-Request-Id": "https-denied-opa-" + role})
			if code != 403 {
				t.Fatalf("OPA failure status=%d", code)
			}
			if strings.Contains(run(t, "docker", "logs", origin), "https-denied-opa-") {
				t.Fatal("OPA failure reached origin")
			}
		})
	}
	handshake := func(name string) (string, error) {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", target, &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12})
		if err != nil {
			return "", err
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.String(), nil
	}
	stats := func() string {
		return run(t, "docker", "exec", workload, "curl", "--silent", "--unix-socket", "/run/gateway/private/envoy-admin.sock", "http://localhost/stats?filter=on_demand_secret.cert_")
	}
	t.Run("certificate-eviction-and-concurrency", func(t *testing.T) {
		for i := 0; i < 70; i++ {
			if _, err := handshake(fmt.Sprintf("evict-%d.origin.test", i)); err != nil {
				t.Fatalf("eviction index=%d: %v", i, err)
			}
			time.Sleep(30 * time.Millisecond)
		}
		serial, err := handshake(host)
		if err != nil {
			t.Fatal(err)
		}
		if serial == coldSerial {
			t.Fatal("LRU victim was not reissued")
		}
		// All callers wait for the same newly requested secret, without retry.
		var wg sync.WaitGroup
		results := make(chan string, 16)
		for range 16 {
			wg.Go(func() {
				serial, err := handshake("concurrent.origin.test")
				if err != nil {
					results <- "error: " + err.Error()
				} else {
					results <- serial
				}
			})
		}
		wg.Wait()
		close(results)
		var first string
		for serial := range results {
			if strings.HasPrefix(serial, "error:") {
				t.Fatal(serial)
			}
			if first == "" {
				first = serial
			}
			if serial != first {
				t.Fatal("concurrent certificate mismatch")
			}
		}
		output := stats()
		if !strings.Contains(output, "cert_active: 64") {
			t.Fatalf("unbounded certificate retention: %s", output)
		}
		t.Log(output)
	})
	t.Run("invalid-SNI", func(t *testing.T) {
		for _, name := range []string{"invalid/name", "*.origin.test", "127.0.0.1"} {
			if _, err := handshake(name); err == nil {
				t.Fatalf("invalid SNI accepted: %s", name)
			}
		}
	})
	t.Run("SDS-unavailable-bounded-wait-and-recovery", func(t *testing.T) {
		heap := func() uint64 {
			raw := run(t, "docker", "exec", workload, "curl", "--silent", "--unix-socket", "/run/gateway/private/envoy-admin.sock", "http://localhost/stats?filter=server.memory_allocated")
			var n uint64
			if _, err := fmt.Sscanf(strings.TrimSpace(raw), "server.memory_allocated: %d", &n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		before := heap()
		run(t, "docker", "kill", "--signal=STOP", workload)
		resumed := false
		defer func() {
			if !resumed {
				run(t, "docker", "kill", "--signal=CONT", workload)
			}
		}()
		started := time.Now()
		var wg sync.WaitGroup
		failures := make(chan error, 16)
		for i := range 16 {
			wg.Go(func() { _, err := handshake(fmt.Sprintf("unavailable-%d.origin.test", i)); failures <- err })
		}
		wg.Wait()
		close(failures)
		for err := range failures {
			if err == nil {
				t.Fatal("SDS failure accepted a new name")
			}
		}
		elapsed := time.Since(started)
		if elapsed < 2500*time.Millisecond || elapsed > 4500*time.Millisecond {
			t.Fatalf("handshake timeout not bounded by 3s: %s", elapsed)
		}
		output := stats()
		after := heap()
		if after > 64<<20 {
			t.Fatalf("SDS fault exceeded heap budget: %d", after)
		}
		t.Logf("SDS fault heap: before=%d after=%d bytes", before, after)
		t.Logf("16 concurrent SDS failures rejected in %s; %s", elapsed, output)
		state := run(t, "docker", "inspect", "--format", "{{json .State}}", workload)
		var health struct{ Running, OOMKilled bool }
		if err := json.Unmarshal([]byte(state), &health); err != nil {
			t.Fatal(err)
		}
		if !health.Running || health.OOMKilled {
			t.Fatal("fault exhausted the proxy")
		}
		run(t, "docker", "kill", "--signal=CONT", workload)
		resumed = true
		until(t, 10*time.Second, func() bool { return exec.Command("docker", "exec", workload, "gateway-daemon", "ready").Run() == nil })
		if _, err := handshake("recovered.origin.test"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stats(), "cert_active: 64") {
			t.Fatal("SDS failure recovery exceeded retention bound")
		}
	})

}

func published(t *testing.T, id string) string {
	t.Helper()
	return strings.TrimSpace(run(t, "docker", "port", id, "8443/tcp"))
}
func run(t *testing.T, command string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, command, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", command, args, err, out)
	}
	return string(out)
}
func until(t *testing.T, limit time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("fixture readiness timeout")
}
func makeCA(t *testing.T, dir, name string) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, name+".pem"), "CERTIFICATE", der)
	return authority{cert, key}
}
func issue(t *testing.T, dir string, ca authority, name string, dns []string, identity string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, DNSNames: dns, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if identity != "" {
		u, err := url.Parse(identity)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = []*url.URL{u}
		template.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, name+".pem"), "CERTIFICATE", der)
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, name+"-key.pem"), "PRIVATE KEY", raw)
}
func writePEM(t *testing.T, path, kind string, data []byte) {
	t.Helper()
	var buffer bytes.Buffer
	if err := pem.Encode(&buffer, &pem.Block{Type: kind, Bytes: data}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
}
