package suite

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/egress-gateway/egress-gateway/test/e2e/environment"
	"github.com/egress-gateway/egress-gateway/test/telemetry"
	"github.com/google/uuid"
)

type scenario struct {
	env           *environment.Environment
	ctx           context.Context
	id, response  string
	https         bool
	originService string
	metricsBefore map[string]float64
	logs          map[string]string
}

func Run(ctx context.Context, e *environment.Environment, tags string) error {
	s := &scenario{env: e, ctx: ctx}
	suite := godog.TestSuite{Name: "gateway-connectivity", Options: &godog.Options{Format: "pretty", Paths: []string{filepath.Join(e.Config.Root, "test/e2e/features")}, Tags: tags, Strict: true, Concurrency: 1}, ScenarioInitializer: func(sc *godog.ScenarioContext) {
		sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
			s.id = uuid.NewString()
			s.response = ""
			s.https = false
			s.originService = ""
			s.logs = map[string]string{}
			return ctx, nil
		})
		sc.After(func(ctx context.Context, _ *godog.Scenario, scenarioErr error) (context.Context, error) {
			if s.originService != "" {
				_, err := s.command("delete", "service", "-n", "gateway-origin", s.originService)
				return ctx, err
			}
			return ctx, scenarioErr
		})
		sc.Step(`^the workload sends its first HTTPS request to a newly selected hostname$`, s.httpsRequest)
		sc.Step(`^the client verifies the inspection certificate and egress verifies origin TLS$`, s.inspectionTLS)
		sc.Step(`^the application cannot access private proxy management$`, s.privateManagement)
		sc.Step(`^the workload has a startup-prepared inspection trust bundle$`, s.trust)
		sc.Step(`^the workload sends an HTTP request to "([^"]*)"$`, s.request)
		sc.Step(`^the origin responds successfully$`, s.success)
		sc.Step(`^both proxies and the origin record the request identifier$`, s.correlate)
		sc.Step(`^the proxy hop uses live Istio mutual TLS$`, s.mutualTLS)
		sc.Step(`^the Collector receives correlated spans from both proxies$`, s.tracing)
		sc.Step(`^Istio telemetry records successful proxy traffic$`, s.telemetry)
		sc.Step(`^the image accepts the on-demand certificate configuration$`, s.capability)
	}}
	if code := suite.Run(); code != 0 {
		return fmt.Errorf("BDD assertions failed (exit %d)", code)
	}
	return nil
}
func (s *scenario) command(args ...string) ([]byte, error) { return s.env.Kubectl(s.ctx, args...) }
func (s *scenario) trust() error {
	ca, err := s.command("exec", "-n", "gateway-test", "workload", "-c", "istio-proxy", "--", "cat", "/run/gateway/trust/inspection-ca.pem")
	if err != nil {
		return fmt.Errorf("public CA: %w", err)
	}
	b, _ := pem.Decode(ca)
	if b == nil {
		return errors.New("published CA is not PEM")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	bundle, err := s.command("exec", "-n", "gateway-test", "workload", "-c", "curl", "--", "cat", "/cacert.pem")
	if err != nil {
		return err
	}
	for len(bundle) > 0 {
		block, rest := pem.Decode(bundle)
		if block == nil {
			break
		}
		if bytes.Equal(cert.Raw, block.Bytes) {
			return nil
		}
		bundle = rest
	}
	return errors.New("workload startup bundle does not contain published inspection CA")
}
func (s *scenario) request(path string) error {
	raw, err := s.command("exec", "-n", "gateway-test", "workload", "-c", "curl", "--", "curl", "--fail", "--silent", "--show-error", "--max-time", "10", "-H", "X-Request-Id: "+s.id, "-H", "traceparent: 00-"+strings.ReplaceAll(s.id, "-", "")+"-0123456789abcdef-01", "-w", "\n%{http_code}\n", "http://origin.gateway-origin.svc.cluster.local"+path)
	s.response = string(raw)
	if err != nil {
		return fmt.Errorf("single request failed: %w: %s", err, raw)
	}
	return nil
}
func (s *scenario) success() error {
	if !strings.Contains(s.response, "\n200\n") || !strings.Contains(s.response, "upstream reached:") {
		return fmt.Errorf("unexpected origin response: %s", s.response)
	}
	return nil
}
func (s *scenario) correlate() error {
	origin := "deployment/origin"
	if s.https {
		origin = "deployment/origin-https"
	}
	for _, target := range []struct{ name, namespace, pod, container string }{{"workload", "gateway-test", "workload", "istio-proxy"}, {"egress", "gateway-test", "deployment/egress", "istio-proxy"}, {"origin", "gateway-origin", origin, "origin"}} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			log, err := s.command("logs", "-n", target.namespace, target.pod, "-c", target.container, "--tail=300")
			if err != nil {
				return fmt.Errorf("read %s evidence: %w", target.name, err)
			}
			for line := range strings.SplitSeq(string(log), "\n") {
				if strings.Contains(line, s.id) {
					s.logs[target.name] = line
					break
				}
			}
			if s.logs[target.name] != "" {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s lacks request %s", target.name, s.id)
			}
			select {
			case <-s.ctx.Done():
				return s.ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	raw, err := json.MarshalIndent(s.logs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.env.Config.Artifacts, s.id+"-path.json"), raw, 0o644)
}
func (s *scenario) mutualTLS() error {
	var eg, wl struct {
		DownstreamPeer string `json:"downstream_peer"`
		UpstreamPeer   string `json:"upstream_peer"`
		DownstreamTLS  string `json:"downstream_tls"`
		UpstreamTLS    string `json:"upstream_tls"`
	}
	if err := json.Unmarshal([]byte(s.logs["egress"]), &eg); err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(s.logs["workload"]), &wl); err != nil {
		return err
	}
	if eg.DownstreamPeer != "spiffe://cluster.local/ns/gateway-test/sa/workload" || !strings.HasPrefix(eg.DownstreamTLS, "TLSv") {
		return fmt.Errorf("egress did not verify workload mTLS identity: %+v", eg)
	}
	if wl.UpstreamPeer != "spiffe://cluster.local/ns/gateway-test/sa/egress" || !strings.HasPrefix(wl.UpstreamTLS, "TLSv") {
		return fmt.Errorf("workload did not verify egress mTLS identity: %+v", wl)
	}
	for _, pod := range []string{"workload", "deployment/egress"} {
		certs, err := s.command("exec", "-n", "gateway-test", pod, "-c", "istio-proxy", "--", "pilot-agent", "request", "GET", "certs?format=json")
		if err != nil {
			return fmt.Errorf("active mesh certificates: %w", err)
		}
		if !bytes.Contains(certs, []byte("spiffe://cluster.local/ns/gateway-test/sa/")) {
			return errors.New("active certificate lacks mesh principal")
		}
		name := strings.ReplaceAll(pod, "/", "-") + "-public-certs.json"
		if err = os.WriteFile(filepath.Join(s.env.Config.Artifacts, name), certs, 0o644); err != nil {
			return err
		}
	}
	return nil
}
func (s *scenario) capability() error {
	cfg := filepath.Join(s.env.Config.Root, "test/e2e/config/inspection-capability.yaml")
	cmd := exec.CommandContext(s.ctx, "docker", "run", "--rm", "--network", "none", "--entrypoint", "/usr/local/bin/envoy", "-v", cfg+":/probe.yaml:ro", s.env.Config.Image, "--mode", "validate", "-c", "/probe.yaml")
	output, err := cmd.CombinedOutput()
	if writeErr := os.WriteFile(filepath.Join(s.env.Config.Artifacts, "inspection-capability.log"), output, 0o644); writeErr != nil {
		return writeErr
	}
	if err != nil {
		return fmt.Errorf("HTTPS implementation blocked: image lacks a validated on-demand certificate path; see inspection-capability.log: %w", err)
	}
	return nil
}

func (s *scenario) httpsRequest() error {
	s.https = true
	s.originService = "late-" + s.id
	if _, err := s.command("expose", "deployment", "origin-https", "-n", "gateway-origin", "--name="+s.originService, "--port=443", "--target-port=8443"); err != nil {
		return err
	}
	host := s.originService + ".gateway-origin.svc.cluster.local"
	// Wait for fixture Service routing, without TLS or certificate provisioning.
	// TCP connect readiness is independent of the application's first request.
	deadline := time.Now().Add(15 * time.Second)
	for {
		output, probeErr := s.command("exec", "-n", "gateway-test", "deployment/egress", "-c", "istio-proxy", "--", "curl", "--noproxy", "*", "--silent", "--connect-timeout", "1", "--max-time", "1", "-w", "%{time_connect}\n", "telnet://"+host+":443")
		first, _, _ := strings.Cut(string(output), "\n")
		connected, _ := strconv.ParseFloat(first, 64)
		exit, ok := errors.AsType[*exec.ExitError](probeErr)
		if connected > 0 && (probeErr == nil || (ok && exit.ExitCode() == 28)) {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("new origin service did not accept TCP: %v %s", probeErr, output)
		}
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	certs, err := s.command("exec", "-n", "gateway-test", "workload", "-c", "istio-proxy", "--", "pilot-agent", "request", "GET", "certs?format=json")
	if err != nil {
		return err
	}
	if bytes.Contains(certs, []byte(host)) {
		return errors.New("new hostname already has an inspection certificate")
	}

	s.metricsBefore = make(map[string]float64)
	for _, pod := range []string{"workload", "deployment/egress"} {
		count, err := s.metricCount(pod)
		if err != nil {
			return err
		}
		s.metricsBefore[pod] = count
	}
	raw, err := s.command("exec", "-n", "gateway-test", "workload", "-c", "curl", "--", "curl", "--fail", "--silent", "--show-error", "--max-time", "10", "-H", "X-Request-Id: "+s.id, "-H", "traceparent: 00-"+strings.ReplaceAll(s.id, "-", "")+"-0123456789abcdef-01", "-w", "\n%{http_code}\n%{ssl_verify_result}\n%{certs}", "https://"+host+"/inspected")
	if writeErr := os.WriteFile(filepath.Join(s.env.Config.Artifacts, s.id+"-client-tls.txt"), raw, 0644); writeErr != nil {
		return writeErr
	}
	s.response = string(raw)
	if err != nil {
		return fmt.Errorf("first HTTPS request failed without retry: %w (see %s-client-tls.txt)", err, s.id)
	}
	return nil
}
func (s *scenario) inspectionTLS() error {
	if !strings.Contains(s.response, "\n200\n0\n") {
		return errors.New("client did not verify TLS")
	}
	start := strings.Index(s.response, "-----BEGIN CERTIFICATE-----")
	if start < 0 {
		return errors.New("curl did not report peer certificate")
	}
	block, _ := pem.Decode([]byte(s.response[start:]))
	if block == nil {
		return errors.New("invalid peer PEM")
	}
	peer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	raw, err := s.command("exec", "-n", "gateway-test", "workload", "-c", "istio-proxy", "--", "cat", "/run/gateway/trust/inspection-ca.pem")
	if err != nil {
		return err
	}
	block, _ = pem.Decode(raw)
	if block == nil {
		return errors.New("invalid inspection root")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if err = peer.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("peer is not inspection-signed: %w", err)
	}
	if err = peer.VerifyHostname(s.originService + ".gateway-origin.svc.cluster.local"); err != nil {
		return err
	}
	var egress struct {
		TLS string `json:"upstream_tls"`
	}
	if err = json.Unmarshal([]byte(s.logs["egress"]), &egress); err != nil {
		return err
	}
	if !strings.HasPrefix(egress.TLS, "TLSv") {
		return errors.New("origin hop did not use TLS")
	}
	return nil
}
func (s *scenario) privateManagement() error {
	// Curl telnet probes raw TCP. A refused socket must return CURLE_COULDNT_CONNECT,
	// not an HTTP status, missing executable, or successful connection timeout.
	podIP, err := s.command("get", "pod", "workload", "-n", "gateway-test", "-o", "jsonpath={.status.podIP}")
	if err != nil {
		return err
	}
	for _, address := range []string{"127.0.0.1", "[::1]", string(podIP)} {
		for _, port := range []string{"15000", "15020", "15004"} {
			output, err := s.command("exec", "-n", "gateway-test", "workload", "-c", "curl", "--", "curl", "--noproxy", "*", "--silent", "--show-error", "--connect-timeout", "2", "--max-time", "3", "telnet://"+address+":"+port)
			exit, ok := errors.AsType[*exec.ExitError](err)
			if !ok || exit.ExitCode() != 7 {
				return fmt.Errorf("management isolation %s:%s: %v %s", address, port, err, output)
			}
		}
	}
	return nil
}

func (s *scenario) metricCount(pod string) (float64, error) {
	raw, err := s.command("exec", "-n", "gateway-test", pod, "-c", "istio-proxy", "--", "pilot-agent", "request", "GET", "stats/prometheus?filter=istio_requests_total")
	if err != nil {
		return 0, err
	}
	var count float64
	for line := range strings.SplitSeq(string(raw), "\n") {
		// Gateway telemetry reports the outbound origin hop; its source principal
		// is not the incoming workload principal already checked in mutualTLS.
		identityMatches := pod != "workload" || strings.Contains(line, `source_principal="spiffe://cluster.local/ns/gateway-test/sa/workload"`)
		if strings.HasPrefix(line, "istio_requests_total{") && strings.Contains(line, `response_code="200"`) && strings.Contains(line, `reporter="source"`) && identityMatches {
			_, value, ok := strings.Cut(line, "} ")
			if !ok {
				return 0, fmt.Errorf("invalid metric: %s", line)
			}
			n, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil {
				return 0, err
			}
			count += n
		}
	}
	return count, nil
}
func (s *scenario) telemetry() error {
	evidence := make(map[string]map[string]float64)
	for _, pod := range []string{"workload", "deployment/egress"} {
		before, ok := s.metricsBefore[pod]
		if !ok {
			return errors.New("missing pre-request telemetry baseline")
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			after, err := s.metricCount(pod)
			if err != nil {
				return err
			}
			if after > before {
				evidence[pod] = map[string]float64{"before": before, "after": after}
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s Istio success counter did not grow for this HTTPS request: before=%v after=%v", pod, before, after)
			}
			select {
			case <-s.ctx.Done():
				return s.ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.env.Config.Artifacts, s.id+"-telemetry.json"), raw, 0644)
}

func (s *scenario) tracing() error {
	traceID := strings.ReplaceAll(s.id, "-", "")
	deadline := time.Now().Add(25 * time.Second)
	for {
		raw, err := s.command("exec", "-n", "gateway-test", "deployment/otel-collector", "-c", "reader", "--", "cat", "/data/envoy.json")
		if err != nil {
			return fmt.Errorf("Collector evidence: %w", err)
		}
		spans, err := telemetry.Read(raw)
		if err != nil {
			return err
		}
		var workload, egress telemetry.Span
		for _, span := range spans {
			if span.Service == "opa-env-boundary" {
				return errors.New("OPA environment changed the Envoy exporter")
			}
			if span.TraceID != traceID || span.Attributes["fixture.request_id"] != s.id {
				continue
			}
			if strings.Contains(span.Service, "workload") {
				workload = span
			}
			if strings.Contains(span.Service, "egress") {
				egress = span
			}
		}
		if workload.ID != "" && egress.ID != "" && telemetry.Descends(spans, egress, workload.ID) && telemetry.Descends(spans, workload, "0123456789abcdef") {
			// The second receiver is the OPA environment target. Envoy must not also export there.
			opaRaw, err := s.command("exec", "-n", "gateway-test", "deployment/otel-collector", "-c", "reader", "--", "cat", "/data/opa.json")
			if err != nil {
				return err
			}
			opaSpans, err := telemetry.Read(opaRaw)
			if err != nil {
				return err
			}
			for _, span := range opaSpans {
				if span.Service != "opa-env-boundary" {
					return errors.New("Envoy exported to the OPA-only endpoint")
				}
			}
			return os.WriteFile(filepath.Join(s.env.Config.Artifacts, s.id+"-otlp.json"), raw, 0644)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Collector lacks correlated proxy spans: trace=%s workload=%s egress=%s total=%d", traceID, workload.ID, egress.ID, len(spans))
		}
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}
