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
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/egress-gateway/egress-gateway/test/e2e/environment"
	"github.com/google/uuid"
)

type scenario struct {
	env          *environment.Environment
	ctx          context.Context
	id, response string
	logs         map[string]string
}

func Run(ctx context.Context, e *environment.Environment, tags string) error {
	s := &scenario{env: e, ctx: ctx}
	suite := godog.TestSuite{Name: "gateway-connectivity", Options: &godog.Options{Format: "pretty", Paths: []string{filepath.Join(e.Config.Root, "test/e2e/features")}, Tags: tags, Strict: true, Concurrency: 1}, ScenarioInitializer: func(sc *godog.ScenarioContext) {
		sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
			s.id = uuid.NewString()
			s.response = ""
			s.logs = map[string]string{}
			return ctx, nil
		})
		sc.Step(`^the workload has a startup-prepared inspection trust bundle$`, s.trust)
		sc.Step(`^the workload sends an HTTP request to "([^"]*)"$`, s.request)
		sc.Step(`^the origin responds successfully$`, s.success)
		sc.Step(`^both proxies and the origin record the request identifier$`, s.correlate)
		sc.Step(`^the proxy hop uses live Istio mutual TLS$`, s.mutualTLS)
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
	bundle, err := s.command("exec", "-n", "gateway-test", "workload", "-c", "curl", "--", "cat", "/etc/ssl/certs/ca-certificates.crt")
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
	raw, err := s.command("exec", "-n", "gateway-test", "workload", "-c", "curl", "--", "curl", "--fail", "--silent", "--show-error", "--max-time", "10", "-H", "X-Request-Id: "+s.id, "-w", "\n%{http_code}\n", "http://origin.gateway-origin.svc.cluster.local"+path)
	s.response = string(raw)
	if err != nil {
		return fmt.Errorf("single request failed: %w: %s", err, raw)
	}
	return nil
}
func (s *scenario) success() error {
	if !strings.HasSuffix(s.response, "\n200\n") || !strings.Contains(s.response, "upstream reached:") {
		return fmt.Errorf("unexpected origin response: %s", s.response)
	}
	return nil
}
func (s *scenario) correlate() error {
	for _, target := range []struct{ name, namespace, pod, container string }{{"workload", "gateway-test", "workload", "istio-proxy"}, {"egress", "gateway-test", "deployment/egress", "istio-proxy"}, {"origin", "gateway-origin", "deployment/origin", "origin"}} {
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
