//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// TestAuthorizationAndPolicyUpdate verifies allow, deny, and policy reload behavior.
func TestAuthorizationAndPolicyUpdate(t *testing.T) {
	api, client := startOPA(t)
	check := func(path string, wantAllowed bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		response, err := client.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{Method: "GET", Path: path},
			}},
		})
		if err != nil {
			t.Fatalf("authorization RPC: %v", err)
		}
		if response.GetStatus() == nil {
			t.Fatal("authorization response has no status")
		}
		allowed := response.GetStatus().GetCode() == 0
		if allowed != wantAllowed {
			t.Fatalf("path %q: allowed=%v, want %v; response=%v", path, allowed, wantAllowed, response)
		}
	}

	putPolicy(t, api, `package envoy.authz
import rego.v1
default allow := false
allow if { input.attributes.request.http.path == "/allowed" }
`)
	check("/allowed", true)
	check("/denied", false)

	// Exercise the upstream runtime's reload path without choosing a production transport.
	putPolicy(t, api, "package envoy.authz\nimport rego.v1\ndefault allow := false\n")
	check("/allowed", false)
}

// TestMissingPolicyDoesNotAllow verifies that an absent policy fails closed.
func TestMissingPolicyDoesNotAllow(t *testing.T) {
	_, client := startOPA(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	response, err := client.Check(ctx, &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
			Http: &authv3.AttributeContext_HttpRequest{Method: "GET", Path: "/allowed"},
		}},
	})
	if err != nil {
		if status.Code(err) != codes.Unknown {
			t.Fatalf("expected evaluation failure for missing policy, got %v", err)
		}
		return
	}
	if response.GetStatus() == nil || response.GetStatus().GetCode() == 0 {
		t.Fatal("missing policy produced an allow decision")
	}
}

// startOPA starts an isolated gateway OPA process and waits for it to become healthy.
func startOPA(t *testing.T) (string, authv3.AuthorizationClient) {
	t.Helper()
	binary := os.Getenv("GATEWAY_OPA_BIN")
	if binary == "" {
		t.Fatal("GATEWAY_OPA_BIN must point to a built gateway-opa; run make integration")
	}
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		httpListener.Close()
		t.Fatal(err)
	}
	httpAddr, grpcAddr := httpListener.Addr().String(), grpcListener.Addr().String()
	httpListener.Close()
	grpcListener.Close()

	dir := t.TempDir()
	config := filepath.Join(dir, "opa.yaml")
	if err := os.WriteFile(config, fmt.Appendf(nil, "plugins:\n  envoy_ext_authz_grpc:\n    addr: %s\n    path: envoy/authz/allow\n", grpcAddr), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "opa.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	cmd := exec.Command(binary, "run", "--server", "--addr="+httpAddr, "--config-file="+config)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			content, _ := os.ReadFile(logPath)
			t.Logf("OPA output:\n%s", content)
		}
	})
	api := "http://" + httpAddr
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(client.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, api+"/health?plugins", nil)
		response, err := client.Do(req)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("OPA did not become healthy within 20 seconds")
		case <-time.After(50 * time.Millisecond):
		}
	}
	connection, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	return api, authv3.NewAuthorizationClient(connection)
}

// putPolicy uploads a fixture policy to the OPA management API.
func putPolicy(t *testing.T, api, source string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, api+"/v1/policies/fixture", strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("policy update: HTTP %d: %s", response.StatusCode, body)
	}
}
