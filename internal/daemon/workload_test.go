package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/extension"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/egress-gateway/egress-gateway/config"
	gatewayopa "github.com/egress-gateway/egress-gateway/internal/opa"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSharedBundleThroughOfficialAuthorizationService(t *testing.T) {
	dir, err := os.MkdirTemp("", "gw-policy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := workload.Policy{RequestConstraints: []workload.Constraint{{Name: "body", Match: workload.Match{Hosts: []workload.HostMatcher{{Type: workload.Exact, Value: "api.example"}}, HTTP: &workload.HTTPMatch{}}, Decode: &workload.Decoder{Format: workload.JSON}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/model"), Operator: workload.In, Values: []string{"good"}}}}}}
	archive, err := policybundle.BuildExecution(p, "component")
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "source.tar.gz")
	write := func(path string, b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(bundlePath, archive)
	opaPath := filepath.Join(dir, "opa.json")
	raw, err := json.Marshal(map[string]any{
		"plugins": map[string]any{extension.PluginName: extension.Config{Role: "egress"}, "envoy_ext_authz_grpc": map[string]any{"addr": "unix://" + filepath.Join(dir, "auth.sock"), "path": "fixture/must/be/overridden"}},
		"bundles": map[string]any{"workload": map[string]any{"resource": "file://" + bundlePath}},
	})
	if err != nil {
		t.Fatal(err)
	}
	write(opaPath, raw)
	params := runtime.NewParams()
	params.ConfigFile = opaPath
	params.Addrs = new([]string{"unix://" + filepath.Join(dir, "api.sock")})
	params.AddrSetByUser = true
	params.ReadyTimeout = 10
	params.GracefulShutdownPeriod = 1
	enabled, err := configurePolicyHost(config.Config{Role: config.Workload, RuntimeDir: dir}, &params)
	if err != nil || !enabled {
		t.Fatalf("configure policy host: enabled=%v err=%v", enabled, err)
	}
	register.Do(gatewayopa.RegisterPlugins)
	embedded, err := runtime.NewRuntime(t.Context(), params)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- embedded.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("OPA exit: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("OPA did not stop")
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		status := embedded.Manager.PluginStatus()[extension.PluginName]
		if status != nil && status.State == plugins.StateOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("extension did not become ready: %+v", status)
		}
		time.Sleep(20 * time.Millisecond)
	}
	conn, err := grpc.NewClient("unix://"+filepath.Join(dir, "auth.sock"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := auth.NewAuthorizationClient(conn)
	for _, tc := range []struct {
		body  string
		allow bool
	}{{`{"model":"good"}`, true}, {`{"model":"bad"}`, false}, {`{"model":"good","model":"bad"}`, false}, {``, false}} {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		response, err := client.Check(ctx, &auth.CheckRequest{Attributes: &auth.AttributeContext{Request: &auth.AttributeContext_Request{Time: timestamppb.Now(), Http: &auth.AttributeContext_HttpRequest{Host: "api.example:443", Method: "POST", Path: "/v1/chat", RawBody: []byte(tc.body), HeaderMap: &core.HeaderMap{Headers: []*core.HeaderValue{{Key: "content-type", RawValue: []byte("application/json")}}}}}}}, grpc.WaitForReady(true))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if got := response.GetStatus().GetCode() == 0; got != tc.allow {
			t.Fatalf("body=%q allowed=%v response=%v", tc.body, got, response)
		}
	}
}
