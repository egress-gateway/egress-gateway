package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/extension"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/egress-gateway/egress-gateway/config"
	gatewayopa "github.com/egress-gateway/egress-gateway/internal/opa"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	bundleplugin "github.com/open-policy-agent/opa/v1/plugins/bundle"
	"github.com/open-policy-agent/opa/v1/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNativeBundleReadinessUpdatesAndRecovery(t *testing.T) {
	dir, err := os.MkdirTemp("", "gw-native-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	var mu sync.Mutex
	var body []byte
	status := 503
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write(body)
	}))
	defer source.Close()
	raw, err := json.Marshal(map[string]any{
		"plugins":  map[string]any{extension.PluginName: extension.Config{Role: "egress"}, "envoy_ext_authz_grpc": map[string]any{"addr": "unix://" + filepath.Join(dir, "opa.sock")}},
		"services": map[string]any{"source": map[string]any{"url": source.URL}},
		"bundles":  map[string]any{"workload": map[string]any{"service": "source", "resource": "bundle", "trigger": "manual"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "opa.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	params := runtime.NewParams()
	params.ConfigFile = file
	params.Addrs = new([]string{"unix://" + filepath.Join(dir, "opa-api.sock")})
	params.AddrSetByUser = true
	params.ReadyTimeout = 10
	params.GracefulShutdownPeriod = 1
	cfg := config.Config{Role: config.Workload, RuntimeDir: dir}
	if enabled, err := configurePolicyHost(cfg, &params); err != nil || !enabled {
		t.Fatalf("host: %v %v", enabled, err)
	}
	register.Do(gatewayopa.RegisterPlugins)
	rt, err := runtime.NewRuntime(t.Context(), params)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("runtime exit: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("runtime did not stop")
		}
	})
	wait := func(check func() bool) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for !check() {
			if time.Now().After(deadline) {
				t.Fatal("native state did not converge")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	wait(func() bool { return rt.ServerStatus() == runtime.ServerWaitingForPlugins })
	plugin := bundleplugin.Lookup(rt.Manager)
	if err = plugin.Trigger(t.Context()); err == nil {
		t.Fatal("unavailable initial bundle was accepted")
	}
	if err = checkOPA(t.Context(), cfg); err == nil {
		t.Fatal("ready before initial usable bundle")
	}
	publish := func(p workload.Policy, revision string) {
		t.Helper()
		archive, err := policybundle.BuildExecution(p, revision)
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		body, status = archive, 200
		mu.Unlock()
		if err = plugin.Trigger(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	publish(workload.Policy{}, "initial")
	wait(func() bool { return checkOPA(t.Context(), cfg) == nil })
	conn, err := grpc.NewClient("unix://"+filepath.Join(dir, "opa.sock"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := auth.NewAuthorizationClient(conn)
	request := &auth.CheckRequest{Attributes: &auth.AttributeContext{Request: &auth.AttributeContext_Request{Time: timestamppb.Now(), Http: &auth.AttributeContext_HttpRequest{Host: "api.example", Method: "POST", Path: "/body", RawBody: []byte(`{"action":"safe"}`), HeaderMap: &core.HeaderMap{Headers: []*core.HeaderValue{{Key: "content-type", RawValue: []byte("application/json")}}}}}}}
	decision := func(want bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		response, err := client.Check(ctx, request)
		if err != nil || (response.GetStatus().GetCode() == 0) != want {
			t.Fatalf("decision want=%v response=%v err=%v", want, response, err)
		}
	}
	decision(true)
	deny := workload.Policy{RequestConstraints: []workload.Constraint{{Name: "body", Match: workload.Match{Hosts: []workload.HostMatcher{{Type: workload.Exact, Value: "api.example"}}, HTTP: &workload.HTTPMatch{}}, Decode: &workload.Decoder{Format: workload.JSON}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/action"), Operator: workload.In, Values: []string{"different"}}}}}}
	publish(deny, "deny")
	decision(false)
	for _, code := range []int{503, 200} {
		mu.Lock()
		body, status = []byte("invalid bundle"), code
		mu.Unlock()
		if err = plugin.Trigger(t.Context()); err == nil {
			t.Fatal("invalid native update accepted")
		}
		if err = checkOPALiveness(t.Context(), cfg); err != nil {
			t.Fatalf("recoverable update failed liveness: %v", err)
		}
		decision(false)
		publish(workload.Policy{}, "recovery")
		wait(func() bool { return checkOPA(t.Context(), cfg) == nil })
		decision(true)
		publish(deny, "deny")
		decision(false)
	}
}
