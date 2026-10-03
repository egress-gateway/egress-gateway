package suite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa-envoy-plugin/envoyauth"
	"github.com/open-policy-agent/opa/v1/rego"
)

func TestMutationFixtureDecisions(t *testing.T) {
	for _, tc := range []struct {
		role, action, principal, scheme string
		allowed                         bool
	}{
		{"workload", "safe", "", "https", true},
		{"egress", "safe", "spiffe://cluster.local/ns/gateway-test/sa/workload", "https", true},
		{"workload", "egress-deny", "", "https", true},
		{"workload", "workload-mutate", "", "https", true},
		{"egress", "egress-mutate", "spiffe://cluster.local/ns/gateway-test/sa/workload", "https", true},
		{"egress", "egress-deny", "spiffe://cluster.local/ns/gateway-test/sa/workload", "https", false},
		{"workload", "workload-deny", "", "https", false},
		{"egress", "safe", "spiffe://attacker/ns/gateway-test/sa/workload", "https", false},
		{"workload", "safe", "", "http", false},
		{"egress", "safe", "spiffe://cluster.local/ns/gateway-test/sa/workload", "http", false},
	} {
		t.Run(tc.role+"/"+tc.action+"/"+tc.scheme+"/"+tc.principal, func(t *testing.T) {
			policy, err := os.ReadFile(filepath.Join("..", "config", tc.role+".rego"))
			if err != nil {
				t.Fatal(err)
			}
			request := &auth.CheckRequest{Attributes: &auth.AttributeContext{
				Source: &auth.AttributeContext_Peer{Principal: tc.principal},
				Request: &auth.AttributeContext_Request{Http: &auth.AttributeContext_HttpRequest{
					RawBody: []byte(`{"action":"` + tc.action + `"}`), Method: "POST", Scheme: tc.scheme, Path: "/body",
				}},
			}}
			input, err := envoyauth.RequestToInput(request, nil, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			results, err := rego.New(rego.Query("data.envoy.authz.allow"), rego.Module(tc.role+".rego", string(policy)), rego.Input(input)).Eval(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 || len(results[0].Expressions) != 1 {
				t.Fatal("missing fixture decision")
			}
			decision, ok := results[0].Expressions[0].Value.(map[string]any)
			if !ok || decision["allowed"] != tc.allowed {
				t.Fatalf("decision: %#v", results)
			}
			if strings.HasSuffix(tc.action, "-mutate") {
				mutation, ok := decision["query_parameters_to_set"].(map[string]any)
				if !ok || mutation["changed"] != "true" {
					t.Fatal("mutation response missing")
				}
			}
		})
	}
}
func TestGovernanceEvidenceRejectsFalsePositives(t *testing.T) {
	entry := func(role string, code int, details string) string {
		b, _ := json.Marshal(map[string]any{"request_id": "probe", "code": code, "details": details, "downstream_peer": "spiffe://cluster.local/ns/gateway-test/sa/workload", "role": role})
		return string(b)
	}
	wl := entry("workload", 403, "via_upstream")
	eg := entry("egress", 403, "ext_authz_denied")
	if err := assertGovernance("egress", 403, "probe", "egress denied", wl, eg, "control request_id=probe-after\n"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, workload, egress, origin string }{
		{"delivered despite denial", wl, eg, "origin request_id=probe\n"},
		{"missing final decision", wl, "", ""},
		{"unrelated proxy error", wl, entry("egress", 403, "route_not_found"), ""},
		{"wrong rejection status", wl, entry("egress", 200, "ext_authz_denied"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := assertGovernance("egress", 403, "probe", "egress denied", tc.workload, tc.egress, tc.origin); err == nil {
				t.Fatal("invalid denial evidence accepted")
			}
		})
	}
	if err := assertGovernance("origin", 200, "probe", "upstream reached", entry("workload", 200, "via_upstream"), entry("egress", 200, "via_upstream"), ""); err == nil {
		t.Fatal("allow accepted without delivery")
	}
}
