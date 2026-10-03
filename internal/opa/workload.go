package opa

import (
	"encoding/json"
	"fmt"

	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/adapter"
	"github.com/egress-gateway/egress-gateway/internal/artifacts"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
	"google.golang.org/protobuf/encoding/protojson"
)

const BridgeModule = `package gateway.adapter
import rego.v1

default allow := false
allow if {
 normalized := gateway.inspect(input)
 decision := data.egress_gateway.workload.decision with input as normalized
 gateway.accepts(decision)
}
`

var inspectDeclaration = &rego.Function{Name: "gateway.inspect", Decl: types.NewFunction(types.Args(types.A), types.A)}
var acceptDeclaration = &rego.Function{Name: "gateway.accepts", Decl: types.NewFunction(types.Args(types.A), types.B)}

func inspect(a *adapter.Adapter) rego.Builtin1 {
	return func(_ rego.BuiltinContext, input *ast.Term) (*ast.Term, error) {
		value, err := ast.JSON(input.Value)
		if err != nil {
			return nil, err
		}
		fields, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("missing Envoy attributes")
		}
		raw, err := json.Marshal(map[string]any{"attributes": fields["attributes"]})
		if err != nil {
			return nil, err
		}
		var req auth.CheckRequest
		if err := protojson.Unmarshal(raw, &req); err != nil {
			return nil, fmt.Errorf("invalid Envoy facts: %w", err)
		}
		normalized, err := a.Normalize(&req)
		if err != nil {
			return nil, err
		}
		result, err := ast.InterfaceToValue(normalized)
		if err != nil {
			return nil, err
		}
		return ast.NewTerm(result), nil
	}
}
func accepts(_ rego.BuiltinContext, term *ast.Term) (*ast.Term, error) {
	value, err := ast.JSON(term.Value)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decision, err := workload.DecodeDecision(raw)
	if err != nil {
		return nil, err
	}
	return ast.BooleanTerm(decision.Allowed), nil
}

// WorkloadOptions uses query-local functions for component tests. The daemon
// registers the same implementations once before creating its single runtime.
func WorkloadOptions(snapshot *artifacts.Workload, role config.Role) []func(*rego.Rego) {
	return []func(*rego.Rego){rego.Function1(inspectDeclaration, inspect(adapter.New(snapshot, role))), rego.Function1(acceptDeclaration, accepts)}
}
func RegisterWorkload(snapshot *artifacts.Workload, role config.Role) {
	rego.RegisterBuiltin1(inspectDeclaration, inspect(adapter.New(snapshot, role)))
	rego.RegisterBuiltin1(acceptDeclaration, accepts)
}
