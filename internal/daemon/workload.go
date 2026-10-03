package daemon

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/artifacts"
	"github.com/egress-gateway/egress-gateway/internal/inspection"
	gatewayopa "github.com/egress-gateway/egress-gateway/internal/opa"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/runtime"
)

func prepareWorkload(c config.Config, params *runtime.Params) error {
	if c.WorkloadConfig == "" {
		return nil
	}
	if len(params.Paths) != 0 {
		return fmt.Errorf("workload configuration cannot be combined with fixture policies")
	}
	snapshot, err := artifacts.LoadWorkload(c.WorkloadConfig, c.Role)
	if err != nil {
		return err
	}
	sharedPath := filepath.Join(c.RuntimeDir, "workload.tar.gz")
	if err := inspection.WriteAtomic(sharedPath, snapshot.Archive, 0600); err != nil {
		return err
	}
	parsed, err := ast.ParseModule("gateway.rego", gatewayopa.BridgeModule)
	if err != nil {
		return err
	}
	bridge := bundle.Bundle{Manifest: bundle.Manifest{Roots: new([]string{"gateway/adapter"}), RegoVersion: new(1)}, Data: map[string]any{}, Modules: []bundle.ModuleFile{{URL: "gateway.rego", Path: "gateway.rego", Raw: []byte(gatewayopa.BridgeModule), Parsed: parsed}}}
	var buffer bytes.Buffer
	if err := bundle.NewWriter(&buffer).Write(bridge); err != nil {
		return err
	}
	bridgePath := filepath.Join(c.RuntimeDir, "adapter.tar.gz")
	if err := inspection.WriteAtomic(bridgePath, buffer.Bytes(), 0600); err != nil {
		return err
	}
	gatewayopa.RegisterWorkload(snapshot, c.Role)
	params.BundleMode = true
	params.Paths = []string{sharedPath, bridgePath}
	params.ConfigOverrides = append(params.ConfigOverrides, "plugins.envoy_ext_authz_grpc.path=gateway/adapter/allow", "plugins.envoy_ext_authz_grpc.skip-request-body-parse=true")
	return nil
}
