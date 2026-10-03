package daemon

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/egress-gateway/egress-gateway-policy/extension"
	"github.com/egress-gateway/egress-gateway/config"
	"github.com/open-policy-agent/opa/v1/runtime"
	"sigs.k8s.io/yaml"
)

// configurePolicyHost supplies host-owned role and authorization settings when
// the native OPA configuration enables Policy's extension. OPA owns the complete
// plugin configuration, bundle transport, loading and compilation.
func configurePolicyHost(c config.Config, params *runtime.Params) (bool, error) {
	raw, err := os.ReadFile(params.ConfigFile)
	if err != nil {
		return false, fmt.Errorf("read OPA configuration: %w", err)
	}
	var native struct {
		Plugins map[string]json.RawMessage `json:"plugins"`
	}
	if err := yaml.Unmarshal(raw, &native); err != nil {
		return false, fmt.Errorf("invalid OPA configuration (content omitted)")
	}
	if _, enabled := native.Plugins[extension.PluginName]; !enabled {
		return false, nil
	}
	if len(params.Paths) != 0 {
		return false, fmt.Errorf("Policy extension cannot be combined with fixture policies")
	}
	params.ConfigOverrides = append(params.ConfigOverrides,
		"plugins."+extension.PluginName+".role="+string(c.Role),
		"plugins.envoy_ext_authz_grpc.path="+extension.DecisionPath,
		"plugins.envoy_ext_authz_grpc.skip-request-body-parse=true",
	)
	return true, nil
}
