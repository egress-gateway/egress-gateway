// Package opa assembles the upstream OPA runtime and its compiled extensions.
package opa

import (
	"github.com/egress-gateway/egress-gateway-policy/extension"
	"github.com/open-policy-agent/opa-envoy-plugin/plugin"
	"github.com/open-policy-agent/opa/v1/runtime"
)

// RegisterPlugins registers compiled extensions before the OPA command starts.
func RegisterPlugins() {
	extension.Register()
	runtime.RegisterPlugin(plugin.PluginName, plugin.Factory{})
}
