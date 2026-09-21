// Package opa assembles the upstream OPA runtime and its compiled extensions.
package opa

import (
	"github.com/open-policy-agent/opa-envoy-plugin/plugin"
	"github.com/open-policy-agent/opa/v1/runtime"
)

// RegisterPlugins registers compiled extensions before the OPA command starts.
func RegisterPlugins() {
	runtime.RegisterPlugin(plugin.PluginName, plugin.Factory{})
}
