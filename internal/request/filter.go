// Package request supplies the Envoy-side target and verified-peer adapter.
package request

import (
	_ "embed"
	"strconv"

	"github.com/egress-gateway/egress-gateway/config"
)

//go:embed guard.lua
var guard string

// Filter is installed before ext_authz and routing. It uses connection facts
// supplied by Envoy, not application headers, to establish the request scheme
// and peer identity. OPA retains its upstream CheckRequest input contract.
func Filter(role config.Role) map[string]any {
	return map[string]any{
		"@type":               "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua",
		"default_source_code": map[string]any{"inline_string": Source(role)},
	}
}

// Source is also consumed by Istiod-owned HTTPS listener configuration.
func Source(role config.Role) string {
	return source(role, "https")
}

// HTTPSource preserves the same target and peer checks on an HTTP origin route.
// Egress still requires the authenticated mesh TLS hop.
func HTTPSource(role config.Role) string { return source(role, "http") }

func source(role config.Role, scheme string) string {
	return "local role = " + strconv.Quote(string(role)) + "\nlocal scheme = " + strconv.Quote(scheme) + "\n" + guard
}
