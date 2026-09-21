# Project plugins

When a custom OPA plugin is needed, create a Go package named for its specific capability here. Use the upstream `plugins.Factory` and `plugins.Plugin` interfaces and register it in `internal/opa/register.go`.

Each plugin owns its configuration validation, Start / Stop / Reconfigure lifecycle, and status reporting. Reuse upstream capabilities where possible. The scaffold directly registers the official OPA-Envoy plugin and has no additional project plugins. It defines no separate plugin framework or dynamic `.so` loading mechanism.

Ordinary request decoding, identity adaptation, and artifact validation can remain private packages called by plugins; they need not each become plugins. Policy types and semantics shared across repositories belong in `egress-gateway-policy`.
