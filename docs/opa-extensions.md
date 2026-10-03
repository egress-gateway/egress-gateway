# OPA extensions

`internal/opa/register.go` registers Policy's `extension.Register()` and the
official `envoy_ext_authz_grpc` factory before creating the upstream OPA runtime.
The daemon supplies the host role, private sockets, authorization entry point and
raw-body setting. Policy owns its plugin, built-ins, normalization, dependency
handling and execution bridge. No policy-specific plugin or compiler is maintained
in Gateway.

The development-only `gateway-opa` utility uses the same registrations and retains
upstream OPA CLI semantics. Production configuration goes through `OPA_CONFIG`;
the daemon is the image entry point. Native bundles contain Policy's execution
artifacts. OPA owns transport, loading, compilation and activation, and exposes
its native bundle/plugin diagnostics.

See [policy integration](policy-contract.md) for configuration, supported wire
formats, failure recovery and migration. Rules and extension contracts belong in
[the Policy repository](https://github.com/egress-gateway/egress-gateway-policy).
New Gateway extensions require a direct Gateway-owned need that existing upstream
configuration and the Policy extension cannot satisfy.
