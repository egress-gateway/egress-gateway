# OPA extensions

The entry point in `cmd/gateway-opa/main.go` calls the registration function before executing the upstream OPA CLI. Commands such as `gateway-opa version`, `run`, and `check` retain upstream semantics.

Currently, `internal/opa/register.go` registers the official `envoy_ext_authz_grpc` plugin. Future project plugins belong in `internal/plugins/<feature>`, implement OPA's Factory / Plugin interfaces, and register in the same place. Keep business logic out of main.

To add an extension:

1. Establish that upstream configuration or existing plugins cannot satisfy the accepted contract.
2. Define inputs, outputs, and lifecycle; obtain shared semantic types from the policy library.
3. Implement configuration validation, Start / Stop / Reconfigure, and necessary state.
4. Register the plugin and add concrete configuration and behavioral tests.
5. Validate it in the final image and document compatibility with the OPA and Envoy versions.

Ordinary parsing functions need not be plugins. Use Rego builtins only for capabilities that rules actually need to call, not for control flows with side effects. If the official Envoy authorization plugin is replaced, retain one explicit authorization path rather than exposing competing decision services.

Identity mapping, the Wiki's full HTTP/JSON and gRPC/Protobuf normalization contracts, artifact digest adaptation, and cross-component activation feedback are not yet implemented. Their directories document ownership, not existing functionality.

References: [OPA runtime extensions](https://www.openpolicyagent.org/docs/extensions#custom-plugins-for-opa-runtime), [OPA-Envoy](https://www.openpolicyagent.org/docs/envoy).
