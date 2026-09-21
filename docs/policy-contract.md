# Shared policy library

The intended dependency direction is gateway → policy ← controller. The gateway and controller do not import each other.

The shared library should own workload policy types, normalized requests, decision results, bundle data contracts, baseline Rego, and shared semantic fixtures. OPA/Envoy input adaptation belongs in the gateway; Kubernetes types and custom resource conversion belong in the controller.

The shared library currently has no published code or version. This scaffold adds no fictitious Go dependency or duplicate public types. Integration must use real packages and a pinned module version from the library. The policy repository defines its API; this repository does not predefine it.

The `fixture.*` rules under `examples/local/policies` only verify proxy connectivity and the location of denials. They do not implement the Wiki's hostDenylist/requestConstraints semantics and must not be distributed as production policies.

OPA configuration retains the upstream default decision path, `envoy/authz/allow`. The image embeds no allow rule; without the corresponding policy, authorization cannot produce an allow decision. The production decision entry point and bundle roots must be updated once the shared contract is defined. This default does not define the final public API.

Use a personal `go.work` for cross-repository development and an explicit dependency version for delivery. Do not commit developer-specific paths or vendor the shared module as a separately maintained copy.
