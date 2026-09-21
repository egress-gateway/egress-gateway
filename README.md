# Egress Gateway

A data plane runtime that packages Envoy, the Istio agent, and an extensible OPA into one image, configured to run as either a Workload Proxy or an Egress Gateway.

This repository is a buildable scaffold with a runnable local example. It provides a custom OPA entry point, the official Envoy authorization plugin, startup for both roles, component tests, and CI. The full GatewayProfile contract, ServiceAccount identity binding, and dynamic policy delivery are not yet implemented.

## Getting started

Go 1.26+ is required. The image example also requires Docker Engine and Compose v2.

```sh
make check
make smoke
```

`make check` builds the custom OPA binary and exercises allow, deny, policy updates, and missing policies through the real gRPC authorization interface. `make smoke` builds the final image, verifies the complete local request path, and cleans up its containers and network afterward.

To run the example manually:

```sh
docker compose -f examples/local/compose.yaml up --build --detach --wait
curl --noproxy '*' http://127.0.0.1:18080/allowed
curl --noproxy '*' -i http://127.0.0.1:18080/workload-denied
curl --noproxy '*' -i http://127.0.0.1:18080/egress-denied
docker compose -f examples/local/compose.yaml down
```

The request path is `Client → Workload Envoy/OPA → Egress Envoy/OPA → Test upstream`. These requests produce an upstream response, a workload denial, and an egress denial, respectively. The local example uses test-only Rego policies and static Envoy configuration; it provides no Istio identity or bypass prevention guarantees.

## Repository layout

```text
cmd/gateway-opa/        Custom OPA executable entry point
internal/opa/           Registration of upstream and future project plugins
internal/plugins/       Extension boundary for future project plugins
internal/request/       Request adaptation boundary
internal/identity/      Trusted identity adaptation boundary
internal/artifacts/     Runtime artifact adaptation boundary
configs/opa/            OPA startup configuration for both roles
configs/envoy/          Envoy configuration ownership
integrations/istio/     Istio integration contract and pending validation
image/                 Single-image build, startup, and health checks
test/integration/      gRPC authorization tests against the custom OPA process
test/image/            Image tests for both roles and process lifecycle
examples/local/        Reproducible local request path and test-only policies
docs/                  Architecture, extensions, configuration, and compatibility
```

`internal/request`, `internal/identity`, and `internal/artifacts` currently document ownership boundaries only. They contain no placeholder services or unimplemented Go APIs. Code will be added as the corresponding features are defined.

## Shared policy library

Public policy types, normalized inputs and decisions, baseline Rego, and shared semantic fixtures belong in [`egress-gateway-policy`](https://github.com/egress-gateway/egress-gateway-policy). Both this repository and the controller will depend on it.

That library has no usable version yet, so this scaffold adds no placeholder `require`, local `replace`, or duplicated public types. The example `fixture.*` policies only verify process connectivity; they do not define the future shared policy contract. See the [shared dependency boundary](docs/policy-contract.md).

## Documentation

- [Architecture and responsibilities](docs/architecture.md)
- [OPA plugin development](docs/opa-extensions.md)
- [Runtime configuration and current limitations](docs/configuration.md)
- [Component versions and validation scope](docs/compatibility.md)
- [Contributing](CONTRIBUTING.md)

The full Kubernetes / Istio development environment, Pod injection, and end-to-end acceptance tests belong in [`egress-gateway-controller`](https://github.com/egress-gateway/egress-gateway-controller). Local image tests in this repository are not cluster E2E tests.
