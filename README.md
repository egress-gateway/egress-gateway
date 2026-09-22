# Egress Gateway

A data plane runtime that packages Envoy, the Istio agent, and an extensible OPA into one image, configured to run as either a Workload Proxy or an Egress Gateway.

The daemon embeds the official OPA runtime and Envoy plugin, supervises Envoy or
pilot-agent, and supplies inspection certificates over private SDS. HTTPS is
terminated at workload Envoy, authorized independently at both roles, and forwarded
over verified origin TLS. The image combines Istio 1.31.0 pilot-agent with the
official Envoy contrib 1.39.0 distribution; see the [capability and resource
boundary](docs/https-capability.md). GatewayProfile binding and dynamic policy
delivery remain separate work.

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
cmd/gateway-daemon/     Embedded OPA and proxy supervision
config/                Public startup and volume contract
cmd/gateway-opa/        Development-only OPA integration-test utility
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

`internal/request` supplies the private HTTPS target guard. Trusted identity uses
the official OPA plugin input from verified TLS; no public policy DTO is introduced.
`internal/identity` and `internal/artifacts` retain ownership documentation.

## Shared policy library

Public policy types, normalized inputs and decisions, baseline Rego, and shared semantic fixtures belong in [`egress-gateway-policy`](https://github.com/egress-gateway/egress-gateway-policy). Both this repository and the controller will depend on it.

That library has no usable version yet, so this scaffold adds no placeholder `require`, local `replace`, or duplicated public types. The example `fixture.*` policies only verify process connectivity; they do not define the future shared policy contract. See the [shared dependency boundary](docs/policy-contract.md).

## Documentation

- [Architecture and responsibilities](docs/architecture.md)
- [OPA plugin development](docs/opa-extensions.md)
- [Runtime configuration and current limitations](docs/configuration.md)
- [Component versions and validation scope](docs/compatibility.md)
- [Contributing](CONTRIBUTING.md)

The gateway repository owns its minimal kind/Istio connectivity fixture. Shared network installation and enrollment belong in networking; admission belongs in controller. Local image tests do not establish real mesh identity or network fail-closed behavior.
