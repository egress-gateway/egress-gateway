# Shared workload policy integration

Gateway consumes the immutable `egress-gateway-policy` module pinned in `go.mod`.
Policy owns public rules, normalized inputs/decisions, fixed Rego, execution
artifacts and its OPA extension. The dependency direction is gateway → policy ←
controller. Gateway registers the extension and supplies host configuration;
upstream OPA owns bundle transport, loading, compilation and activation.

## Native OPA configuration

A trusted consumer calls `bundle.BuildExecution(policy, revision)` and publishes
the resulting standard snapshot. Point `OPA_CONFIG` at ordinary OPA configuration:

```yaml
plugins:
  egress_gateway_workload:
    role: egress
    allowedPeers: ["spiffe://cluster.local/ns/application/sa/client"]
    descriptors:
      - url: https://artifacts.example/api.pb
        digest: sha256:<64 lowercase hex characters>
        path: /etc/gateway/policy/api.pb
services:
  policies:
    url: https://bundles.example
bundles:
  workload:
    service: policies
    resource: workload.tar.gz
    polling:
      min_delay_seconds: 10
      max_delay_seconds: 20
status:
  console: true
```

Use native `resource: file:///etc/gateway/policy/workload.tar.gz` without a service
for a staged, one-time file load. HTTP pull is needed for the update scenarios.
OPA owns source authentication, polling and error diagnostics.

`descriptors` is omitted when no Protobuf dependency is needed. Policy verifies
staged bytes, SHA-256, imports, selected services and methods. URLs identify
artifacts; they are not descriptor download instructions. Descriptors remain
immutable for that plugin configuration, so stage all required views before
adopting a policy that uses them. Applications must not write configuration,
bundles or descriptors. Egress requires exact verified SPIFFE `allowedPeers`,
independently of a valid empty or permitting workload policy.

Gateway derives the role from `GATEWAY_ROLE`, fixes the official Envoy plugin
query to `egress_gateway/workload/authorization/allow`, and disables its body
parser. Policy's registered extension and execution artifact perform inspection
and strict decision adaptation in the same native OPA evaluation. Gateway does
not read DSL fields, prepare descriptors, generate bridge Rego or fetch policies
on requests. Undefined, erroneous or malformed decisions cannot authorize.

Startup waits for the first usable bundle and extension dependencies before proxy
startup. Native download/load/compile failures retain the last activated policy.
The native status log records errors and the actual active revision. An activated
bundle with incompatible inspection dependencies is not ready and cannot authorize
uninspected traffic. A later compatible update recovers without a runtime restart.
Readiness uses `/health?plugins&bundles`; liveness uses `/health` and the private
authorization listener, allowing OPA's own update loop to recover.

### Migration

Remove `GATEWAY_WORKLOAD_CONFIG` and its old `runtime.json`; setting that variable
now fails with a migration error. Move the staged descriptors and peer binding
into Policy's plugin configuration under `OPA_CONFIG`. Publish `BuildExecution`
artifacts; core-only `bundle.Build` artifacts are not ready extension artifacts.
The public normalized-input library contract remains unchanged. `--policy` stays
available for explicit test fixtures and cannot be combined with the extension.

Both roles evaluate their own active bundle. Peer admission, target guards,
mesh/origin TLS and network controls remain independent. No product publisher,
Controller integration or fleet convergence guarantee is introduced here.

## Envoy consumer requirements

Shared standalone startup requires an ext_authz HTTP filter. Preparation forces
`failure_mode_allow: false`, sets `encode_raw_headers: true` and complete raw request
body buffering on each ext_authz filter. Istiod-owned filters must supply the same
configuration: `with_request_body.max_request_bytes: 65536`,
`allow_partial_message: false`, `pack_as_bytes: true`, `encode_raw_headers: true`.
Use the private target guards before and after authorization, fail-closed
ext_authz, HTTP/2 and ALPN on gRPC hops, and mandatory peer/origin TLS verification.
Gateway does not publish competing mesh discovery resources.

Headers and query parameters retain individual repeated values. Commas are not
split into invented values. Header and text metadata keys are lowercase; query
names remain case-sensitive. Binary metadata is excluded. Legacy lossy header
maps are unavailable inspection, so required attribute checks fail closed.

Paths are percent-decoded once for operation matching; query values are decoded
once. Existing Envoy path normalization and escaped-slash rejection still apply.
A configured RPC service path is recognized even with a spoofed Content-Type;
required Protobuf inspection also requires a valid gRPC HTTP/2 POST. HTTP-carrier
constraints continue to apply to gRPC. Decoder failures are payload-view status,
so unrelated and attribute-only rules do not acquire decoding prerequisites.

## Supported payloads and limits

- JSON: one complete UTF-8 value, with duplicate keys, trailing data, malformed
  syntax and unpaired UTF-16 surrogates rejected. Numbers retain their JSON type;
  missing, null, empty keys, arrays and RFC 6901 selection remain distinct.
  Inspection supports up to 256 nested containers.
- Protobuf: `application/grpc` or `application/grpc+proto` only; other codec
  subtypes are recognized as gRPC but cannot satisfy Protobuf inspection. One
  complete uncompressed unary message is accepted, including its five-byte
  envelope within the 64 KiB body limit. Truncation, extra frames/trailing bytes,
  compression and client/server/bidirectional streaming payloads are rejected.
  A framed zero-length message is valid and maps to an empty message when allowed
  by its descriptor. Text metadata rules make no per-message streaming claim.
- ProtoJSON: standard protobuf JSON names, types, enum/64-bit representations and
  presence/default behavior, without forcing absent defaults. Each distinct
  descriptor digest produces its own verified view.

Non-identity HTTP Content-Encoding is rejected before authorization. Envoy rejects
oversized/partial bodies. Invalid, unavailable, truncated or unsupported required
inspection denies the matching rule. Access logs identify the rejecting role and
correlation ID; dependency failures identify the affected constraint at startup.
Keep payload-bearing OPA decision logging disabled unless separately configured
and protected by the trusted operator.

## Evidence boundaries

Policy's component tests own normalized rule and decoder conformance. Gateway's
component tests exercise registration, role/entrypoint configuration and native
readiness/update/recovery through the official authorization service. Image tests
exercise native HTTP pull, policy changes and failure recovery through real
HTTP/HTTPS and unary gRPC traffic with verified TLS. Mesh tests additionally prove
Istio identity, Pod confinement and attributable origin delivery/non-delivery.

## Real mesh fixture and update duration

The trusted test consumer builds the execution bundles and stages descriptors.
A fixture-only publisher exposes read-only bundle URLs; its write listener is
loopback-only and accessed using the test runner's authenticated `kubectl exec`.
Both roles use native OPA polling at one second. The suite changes each role
independently while keeping the other permissive, with three allow/deny cycles.

The publisher records when the new bytes become available. An application-side
probe records real response times and request IDs, at a 200 ms cadence plus
request time. Publisher, OPA and probe share the kind node clock. Artifacts retain
publication-to-observed-enforcement duration, native activation time separately,
and the observation interval/uncertainty, along with revision and candidate
identity. Polling, response time and probe launch delay are included in the
primary measurement; no latency SLO is asserted. Pod UIDs, container IDs and
restart counts must remain unchanged. Denials require responsible-proxy evidence
and healthy-origin non-delivery; allows require actual protected-operation delivery.

See the [fixture matrix](../test/e2e/README.md#shared-http-and-grpc-policy) for
selector, invalid-input, dependency, empty-policy, peer-admission and update cases.
Explicit mutation/fault policies remain separate from shared baseline proof.
