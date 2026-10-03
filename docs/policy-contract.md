# Shared workload policy integration

Gateway consumes `egress-gateway-policy` at
`v0.0.0-20261003102545-355f8aa1aa88`. Public `workload.Policy`, validation,
normalized inputs/decisions, fixed Rego and `bundle.Build` belong to that library.
The dependency direction is gateway → policy ← controller. No public rule types
or baseline evaluator are duplicated here.

## Static configuration

A trusted consumer constructs and validates a `workload.Policy`, calls
`bundle.Build`, and stages the resulting archive for each role. Set
`GATEWAY_WORKLOAD_CONFIG` to an absolute JSON file path:

```json
{
  "bundle": "/etc/gateway/policy/workload.tar.gz",
  "descriptors": [{
    "url": "https://artifacts.example/api.pb",
    "digest": "sha256:<64 lowercase hex characters>",
    "path": "/etc/gateway/policy/api.pb"
  }],
  "allowedPeers": ["spiffe://cluster.local/ns/application/sa/client"]
}
```

`descriptors` is omitted when no Protobuf decoder is required. Each entry binds
exact staged bytes to the URL and digest in a public rule; the URL is an identity,
not a download instruction. Egress requires a nonempty `allowedPeers` list of exact
verified SPIFFE identities, independently of any baseline pass. Workload does not
use that binding. Applications must not write these files or choose their paths.

Startup validates the standard bundle root `egress_gateway/workload`, Rego v1,
contract version `v1`, policy data, descriptor SHA-256, imports, selected service
and methods. Invalid dependencies stop startup before forwarding becomes available.
The already verified archive and fixed gateway adapter bundle are loaded through
upstream OPA. Verified descriptors remain in memory. The request path does no
artifact reads or downloads. Changes require process/Pod replacement; dynamic
publication, binding and activation belong to the later controller milestone.
Do not combine this static mode with independently updated OPA bundles. Do not
combine it with `--policy`; that flag remains for explicit test fixtures.

## Authorization boundary

The daemon fixes the official Envoy plugin query to `gateway/adapter/allow` and
turns off its first-message/body parser. A private `gateway.inspect` built-in
normalizes Envoy's trusted attributes and performs the required wire decoding.
The fixed bridge evaluates `data.egress_gateway.workload.decision` with the public
normalized input. `gateway.accepts` uses the library's strict decision decoder;
undefined results, evaluation errors or malformed decisions cannot allow.

The valid empty baseline is supported. Missing data or dependencies are not an
empty policy. Peer admission, target guards, mesh/origin TLS validation and network
controls remain independent requirements. Both roles evaluate their own static
baseline; application identity or prior-allow headers confer no permission.

## Envoy consumer requirements

Standalone preparation sets `encode_raw_headers: true` and complete raw request
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
- Protobuf: one complete uncompressed unary gRPC message, including its five-byte
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

Component tests exercise the public bundle through the official gRPC authorization
service, all public selector/operator families, strict decisions, immutable startup
snapshots, decoder failures and separate descriptor views. Image tests use real
HTTP/HTTPS and gRPC, verified TLS, independent egress decisions and origin
non-delivery. Existing fixture policies remain for mutation/fault injection and
legacy regression. Shared-policy real-mesh acceptance is delivered by #13; image
proof alone does not establish that result.
