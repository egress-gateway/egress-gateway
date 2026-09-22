# Gateway startup configuration

The public `github.com/egress-gateway/egress-gateway/config` package is the
configuration and volume contract. It stays in this module and has no Kubernetes,
OPA or Envoy dependencies. The daemon consumes this package directly.

| Environment | Default | Meaning |
|---|---|---|
| `GATEWAY_ROLE` | `workload` | `workload` selects a sidecar; `egress` selects a router |
| `GATEWAY_PROXY_MODE` | `istio` | `standalone` supervises Envoy; `istio` supervises pilot-agent |
| `GATEWAY_IDENTITY_PROVIDER` | `istio-mtls` | Verified peer TLS principal through the official OPA plugin; other providers fail startup |
| `OPA_CONFIG` | `/etc/gateway/opa/<role>.yaml` | Embedded OPA configuration; upstream bundle capabilities remain available |
| `ENVOY_CONFIG` | Unset | Required standalone bootstrap; rejected in Istio mode |
| `GATEWAY_STATE_DIR` | `/var/lib/gateway/private` | Private Pod-lifetime inspection CA state |
| `GATEWAY_PUBLIC_DIR` | `/run/gateway/trust` | Separately mountable public inspection certificate directory |
| `GATEWAY_RUNTIME_DIR` | `/run/gateway/private` | Private sockets and generated standalone bootstrap |

Unset variables use defaults. Explicit empty values are rejected. Paths must be
clean absolute paths. All three directories must be disjoint; directory symlinks
and group/world-accessible private directories are rejected. Public directories
must not be group- or world-writable. Deployment must
prepare private volume ownership for UID 1337 with mode 0700. Mounting one shared
parent directory into an application does not satisfy the contract.

The daemon accepts repeated `--policy /absolute/path` arguments for local startup
policy files. OPA CLI passthrough (`--set`, positional policies, `run`, etc.) is
removed and unsupported arguments fail startup. Move upstream configuration into
`OPA_CONFIG`; use `--policy` for local fixture policy files. `gateway-opa` remains
a development integration-test utility; it is not shipped in the image.

The daemon fixes the official OPA plugin's listener to
`<runtime>/opa.sock`, disables dry-run/reflection, and exposes OPA HTTP management
only at `<runtime>/opa-api.sock`. The private directory must never be mounted into
the workload. In standalone mode, initialization preserves the bootstrap's
listeners/routes, changes its admin interface to `<runtime>/envoy-admin.sock`,
and changes the named `opa` cluster to the private authorization socket. Envoy
validates the resulting configuration. Istiod retains all mesh discovery ownership.

## Inspection CA and startup trust

Only the workload role creates CA state. `<state>/inspection-ca.json` contains the
certificate and signing key in one atomic mode-0600 file. It is exclusively owned
while the daemon runs. An empty state directory creates an ECDSA P-256 root valid
for ten years. Restarting with the same directory reuses it; fresh Pod volumes
create different roots. Corrupt, expired, mismatched or incomplete existing state
fails startup without replacing it. Public trust without private state also fails
rather than silently changing the running application's CA.

`<public>/inspection-ca.pem` contains only the root certificate. This file is
published atomically without replacing an existing file before either managed
runtime starts. An existing certificate must match the private CA, including when
another process publishes first. It is not a complete
operating-system trust bundle and does not authorize trusting origins.

A deployment prepares an application bundle before application startup:

```sh
gateway-daemon trust-init \
  --base /base-image/ca-certificates.crt \
  --ca /gateway-public/inspection-ca.pem \
  --output /application-trust/ca-bundle.pem
```

`--base` must be the explicitly selected application image's PEM store. The command
validates and combines both inputs; replacing a file never implicitly merges the
application's original store. Mount the prepared bundle read-only at that
application's declared trust path. Never mount private state or runtime sockets.
A native sidecar startup probe running `gateway-daemon ready`, followed by a trust
init container, provides the required ordering; ordinary Pod readiness alone does
not prevent applications from starting too early.

Inspection trust, origin trust, and Istio identity are separate. No inspection
certificate is installed into an origin trust store or used for mesh identity.

## HTTPS and private interfaces

`Config.InspectionSDSPath()` identifies `<runtime>/inspection-sds.sock`; the workload
role serves inspection secrets there before starting Envoy. `Config.RequestGuardPath()`
identifies the generated `<runtime>/https-guard.lua`, shared by standalone and
Istiod-owned listener configuration. Both files stay private. Standalone preparation
rewrites the named `inspection_sds` cluster and `gateway.request`/`gateway.dispatch` filters. Istio
integration references the same paths through EnvoyFilter; the daemon does not
publish competing mesh xDS resources.

Install the guard only on dedicated HTTPS listeners. It validates SNI against the
canonical authority at workload ingress and fixes scheme to HTTPS at both roles.
Egress obtains the official OPA `input.source_principal` from Envoy-verified TLS.
There is no custom identity or original-scheme header protocol. Authorization must
buffer complete bodies up to 64 KiB, reject partial bodies and errors, prohibit
decision mutations of the authorized target, and precede dynamic forward proxy.
Install `gateway.request` before authorization and `gateway.dispatch` immediately
after it. The second guard rejects any authority, scheme or path/query change from
the original canonical target; Envoy header mutation rules alone do not cover OPA
query mutations. Non-identity Content-Encoding is rejected with 415 before body
authorization; no decompressor is provided. The component configuration under
`test/image/https` demonstrates this contract.

Istio requires TCP management ports for its agent and Envoy. Deployments run
`gateway-management-init` once with UID 0 and NET_ADMIN/NET_RAW before applications
start. Its IPv4/IPv6 rules permit local management on 15000/15020/15004 only to
proxy UID 1337 and reject remote ingress to those ports. Runtime containers drop
all capabilities, disable privilege escalation, and applications use a different
UID. Do not share UID 1337 or private mounts with an application. Readiness 15021
remains accessible. The image defaults `ISTIO_BOOTSTRAP_OVERRIDE` to
`/etc/gateway/envoy-limits.json`; custom bootstrap inputs must preserve the supplied
inspection resource bounds. The script is safe to rerun after interrupted init.

Origin trust must be mounted independently; inspection trust never grants origin
trust. See [capability limits](https-capability.md) and [validation scope](compatibility.md).
