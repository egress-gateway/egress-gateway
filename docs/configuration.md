# Gateway startup configuration

The public `github.com/egress-gateway/egress-gateway/config` package is the
configuration and volume contract. It stays in this module and has no Kubernetes,
OPA or Envoy dependencies. The daemon consumes this package directly.

| Environment | Default | Meaning |
|---|---|---|
| `GATEWAY_ROLE` | `workload` | `workload` selects a sidecar; `egress` selects a router |
| `GATEWAY_PROXY_MODE` | `istio` | `standalone` supervises Envoy; `istio` supervises pilot-agent |
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

## Current implementation boundary

The standalone HTTP fixture tests embedded OPA, complete-body authorization at
both roles (64 KiB buffering, partial bodies disabled), private interfaces and
process/CA lifecycle. It does **not** implement or certify HTTPS inspection.
Dynamic certificate SDS, target binding, verified origin TLS, trusted peer identity
adaptation and the full mesh management boundary remain incomplete behind the
[certificate capability blocker](https-capability.md). In particular, stock
pilot-agent's management listeners have not yet been isolated from applications
sharing its network namespace. Do not treat this partial candidate as V01-01
acceptance or as a production boundary for untrusted workloads.
