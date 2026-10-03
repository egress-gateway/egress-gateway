# Runtime ownership

`gateway-daemon` embeds the upstream OPA runtime and official Envoy plugin in its
Go process. Standalone mode supervises Envoy; Istio mode supervises pilot-agent,
which owns Envoy. The daemon does not publish mesh discovery resources or issue
Istio identities. The same image serves workload and egress roles.

Initialization validates the public config, locks private runtime state, prepares
the workload inspection CA, and starts OPA. After its plugins and authorization
socket are ready, it starts the proxy. Readiness requires public trust for workload,
OPA health and the selected proxy's readiness. An unexpected proxy exit or lost
required service terminates the runtime; no daemon restart loop is introduced.
SIGTERM/SIGINT stop the proxy process group and cancel embedded OPA. Process-group
shutdown has a five-second bound before forced termination. Linux also requests
termination of the direct child if its parent exits unexpectedly.

The authorization socket and OPA management socket are private filesystem sockets.
Standalone Envoy's admin socket uses the same private directory. The trusted
configuration producer still owns listener and route contents; arbitrary mounted
configuration is not treated as untrusted workload input. Istio management
isolation uses the one-time Pod UID rules described in
[configuration](configuration.md).

| Owner | Responsibility |
|---|---|
| gateway | Public runtime config, trusted Pod composition, Istio integration, private runtime resources, daemon/image and consumer acceptance |
| policy | Public workload semantics, normalized contract and fixed baseline Rego |
| networking | Calico installation, policy expansion, platform permission validation and pre-business IPv6 disablement |
| controller | CRDs, binding, admission, publication and desired-state status |
| Istio | Mesh discovery, workload identity, mTLS and Envoy ownership under pilot-agent |
| workload manager | Pod creation and its volume lifetime |

The HTTP fixture uses two independent OPA checks with bounded complete-body
buffering. These test-only policies do not define shared policy semantics. No
application-supplied identity is promoted into a verified principal. The HTTPS fixture verifies the official plugin
principal against a validated mesh-style peer certificate. Only the separate
kind suite establishes real Istiod credentials and transparent CNI capture.

The kind consumer applies its test-only OPA policies and guarded HTTP/HTTPS routes
before starting enrolled Pods. The same private target guard supports HTTP origin
routes while retaining mandatory mesh TLS and verified peer identity at egress.
Workload raw routes to the allowed gateway ports are removed; those listeners also
require client identity. Networking policy remains Pod-wide, and protocol/fault
evidence is collected separately from content authorization.

Shared static mode loads verified library-built bundles and descriptor snapshots before
proxy startup. Its private adapter reuses the official OPA Envoy plugin and public
shared Rego query. See [policy integration](policy-contract.md) for the consumer
inputs and supported wire formats.
