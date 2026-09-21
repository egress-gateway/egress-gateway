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
isolation is not yet verified; see the explicit partial-delivery boundary in
[configuration](configuration.md).

| Owner | Responsibility |
|---|---|
| gateway | Public runtime config, daemon/image, inspection trust, data-plane adapters, component and minimal connectivity tests |
| policy | Future shared policy semantics and baseline fixtures |
| networking | Shared installation, workload enrollment and network mechanics |
| controller | CRDs, binding, admission, publication and desired-state status |
| Istio | Mesh discovery, workload identity, mTLS and Envoy ownership under pilot-agent |
| workload manager | Pod creation and its volume lifetime |

The HTTP fixture uses two independent OPA checks with bounded complete-body
buffering. These test-only policies do not define shared policy semantics. No
application-supplied identity is promoted into a verified principal. The real
Istio principal adapter and HTTPS enforcement remain incomplete; do not infer
those guarantees from the HTTP fixture or prepared CA files.
