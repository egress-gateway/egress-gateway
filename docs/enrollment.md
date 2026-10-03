# Gateway-owned Kubernetes composition

`enrollment.ComposePod(business, Options)` is a pure public boundary in this module.
The runtime `config` package stays independent of Kubernetes. The current helper
supports the existing Istio workload and egress roles and default runtime paths.

The trusted caller resolves the ServiceAccount, namespace, unique networking
binding, exact peers/ports, Gateway image, original application trust image/path,
provider configuration, optional origin trust ConfigMap and optional policy
ConfigMap (`policy.rego`). These options must be
independent of submitted business inputs. The helper never looks up resources or
writes to Kubernetes. It returns a copied final Pod and `networking.Policy`, or
nil outputs and an error; caller inputs remain unchanged.

The caller installs the returned policy before creating any selected Pod, including
Deployment templates, and keeps it until the old sandboxes are gone. It owns final
admission, namespace labels, endpoint/binding labels, image and referenced resource
integrity. A controller can call the same boundary with resolved inputs; no running
controller is needed by the static consumer in `cmd/gateway-e2e-compose`.

## Managed composition

Gateway derives the complete trusted specification from its own embedded managed
components, never from the business Pod. It owns:

1. Bounded root volume preparation (CHOWN, FOWNER, DAC_OVERRIDE).
2. Terminating `gateway-management-init` (NET_ADMIN, NET_RAW), explicitly declared
   through networking's `NetworkInitContainers` authorization.
3. A restricted UID/GID 1337 resident proxy; workload uses a native sidecar and
   readiness gates the remaining startup steps.
4. Original trust-store copying and inspection CA merging before business init/app
   execution. `TrustMounts` exposes only the final read-only certificate bundle.

Business and resident containers retain explicit nonroot identities, no added
capabilities and no privilege escalation. Reserved UID/GID 1337, managed names,
private mounts/volume substitutions, Istio injection/capture metadata and business
ServiceAccount token projection are rejected. Gateway disables implicit credential
automount and mounts its own audience-limited token only in the proxy. Platform
permissions alone would not protect these Gateway-specific resources.

`PolicyConfigMap` mounts the selected policy read-only into the managed proxy
and passes its private path to the daemon. Business containers cannot mount or
replace this reserved resource. Policy publication and content remain caller-owned.

`ProxyEnv` is trusted provider/telemetry configuration; it cannot override canonical
Gateway/runtime fields. Other secrets or configuration used by business execution
remain the caller's responsibility. The helper validates declarations, not mutable
ConfigMap content or image provenance. Admission must prevent later mutations from
invalidating the composition.

## Networking dependency and limits

The Go dependency and installer resolve the same immutable networking module from
`go.mod` (`3eb458d91ad06a29bd20d60a153476db0ba18ede`). The fixture uses the supported
single-node IPv4 kind/Calico profile. Networking owns Calico, policy expansion,
platform validation and pre-business IPv6 disablement. Gateway owns Istio CNI
composition, management isolation and runtime startup semantics.

Network exceptions apply to the entire Pod. They cannot authenticate a caller
inside an allowed TCP listener, and other additive NetworkPolicies can widen them.
The caller must protect policy and binding writes. The kind consumer installs fail-closed body authorization at both proxy roles
before creating Pods. It removes direct workload routes to the gateway ports and
requires verified mesh identity at both allowed gateway listeners. Component HTTPS
smoke and the live mesh/network suite certify different layers.
