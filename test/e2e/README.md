# Gateway governance BDD fixture

This suite covers transparent HTTP and HTTPS through both proxy roles, startup
inspection trust, real Istiod identities, independently verified origin TLS, two-stage body
authorization, protocol confinement and component failure recovery.
The selector configuration probe is only a prerequisite; the HTTPS scenario must
also complete its first request to a hostname chosen after proxy startup.

## Run and retain

Prerequisites: Go 1.26+, Bash 4+, Docker with Compose/build support, jq and
envsubst and OpenSSL. `config/versions.env` pins kind, kubectl, Helm, Kubernetes, Istio and curl.
On macOS the runner selects installed Homebrew Bash; scripts can also be called
directly with that Bash. Approximately 6 GiB available Docker memory is sufficient
for the dedicated one-node fixture. Do not use these scripts to enroll an external
or shared cluster.

```sh
make e2e
make e2e-up
make e2e-test
make e2e-down
```

Make only dispatches the Go entrypoint. Go performs one setup for all scenarios,
serial BDD execution, diagnostics and owned teardown. Every scenario uses a fresh
request UUID. `up` retains a successful environment; `test` validates the saved
inputs/node identity and retains it even after assertions fail. `down` requires the
recorded Docker node identity. Repeating `up` against an existing environment is an
error and must not delete it. Failed creation retains kind's partial resources just
long enough to collect available diagnostics and remove the recorded node.

For HTTP-only diagnosis use `E2E_TAGS=@connectivity`; this is not full acceptance.
The official Istio release archive is SHA-256 pinned and supplies the Helm charts.

Use the same `E2E_CLUSTER`, `E2E_IMAGE`, `E2E_STATE` and `E2E_ARTIFACTS` inputs for
retained operations. `.e2e/state` contains the local administrative kubeconfig and
must remain private. Only `.e2e/artifacts` is safe to attach to CI results. Diagnostic
collection excludes Secrets, environment dumps, private CA files and Envoy secret
config dumps. The fixture has no public origin dependency after setup.

## Executable phase scripts

Every phase accepts the complete explicit input set, for example:

```sh
bash test/e2e/scripts/mesh-install.sh \
  --root "$PWD" --cluster gateway-e2e-local \
  --kubeconfig "$PWD/.e2e/state/kubeconfig" \
  --image egress-gateway:e2e --state-dir "$PWD/.e2e/state" \
  --config-dir "$PWD/test/e2e/config" --artifacts "$PWD/.e2e/artifacts"
```

`cluster-up`, `foundation-install`, `image-load`, `mesh-install`, `fixtures-deploy`, `verify`, `diagnostics`
and `cluster-down` own their operation prerequisites/readiness and return nonzero
on failure. The node ID receipt is a declared file, not parsed human log output.
Go owns sequencing and cleanup decisions. YAML owns kind/Helm/deployment input.
`foundation-install` and `foundation-check` call scripts from the same immutable
networking Go module recorded in `go.mod`; downloaded installer cache is explicitly
placed in private fixture state, never in the read-only module artifact.

## Topology and evidence

The fresh single-node IPv4 kind cluster disables its default CNI. The networking
installer configures Calico and pre-business IPv6 disablement before Gateway
installs Istio CNI. Its foundation check runs after composition, agent restarts and
retained reuse. The static Go consumer calls `enrollment.ComposePod` for both
roles and applies generated NetworkPolicies before Pods. Root volume preparation
and the explicitly authorized management initializer precede the restricted native
sidecar; proxy readiness gates base-store copying and bundle preparation. The curl application sees its final read-only trust bundle and public receiver CA
certificates. The test-only client image extends curl with a Go protocol probe;
that binary and its QUIC dependency are absent from the Gateway runtime image.
The egress deployment uses the same gateway image. A sidecar-free controlled origin
receives HTTP or independently verified HTTPS after the two proxies.

A gateway-only EnvoyFilter preserves the supplied request UUID for correlation;
this fixture logging choice is not an authorization or trusted-identity input.
The workload has no inject-disabled annotation: the namespace disables automatic
injection while the declared sidecar status lets Istio CNI capture its traffic.

Both roles load test-only policies from trusted ConfigMaps. HTTP and HTTPS routes
use complete-body ext_authz (64 KiB, no partial authorization, fail closed) between
the target guard and its dispatch check. The gateway requires the verified workload
SPIFFE principal. Application headers cannot supply that identity. Each HTTP scenario requires correlated
request IDs at both Envoys and the origin, verified SPIFFE peer identities at both
ends of the mTLS hop, and active public mesh certificate metadata. Certificates
are obtained by the real pilot-agent from the dedicated Istiod; no static workload
identity certificates are mounted.

The foundation scenarios observe the actual initializer, IPv6 state, captured
traffic rules and source-endpoint Calico DROP counters against a healthy controlled
origin. Direct probes from the resident proxy UID bypass transparent capture and
prove Pod-wide policy independently of Envoy. Both normal and post-CNI-restart
connectivity are checked. Controller admission and production installation remain separate acceptance.

`config/enrollment.yaml` declares exact Pod peers and ports: workload to egress
8080/8443, both roles to Istiod 15012 and telemetry 4317/4318, and egress to fixture
origin listeners 8080/8443. Explicit kube-dns peers allow TCP/UDP 53. All exceptions
are Pod-wide, including business traffic to control endpoints, and do not establish
identity or authorization inside an allowed endpoint. No Kubernetes API permission
or non-DNS UDP permission is implicit.

## HTTPS fixture boundary

The image retains Istio ALPN, metadata exchange and telemetry. A dedicated workload
HTTPS listener receives CNI-redirected traffic and uses private on-demand SDS.
A separate Istio gateway listener fixes origin scheme to HTTPS and sends the
canonical authority through dynamic forward proxy with the independent origin CA.
Both roles load the same private request guard generated by the daemon.

The application image's actual default trust store is `/cacert.pem`. An init
container copies that original store; `trust-init` validates and merges the Pod
inspection root before mounting the final bundle at the same path. Keys and proxy
runtime sockets are never mounted into the application.

The HTTPS scenario chooses a new Service hostname after startup, waits for fixture
TCP routing to become ready from the egress container (without TLS), and checks
that no inspection certificate exists for it. It then runs one ordinary curl in
the application. There is no proxy option, insecure verification, or request retry.
Client certificate evidence is public; origin keys stay in the private state
folder and its origin-only Secret. Teardown removes the state folder after deleting
the owned cluster. Diagnostics never retrieve Secret contents or signing state.

Management initialization applies UID-based IPv4/IPv6 rules with one-time
NET_ADMIN/NET_RAW. Application and runtime containers drop all capabilities. The
scenario probes management sockets over IPv4, IPv6 and the Pod IP; pilot-agent's
successful public-certificate query proves proxy access still works.

## Tracing collection

The version/digest-pinned upstream Collector writes structured OTLP JSON to a
fixture-only shared volume. Its reader container exposes no service. HTTP and
HTTPS requests carry a correlation UUID but no trace context. The Collector must
receive a valid trace ID generated by the workload proxy, a workload root span
with no parent, and egress spans whose exported parent chains reach that root.
All spans carrying the request UUID must share that trace ID. `Telemetry`
configures ordinary listeners; the custom HTTPS listener explicitly selects the same native provider. OPA
environment variables point at a different receiver, so a misdirected or duplicate
Envoy exporter is observable. Successful OTLP records are retained with the other
public fixture artifacts. OPA authorization spans are verified by `make smoke`.

## Body, bypass and fault scenarios

The body matrix uses the same HTTPS authority and path with allow/deny JSON values.
It checks independent workload and egress decisions, spoofed identity headers,
malformed/missing/encoded/oversized bodies and authorization target mutation.
An HTTP alternative must obey the same two-stage checks. Correlated role logs and
origin receipt/non-receipt accompany each response; independent origin controls
bracket attempts. No application proxy option or disabled TLS verification is used.

The protocol matrix sends identifiable TCP (8081/8444), UDP (5353/7777), DNS (53 to
an unapproved resolver) and actual QUIC (443) traffic from business execution,
business init and a running application while its proxy is held absent. Independent
controls reach the same receiver before and after every attempt. Source Pod UID,
CRI sandbox and veth identify the observed counters. TCP requires executed capture
and Envoy BlackHole rejection (or verified proxy absence); datagrams require actual
sent bytes and a source-endpoint Calico DROP increase. Receiver logs must contain
both controls and no restricted identifier. Timeout alone cannot pass a case.

Direct business requests to gateway 8080/8443 must hit the workload's closed route.
An independent client then reaches each gateway listener with a verified server
chain/SPIFFE identity but no client identity; server TLS rejection counters prove
that the endpoint itself rejects that caller. ConfigMap and mesh routes are applied
before Pods, with REGISTRY_ONLY workload routing and no raw gateway-port listener.

Fault cases stop embedded OPA separately at each role while Envoy remains running,
remove all gateway replicas, and fail a case-specific workload's required policy
startup. Each has observed failure state, healthy receiver controls, fail-closed
or prevented business execution, and allow/deny recovery checks. Fixtures use process
signals or Kubernetes lifecycle actions, with restoration traps; the product has
no fault-control API. Proxy-absence recovery also requires an observed restart and
readiness. Retained `test` runs recreate case-specific Pods and restore shared ones.
