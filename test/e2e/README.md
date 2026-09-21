# Minimal gateway connectivity BDD fixture

This is an **incomplete V01-01 candidate**. It implements transparent HTTP,
startup trust and live mesh identity observations. The inspection capability
scenario currently fails on the pinned image. HTTPS interception, first-unseen-host
success and verified origin TLS scenarios remain blocked by the foundation's
[capability investigation](../../docs/https-capability.md). A passing HTTP scenario
or selector configuration parse is not full Issue acceptance.

## Run and retain

Prerequisites: Go 1.26+, Bash 4+, Docker with Compose/build support, jq and
envsubst. `config/versions.env` pins kind, kubectl, Helm, Kubernetes, Istio and curl.
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

`cluster-up`, `image-load`, `mesh-install`, `fixtures-deploy`, `verify`, `diagnostics`
and `cluster-down` own their operation prerequisites/readiness and return nonzero
on failure. The node ID receipt is a declared file, not parsed human log output.
Go owns sequencing and cleanup decisions. YAML owns kind/Helm/deployment input.
These are gateway test fixtures; networking can replace this installation layer
later without replacing the behavioral feature/step layer.

## Topology and evidence

Default kind networking is retained. Istio CNI performs sidecar interception; no
isolation CNI or NetworkPolicy guarantee is implied. A manually declared native
sidecar uses our workload image; a root volume-preparation init sets private
permissions, then the proxy startup probe gates base-store copying and bundle
preparation. The curl application sees only its final read-only trust bundle.
The egress deployment uses the same gateway image. A sidecar-free controlled origin
receives HTTP after the two proxies.

The connectivity fixture has no OPA authorization filter. This is mesh test
configuration, not a product authorization bypass switch. HTTP body authorization
remains in component/image smoke coverage. Each HTTP scenario requires correlated
request IDs at both Envoys and the origin, verified SPIFFE peer identities at both
ends of the mTLS hop, and active public mesh certificate metadata. Certificates
are obtained by the real pilot-agent from the dedicated Istiod; no static workload
identity certificates are mounted.

Full network fail-closed, UDP/QUIC prevention, failure isolation, controller
admission, shared enrollment and production installation remain later milestones.
