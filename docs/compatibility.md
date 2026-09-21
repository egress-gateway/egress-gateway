# Versions and validation scope

| Component | Pinned version or source |
|---|---|
| Minimum Go module version | 1.26.0 |
| CI and image build toolchain | 1.26.7 |
| OPA | v1.20.2 |
| OPA-Envoy plugin | v1.20.2-envoy; its go.mod depends on OPA v1.20.2 |
| Istio proxy image | istio/proxyv2:1.31.0, retaining its Envoy and pilot-agent |
| Shared policy library | No usable version yet |

Pinned versions do not establish full mesh compatibility. CI Go checks validate the custom executable; image smoke tests validate the standalone local request path. Record the host architecture in pull request validation results as well.

The image uses the standard upstream proxyv2 distribution, which includes bash and curl. A distroless variant lacking these tools is not a drop-in replacement.

Not yet validated or implemented: Kubernetes admission, Istio injection, Istiod connectivity, mTLS rotation, ServiceAccount/Profile isolation, prevention of real egress bypass, HTTPS visibility, the full gRPC payload contract, and dynamic policy activation across instances.

The image tag is used only for local builds. Workflows do not publish images or releases. Publishing public artifacts and establishing a production compatibility matrix require separate authorization and validation.
