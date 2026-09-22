# Versions and validation scope

| Component | Pinned version or source |
|---|---|
| Minimum Go module version | 1.26.0 |
| CI and image build toolchain | 1.26.7 |
| OPA | v1.20.2 |
| OPA-Envoy plugin | v1.20.2-envoy; its go.mod depends on OPA v1.20.2 |
| Istio proxy image | istio/proxyv2:1.31.0, retaining pilot-agent |
| Envoy binary | Official envoyproxy/envoy:contrib-v1.39.0, digest pinned in image/Dockerfile |
| Shared policy library | No usable version yet |

Pinned versions do not establish full mesh compatibility. CI Go checks validate the custom executable; image smoke tests validate the standalone local request path. Record the host architecture in pull request validation results as well.

The image uses the standard upstream proxyv2 distribution, which includes bash and curl. A distroless variant lacking these tools is not a drop-in replacement.

Not yet validated or implemented: Kubernetes admission, Istio injection, automatic mTLS rotation, ServiceAccount/Profile isolation, prevention of real egress bypass, the future shared policy contract, and dynamic policy activation across instances.

The component suite covers HTTPS first handshake, certificate reuse/eviction, concurrent
requests, independent full-body decisions, target binding, verified mesh-style peer
identity, origin TLS failures and OPA/SDS failures. Real Istiod, CNI and HTTP/HTTPS
connectivity are validated separately by the stacked E2E change; neither layer
substitutes for the other. Istio ALPN, metadata exchange and telemetry remain enabled.

The image tag is used only for local builds. Workflows do not publish images or releases. Publishing public artifacts and establishing a production compatibility matrix require separate authorization and validation.
