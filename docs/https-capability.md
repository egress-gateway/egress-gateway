# HTTPS inspection capability

The image retains Istio 1.31.0 pilot-agent and copies the existing official
`envoyproxy/envoy:contrib-v1.39.0` binary, pinned by multi-platform digest
`sha256:7aca259c848ed1b0355d91227056155fb78ad864680efe684a0e9f5c032b857f`.
It includes the upstream on-demand certificate selector and Istio ALPN, metadata
exchange and telemetry extensions. No Envoy source build, fork or project-owned
certificate selector is maintained. Mesh identity and xDS remain owned by Istiod.

The [upstream on-demand selector](https://www.envoyproxy.io/docs/envoy/v1.39.0/api-v3/extensions/transport_sockets/tls/cert_selectors/on_demand_secret/v3/config.proto)
has an unknown security posture and trusted-endpoint caveat. Configuration parsing
alone is insufficient. The component suite exercises actual first handshakes,
invalid SNI, concurrent subscriptions, eviction and SDS unavailability. This is
bounded behavioral validation, not a security certification of upstream code.

The daemon serves delta SDS over a mode-0600 socket in its private directory. DNS
names are validated before signing. The cache retains 64 leaves, with ten-minute
SDS resource TTL and one-hour leaf validity capped by CA expiration. Eviction
sends removal to the resource's own subscription stream, including when a different
stream caused eviction. Leaf keys are memory-only. Session resumption is disabled
on inspection listeners so a new connection cannot outlive the selected resource.

The HTTPS fixture uses a three-second TLS handshake deadline, 64 concurrent
connections, 64 accepted connections per second, 64 KiB complete request bodies,
and bounded DNS/authorization queues. SDS permits 128 active subscriptions so the
65th request can trigger eviction instead of deadlocking a full cache. Each
subscription has bounded updates and name counts. SDS messages have a 256 KiB
receive limit to accommodate the official contrib binary's Node build metadata;
this is independent of the 64 KiB HTTP request-body limit. Envoy's heap overload monitor
stops accepting connections at 48 MiB of accounted heap (64 MiB monitor budget);
the test container additionally has a 256 MiB memory limit. The supplied Istio
bootstrap overlay applies the same connection and heap admission limits.

An unavailable SDS server cannot send resource removals: the upstream selector
retains pending subscriptions after handshake timeout. The certificate cache bound
is therefore distinct from the number of pending subscriptions during a fault.
Connection/rate limits and heap admission bound fault growth; tests verify timed
rejection, retained-resource counts, process survival and recovery to 64 active
resources. Do not remove these limits when deploying the inspection listener.

`make smoke` records cold/warm request timings and runs the isolated HTTPS path
with separate inspection, mesh and origin trust roots. Its static mesh certificates
are not proof of Istiod issuance or transparent CNI capture. The stacked E2E PR
uses the same image with real Istiod and checks the complete three-hop TLS path.
