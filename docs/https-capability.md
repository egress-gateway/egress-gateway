# HTTPS inspection capability investigation

Status: **implementation blocked; V01-01 acceptance is incomplete**.

The required owner boundary remains: the daemon supplies inspection certificates;
workload Envoy terminates application TLS; Istio supplies mesh identity and mTLS.
No Go TLS forwarding proxy, custom selector, Envoy fork or custom build has been
introduced. No insecure client option or retry-based certificate provisioning is
an accepted substitute.

Probes on 2026-09-21 used Linux arm64 containers on Docker 29.4.0:

| Existing distribution | Observed result |
|---|---|
| `istio/proxyv2:1.31.0` | Envoy `0a12a02f.../1.39.1-dev`; rejects the on-demand selector type URL |
| `istio/proxyv2:1.31.1` | Also rejects the on-demand selector type URL |
| `envoyproxy/envoy:v1.39.0` | Envoy `9aed67d3.../1.39.0`; parses the selector after disabling stateful and stateless session resumption and specifying an SNI fallback resource |

Upstream image digest:
`sha256:d59f7f5fa10cff6d5892b6c5e7df5c9297ddfb2c3683e33fbfb82da24de4fa66`.
Istio 1.31.0 image digest:
`sha256:e3b973cce2442c2883188d8cf839dff8a21075fab0e00e5079df6ef28c9caf17`.

Configuration parsing proves extension availability only. It does not prove an
unseen hostname's first handshake, origin verification or pilot-agent compatibility.
Replacing Istio's Envoy with the upstream binary has not been validated and is not
part of the image change.

The [upstream selector documentation](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/cert_selectors/on_demand_secret/v3/config.proto)
states that the extension's security posture is unknown and restricts intended use
to trusted downstream and upstream endpoints. An untrusted application directly
supplies ClientHello/SNI in the accepted gateway contract, so that caveat cannot be
satisfied by assuming the local SDS endpoint alone is trusted.

The [v1.39.0 implementation](https://github.com/envoyproxy/envoy/blob/v1.39.0/source/extensions/transport_sockets/tls/cert_selectors/on_demand/config.cc)
inserts each requested name into its subscription map. Removal is triggered by an
SDS resource-removal callback, not by a disconnected handshake. An isolated probe
with an unavailable SDS endpoint attempted eight different SNI names; after all
clients disconnected, `cert_active=4`, `cert_requested=4`, `cert_updated=0` remained.
This is an observation of retained subscriptions, not a load benchmark or proof
that every possible deployment is exploitable. The code and public configuration
provide no selector-local retention limit. A working deployment would need proven
limits and failure behavior, including when SDS cannot deliver removals.

No tested existing combination currently establishes the accepted untrusted-client,
bounded first-handshake contract together with live Istio compatibility. This is a
specific evidence/compatibility blocker, not proof that no distribution can ever
satisfy it. Enabling this experimental path despite its endpoint restrictions or
starting a custom build/selector program requires an owner decision outside the
currently authorized implementation. Independent runtime and CA work remains
reviewable; it must not be reported as general HTTPS MITM or completed V01-01.
