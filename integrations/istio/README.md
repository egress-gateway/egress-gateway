# Istio integration

The image inherits a pinned `istio/proxyv2` version and retains pilot-agent and bootstrap files, adding the official Envoy contrib binary. With `GATEWAY_PROXY_MODE=istio`, it starts either `pilot-agent proxy sidecar` or `pilot-agent proxy router`, according to the role.

The deployment must supply the identity, certificate/token mounts, Istiod address, and proxy metadata required by upstream, and configure Envoy's authorization filter to call local OPA. Starting the agent alone does not install complete routing and enforcement rules.

Shared network installation and enrollment belong to networking; admission belongs to controller. This directory documents gateway integration contracts and compatibility evidence; it does not maintain a second set of cluster installation scripts.

Local Compose starts Envoy directly and only validates communication between image components. The separate kind/Istio suite establishes control-plane connectivity, real mTLS identity and transparent traffic capture.
