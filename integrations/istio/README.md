# Istio integration

The image inherits a pinned `istio/proxyv2` version and retains upstream Envoy, pilot-agent, and bootstrap files. With `GATEWAY_PROXY_MODE=istio`, it starts either `pilot-agent proxy sidecar` or `pilot-agent proxy router`, according to the role.

The deployment must supply the identity, certificate/token mounts, Istiod address, and proxy metadata required by upstream, and configure Envoy's authorization filter to call local OPA. Starting the agent alone does not install complete routing and enforcement rules.

The controller repository owns the full environment, injection integration, and deployment configuration. This directory documents gateway integration contracts and compatibility evidence; it does not maintain a second set of cluster installation scripts.

Local Compose starts Envoy directly and only validates communication between image components. This scaffold does not establish Istio control plane connectivity, mTLS, ServiceAccount identity, or traffic interception.
