# Runtime configuration

| Setting | Default | Meaning |
|---|---|---|
| `GATEWAY_ROLE` | `workload` | `workload` maps to an Istio sidecar; `egress` maps to a router |
| `GATEWAY_PROXY_MODE` | `istio` | `istio` uses pilot-agent; `standalone` uses mounted Envoy configuration |
| `OPA_CONFIG` | `/etc/gateway/opa/<role>.yaml` | OPA configuration file |
| `ENVOY_CONFIG` | None | Required Envoy configuration path in standalone mode |

Container arguments are appended to `gateway-opa run --server`. Istio mode follows the upstream agent's environment and mount requirements. The scaffold adds no generic proxy argument string or shell evaluation of such a string.

The OPA HTTP management endpoint binds to `127.0.0.1:8181`; ext_authz gRPC binds to `127.0.0.1:9191`. The local example publishes only Workload Envoy port 8080 to the host loopback interface.

**Applications in the same Pod can also reach localhost, so these bindings do not provide security isolation.** Before production integration, define management API access controls, trusted identity inputs, and bypass prevention against the actual trust boundary. This scaffold cannot directly serve as a production security boundary for untrusted workloads.

Health checks cover OPA plugins/bundles and proxy readiness. They indicate the state of current processes and configured dependencies; they do not establish that a GatewayProfile generation is `Applied` or that the identity and policy contracts are fully implemented.

The image contains no user certificates, private keys, Profile instances, or egress credentials. Without a configured production policy, authorization checks do not allow requests. Policy synchronization, retention of previous policies after failures, descriptor updates, and version feedback remain to be implemented in their respective stages.
