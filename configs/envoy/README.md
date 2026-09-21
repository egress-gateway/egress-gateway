# Envoy configuration

Deployment integration supplies the full Istio routing and filter configuration. Runnable minimal static configurations live in `examples/local/` and only verify Envoy-to-OPA connectivity and denial behavior.

The scaffold does not embed static demonstration configuration in the product image or combine Istio configuration, OPA policies, and GatewayProfile into a new public configuration format.
