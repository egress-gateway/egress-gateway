#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require kubectl envsubst openssl go
verify_owner
# Exact fixture DNS aliases preserve the HTTP authority while mapping child
# names to the same origin Service; this distinguishes Exact from DomainSuffix.
"$BASH" "$root/test/e2e/scripts/host-aliases.sh" --root "$root" --cluster "$cluster" --kubeconfig "$kubeconfig" --image "$image" --config-dir "$config_dir" --artifacts "$artifacts" --state-dir "$state_dir"
# Fixture origin credentials stay in private state and are never diagnostics.
for ns in gateway-test gateway-origin; do
  k create namespace "$ns" --dry-run=client -o yaml | k apply -f -
done
origin_tls="$state_dir/origin-tls"
mkdir -m 0700 "$origin_tls"
(umask 077
  openssl req -sha256 -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -nodes -days 2 \
    -subj '/CN=Gateway E2E origin root' -keyout "$origin_tls/ca.key" -out "$origin_tls/ca.pem" 2>/dev/null
  openssl req -sha256 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -nodes \
    -subj '/CN=Gateway E2E origin' -keyout "$origin_tls/tls.key" -out "$origin_tls/tls.csr" 2>/dev/null
  printf '%s\n' 'subjectAltName=DNS:*.gateway-origin.svc.cluster.local' 'extendedKeyUsage=serverAuth' > "$origin_tls/extensions"
  openssl x509 -sha256 -req -in "$origin_tls/tls.csr" -CA "$origin_tls/ca.pem" -CAkey "$origin_tls/ca.key" \
    -CAcreateserial -CAserial "$origin_tls/ca.srl" -days 2 -extfile "$origin_tls/extensions" -out "$origin_tls/tls.crt" 2>/dev/null
)
k create secret tls origin-tls -n gateway-origin --cert="$origin_tls/tls.crt" --key="$origin_tls/tls.key" --dry-run=client -o yaml | k apply -f -
k create configmap origin-trust -n gateway-test --from-file=ca.pem="$origin_tls/ca.pem" --dry-run=client -o yaml | k apply -f -
for role in workload egress; do
  k create configmap "$role-policy" -n gateway-test --from-file=policy.rego="$config_dir/$role.rego" --from-file=opa.yaml="$config_dir/fault-opa.yaml" --dry-run=client -o yaml | k apply -f -
done
k -n istio-system get configmap istio-ca-root-cert -o jsonpath='{.data.root-cert\.pem}' > "$state_dir/mesh-public-root.pem"
for ns in gateway-test gateway-origin; do
  k create configmap receiver-trust -n "$ns" --from-file=ca.pem="$origin_tls/ca.pem" --from-file=mesh-ca.pem="$state_dir/mesh-public-root.pem" --dry-run=client -o yaml | k apply -f -
done
export GATEWAY_TEST_IMAGE="$image" ORIGIN_TEST_IMAGE="$image-origin" CURL_TEST_IMAGE="$image-probe" OTEL_COLLECTOR_IMAGE
envsubst '${CURL_TEST_IMAGE}' < "$config_dir/receivers.yaml" > "$artifacts/rendered-receivers.yaml"
k apply -f "$artifacts/rendered-receivers.yaml"
k rollout status deployment/receiver -n gateway-origin --timeout=180s
k wait -n gateway-origin --for=condition=Ready pod/probe-control --timeout=180s
envsubst '${OTEL_COLLECTOR_IMAGE} ${CURL_TEST_IMAGE}' < "$config_dir/tracing.yaml" > "$artifacts/rendered-tracing.yaml"
k apply -f "$artifacts/rendered-tracing.yaml"
k rollout status deployment/otel-collector -n gateway-test --timeout=180s
envsubst '${GATEWAY_TEST_IMAGE} ${ORIGIN_TEST_IMAGE} ${CURL_TEST_IMAGE}' < "$config_dir/fixtures.yaml" > "$state_dir/business-fixtures.yaml"
envsubst '${GATEWAY_TEST_IMAGE} ${CURL_TEST_IMAGE}' < "$config_dir/enrollment.yaml" > "$state_dir/enrollment.yaml"
(cd "$root" && go run ./cmd/gateway-e2e-compose --input "$state_dir/business-fixtures.yaml" --options "$state_dir/enrollment.yaml") > "$artifacts/rendered-fixtures.yaml"
k apply -f "$config_dir/routes.yaml"
k apply -f "$config_dir/https.yaml"
k apply -f "$config_dir/authorization.yaml"
k apply -f "$artifacts/rendered-fixtures.yaml"
envsubst '${CURL_TEST_IMAGE}' < "$config_dir/publisher.yaml" > "$artifacts/rendered-publisher.yaml"
k apply -f "$artifacts/rendered-publisher.yaml"
k rollout status deployment/policy-publisher -n gateway-test --timeout=120s
k get configmap workload-shared egress-shared -n gateway-test -o json | jq -S '[.items[] | {name:.metadata.name,data,binaryData}] | sort_by(.name)' > "$artifacts/shared-artifacts.json"
k rollout status deployment/origin-https -n gateway-origin --timeout=180s
k rollout status deployment/origin -n gateway-origin --timeout=180s
k rollout status deployment/egress -n gateway-test --timeout=180s
k wait -n gateway-test --for=condition=Ready pod/workload --timeout=180s
k get pod workload -n gateway-test -o json | jq '{apiVersion,kind,metadata:{name:.metadata.name,namespace:.metadata.namespace,labels:.metadata.labels,annotations:.metadata.annotations},spec} | del(.spec.nodeName)' > "$state_dir/workload-template.json"
k get pods -n gateway-test -o json > "$artifacts/fixture-pods.json"
