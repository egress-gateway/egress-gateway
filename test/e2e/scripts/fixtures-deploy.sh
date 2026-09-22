#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require kubectl envsubst openssl
verify_owner
# Fixture origin credentials stay in private state and are never diagnostics.
for ns in gateway-test gateway-origin; do
  k create namespace "$ns" --dry-run=client -o yaml | k apply -f -
done
origin_tls="$state_dir/origin-tls"
mkdir -m 0700 "$origin_tls"
(umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -nodes -days 2 \
    -subj '/CN=Gateway E2E origin root' -keyout "$origin_tls/ca.key" -out "$origin_tls/ca.pem" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -nodes \
    -subj '/CN=Gateway E2E origin' -keyout "$origin_tls/tls.key" -out "$origin_tls/tls.csr" 2>/dev/null
  printf '%s\n' 'subjectAltName=DNS:*.gateway-origin.svc.cluster.local' 'extendedKeyUsage=serverAuth' > "$origin_tls/extensions"
  openssl x509 -req -in "$origin_tls/tls.csr" -CA "$origin_tls/ca.pem" -CAkey "$origin_tls/ca.key" \
    -CAcreateserial -CAserial "$origin_tls/ca.srl" -days 2 -extfile "$origin_tls/extensions" -out "$origin_tls/tls.crt" 2>/dev/null
)
k create secret tls origin-tls -n gateway-origin --cert="$origin_tls/tls.crt" --key="$origin_tls/tls.key" --dry-run=client -o yaml | k apply -f -
k create configmap origin-trust -n gateway-test --from-file=ca.pem="$origin_tls/ca.pem" --dry-run=client -o yaml | k apply -f -
export GATEWAY_TEST_IMAGE="$image" ORIGIN_TEST_IMAGE="$image-origin" CURL_TEST_IMAGE="$CURL_IMAGE"
envsubst '${GATEWAY_TEST_IMAGE} ${ORIGIN_TEST_IMAGE} ${CURL_TEST_IMAGE}' < "$config_dir/fixtures.yaml" > "$artifacts/rendered-fixtures.yaml"
k apply -f "$artifacts/rendered-fixtures.yaml"
k apply -f "$config_dir/https.yaml"
k rollout status deployment/origin-https -n gateway-origin --timeout=180s
k rollout status deployment/origin -n gateway-origin --timeout=180s
k rollout status deployment/egress -n gateway-test --timeout=180s
k wait -n gateway-test --for=condition=Ready pod/workload --timeout=180s
k get pods -n gateway-test -o json > "$artifacts/fixture-pods.json"
