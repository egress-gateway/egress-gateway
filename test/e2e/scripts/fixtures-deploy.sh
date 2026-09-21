#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require kubectl envsubst
verify_owner
export GATEWAY_TEST_IMAGE="$image" ORIGIN_TEST_IMAGE="$image-origin" CURL_TEST_IMAGE="$CURL_IMAGE"
envsubst '${GATEWAY_TEST_IMAGE} ${ORIGIN_TEST_IMAGE} ${CURL_TEST_IMAGE}' < "$config_dir/fixtures.yaml" > "$artifacts/rendered-fixtures.yaml"
k apply -f "$artifacts/rendered-fixtures.yaml"
k rollout status deployment/origin -n gateway-origin --timeout=180s
k rollout status deployment/egress -n gateway-test --timeout=180s
k wait -n gateway-test --for=condition=Ready pod/workload --timeout=180s
k get pods -n gateway-test -o json > "$artifacts/fixture-pods.json"
