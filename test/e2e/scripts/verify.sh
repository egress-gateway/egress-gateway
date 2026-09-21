#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require kubectl kind
verify_owner
k wait --for=condition=Ready node --all --timeout=30s
k rollout status deployment/istiod -n istio-system --timeout=30s
k rollout status daemonset/istio-cni-node -n istio-system --timeout=30s
k wait -n gateway-test --for=condition=Ready pod/workload --timeout=30s
actual="$(k get pod workload -n gateway-test -o jsonpath='{.spec.initContainers[?(@.name=="istio-proxy")].image}')"
[[ "$actual" == "$image" ]] || { echo 'retained workload image mismatch' >&2; exit 2; }

actual="$(k get deployment egress -n gateway-test -o jsonpath='{.spec.template.spec.containers[0].image}')"
[[ "$actual" == "$image" ]] || { echo 'retained egress image mismatch' >&2; exit 2; }
[[ "$(docker image inspect --format '{{.Id}}' "$image")" == "$(cat "$artifacts/gateway-image-id.txt")" ]] || { echo 'local image changed since setup; recreate the environment' >&2; exit 2; }
