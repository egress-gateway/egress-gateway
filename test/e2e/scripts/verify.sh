#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require kubectl kind jq base64 shasum
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
"$BASH" "$root/test/e2e/scripts/foundation-check.sh" --root "$root" --cluster "$cluster" --kubeconfig "$kubeconfig" --image "$image" --config-dir "$config_dir" --artifacts "$artifacts" --state-dir "$state_dir"

# The retained process must still use the staged public fixture inputs recorded at setup.
k get configmap workload-shared egress-shared -n gateway-test -o json | jq -S '[.items[] | {name:.metadata.name,data,binaryData}] | sort_by(.name)' > "$state_dir/shared-current.json"
cmp -s "$artifacts/shared-artifacts.json" "$state_dir/shared-current.json" || { echo 'retained shared artifacts changed; restore inputs or recreate the environment' >&2; exit 2; }

# Served bytes, not just the source ConfigMaps, must match the retained fixture.
for role in workload egress; do
  expected="$(k get configmap "$role-shared" -n gateway-test -o json | jq -r '.binaryData["workload.tar.gz"]' | base64 -d | shasum -a 256 | cut -d' ' -f1)"
  actual="$(k exec -n gateway-test deployment/policy-publisher -c publisher -- curl --noproxy '*' --fail --silent --show-error "http://127.0.0.1:8086/bundles/$role" | jq -r '.digest')"
  [[ "$actual" == "sha256:$expected" ]] || { echo 'retained served bundle changed; restore inputs or recreate the environment' >&2; exit 2; }
done
