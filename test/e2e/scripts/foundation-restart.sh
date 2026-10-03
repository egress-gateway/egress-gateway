#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
verify_owner
k rollout restart daemonset/istio-cni-node -n istio-system
k rollout status daemonset/istio-cni-node -n istio-system --timeout=180s
k rollout restart daemonset/calico-node -n calico-system
k rollout status daemonset/calico-node -n calico-system --timeout=180s
"$BASH" "$root/test/e2e/scripts/foundation-check.sh" --root "$root" --cluster "$cluster" --kubeconfig "$kubeconfig" --image "$image" --config-dir "$config_dir" --artifacts "$artifacts" --state-dir "$state_dir"
