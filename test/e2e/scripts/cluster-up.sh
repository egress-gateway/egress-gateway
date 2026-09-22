#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require docker kind kubectl
[[ "$(kind version)" == "kind $KIND_VERSION "* ]] || { echo "kind $KIND_VERSION required" >&2; exit 2; }
docker info >/dev/null
if docker inspect "$cluster-control-plane" >/dev/null 2>&1; then echo 'cluster already exists; refusing takeover' >&2; exit 2; fi
[[ ! -e "$kubeconfig" && ! -e "$state_dir/node-id" ]] || { echo 'state already exists; use retained mode' >&2; exit 2; }
# Record only this newly created node, even after partial kind setup failure.
receipt() {
  rc=$?
  docker inspect --format '{{.Id}}' "$cluster-control-plane" > "$state_dir/node-id.tmp" 2>/dev/null && mv "$state_dir/node-id.tmp" "$state_dir/node-id" || true
  exit "$rc"
}
trap receipt EXIT
kind create cluster --name "$cluster" --image "$KIND_IMAGE" --config "$config_dir/kind.yaml" --kubeconfig "$kubeconfig" --wait 120s --retain
k wait --for=condition=Ready node --all --timeout=120s
