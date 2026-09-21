#!/usr/bin/env bash
set -euo pipefail
[[ ${BASH_VERSINFO[0]} -ge 4 ]] || { echo 'Bash 4+ is required' >&2; exit 2; }
phase="$(basename "$0" .sh)"
trap 'rc=$?; echo "phase=$phase line=$LINENO exit=$rc" >&2; exit "$rc"' ERR
cluster= kubeconfig= image= config_dir= artifacts= state_dir= root=
while (($#)); do
  (($# >= 2)) || { echo "missing value for $1" >&2; exit 2; }
  case "$1" in
    --cluster) cluster=$2 ;; --kubeconfig) kubeconfig=$2 ;; --image) image=$2 ;;
    --config-dir) config_dir=$2 ;; --artifacts) artifacts=$2 ;;
    --state-dir) state_dir=$2 ;; --root) root=$2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift 2
done
for value in "$cluster" "$kubeconfig" "$image" "$config_dir" "$artifacts" "$state_dir" "$root"; do
  [[ -n "$value" ]] || { echo 'all explicit script inputs are required' >&2; exit 2; }
done
[[ "$cluster" =~ ^gateway-e2e-[a-z0-9-]+$ ]] || { echo 'dedicated gateway-e2e cluster name required' >&2; exit 2; }
for value in "$kubeconfig" "$config_dir" "$artifacts" "$state_dir" "$root"; do [[ "$value" == /* ]] || exit 2; done
source "$config_dir/versions.env"
mkdir -p "$artifacts" "$state_dir"
chmod 0700 "$state_dir"
require() {
  for tool in "$@"; do
    command -v "$tool" >/dev/null || { echo "missing prerequisite: $tool" >&2; exit 2; }
    case "$tool" in
      kubectl) [[ "$(kubectl version --client -o json | jq -r .clientVersion.gitVersion)" == "$KUBECTL_VERSION" ]] || { echo "kubectl $KUBECTL_VERSION required" >&2; exit 2; } ;;
      helm) [[ "$(helm version --short)" == "$HELM_VERSION"* ]] || { echo "Helm $HELM_VERSION required" >&2; exit 2; } ;;
    esac
  done
}
k() { kubectl --kubeconfig "$kubeconfig" --context "kind-$cluster" --request-timeout=30s "$@"; }
verify_owner() {
  require docker kind kubectl
  [[ -s "$state_dir/node-id" ]] || { echo 'no ownership receipt; refusing operation' >&2; exit 2; }
  expected="$(cat "$state_dir/node-id")"
  actual="$(docker inspect --format '{{.Id}}' "$cluster-control-plane")"
  [[ "$actual" == "$expected" ]] || { echo 'node identity mismatch; refusing operation' >&2; exit 2; }
  if [[ "$phase" != cluster-down && -f "$kubeconfig" ]]; then
    expected_server="$(kind get kubeconfig --name "$cluster" | kubectl config view --kubeconfig /dev/stdin -o jsonpath='{.clusters[0].cluster.server}')"
    actual_server="$(kubectl config view --kubeconfig "$kubeconfig" -o jsonpath='{.clusters[0].cluster.server}')"
    [[ "$actual_server" == "$expected_server" ]] || { echo 'kubeconfig endpoint mismatch' >&2; exit 2; }
  fi
}
