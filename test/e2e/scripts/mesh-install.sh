#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require helm kubectl curl tar shasum
verify_owner
# Use the pinned official release's charts; the public Helm index may lag a
# published release. The archive's binary is not executed on either host platform.
archive="$state_dir/istio-$ISTIO_VERSION-linux-amd64.tar.gz"
if [[ ! -f "$archive" ]]; then
  curl --fail --silent --show-error --location --retry 3 --max-time 120 \
    "https://github.com/istio/istio/releases/download/$ISTIO_VERSION/istio-$ISTIO_VERSION-linux-amd64.tar.gz" -o "$archive.tmp"
  mv "$archive.tmp" "$archive"
fi
[[ "$(shasum -a 256 "$archive" | cut -d ' ' -f 1)" == "$ISTIO_ARCHIVE_SHA256" ]] || { echo 'Istio release checksum mismatch' >&2; exit 2; }
tar -xzf "$archive" -C "$state_dir"
charts="$state_dir/istio-$ISTIO_VERSION/manifests/charts"
helm upgrade --install istio-base "$charts/base" --namespace istio-system --create-namespace --kubeconfig "$kubeconfig" --kube-context "kind-$cluster" --wait --timeout 5m
helm upgrade --install istiod "$charts/istio-control/istio-discovery" --namespace istio-system --kubeconfig "$kubeconfig" --kube-context "kind-$cluster" -f "$config_dir/istiod-values.yaml" --wait --timeout 5m
helm upgrade --install istio-cni "$charts/istio-cni" --namespace istio-system --kubeconfig "$kubeconfig" --kube-context "kind-$cluster" -f "$config_dir/cni-values.yaml" --wait --timeout 5m
k rollout status deployment/istiod -n istio-system --timeout=180s
k rollout status daemonset/istio-cni-node -n istio-system --timeout=180s
