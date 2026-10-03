#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require go jq
verify_owner
networking_root="$(cd "$root" && go mod download -json github.com/egress-gateway/egress-gateway-networking | jq -er .Dir)"
"$BASH" "$networking_root/install/scripts/check.sh" --kubeconfig "$kubeconfig" --context "kind-$cluster" --cni-scope foundation
