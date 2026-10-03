#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require go
verify_owner
networking_root="$(cd "$root" && go list -m -f '{{.Dir}}' github.com/egress-gateway/egress-gateway-networking)"
"$BASH" "$networking_root/install/scripts/check.sh" --kubeconfig "$kubeconfig" --context "kind-$cluster" --cni-scope foundation
