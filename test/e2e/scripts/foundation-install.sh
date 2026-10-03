#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require go jq
verify_owner
(cd "$root" && go mod download -json github.com/egress-gateway/egress-gateway-networking) > "$artifacts/networking-module.json"
networking_root="$(jq -er .Dir "$artifacts/networking-module.json")"
[[ -n "$networking_root" && -f "$networking_root/install/scripts/install.sh" ]] || { echo 'pinned networking installation artifact missing' >&2; exit 2; }
"$BASH" "$networking_root/install/scripts/install.sh" --kubeconfig "$kubeconfig" --context "kind-$cluster" --cache-dir "$state_dir/networking-cache" --artifacts "$artifacts/networking"
k wait --for=condition=Ready node --all --timeout=180s
