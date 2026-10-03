#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require kubectl jq
verify_owner
k get configmap coredns -n kube-system -o json > "$state_dir/coredns-host-aliases.json"
# Setup-only, fixed fixture names. Never rewrite an external application's DNS.
jq '.data.Corefile |= sub("    ready\n"; "    ready\n    rewrite name exact child.blocked-workload.gateway-origin.svc.cluster.local blocked-workload.gateway-origin.svc.cluster.local\n    rewrite name exact child.blocked-egress.gateway-origin.svc.cluster.local blocked-egress.gateway-origin.svc.cluster.local\n")' "$state_dir/coredns-host-aliases.json" > "$state_dir/coredns-host-aliases-applied.json"
k apply -f "$state_dir/coredns-host-aliases-applied.json"
k rollout restart deployment/coredns -n kube-system
k rollout status deployment/coredns -n kube-system --timeout=120s
