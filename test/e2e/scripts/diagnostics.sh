#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require kubectl docker
verify_owner
# Deliberately do not collect Secrets, kubeconfigs, environment variables,
# filesystem archives, or Envoy config dumps containing SDS private material.
k get nodes,pods -A -o wide > "$artifacts/status.txt" 2>&1 || true
k get events -A --sort-by=.metadata.creationTimestamp > "$artifacts/events.txt" 2>&1 || true
for ns in istio-system gateway-test gateway-origin; do
  pods="$(k get pods -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)" || continue
  for pod in $pods; do
    containers="$(k get pod "$pod" -n "$ns" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}')" || continue
    for container in $containers; do
      k logs -n "$ns" "$pod" -c "$container" --tail=1000 > "$artifacts/$ns-$pod-$container.log" 2>&1 || true
    done
  done
done
# These admin endpoints contain counters and listener addresses, never SDS material.
for proxy in workload deployment/egress; do
  name="${proxy//\//-}"
  for endpoint in 'stats?filter=on_demand_secret%7Cinspection_sds%7Cssl%7Coverload%7Cmemory%7Clistener_manager' 'listeners?format=json'; do
    kind="${endpoint%%\?*}"
    k exec -n gateway-test "$proxy" -c istio-proxy -- pilot-agent request GET "$endpoint" \
      > "$artifacts/$name-$kind.txt" 2>&1 || true
  done
done
