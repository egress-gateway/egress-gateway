#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require jq
verify_owner
source "$(dirname "$0")/fault-observations.sh"
mkdir -p "$artifacts/direct"
case_id="$(basename "$artifacts")"
gateway="$(k -n gateway-test get pods -l app=egress -o json | jq -er '.items | if length==1 then .[0] else error("ambiguous gateway") end')"
gateway_uid="$(jq -r .metadata.uid <<< "$gateway")"
gateway_ip="$(jq -r .status.podIP <<< "$gateway")"
origin_control "$case_id-direct-before" > "$artifacts/direct/receiver-before.txt"
for port in 8080 8443; do
  output="$artifacts/direct/$port"
  mkdir -p "$output"
  k -n gateway-test exec workload -c istio-proxy -- pilot-agent request GET 'stats?filter=BlackHoleCluster' > "$output/business-before.txt"
  if k -n gateway-test exec workload -c curl -- curl --noproxy '*' --silent --show-error --max-time 4 -H 'Host: origin-https.gateway-origin.svc.cluster.local:443' -H "X-Request-Id: $case_id-business-$port" -H 'Content-Type: application/json' -H 'X-Workload-Allowed: true' --data-binary '{"action":"safe"}' -w '\n%{http_code}\n' "http://egress.gateway-test.svc.cluster.local:$port/body" > "$output/business-response.txt" 2> "$output/business.stderr"; then rc=0; else rc=$?; fi
  printf '%s\n' "$rc" > "$output/business-exit.txt"
  k -n gateway-test exec workload -c istio-proxy -- pilot-agent request GET 'stats?filter=BlackHoleCluster' > "$output/business-after.txt"
  k -n gateway-test exec deployment/egress -c istio-proxy -- pilot-agent request GET 'stats?filter=ssl.fail_verify_no_cert' > "$output/identity-before.txt"
  if k -n gateway-origin exec probe-control -c probe -- gateway-e2e-probe -protocol mesh -target "$gateway_ip:$port" -ca /etc/receiver-trust/mesh-ca.pem -id "$case_id-unverified-$port" > "$output/unverified.json" 2> "$output/unverified.stderr"; then rc=0; else rc=$?; fi
  printf '%s\n' "$rc" > "$output/unverified-exit.txt"
  k -n gateway-test exec deployment/egress -c istio-proxy -- pilot-agent request GET 'stats?filter=ssl.fail_verify_no_cert' > "$output/identity-after.txt"
done
origin_control "$case_id-direct-after" > "$artifacts/direct/receiver-after.txt"
[[ "$(k -n gateway-test get pods -l app=egress -o json | jq -er '.items | if length==1 then .[0].metadata.uid else error("ambiguous gateway") end')" == "$gateway_uid" ]] || exit 2
k -n gateway-origin logs deployment/origin-https -c origin --tail=1000 > "$artifacts/direct/origin.log"
