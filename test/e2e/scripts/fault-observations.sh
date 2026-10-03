# Complete fixture operations use these bounded request and public-log observations.
origin_control() {
  k -n gateway-origin exec probe-control -c probe -- curl --noproxy '*' --fail --silent --show-error --max-time 5 --cacert /etc/receiver-trust/ca.pem -H "X-Request-Id: $1" -H 'Content-Type: application/json' --data-binary '{"action":"safe"}' 'https://origin-https.gateway-origin.svc.cluster.local/body'
}
body_request() {
  k -n gateway-test exec "$1" -c curl -- curl --noproxy '*' --silent --show-error --max-time 8 -H "X-Request-Id: $2" -H 'Content-Type: application/json' --data-binary "$3" -w '\n%{http_code}\n' 'https://origin-https.gateway-origin.svc.cluster.local/body'
}
fault_logs() {
  local pod="$1" after_id="$2" require_egress="$3" id ready
  shift 3
  local deadline=$((SECONDS + 5))
  # Poll asynchronous log delivery without sending the governed request again.
  while :; do
    k -n gateway-test logs "$pod" -c istio-proxy --tail=1000 > "$artifacts/fault/workload.log"
    if [[ "${gateway_absent:-false}" != true ]]; then
      k -n gateway-test logs deployment/egress -c istio-proxy --tail=1000 > "$artifacts/fault/egress.log"
    fi
    k -n gateway-origin logs deployment/origin-https -c origin --tail=1000 > "$artifacts/fault/origin.log"
    ready=true
    for id in "$@"; do
      jq -Rse --arg id "$id" 'any(split("\n")[] | fromjson?; .request_id == $id)' "$artifacts/fault/workload.log" > /dev/null || ready=false
      if [[ "$require_egress" == true ]]; then
        jq -Rse --arg id "$id" 'any(split("\n")[] | fromjson?; .request_id == $id)' "$artifacts/fault/egress.log" > /dev/null || ready=false
      fi
    done
    jq -Rse --arg suffix "request_id=$after_id" 'any(split("\n")[]; endswith($suffix))' "$artifacts/fault/origin.log" > /dev/null || ready=false
    if "$ready"; then return 0; fi
    if ((SECONDS >= deadline)); then
      echo 'timed out waiting for correlated fault logs' >&2
      return 1
    fi
    sleep 0.1
  done
}
