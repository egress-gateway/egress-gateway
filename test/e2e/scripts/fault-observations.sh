# Complete fixture operations use these bounded request and public-log observations.
origin_control() {
  k -n gateway-origin exec probe-control -c probe -- curl --noproxy '*' --fail --silent --show-error --max-time 5 --cacert /etc/receiver-trust/ca.pem -H "X-Request-Id: $1" -H 'Content-Type: application/json' --data-binary '{"action":"safe"}' 'https://origin-https.gateway-origin.svc.cluster.local/body'
}
body_request() {
  k -n gateway-test exec "$1" -c curl -- curl --noproxy '*' --silent --show-error --max-time 8 -H "X-Request-Id: $2" -H 'Content-Type: application/json' --data-binary "$3" -w '\n%{http_code}\n' 'https://origin-https.gateway-origin.svc.cluster.local/body'
}
fault_logs() {
  # Allow asynchronous access logs to flush without resending the request.
  sleep 1
  k -n gateway-test logs "$1" -c istio-proxy --tail=1000 > "$artifacts/fault/workload.log"
  if [[ "${gateway_absent:-false}" != true ]]; then
    k -n gateway-test logs deployment/egress -c istio-proxy --tail=1000 > "$artifacts/fault/egress.log"
  fi
  k -n gateway-origin logs deployment/origin-https -c origin --tail=1000 > "$artifacts/fault/origin.log"
}
