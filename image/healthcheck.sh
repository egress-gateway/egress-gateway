#!/usr/bin/env bash
set -euo pipefail

curl --noproxy '*' --fail --silent --max-time 2 \
  'http://127.0.0.1:8181/health?plugins&bundles' >/dev/null
case "${GATEWAY_PROXY_MODE:-istio}" in
  istio) proxy_health=http://127.0.0.1:15021/healthz/ready ;;
  standalone) proxy_health=http://127.0.0.1:15000/ready ;;
  *) exit 1 ;;
esac
curl --noproxy '*' --fail --silent --max-time 2 "$proxy_health" >/dev/null
