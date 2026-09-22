#!/usr/bin/env bash
set -euo pipefail
# Run once in the Pod network namespace, before application startup. Runtime
# containers retain neither NET_ADMIN nor permission to assume the proxy UID.
for tool in iptables ip6tables; do
  "$tool" -w -N GATEWAY_MANAGEMENT 2>/dev/null || "$tool" -w -S GATEWAY_MANAGEMENT >/dev/null
  "$tool" -w -C GATEWAY_MANAGEMENT -m owner --uid-owner 1337 -j RETURN 2>/dev/null ||
    "$tool" -w -A GATEWAY_MANAGEMENT -m owner --uid-owner 1337 -j RETURN
  "$tool" -w -C GATEWAY_MANAGEMENT -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null ||
    "$tool" -w -A GATEWAY_MANAGEMENT -p tcp -j REJECT --reject-with tcp-reset
  "$tool" -w -C OUTPUT -p tcp -m multiport --dports 15000,15020,15004 -m addrtype --dst-type LOCAL -j GATEWAY_MANAGEMENT 2>/dev/null ||
    "$tool" -w -I OUTPUT 1 -p tcp -m multiport --dports 15000,15020,15004 -m addrtype --dst-type LOCAL -j GATEWAY_MANAGEMENT
  "$tool" -w -C INPUT ! -i lo -p tcp -m multiport --dports 15000,15020,15004 -j REJECT --reject-with tcp-reset 2>/dev/null ||
    "$tool" -w -I INPUT 1 ! -i lo -p tcp -m multiport --dports 15000,15020,15004 -j REJECT --reject-with tcp-reset
done
