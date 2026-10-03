# Fixed protocol observations shared by the normal, init and absent-proxy cases.
# The caller has sourced common.sh and verified ownership.
network_source() {
  source_pod="$1"
  source_json="$(k -n gateway-test get pod "$source_pod" -o json)"
  source_uid="$(jq -r .metadata.uid <<< "$source_json")"
  source_ip="$(jq -r .status.podIP <<< "$source_json")"
  sandbox_id="$(docker exec "$cluster-control-plane" crictl pods --namespace '^gateway-test$' --name "^$source_pod$" --state Ready -q)"
  [[ "$sandbox_id" =~ ^[a-f0-9]+$ ]] || { echo 'ambiguous source sandbox' >&2; exit 2; }
  sandbox_json="$(docker exec "$cluster-control-plane" crictl inspectp "$sandbox_id")"
  [[ "$(jq -r .status.metadata.uid <<< "$sandbox_json")" == "$source_uid" ]] || exit 2
  sandbox_pid="$(jq -er '.info.pid | select(.>0)' <<< "$sandbox_json")"
  peer_index="$(docker exec "$cluster-control-plane" nsenter -t "$sandbox_pid" -n ip -j link show dev eth0 | jq -er '.[0].link_index')"
  source_interface="$(docker exec "$cluster-control-plane" ip -j link show | jq -er --argjson index "$peer_index" '[.[] | select(.ifindex==$index) | .ifname] | if length==1 then .[0] else error("ambiguous endpoint") end')"
  [[ "$source_interface" =~ ^cali[a-zA-Z0-9]+$ ]] || exit 2
  receiver="$(k -n gateway-origin get pods -l app=receiver -o json | jq -er '.items | if length==1 then .[0] else error("ambiguous receiver") end')"
  receiver_uid="$(jq -r .metadata.uid <<< "$receiver")"
  receiver_ip="$(jq -r .status.podIP <<< "$receiver")"
  receiver_pod="$(jq -r .metadata.name <<< "$receiver")"
  mkdir -p "$artifacts/network"
  jq -n --arg uid "$source_uid" --arg ip "$source_ip" --arg interface "$source_interface" --arg receiverUID "$receiver_uid" --arg receiverIP "$receiver_ip" --arg mode "$probe_mode" '{uid:$uid,ip:$ip,interface:$interface,receiverUID:$receiverUID,receiverIP:$receiverIP,mode:$mode}' > "$artifacts/network/source.json"
}
network_snapshot() {
  docker exec "$cluster-control-plane" iptables-save -c -t filter | awk -v chain="cali-fw-$source_interface" '$2=="-A" && $3==chain {print}' > "$1-drop.txt"
  docker exec "$cluster-control-plane" nsenter -t "$sandbox_pid" -n iptables-save -c -t nat > "$1-capture.txt"
  if [[ "$probe_mode" != absent ]]; then
    k -n gateway-test exec "$source_pod" -c istio-proxy -- pilot-agent request GET 'stats?filter=BlackHoleCluster' > "$1-blackhole.txt"
  fi
}
network_probes() {
  probe_index=0
  for probe in tcp:8081 tcp:8444 udp:5353 udp:7777 dns:53 quic:443; do
    protocol="${probe%:*}" port="${probe#*:}"
    output="$artifacts/network/$protocol-$port"
    mkdir -p "$output"
    request_id="net-$(basename "$artifacts")-$probe_index"
    k -n gateway-origin exec probe-control -c probe -- gateway-e2e-probe -protocol "$protocol" -target "$receiver_ip:$port" -id "$request_id-before" > "$output/receiver-before.json" 2> "$output/receiver-before.stderr"
    network_snapshot "$output/before"
    if [[ "$probe_mode" == init ]]; then
      k -n gateway-test exec "$source_pod" -c business-network-state -- touch "/tmp/release-$probe_index"
      done_probe=false
      for ((attempt=0; attempt<30; attempt++)); do
        if k -n gateway-test exec "$source_pod" -c business-network-state -- test -f "/tmp/done-$probe_index"; then done_probe=true; break; fi
        sleep 1
      done
      "$done_probe" || { echo 'init probe did not terminate' >&2; exit 2; }
      k -n gateway-test exec "$source_pod" -c business-network-state -- cat "/tmp/result-$probe_index.json" > "$output/sender.json"
      k -n gateway-test exec "$source_pod" -c business-network-state -- cat "/tmp/result-$probe_index.stderr" > "$output/sender.stderr"
      k -n gateway-test exec "$source_pod" -c business-network-state -- cat "/tmp/exit-$probe_index" > "$output/sender-exit.txt"
    else
      if k -n gateway-test exec "$source_pod" -c curl -- gateway-e2e-probe -protocol "$protocol" -target "$receiver_ip:$port" -id "$request_id" > "$output/sender.json" 2> "$output/sender.stderr"; then sender_exit=0; else sender_exit=$?; fi
      printf '%s\n' "$sender_exit" > "$output/sender-exit.txt"
    fi
    network_snapshot "$output/after"
    k -n gateway-origin exec probe-control -c probe -- gateway-e2e-probe -protocol "$protocol" -target "$receiver_ip:$port" -id "$request_id-after" > "$output/receiver-after.json" 2> "$output/receiver-after.stderr"
    [[ "$(k -n gateway-origin get pods -l app=receiver -o json | jq -er '.items | if length==1 then .[0].metadata.uid else error("ambiguous receiver") end')" == "$receiver_uid" ]] || exit 2
    k -n gateway-origin logs "$receiver_pod" -c receiver > "$output/receiver.log"
    probe_index=$((probe_index+1))
  done
  [[ "$(k -n gateway-test get pod "$source_pod" -o jsonpath='{.metadata.uid}')" == "$source_uid" ]] || exit 2
}
