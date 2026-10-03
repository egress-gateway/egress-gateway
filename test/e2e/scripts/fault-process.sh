# Signal container init from the owned node's parent PID namespace. In-container
# SIGSTOP did not stop PID 1 in the real fixture. Bind each signal to the CRI ID.
fault_process() {
  fault_pod="$1"
  process_pod="$(k -n gateway-test get pod "$fault_pod" -o json)"
  process_uid="$(jq -er .metadata.uid <<< "$process_pod")"
  process_id="$(jq -er '[.status.initContainerStatuses[]?,.status.containerStatuses[]?] | .[] | select(.name=="istio-proxy") | .containerID | sub("^containerd://";"")' <<< "$process_pod")"
  [[ "$process_id" =~ ^[a-f0-9]+$ ]] || return 2
  process_json="$(docker exec "$cluster-control-plane" crictl inspect "$process_id")"
  [[ "$(jq -r '.status.labels["io.kubernetes.pod.uid"]' <<< "$process_json")" == "$process_uid" ]] || return 2
  process_pid="$(jq -er '.info.pid | select(.>0)' <<< "$process_json")"
  [[ "$(docker exec "$cluster-control-plane" cat "/proc/$process_pid/comm")" == gateway-daemon ]] || return 2
}
fault_signal() {
  current_process="$(docker exec "$cluster-control-plane" crictl inspect "$process_id")"
  [[ "$(jq -r .info.pid <<< "$current_process")" == "$process_pid" && "$(jq -r .status.state <<< "$current_process")" == CONTAINER_RUNNING ]] || return 2
  docker exec "$cluster-control-plane" kill "-$1" "$process_pid"
}
