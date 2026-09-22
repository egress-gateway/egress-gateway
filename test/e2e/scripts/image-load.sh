#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require docker kind
verify_owner
docker build -f "$root/image/Dockerfile" -t "$image" "$root"
docker build -f "$root/examples/local/upstream/Dockerfile" -t "$image-origin" "$root"
docker pull "$CURL_IMAGE"
kind load docker-image --name "$cluster" "$image" "$image-origin" "$CURL_IMAGE"
docker image inspect --format '{{.Id}}' "$image" > "$artifacts/gateway-image-id.txt"
git -C "$root" rev-parse HEAD > "$artifacts/code-head.txt"
git -C "$root" status --porcelain > "$artifacts/code-status.txt"
cp "$config_dir/versions.env" "$artifacts/test-inputs.env"
docker run --rm --network none --entrypoint /usr/local/bin/envoy "$image" --version > "$artifacts/envoy-version.txt"
docker run --rm --network none --entrypoint /usr/local/bin/pilot-agent "$image" version > "$artifacts/pilot-agent-version.txt"
