#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require kind docker
verify_owner
kind delete cluster --name "$cluster"
rm -f "$state_dir/node-id" "$kubeconfig"
