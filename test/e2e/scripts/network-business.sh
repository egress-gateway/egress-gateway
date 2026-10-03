#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require jq docker
verify_owner
source "$(dirname "$0")/network-probes.sh"
probe_mode=business
network_source workload
network_probes
