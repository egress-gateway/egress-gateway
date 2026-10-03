package envoy.authz

import rego.v1

default permitted := false

permitted if {
	input.source_principal == "spiffe://cluster.local/ns/gateway-test/sa/workload"
	input.attributes.request.http.method == "GET"
	input.attributes.request.http.path in {"/first", "/second", "/inspected", "/recovery"}
}

permitted if {
	input.source_principal == "spiffe://cluster.local/ns/gateway-test/sa/workload"
	input.attributes.request.http.method == "POST"
	input.attributes.request.http.scheme == "https"
	input.attributes.request.http.path == "/body"
	input.attributes.request.http.headers["content-type"] == "application/json"
	not input.truncated_body
	input.parsed_body.action in {"safe", "egress-mutate"}
}

allow := {"allowed": permitted, "query_parameters_to_set": {"changed": "true"}} if {
	input.parsed_body.action == "egress-mutate"
} else := {"allowed": permitted, "body": "egress denied", "http_status": 403}
