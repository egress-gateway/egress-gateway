# Mutation-only fault injection, never the shared workload baseline.
package envoy.authz

import rego.v1

default permitted := false

payload := json.unmarshal(base64.decode(input.attributes.request.http.raw_body))

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
	not input.truncated_body
	payload.action in {"safe", "egress-mutate"}
}

allow := {"allowed": permitted, "query_parameters_to_set": {"changed": "true"}} if {
	payload.action == "egress-mutate"
} else := {"allowed": permitted, "body": "egress denied", "http_status": 403}
