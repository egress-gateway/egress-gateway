package fixture.egress

import rego.v1

default allow := false

allow if {
	input.source_principal == "spiffe://fixture.test/ns/gateway/sa/workload"
	input.attributes.request.http.method == "POST"
	input.attributes.request.http.scheme == "https"
	input.attributes.request.http.path == "/body"
	input.attributes.request.http.headers["content-type"] == "application/json"
	not input.truncated_body
	input.parsed_body.action in {"safe", "egress-mutate"}
}

decision := {"allowed": allow, "query_parameters_to_set": {"changed": "true"}} if {
    input.parsed_body.action == "egress-mutate"
} else := {"allowed": allow, "body": "egress denied", "http_status": 403}
