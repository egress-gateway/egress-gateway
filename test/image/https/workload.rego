package fixture.workload

import rego.v1

default allow := false

allow if {
	input.attributes.request.http.method == "POST"
	input.attributes.request.http.scheme == "https"
	input.attributes.request.http.path == "/body"
	input.attributes.request.http.headers["content-type"] == "application/json"
	not input.truncated_body
	input.parsed_body.action in {"safe", "egress-deny", "workload-mutate", "egress-mutate"}
}

decision := {"allowed": allow, "query_parameters_to_set": {"changed": "true"}} if {
    input.parsed_body.action == "workload-mutate"
} else := {"allowed": allow, "body": "workload denied", "http_status": 403}
