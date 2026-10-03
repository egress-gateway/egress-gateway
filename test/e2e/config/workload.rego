package envoy.authz

import rego.v1

default permitted := false

permitted if {
	input.attributes.request.http.method == "GET"
	input.attributes.request.http.path in {"/first", "/second", "/inspected", "/recovery"}
}

permitted if {
	input.attributes.request.http.method == "POST"
	input.attributes.request.http.scheme == "https"
	input.attributes.request.http.path == "/body"
	input.attributes.request.http.headers["content-type"] == "application/json"
	not input.truncated_body
	input.parsed_body.action in {"safe", "egress-deny", "workload-mutate", "egress-mutate"}
}

allow := {"allowed": permitted, "query_parameters_to_set": {"changed": "true"}} if {
	input.parsed_body.action == "workload-mutate"
} else := {"allowed": permitted, "body": "workload denied", "http_status": 403}
