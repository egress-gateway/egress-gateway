package fixture.workload

import rego.v1

default allow := false

allow if {
	input.attributes.request.http.method == "GET"
	input.attributes.request.http.path in {"/allowed", "/egress-denied"}
}

decision := {"allowed": allow, "body": "workload denied", "http_status": 403}

allow if {
	input.attributes.request.http.method == "POST"
	input.attributes.request.http.path == "/body"
	input.attributes.request.http.headers["content-type"] == "application/json"
	input.parsed_body.action in {"safe", "egress-deny"}
}
