package fixture.workload

import rego.v1

default allow := false

allow if {
	input.attributes.request.http.method == "GET"
	input.attributes.request.http.path in {"/allowed", "/egress-denied"}
}

decision := {"allowed": allow, "body": "workload denied", "http_status": 403}
