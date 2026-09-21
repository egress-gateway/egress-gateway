package fixture.egress

import rego.v1

default allow := false

allow if {
	input.attributes.request.http.method == "GET"
	input.attributes.request.http.path == "/allowed"
}

decision := {"allowed": allow, "body": "egress denied", "http_status": 403}
