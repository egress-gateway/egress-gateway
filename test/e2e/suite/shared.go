package suite

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func sharedHTTPCases() map[string]contentCase {
	base := contentCase{scheme: "https", role: "origin", status: 200, path: "/select?in=good&not=ok&exists=", body: `{"model":"good","blocked":"ok","items":[{"a/b~":false}],"":""}`, headers: []string{"x-in: good", "x-not: ok", "x-exists;"}}
	cases := map[string]contentCase{"selectors": base}
	add := func(name string, change func(*contentCase), allow bool) {
		c := base
		c.headers = append([]string(nil), base.headers...)
		change(&c)
		if !allow {
			c.role = "workload"
			c.status = 403
		}
		cases[name] = c
	}
	add("http-selectors", func(c *contentCase) { c.scheme = "http" }, true)
	add("empty-values", func(c *contentCase) {
		c.body = strings.ReplaceAll(c.body, `"good"`, `""`)
		c.path = "/select?in=&not=&exists="
		c.headers = []string{"x-in;", "x-not;", "x-exists;"}
	}, true)
	add("repeated-in", func(c *contentCase) { c.path += "&in="; c.headers = append(c.headers, "x-in;") }, true)
	add("repeated-header-in-deny", func(c *contentCase) { c.headers = append(c.headers, "x-in: no") }, false)
	add("repeated-query-in-deny", func(c *contentCase) { c.path += "&in=no" }, false)
	add("pointer-null", func(c *contentCase) { c.body = strings.ReplaceAll(c.body, `"a/b~":false`, `"a/b~":null`) }, false)
	add("repeated-header-notin", func(c *contentCase) { c.headers = append(c.headers, "x-not: bad") }, false)
	add("repeated-query-notin", func(c *contentCase) { c.path += "&not=bad" }, false)
	add("missing-header-in", func(c *contentCase) { c.headers = c.headers[1:] }, false)
	add("missing-header-exists", func(c *contentCase) { c.headers = c.headers[:2] }, false)
	add("missing-query-in", func(c *contentCase) { c.path = "/select?not=ok&exists=" }, false)
	add("missing-query-exists", func(c *contentCase) { c.path = "/select?in=good&not=ok" }, false)
	add("missing-notin", func(c *contentCase) {
		c.path = "/select?in=good&exists="
		c.headers = []string{"x-in: good", "x-exists;"}
		c.body = `{"model":"good","items":[{"a/b~":false}],"":""}`
	}, false)
	add("null-notin", func(c *contentCase) { c.body = strings.ReplaceAll(c.body, `"blocked":"ok"`, `"blocked":null`) }, false)
	add("payload-notin", func(c *contentCase) { c.body = strings.ReplaceAll(c.body, `"blocked":"ok"`, `"blocked":"bad"`) }, false)
	add("payload-null", func(c *contentCase) { c.body = strings.ReplaceAll(c.body, `"model":"good"`, `"model":null`) }, false)
	add("payload-missing", func(c *contentCase) { c.body = strings.ReplaceAll(c.body, `"model":"good",`, ``) }, false)
	add("pointer-missing", func(c *contentCase) { c.body = strings.ReplaceAll(c.body, `"a/b~":false`, `"other":false`) }, false)
	add("duplicate-json", func(c *contentCase) {
		c.body = strings.Replace(c.body, `"model":"good"`, `"model":"bad","model":"good"`, 1)
	}, false)
	add("trailing-json", func(c *contentCase) { c.body += " {}" }, false)
	return cases
}
func (s *scenario) sharedHTTP(name string) error {
	c, ok := sharedHTTPCases()[name]
	if !ok {
		return fmt.Errorf("unknown HTTP selection %q", name)
	}
	if err := s.governedRequest("workload", s.id, c); err != nil {
		return err
	}
	return s.sharedDecision(s.id, c.role, c.status)
}
func (s *scenario) sharedHost(role string) error {
	alias := "blocked-" + role
	boundary := "not" + alias
	childRole := role
	if role == "workload" {
		childRole = "origin"
	}
	for _, tc := range []struct{ name, host, role string }{
		{"match", alias, role}, {"child", "child." + alias, childRole}, {"boundary", boundary, "origin"},
	} {
		id := s.id + "-" + tc.name
		status := 403
		if tc.role == "origin" {
			status = 200
		}
		c := contentCase{scheme: "http", host: tc.host + ".gateway-origin.svc.cluster.local", body: `{"action":"safe"}`, role: tc.role, status: status}
		if err := s.governedRequest("workload", id, c); err != nil {
			return err
		}
		if err := s.sharedDecision(id, tc.role, status); err != nil {
			return err
		}
	}
	return nil
}

type meshRPC struct {
	method, payload, protocol, contentType, encoding, role string
	metadata                                               []string
	status                                                 int
}

func sharedRPCCases() map[string]meshRPC {
	base := meshRPC{method: "Check", payload: "safe", protocol: "grpc", contentType: "application/grpc", role: "origin", status: 200, metadata: []string{"x-role=reader", "x-not=ok", "x-exists=", "x-carrier=ok"}}
	cases := map[string]meshRPC{"safe": base}
	add := func(name string, change func(*meshRPC), role string) {
		c := base
		c.metadata = append([]string(nil), base.metadata...)
		change(&c)
		c.role = role
		if role != "origin" {
			c.status = 403
		}
		cases[name] = c
	}
	add("egress-deny", func(c *meshRPC) { c.payload = "egress-deny" }, "egress")
	add("workload-deny", func(c *meshRPC) { c.payload = "blocked" }, "workload")
	add("default-field", func(c *meshRPC) { c.payload = "" }, "workload")
	add("metadata-empty", func(c *meshRPC) { c.metadata[0] = "x-role=" }, "origin")
	add("metadata-repeated-in", func(c *meshRPC) { c.metadata = append(c.metadata, "x-role=other") }, "workload")
	add("metadata-repeated-notin", func(c *meshRPC) { c.metadata = append(c.metadata, "x-not=bad") }, "workload")
	add("metadata-missing-in", func(c *meshRPC) { c.metadata = c.metadata[1:] }, "workload")
	add("metadata-missing-exists", func(c *meshRPC) { c.metadata = append(c.metadata[:2], c.metadata[3:]...) }, "workload")
	add("metadata-missing-notin", func(c *meshRPC) { c.metadata = []string{"x-role=reader", "x-exists=", "x-carrier=ok"} }, "workload")
	add("http-carrier", func(c *meshRPC) { c.metadata = append(c.metadata, "x-carrier=blocked") }, "workload")
	add("spoof", func(c *meshRPC) {
		c.payload = "egress-deny"
		c.metadata = append(c.metadata, "x-workload-allowed=true", "x-workload-identity=spiffe://cluster.local/ns/gateway-test/sa/egress")
	}, "egress")
	add("stream", func(c *meshRPC) { c.method = "Watch" }, "workload")
	frame := func(body []byte) []byte {
		b := make([]byte, 5)
		binary.BigEndian.PutUint32(b[1:], uint32(len(body)))
		return append(b, body...)
	}
	good := frame([]byte{10, 4, 's', 'a', 'f', 'e'})
	wire := func(name string, b []byte, ctype, encoding string, allow bool) {
		role := "workload"
		if allow {
			role = "origin"
		}
		add(name, func(c *meshRPC) {
			c.protocol = "grpc-wire"
			c.payload = base64.StdEncoding.EncodeToString(b)
			c.contentType = ctype
			c.encoding = encoding
		}, role)
	}
	wire("wire-valid", good, "application/grpc+proto", "", true)
	wire("unsupported-codec", good, "application/grpc+json", "", false)
	wire("spoof-content-type", good, "application/json", "", false)
	wire("framed-default", frame(nil), "application/grpc", "", false)
	wire("truncated-header", good[:4], "application/grpc", "", false)
	wire("truncated-payload", good[:len(good)-1], "application/grpc", "", false)
	wire("extra-frame", append(append([]byte(nil), good...), good...), "application/grpc", "", false)
	compressed := append([]byte(nil), good...)
	compressed[0] = 1
	wire("compressed-flag", compressed, "application/grpc", "", false)
	wire("encoding", good, "application/grpc", "gzip", false)
	wire("malformed-protobuf", frame([]byte{10, 255}), "application/grpc", "", false)
	wire("missing-frame", nil, "application/grpc", "", false)
	wire("oversized", frame(append([]byte{10, 128, 128, 4}, []byte(strings.Repeat("x", 65536))...)), "application/grpc", "", false)
	c := cases["oversized"]
	c.status = 413
	cases["oversized"] = c
	return cases
}
func (s *scenario) rpcProbe(id, namespace, pod, container, host, ca string, c meshRPC) ([]byte, error) {
	args := []string{"exec", "-n", namespace, pod, "-c", container, "--", "/usr/local/bin/gateway-e2e-probe", "-protocol", c.protocol, "-target", host + ":443", "-id", id, "-ca", ca, "-timeout", "8s", "-rpc-method", c.method, "-payload", c.payload, "-content-type", c.contentType, "-encoding", c.encoding}
	for _, md := range c.metadata {
		args = append(args, "-metadata", md)
	}
	return s.command(args...)
}
func (s *scenario) rpcControl(id, method string) error {
	c := sharedRPCCases()["safe"]
	c.method = method
	raw, err := s.rpcProbe(id, "gateway-origin", "probe-control", "probe", governedHost, "/etc/receiver-trust/ca.pem", c)
	if e := s.evidence(id+"-control.json", raw); e != nil {
		return e
	}
	var result struct {
		Code    int
		Serving bool
	}
	if err != nil {
		return fmt.Errorf("RPC origin control: %w: %s", err, raw)
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		return err
	}
	if result.Code != 0 || !result.Serving {
		return fmt.Errorf("unhealthy RPC control: %s", raw)
	}
	return nil
}
func (s *scenario) sharedRPC(name string) error {
	c, ok := sharedRPCCases()[name]
	if !ok {
		return fmt.Errorf("unknown RPC case %q", name)
	}
	if err := s.rpcControl(s.id+"-before", c.method); err != nil {
		return err
	}
	uid, err := s.singlePodUID("gateway-origin", "app=origin-https")
	if err != nil {
		return err
	}
	raw, err := s.rpcProbe(s.id, "gateway-test", "workload", "curl", governedHost, "/cacert.pem", c)
	if e := s.evidence(s.id+"-rpc.json", raw); e != nil {
		return e
	}
	if err != nil {
		return fmt.Errorf("RPC transport failed without enforcement proof: %w: %s", err, raw)
	}
	var result struct {
		Code        int
		Serving     bool
		HTTPStatus  int
		HTTPVersion int
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		return err
	}
	if c.protocol == "grpc-wire" && result.HTTPVersion != 2 {
		return fmt.Errorf("wire RPC lost HTTP/2: %s", raw)
	}
	if c.role == "origin" {
		if result.Code != 0 || (c.protocol == "grpc" && !result.Serving) {
			return fmt.Errorf("allowed RPC failed: %s", raw)
		}
	} else if c.protocol == "grpc" {
		if result.Code != 7 {
			return fmt.Errorf("expected PermissionDenied, got: %s", raw)
		}
	} else {
		expectedRPC := 7
		if result.HTTPStatus != c.status && !(result.HTTPStatus == 200 && result.Code == expectedRPC) {
			return fmt.Errorf("expected HTTP %d or gRPC %d, got: %s", c.status, expectedRPC, raw)
		}
	}
	if err = s.rpcControl(s.id+"-after", c.method); err != nil {
		return err
	}
	after, err := s.singlePodUID("gateway-origin", "app=origin-https")
	if err != nil {
		return err
	}
	if uid != after {
		return errors.New("RPC receiver changed during case")
	}
	observedStatus := c.status
	if c.protocol == "grpc-wire" {
		observedStatus = result.HTTPStatus
	} else if c.role != "origin" {
		observedStatus = 0
	}
	if err = s.observeGovernance("workload", s.id, c.role, observedStatus, string(raw), "origin-https"); err != nil {
		return err
	}
	if err = s.sharedDecision(s.id, c.role, c.status); err != nil {
		return err
	}
	if c.role == "origin" {
		origin, err := os.ReadFile(filepath.Join(s.env.Config.Artifacts, "cases", s.id, s.id+"-origin.log"))
		if err != nil {
			return err
		}
		if !strings.Contains(string(origin), "origin rpc=grpc.health.v1.Health/"+c.method+" request_id="+s.id+"\n") {
			return errors.New("allowed RPC did not reach the intended upstream method")
		}
	}
	return nil
}

func (s *scenario) sharedDecision(id, role string, status int) error {
	if role == "origin" || status == 413 {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(s.env.Config.Artifacts, "cases", s.id, id+"-"+role+".log"))
	if err != nil {
		return err
	}
	entry, ok := proxyEntry(string(raw), id)
	if !ok || entry["details"] != "ext_authz_denied" {
		return fmt.Errorf("shared denial lacks executed ext_authz decision: %v", entry)
	}
	return nil
}
