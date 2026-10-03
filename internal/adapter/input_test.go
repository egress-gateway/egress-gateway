package adapter

import (
	"testing"

	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/artifacts"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

func request(path string, body []byte, headers ...*core.HeaderValue) *auth.CheckRequest {
	return &auth.CheckRequest{Attributes: &auth.AttributeContext{Request: &auth.AttributeContext_Request{Http: &auth.AttributeContext_HttpRequest{Host: "API.example:443", Method: "POST", Path: path, Scheme: "https", Protocol: "HTTP/2", RawBody: body, HeaderMap: &core.HeaderMap{Headers: headers}}}}}
}
func TestNormalizeLosslessAttributes(t *testing.T) {
	a := New(&artifacts.Workload{}, config.Workload)
	in, err := a.Normalize(request("/v1/chat?tag=a&tag=b", nil, &core.HeaderValue{Key: "X-Tag", RawValue: []byte("a,b")}, &core.HeaderValue{Key: "x-tag", RawValue: []byte("c")}))
	if err != nil {
		t.Fatal(err)
	}
	if in.Host != "api.example" || len(in.HTTP.Headers["x-tag"]) != 2 || in.HTTP.Headers["x-tag"][0] != "a,b" || len(in.HTTP.Query["tag"]) != 2 {
		t.Fatalf("lost request facts: %+v", in)
	}
}
func TestStrictJSON(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":{"x":1,"x":2}}`, `{} {}`, "{\"x\":\"\xff\"}", `[1,]`, `"\ud800"`} {
		if _, err := decodeJSON([]byte(raw)); err == nil {
			t.Fatalf("accepted ambiguous/invalid JSON %q", raw)
		}
	}
	for _, raw := range []string{`null`, `{"items":[{"model":"allowed"}]}`, `12345678901234567890`} {
		if _, err := decodeJSON([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
}
func TestRecognizeRPCWithoutContentType(t *testing.T) {
	a := New(&artifacts.Workload{Policy: workload.Policy{RequestConstraints: []workload.Constraint{{Match: workload.Match{GRPC: &workload.GRPCMatch{Service: "test.Service"}}}}}}, config.Workload)
	in, err := a.Normalize(request("/test.Service/Call", nil, &core.HeaderValue{Key: "content-type", Value: "application/json"}, &core.HeaderValue{Key: "x-role", Value: "one"}, &core.HeaderValue{Key: "x-role", Value: "two"}, &core.HeaderValue{Key: "secret-bin", Value: "ignored"}))
	if err != nil {
		t.Fatal(err)
	}
	if in.Protocol != workload.GRPC || in.GRPC.Service != "test.Service" || len(in.GRPC.Metadata["x-role"]) != 2 || in.GRPC.Metadata["secret-bin"] != nil {
		t.Fatalf("wrong RPC facts: %+v", in)
	}
}
