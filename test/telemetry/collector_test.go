package telemetry

import "testing"

func TestCollectorHexIDsAndParentChain(t *testing.T) {
	raw := []byte(`{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"workload-envoy"}}]},"scopeSpans":[{"spans":[{"traceId":"0123456789abcdef0123456789abcdef","spanId":"0123456789abcdef","parentSpanId":"fedcba9876543210","name":"ingress"},{"traceId":"0123456789abcdef0123456789abcdef","spanId":"1123456789abcdef","parentSpanId":"0123456789abcdef","name":"child"}]}]}]}` + "\n" + `{"resourceSpans":`)
	spans, err := Read(raw)
	if err != nil || len(spans) != 2 {
		t.Fatalf("records=%+v err=%v", spans, err)
	}
	if spans[0].TraceID != "0123456789abcdef0123456789abcdef" || spans[0].ID != "0123456789abcdef" || spans[0].Service != "workload-envoy" {
		t.Fatalf("OTLP hex IDs or resource corrupted: %+v", spans[0])
	}
	if !Descends(spans, spans[1], "fedcba9876543210") {
		t.Fatal("lost indirect parent chain")
	}
	spans[0].TraceID = "different-trace"
	if Descends(spans, spans[1], "fedcba9876543210") {
		t.Fatal("followed a parent in another trace")
	}
	if _, err := Read([]byte("malformed complete record\n")); err == nil {
		t.Fatal("accepted corrupt complete record")
	}
}
