package suite

import "testing"

func TestNativeStatusDecodesWireMetricsAndCompileErrors(t *testing.T) {
	raw := `not a status line
{"type":"openpolicyagent.org/status","bundles":{"workload":{"active_revision":"last-good","last_request":"2026-10-03T16:14:13.88541704Z","last_successful_activation":"2026-10-03T16:14:10Z","code":"bundle_error","message":"compile failed","errors":[{"code":"rego_type_error","message":"undefined function"}],"metrics":{"timer_rego_module_compile_ns":123}}},"plugins":{"egress_gateway_workload":{"state":"OK"}}}`
	status, ok := latestNativeStatus(raw)
	if !ok || status.Bundles["workload"] == nil {
		t.Fatal("native wire status with metrics/errors not decoded")
	}
	b := status.Bundles["workload"]
	if b.ActiveRevision != "last-good" || b.Code != "bundle_error" || b.LastRequest.IsZero() || b.LastSuccessfulActivation.IsZero() || status.Plugins["egress_gateway_workload"].State != "OK" {
		t.Fatalf("lost update evidence: %+v", status)
	}
}
