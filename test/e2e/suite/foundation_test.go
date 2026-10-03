package suite

import "testing"

func TestDropEvidenceMustBelongToSourceEndpoint(t *testing.T) {
	text := `[2:120] -A cali-fw-cali123 -m comment --comment "drop" -j DROP
[200:12000] -A cali-fw-cali456 -j DROP
[400:24000] -A cali-fw-cali123 -j ACCEPT
[1:60] -A cali-fw-cali123 -j DROP
`
	n, err := dropCount(text, "cali123")
	if err != nil || n != 3 {
		t.Fatalf("count %d: %v", n, err)
	}
	if _, err := dropCount(text, "missing"); err == nil {
		t.Fatal("missing endpoint counted as denial")
	}
}
