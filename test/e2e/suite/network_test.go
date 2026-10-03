package suite

import "testing"

func TestBlackholeCounterRequiresThePinnedIstioStatName(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       uint64
		valid      bool
	}{
		{"rejection", "cluster.BlackHoleCluster;.upstream_cx_none_healthy: 3\n", 3, true},
		{"unused", "cluster.BlackHoleCluster;.upstream_cx_none_healthy: 0\n", 0, true},
		{"missing-delimiter", "cluster.BlackHoleCluster.upstream_cx_none_healthy: 3\n", 0, false},
		{"other-cluster", "cluster.PassthroughCluster;.upstream_cx_none_healthy: 3\n", 0, false},
		{"missing", "", 0, false},
		{"malformed", "cluster.BlackHoleCluster;.upstream_cx_none_healthy: invalid\n", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := blackholeCount(tc.text)
			if (err == nil) != tc.valid || got != tc.want {
				t.Fatalf("got %d, %v; want %d, valid=%v", got, err, tc.want, tc.valid)
			}
		})
	}
}
