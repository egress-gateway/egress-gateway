package suite

import "testing"

func TestBlackholeCounterRequiresThePinnedEmptyIstioCluster(t *testing.T) {
	const empty = "cluster.BlackHoleCluster;.membership_total: 0\n"
	for _, tc := range []struct {
		name, text string
		want       uint64
		valid      bool
	}{
		// Fresh Envoy snapshots contain eager cluster stats, but no upstream_cx_*
		// traffic counters until a connection selects that cluster.
		{"before-first-connection", empty + "cluster.BlackHoleCluster;.lb_healthy_panic: 0\n", 0, true},
		{"after-rejection", empty + "cluster.BlackHoleCluster;.lb_healthy_panic: 3\ncluster.BlackHoleCluster;.upstream_cx_none_healthy: 3\n", 3, true},
		{"missing-delimiter", empty + "cluster.BlackHoleCluster.lb_healthy_panic: 3\n", 0, false},
		{"other-cluster", empty + "cluster.PassthroughCluster;.lb_healthy_panic: 3\n", 0, false},
		{"not-empty", "cluster.BlackHoleCluster;.membership_total: 1\ncluster.BlackHoleCluster;.lb_healthy_panic: 3\n", 0, false},
		{"missing-membership", "cluster.BlackHoleCluster;.lb_healthy_panic: 3\n", 0, false},
		{"missing-counter", empty, 0, false},
		{"missing", "", 0, false},
		{"malformed", empty + "cluster.BlackHoleCluster;.lb_healthy_panic: invalid\n", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := blackholeCount(tc.text)
			if (err == nil) != tc.valid || got != tc.want {
				t.Fatalf("got %d, %v; want %d, valid=%v", got, err, tc.want, tc.valid)
			}
		})
	}
}
