package suite

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFaultLogObservation(t *testing.T) {
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("shell observation regression requires %s: %v", tool, err)
		}
	}
	for _, mode := range []string{"delayed", "missing-egress", "gateway-absent"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.CommandContext(t.Context(), "bash", "-c", `
set -euo pipefail
source ../scripts/fault-observations.sh
artifacts=$1
mode=$2
mkdir -p "$artifacts/fault"
start=$SECONDS
k() {
  [[ "$3" == logs ]] || { echo 'unexpected non-log operation' >&2; return 2; }
  printf '%s\n' "$4" >> "$artifacts/reads"
  case "$4" in
    workload)
      printf '%s\n' 'daemon startup message' '{"request_id": "startup-safe"}' '{"request_id":"startup-denied"}'
      ;;
    deployment/egress)
      [[ "$mode" != gateway-absent ]] || return 2
      printf '%s\n' '{"request_id":"startup-denied"}'
      if [[ "$mode" != missing-egress ]] && ((SECONDS >= start + 2)); then
        printf '%s\n' '{"request_id":"startup-safe"}'
      fi
      ;;
    deployment/origin-https)
      printf '%s\n' 'origin request_id=startup-after-unrelated'
      if [[ "$mode" == gateway-absent ]] || ((SECONDS >= start + 2)); then
        printf '%s\n' 'origin request_id=startup-after'
      fi
      ;;
    *) return 2 ;;
  esac
}
if [[ "$mode" == gateway-absent ]]; then
  gateway_absent=true
  fault_logs workload startup-after false startup-safe startup-denied
else
  fault_logs workload startup-after true startup-safe startup-denied
fi
`, "fault-log-test", dir, mode)
			output, err := cmd.CombinedOutput()
			if mode == "missing-egress" {
				if err == nil || !strings.Contains(string(output), "timed out waiting for correlated fault logs") {
					t.Fatalf("missing egress evidence did not time out: %v %s", err, output)
				}
			} else if err != nil {
				t.Fatalf("observation failed: %v %s", err, output)
			}
			for _, name := range []string{"workload", "origin"} {
				data, err := os.ReadFile(filepath.Join(dir, "fault", name+".log"))
				if err != nil || len(data) == 0 {
					t.Fatalf("final %s evidence not preserved: %v", name, err)
				}
			}
			reads, err := os.ReadFile(filepath.Join(dir, "reads"))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "gateway-absent" {
				if strings.Contains(string(reads), "deployment/egress") {
					t.Fatal("attempted logs from the absent gateway")
				}
			} else {
				if strings.Count(string(reads), "deployment/egress\n") < 2 {
					t.Fatal("did not retry delayed log observation")
				}
				data, err := os.ReadFile(filepath.Join(dir, "fault", "egress.log"))
				if err != nil || !strings.Contains(string(data), "startup-denied") {
					t.Fatalf("final egress evidence not preserved: %v", err)
				}
			}
		})
	}
}
