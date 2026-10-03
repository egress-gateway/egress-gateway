package suite

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/egress-gateway/egress-gateway/test/e2e/environment"
	core "k8s.io/api/core/v1"
)

type probeResult struct {
	Kind, Protocol, Target, ID, Local, Error string
	Attempted, Delivered                     bool
	Sent                                     int64
	UID                                      int
}

func (s *scenario) network(stage string) error {
	operations := map[string]string{"business": "network-business", "init": "network-init", "absent": "network-proxy-absent"}
	operation, ok := operations[stage]
	if !ok {
		return errors.New("unknown network stage")
	}
	cfg := s.env.Config
	cfg.Artifacts = filepath.Join(cfg.Artifacts, "cases", s.id)
	if err := environment.New(cfg).Operation(s.ctx, operation); err != nil {
		return err
	}
	if err := assertNetwork(filepath.Join(cfg.Artifacts, "network"), stage); err != nil {
		return err
	}
	if stage == "absent" {
		if err := s.governedRequest("workload", s.id+"-recovered", contentCases()["safe"]); err != nil {
			return err
		}
		return s.governedRequest("workload", s.id+"-still-denied", contentCases()["egress-deny"])
	}
	return nil
}
func readJSON(path string, value any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, value)
}
func readText(path string) (string, error) { raw, err := os.ReadFile(path); return string(raw), err }
func assertNetwork(dir, stage string) error {
	var source struct{ UID, IP, Interface, ReceiverUID, ReceiverIP, Mode string }
	if err := readJSON(filepath.Join(dir, "source.json"), &source); err != nil {
		return err
	}
	if source.UID == "" || source.ReceiverUID == "" || source.Mode != stage {
		return errors.New("missing source/receiver identity")
	}
	for _, probe := range []string{"tcp-8081", "tcp-8444", "udp-5353", "udp-7777", "dns-53", "quic-443"} {
		path := filepath.Join(dir, probe)
		protocol, port, _ := strings.Cut(probe, "-")
		var sender, before, after probeResult
		for file, result := range map[string]*probeResult{"sender.json": &sender, "receiver-before.json": &before, "receiver-after.json": &after} {
			if err := readJSON(filepath.Join(path, file), result); err != nil {
				return err
			}
		}
		exit, err := readText(filepath.Join(path, "sender-exit.txt"))
		if err != nil {
			return err
		}
		target := source.ReceiverIP + ":" + port
		if !sender.Attempted || sender.Delivered || sender.Error == "" || sender.UID != 1000 || sender.Target != target || sender.Protocol != protocol || strings.TrimSpace(exit) != "1" {
			return fmt.Errorf("%s: missing actual restricted sender failure: %+v exit=%s", probe, sender, exit)
		}
		for _, control := range []struct {
			result probeResult
			suffix string
		}{{before, "before"}, {after, "after"}} {
			c := control.result
			if !c.Delivered || c.Target != target || c.Protocol != protocol || c.ID != sender.ID+"-"+control.suffix {
				return fmt.Errorf("%s: unhealthy independent receiver control %+v", probe, c)
			}
		}
		logs, err := readText(filepath.Join(path, "receiver.log"))
		if err != nil {
			return err
		}
		received := map[string]bool{}
		for line := range strings.SplitSeq(logs, "\n") {
			var e probeResult
			if json.Unmarshal([]byte(line), &e) == nil && e.Kind == "receiver" && e.Protocol == protocol && e.Delivered {
				received[e.ID] = true
			}
		}
		if received[sender.ID] || !received[before.ID] || !received[after.ID] {
			return fmt.Errorf("%s: receiver delivery/non-delivery evidence invalid", probe)
		}
		if protocol == "tcp" {
			first, err := readText(filepath.Join(path, "before-capture.txt"))
			if err != nil {
				return err
			}
			last, err := readText(filepath.Join(path, "after-capture.txt"))
			if err != nil {
				return err
			}
			a, err := captureCount(first)
			if err != nil {
				return err
			}
			b, err := captureCount(last)
			if err != nil {
				return err
			}
			if b <= a {
				return fmt.Errorf("%s: no executed TCP capture increment", probe)
			}
			if stage != "absent" {
				first, err = readText(filepath.Join(path, "before-blackhole.txt"))
				if err != nil {
					return err
				}
				last, err = readText(filepath.Join(path, "after-blackhole.txt"))
				if err != nil {
					return err
				}
				a, err = blackholeCount(first)
				if err != nil {
					return err
				}
				b, err = blackholeCount(last)
				if err != nil {
					return err
				}
				if b <= a {
					return fmt.Errorf("%s: captured TCP lacks an attributable Envoy rejection", probe)
				}
			}
		} else {
			if sender.Sent <= 0 {
				return fmt.Errorf("%s: no datagram was actually sent", probe)
			}
			first, err := readText(filepath.Join(path, "before-drop.txt"))
			if err != nil {
				return err
			}
			last, err := readText(filepath.Join(path, "after-drop.txt"))
			if err != nil {
				return err
			}
			a, err := dropCount(first, source.Interface)
			if err != nil {
				return err
			}
			b, err := dropCount(last, source.Interface)
			if err != nil {
				return err
			}
			if b <= a {
				return fmt.Errorf("%s: no attributable Calico DROP increment", probe)
			}
		}
	}
	if stage == "absent" {
		for _, point := range []string{"before", "after"} {
			text, err := readText(filepath.Join(dir, "proxy-absent-"+point+".txt"))
			if err != nil {
				return err
			}
			if !strings.Contains(text, "State:\tT") {
				return errors.New("proxy absence was not held by stopped supervision")
			}
		}
		raw, err := readText(filepath.Join(dir, "restart-before.txt"))
		if err != nil {
			return err
		}
		before, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return err
		}
		var recovered struct {
			UID  string
			Init []core.ContainerStatus
		}
		if err = readJSON(filepath.Join(dir, "recovered.json"), &recovered); err != nil {
			return err
		}
		if recovered.UID != source.UID {
			return errors.New("proxy recovery changed the selected Pod")
		}
		restarted := false
		for _, c := range recovered.Init {
			if c.Name == "istio-proxy" {
				restarted = c.RestartCount > int32(before) && c.Ready && c.State.Running != nil
			}
		}
		if !restarted {
			return errors.New("proxy did not restart and recover readiness")
		}
	}
	if stage == "init" {
		var startup struct{ Init []core.ContainerStatus }
		if err := readJSON(filepath.Join(dir, "startup.json"), &startup); err != nil {
			return err
		}
		var business, management *core.ContainerStateTerminated
		var proxy *core.ContainerStateRunning
		for _, c := range startup.Init {
			switch c.Name {
			case "business-network-state":
				business = c.State.Terminated
			case "management-init":
				management = c.State.Terminated
			case "istio-proxy":
				proxy = c.State.Running
			}
		}
		if business == nil || management == nil || proxy == nil || business.ExitCode != 0 || management.ExitCode != 0 || business.StartedAt.Before(&proxy.StartedAt) || proxy.StartedAt.Before(&management.FinishedAt) {
			return errors.New("init probes did not execute after managed startup and complete")
		}
	}
	return nil
}
func captureCount(text string) (uint64, error) {
	for line := range strings.SplitSeq(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[1] != "-A" || fields[2] != "ISTIO_REDIRECT" || !strings.Contains(line, "-j REDIRECT --to-ports 15001") {
			continue
		}
		packets, _, ok := strings.Cut(strings.Trim(fields[0], "[]"), ":")
		if !ok {
			return 0, errors.New("invalid capture counter")
		}
		return strconv.ParseUint(packets, 10, 64)
	}
	return 0, errors.New("missing executed Istio TCP capture rule")
}
func blackholeCount(text string) (uint64, error) {
	for line := range strings.SplitSeq(text, "\n") {
		name, value, ok := strings.Cut(line, ": ")
		if ok && name == "cluster.BlackHoleCluster.upstream_cx_none_healthy" {
			return strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		}
	}
	return 0, errors.New("missing Envoy BlackHoleCluster rejection counter")
}
