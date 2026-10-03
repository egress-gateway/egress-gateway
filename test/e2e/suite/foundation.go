package suite

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	core "k8s.io/api/core/v1"
)

func (s *scenario) foundation() error {
	if err := s.env.Operation(s.ctx, "foundation-observe"); err != nil {
		return err
	}
	dir := filepath.Join(s.env.Config.Artifacts, "foundation")
	read := func(name string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		return string(raw), err
	}
	for _, name := range []string{"init-ipv6.txt", "business-state.txt", "resident-state.txt"} {
		text, err := read(name)
		if err != nil {
			return err
		}
		for _, key := range []string{"all", "default", "lo", "eth0"} {
			if !strings.Contains(text, key+"=1\n") {
				return fmt.Errorf("%s: IPv6 %s not disabled", name, key)
			}
		}
		if name != "init-ipv6.txt" && !strings.Contains(text, "CapEff:\t0000000000000000") {
			return fmt.Errorf("%s: resident/business gained capability", name)
		}
	}
	for name, required := range map[string][]string{
		"capture-rules.txt":   {"-A OUTPUT -j ISTIO_OUTPUT", "--uid-owner 1337 -j RETURN"},
		"management-ipv4.txt": {"-A GATEWAY_MANAGEMENT -m owner --uid-owner 1337 -j RETURN", "-j GATEWAY_MANAGEMENT"},
		"management-ipv6.txt": {"-A GATEWAY_MANAGEMENT -m owner --uid-owner 1337 -j RETURN", "-j GATEWAY_MANAGEMENT"},
	} {
		text, err := read(name)
		if err != nil {
			return err
		}
		for _, expected := range required {
			if !strings.Contains(text, expected) {
				return fmt.Errorf("%s: missing executed rule %s", name, expected)
			}
		}
	}
	raw, err := read("startup.json")
	if err != nil {
		return err
	}
	var startup struct{ Init, Containers []core.ContainerStatus }
	if err = json.Unmarshal([]byte(raw), &startup); err != nil {
		return err
	}
	status := map[string]core.ContainerStatus{}
	for _, c := range startup.Init {
		status[c.Name] = c
	}
	preparation := status["management-init"].State.Terminated
	business := status["business-network-state"].State.Terminated
	proxy := status["istio-proxy"].State.Running
	if preparation == nil || business == nil || proxy == nil || preparation.ExitCode != 0 || business.ExitCode != 0 || preparation.FinishedAt.IsZero() || proxy.StartedAt.Before(&preparation.FinishedAt) || business.StartedAt.Before(&preparation.FinishedAt) {
		return fmt.Errorf("management preparation did not complete before execution")
	}
	raw, err = read("result.json")
	if err != nil {
		return err
	}
	var result struct {
		ID, IP, UID, ReceiverUID, Interface string
		SenderExit                          int
	}
	if err = json.Unmarshal([]byte(raw), &result); err != nil {
		return err
	}
	if result.SenderExit != 124 || result.UID == "" || result.ReceiverUID == "" || result.ID == "" {
		return fmt.Errorf("direct sender did not execute expected TCP timeout: %+v", result)
	}
	sender, err := read("sender.txt")
	if err != nil {
		return err
	}
	if !strings.Contains(sender, "attempt tcp "+result.IP+":8080 id="+result.ID) {
		return fmt.Errorf("missing sender attempt")
	}
	before, err := read("drop-before.txt")
	if err != nil {
		return err
	}
	after, err := read("drop-after.txt")
	if err != nil {
		return err
	}
	first, err := dropCount(before, result.Interface)
	if err != nil {
		return err
	}
	last, err := dropCount(after, result.Interface)
	if err != nil {
		return err
	}
	if last <= first {
		return fmt.Errorf("no attributable source-endpoint Calico DROP increment")
	}
	for _, name := range []string{"receiver-before.txt", "receiver-after.txt"} {
		text, err := read(name)
		if err != nil {
			return err
		}
		if !strings.Contains(text, "200 OK") || !strings.Contains(text, "upstream reached:") {
			return fmt.Errorf("receiver control failed: %s", name)
		}
	}
	logs, err := read("receiver.log")
	if err != nil {
		return err
	}
	if strings.Contains(logs, "request_id="+result.ID+"\n") {
		return fmt.Errorf("forbidden request reached origin")
	}
	for _, suffix := range []string{"before", "after"} {
		if !strings.Contains(logs, "request_id="+result.ID+"-"+suffix) {
			return fmt.Errorf("receiver missing healthy %s control", suffix)
		}
	}
	return nil
}
func dropCount(text, iface string) (uint64, error) {
	var total uint64
	found := false
	for line := range strings.SplitSeq(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[1] != "-A" || fields[2] != "cali-fw-"+iface || fields[len(fields)-2] != "-j" || fields[len(fields)-1] != "DROP" {
			continue
		}
		packets, _, ok := strings.Cut(strings.Trim(fields[0], "[]"), ":")
		if !ok {
			return 0, fmt.Errorf("invalid counter")
		}
		n, err := strconv.ParseUint(packets, 10, 64)
		if err != nil {
			return 0, err
		}
		total += n
		found = true
	}
	if !found {
		return 0, fmt.Errorf("missing source-endpoint Calico DROP rule")
	}
	return total, nil
}
