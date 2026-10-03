package suite

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/egress-gateway/egress-gateway/test/e2e/environment"
	core "k8s.io/api/core/v1"
)

func (s *scenario) fault(kind string) error {
	if kind != "opa-workload" && kind != "opa-egress" && kind != "gateway" && kind != "startup" {
		return errors.New("unknown component fault")
	}
	if err := s.governedRequest("workload", s.id+"-warm", contentCases()["safe"]); err != nil {
		return err
	}
	originUID, err := s.singlePodUID("gateway-origin", "app=origin-https")
	if err != nil {
		return err
	}
	cfg := s.env.Config
	cfg.Artifacts = filepath.Join(cfg.Artifacts, "cases", s.id)
	if err = environment.New(cfg).Operation(s.ctx, "fault-"+kind); err != nil {
		return err
	}
	currentUID, err := s.singlePodUID("gateway-origin", "app=origin-https")
	if err != nil {
		return err
	}
	if currentUID != originUID {
		return errors.New("healthy origin changed during fault")
	}
	if err = assertFault(filepath.Join(cfg.Artifacts, "fault"), s.id, kind); err != nil {
		return err
	}
	if err = s.governedRequest("workload", s.id+"-recovered", contentCases()["safe"]); err != nil {
		return err
	}
	return s.governedRequest("workload", s.id+"-still-denied", contentCases()["egress-deny"])
}
func assertFault(dir, id, kind string) error {
	read := func(name string) (string, error) { return readText(filepath.Join(dir, name)) }
	requestID := id + "-fault"
	if kind == "startup" {
		requestID = id + "-startup"
	}
	for _, point := range []string{"before", "after"} {
		control, err := read("receiver-" + point + ".txt")
		if err != nil {
			return err
		}
		if !strings.Contains(control, "upstream reached: /body") {
			return errors.New("fault lacks healthy independent receiver")
		}
	}
	origin, err := read("origin.log")
	if err != nil {
		return err
	}
	if hasRequest(origin, requestID) || !hasRequest(origin, requestID+"-before") || !hasRequest(origin, requestID+"-after") {
		return errors.New("fault origin controls/non-delivery invalid")
	}
	workload, err := read("workload.log")
	if err != nil {
		return err
	}
	if kind == "startup" {
		return assertStartup(dir, requestID, workload, origin)
	}
	response, err := read("response.txt")
	if err != nil {
		return err
	}
	exit, err := read("request-exit.txt")
	if err != nil {
		return err
	}
	if strings.TrimSpace(exit) != "0" {
		return fmt.Errorf("fault request failed outside HTTP governance: exit=%s response=%s", exit, response)
	}
	if kind == "gateway" {
		var absent, recovered core.PodList
		var before struct{ UID string }
		if err = readJSON(filepath.Join(dir, "gateway-before.json"), &before); err != nil {
			return err
		}
		if err = readJSON(filepath.Join(dir, "gateway-unavailable.json"), &absent); err != nil {
			return err
		}
		if err = readJSON(filepath.Join(dir, "gateway-recovered.json"), &recovered); err != nil {
			return err
		}
		if before.UID == "" || len(absent.Items) != 0 || len(recovered.Items) != 1 || string(recovered.Items[0].UID) == before.UID || !podReady(recovered.Items[0]) {
			return errors.New("gateway absence/recreation not observed")
		}
		entry, ok := proxyEntry(workload, requestID)
		if !ok || entry["code"] != float64(503) || !strings.HasSuffix(response, "\n503\n") {
			return errors.New("gateway outage lacks correlated 503")
		}
		details, _ := entry["details"].(string)
		if !strings.Contains(details, "no_healthy_upstream") && !strings.Contains(details, "upstream_reset") && !strings.Contains(details, "connection_failure") {
			return fmt.Errorf("gateway failure lacks upstream rejection: %s", details)
		}
		return nil
	}
	role := strings.TrimPrefix(kind, "opa-")
	unavailable, err := read("process-unavailable.txt")
	if err != nil {
		return err
	}
	parts := strings.Split(unavailable, "Name:\t")
	daemonStopped, envoyRunning := false, false
	for _, part := range parts {
		if strings.HasPrefix(part, "gateway-daemon\n") {
			daemonStopped = strings.Contains(part, "State:\tT")
		}
		if strings.HasPrefix(part, "envoy\n") {
			envoyRunning = !strings.Contains(part, "State:\tT") && !strings.Contains(part, "State:\tZ")
		}
	}
	if !daemonStopped || !envoyRunning {
		return errors.New("OPA process was not stopped independently of Envoy")
	}
	recoveredProcess, err := read("process-recovered.txt")
	if err != nil {
		return err
	}
	if strings.Contains(recoveredProcess, "State:\tT") {
		return errors.New("OPA process was not resumed")
	}
	var before, recovered core.PodList
	if err = readJSON(filepath.Join(dir, "pod-before.json"), &before); err != nil {
		return err
	}
	if err = readJSON(filepath.Join(dir, "pod-recovered.json"), &recovered); err != nil {
		return err
	}
	if len(before.Items) != 1 || len(recovered.Items) != 1 || before.Items[0].UID != recovered.Items[0].UID {
		return errors.New("OPA fault changed the selected Pod")
	}
	egress, err := read("egress.log")
	if err != nil {
		return err
	}
	if !strings.HasSuffix(response, "\n403\n") {
		return fmt.Errorf("OPA outage did not fail closed: %s", response)
	}
	if err = assertGovernance(role, 403, requestID, response, workload, egress, origin); err != nil {
		return err
	}
	responsible := workload
	if role == "egress" {
		responsible = egress
	}
	entry, _ := proxyEntry(responsible, requestID)
	if entry["details"] != "ext_authz_error" {
		return fmt.Errorf("OPA outage lacks an authorization service error: %v", entry)
	}
	return nil
}
func podReady(p core.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == core.PodReady {
			return c.Status == core.ConditionTrue
		}
	}
	return false
}
func assertStartup(dir, id, workload, origin string) error {
	var before, recovered core.Pod
	if err := readJSON(filepath.Join(dir, "startup-unavailable.json"), &before); err != nil {
		return err
	}
	if err := readJSON(filepath.Join(dir, "startup-recovered.json"), &recovered); err != nil {
		return err
	}
	if before.UID == "" || before.UID == recovered.UID || podReady(before) || !podReady(recovered) {
		return errors.New("startup prevention and recreated recovery not observed")
	}
	failed := false
	for _, c := range before.Status.InitContainerStatuses {
		if c.Name == "istio-proxy" {
			failed = (c.State.Terminated != nil && c.State.Terminated.ExitCode != 0) || (c.LastTerminationState.Terminated != nil && c.LastTerminationState.Terminated.ExitCode != 0)
		}
		if c.Name == "business-network-state" && (c.State.Running != nil || c.State.Terminated != nil) {
			return errors.New("business init executed before governance startup")
		}
	}
	for _, c := range before.Status.ContainerStatuses {
		if c.State.Running != nil || c.State.Terminated != nil {
			return errors.New("business container executed before governance startup")
		}
	}
	if !failed {
		return errors.New("required startup service failure missing")
	}
	logs, err := readText(filepath.Join(dir, "startup-error.log"))
	if err != nil {
		return err
	}
	if !strings.Contains(logs, "read workload configuration") || !strings.Contains(logs, "/etc/gateway/shared/not-present.json") {
		return errors.New("startup prevention is not attributable to required policy initialization")
	}
	egress, err := readText(filepath.Join(dir, "egress.log"))
	if err != nil {
		return err
	}
	for _, tc := range []struct {
		file, suffix, role string
		status             int
	}{{"recovery-safe.txt", "safe", "origin", 200}, {"recovery-denied.txt", "denied", "egress", 403}} {
		response, err := readText(filepath.Join(dir, tc.file))
		if err != nil {
			return err
		}
		if !strings.HasSuffix(response, fmt.Sprintf("\n%d\n", tc.status)) {
			return fmt.Errorf("startup recovery response %s: %s", tc.suffix, response)
		}
		if err = assertGovernance(tc.role, tc.status, id+"-"+tc.suffix, response, workload, egress, origin); err != nil {
			return err
		}
	}
	return nil
}
