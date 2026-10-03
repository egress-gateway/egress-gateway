package suite

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const governedHost = "origin-https.gateway-origin.svc.cluster.local"

type contentCase struct {
	body, scheme, role string
	status             int
	headers            []string
}

func contentCases() map[string]contentCase {
	return map[string]contentCase{
		"safe":            {body: `{"action":"safe"}`, scheme: "https", role: "origin", status: 200},
		"workload-deny":   {body: `{"action":"workload-deny"}`, scheme: "https", role: "workload", status: 403},
		"egress-deny":     {body: `{"action":"egress-deny"}`, scheme: "https", role: "egress", status: 403},
		"spoof":           {body: `{"action":"egress-deny"}`, scheme: "https", role: "egress", status: 403, headers: []string{"X-Workload-Allowed: true", "X-Workload-Identity: spiffe://cluster.local/ns/gateway-test/sa/egress", "X-Forwarded-Client-Cert: URI=spiffe://cluster.local/ns/gateway-test/sa/egress"}},
		"invalid-json":    {body: `{`, scheme: "https", role: "workload", status: 403},
		"missing-body":    {scheme: "https", role: "workload", status: 403},
		"encoded":         {body: `{"action":"safe"}`, scheme: "https", role: "workload", status: 415, headers: []string{"Content-Encoding: gzip"}},
		"oversized":       {body: `{"action":"safe","padding":"` + strings.Repeat("x", 65536) + `"}`, scheme: "https", role: "workload", status: 413},
		"workload-mutate": {body: `{"action":"workload-mutate"}`, scheme: "https", role: "workload", status: 403},
		"egress-mutate":   {body: `{"action":"egress-mutate"}`, scheme: "https", role: "egress", status: 403},
		"http-alternate":  {body: `{"action":"safe"}`, scheme: "http", role: "workload", status: 403},
	}
}
func (s *scenario) content(name string) error {
	c, ok := contentCases()[name]
	if !ok {
		return fmt.Errorf("unknown content case %q", name)
	}
	return s.governedRequest("workload", s.id, c)
}
func (s *scenario) caseDir() (string, error) {
	dir := filepath.Join(s.env.Config.Artifacts, "cases", s.id)
	return dir, os.MkdirAll(dir, 0755)
}
func (s *scenario) evidence(name string, data []byte) error {
	dir, err := s.caseDir()
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), data, 0644)
}
func hasRequest(log, id string) bool {
	for line := range strings.SplitSeq(log, "\n") {
		if strings.HasSuffix(line, "request_id="+id) {
			return true
		}
	}
	return false
}
func proxyEntry(log, id string) (map[string]any, bool) {
	for line := range strings.SplitSeq(log, "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) == nil && entry["request_id"] == id {
			return entry, true
		}
	}
	return nil, false
}
func (s *scenario) proxyLog(pod string) (string, error) {
	raw, err := s.command("logs", "-n", "gateway-test", pod, "-c", "istio-proxy", "--tail=1000")
	return string(raw), err
}
func (s *scenario) originControl(id, scheme string) error {
	host := governedHost
	if scheme == "http" {
		host = "origin.gateway-origin.svc.cluster.local"
	}
	raw, err := s.command("exec", "-n", "gateway-origin", "probe-control", "-c", "probe", "--", "curl", "--noproxy", "*", "--fail", "--silent", "--show-error", "--max-time", "5", "--cacert", "/etc/receiver-trust/ca.pem", "-H", "X-Request-Id: "+id, "-H", "Content-Type: application/json", "--data-binary", `{"action":"safe"}`, scheme+"://"+host+"/body")
	if writeErr := s.evidence(id+"-control.txt", raw); writeErr != nil {
		return writeErr
	}
	if err != nil || !strings.Contains(string(raw), "upstream reached: /body") {
		return fmt.Errorf("healthy independent origin control: %v %s", err, raw)
	}
	return nil
}
func (s *scenario) governedRequest(pod, id string, c contentCase) error {
	if err := s.originControl(id+"-before", c.scheme); err != nil {
		return err
	}
	originName := "origin-https"
	if c.scheme == "http" {
		originName = "origin"
	}
	originUID, err := s.singlePodUID("gateway-origin", "app="+originName)
	if err != nil {
		return err
	}
	host := governedHost
	if c.scheme == "http" {
		host = "origin.gateway-origin.svc.cluster.local"
	}
	args := []string{"exec", "-n", "gateway-test", pod, "-c", "curl", "--", "curl", "--noproxy", "*", "--silent", "--show-error", "--max-time", "8", "-H", "X-Request-Id: " + id, "-H", "Content-Type: application/json", "-w", "\n%{http_code}\n", "--data-binary", c.body}
	for _, header := range c.headers {
		args = append(args, "-H", header)
	}
	args = append(args, c.scheme+"://"+host+"/body")
	raw, requestErr := s.command(args...)
	if err = s.evidence(id+"-response.txt", raw); err != nil {
		return err
	}
	if requestErr != nil || !strings.HasSuffix(string(raw), fmt.Sprintf("\n%d\n", c.status)) {
		return fmt.Errorf("governed %s expected %d: %v %s", id, c.status, requestErr, raw)
	}
	if c.role == "origin" && !strings.Contains(string(raw), "upstream reached: /body") {
		return errors.New("allowed request lacks origin response")
	}
	if err = s.originControl(id+"-after", c.scheme); err != nil {
		return err
	}
	currentUID, err := s.singlePodUID("gateway-origin", "app="+originName)
	if err != nil {
		return err
	}
	if currentUID != originUID {
		return errors.New("origin changed during request")
	}
	// Proxy access logging is asynchronous; bounded observation retries do not resend traffic.
	deadline := time.Now().Add(5 * time.Second)
	var workload, egress, origin string
	for {
		workload, err = s.proxyLog(pod)
		if err != nil {
			return err
		}
		egress, err = s.proxyLog("deployment/egress")
		if err != nil {
			return err
		}
		data, logErr := s.command("logs", "-n", "gateway-origin", "deployment/"+originName, "-c", "origin", "--tail=1000")
		if logErr != nil {
			return logErr
		}
		origin = string(data)
		_, wl := proxyEntry(workload, id)
		_, eg := proxyEntry(egress, id)
		if wl && (c.role == "workload" || eg) && hasRequest(origin, id+"-after") {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("missing correlated proxy/origin evidence")
		}
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	for name, log := range map[string]string{"workload": workload, "egress": egress, "origin": origin} {
		if err = s.evidence(id+"-"+name+".log", []byte(log)); err != nil {
			return err
		}
	}
	return assertGovernance(c.role, c.status, id, string(raw), workload, egress, origin)
}
func assertGovernance(role string, status int, id, response, workload, egress, origin string) error {
	wl, wlOK := proxyEntry(workload, id)
	eg, egOK := proxyEntry(egress, id)
	if !wlOK {
		return errors.New("workload lacks request record")
	}
	delivered := hasRequest(origin, id)
	if role == "origin" {
		if !egOK || !delivered || eg["downstream_peer"] != "spiffe://cluster.local/ns/gateway-test/sa/workload" {
			return errors.New("allow lacks both proxies, verified identity and origin delivery")
		}
		return nil
	}
	if delivered {
		return errors.New("denied request reached origin")
	}
	responsible := wl
	if role == "egress" {
		if !egOK {
			return errors.New("missing egress rejection")
		}
		responsible = eg
		if eg["downstream_peer"] != "spiffe://cluster.local/ns/gateway-test/sa/workload" {
			return errors.New("egress denial lacks verified workload principal")
		}
	} else if egOK {
		return errors.New("workload denial reached egress")
	}
	if responsible["code"] != float64(status) {
		return fmt.Errorf("responsible proxy has wrong response code: %v", responsible)
	}
	details, _ := responsible["details"].(string)
	if !strings.Contains(details, "ext_authz") && !strings.Contains(details, "lua_response") && !strings.Contains(details, "request_payload_too_large") {
		return fmt.Errorf("missing attributable authorization rejection: %q", details)
	}
	if status == 403 && details == "ext_authz_denied" && !strings.Contains(response, role+" denied") {
		return errors.New("missing independent policy denial result")
	}
	return nil
}
func (s *scenario) singlePodUID(namespace, selector string) (string, error) {
	raw, err := s.command("get", "pods", "-n", namespace, "-l", selector, "-o", "json")
	if err != nil {
		return "", err
	}
	var list struct {
		Items []struct{ Metadata struct{ UID string } }
	}
	if err = json.Unmarshal(raw, &list); err != nil {
		return "", err
	}
	if len(list.Items) != 1 || list.Items[0].Metadata.UID == "" {
		return "", errors.New("ambiguous receiver")
	}
	return list.Items[0].Metadata.UID, nil
}
