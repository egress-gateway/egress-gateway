package suite

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/extension"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	opabundle "github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/plugins"
	core "k8s.io/api/core/v1"
)

type publication struct {
	Role        string    `json:"role"`
	Revision    string    `json:"revision"`
	PublishedAt time.Time `json:"publishedAt"`
	Digest      string    `json:"digest"`
	Status      int       `json:"status"`
}

type policyObservation struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"startedAt"`
	ObservedAt time.Time `json:"observedAt"`
	Status     int       `json:"status"`
	Body       string    `json:"body"`
}

type policyObservations struct {
	Interval time.Duration       `json:"intervalNs"`
	Attempts []policyObservation `json:"attempts"`
}

type updateMeasurement struct {
	Publication        publication        `json:"publication"`
	Role               string             `json:"role"`
	Direction          string             `json:"direction"`
	NativeActivation   time.Time          `json:"nativeActivation"`
	Observed           policyObservations `json:"observed"`
	Duration           time.Duration      `json:"publicationToObservedEnforcementNs"`
	ActivationDuration time.Duration      `json:"publicationToNativeActivationNs"`
	ObservationWindow  time.Duration      `json:"observationWindowNs"`
	Polling            string             `json:"polling"`
	Clock              string             `json:"clock"`
}

func (s *scenario) publishBundle(role, revision string, body []byte, status int) (publication, error) {
	endpoint := "http://127.0.0.1:8086/bundles/" + role + "?revision=" + url.QueryEscape(revision)
	if status != 200 {
		endpoint += fmt.Sprintf("&status=%d", status)
	}
	raw, err := s.env.KubectlInput(s.ctx, body, "exec", "-i", "-n", "gateway-test", "deployment/policy-publisher", "-c", "publisher", "--", "curl", "--noproxy", "*", "--fail-with-body", "--silent", "--show-error", "--max-time", "5", "-X", "PUT", "--data-binary", "@-", endpoint)
	var result publication
	if err != nil {
		return result, fmt.Errorf("publish bundle: %w: %s", err, raw)
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		return result, err
	}
	if result.Revision != revision || result.Role != role || result.PublishedAt.IsZero() || result.Status != status {
		return result, fmt.Errorf("invalid publication receipt: %s", raw)
	}
	err = s.evidence(revision+"-publication.json", raw)
	return result, err
}

func (s *scenario) publishPolicy(role, revision string, p workload.Policy) (publication, error) {
	raw, err := policybundle.BuildExecution(p, revision)
	if err != nil {
		return publication{}, err
	}
	return s.publishBundle(role, revision, raw, 200)
}

// OPA's in-process Status includes error and metrics interfaces which cannot be
// unmarshaled from JSON. Consume only the native wire fields needed as evidence.
type nativeBundleStatus struct {
	ActiveRevision           string          `json:"active_revision"`
	LastRequest              time.Time       `json:"last_request"`
	LastSuccessfulActivation time.Time       `json:"last_successful_activation"`
	Code                     string          `json:"code,omitempty"`
	Message                  string          `json:"message,omitempty"`
	Errors                   json.RawMessage `json:"errors,omitempty"`
}
type nativeStatus struct {
	Type    string                         `json:"type"`
	Bundles map[string]*nativeBundleStatus `json:"bundles"`
	Plugins map[string]*plugins.Status     `json:"plugins"`
}

func latestNativeStatus(raw string) (nativeStatus, bool) {
	var latest nativeStatus
	found := false
	for line := range strings.SplitSeq(raw, "\n") {
		var entry nativeStatus
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Type == "openpolicyagent.org/status" && entry.Bundles["workload"] != nil {
			latest, found = entry, true
		}
	}
	return latest, found
}

func (s *scenario) waitNative(role, revision string, after time.Time, wantFailure bool) (nativeBundleStatus, error) {
	pod := "workload"
	if role == "egress" {
		pod = "deployment/egress"
	}
	deadline := time.Now().Add(30 * time.Second)
	var last nativeStatus
	for {
		raw, err := s.proxyLog(pod)
		if err != nil {
			return nativeBundleStatus{}, err
		}
		if entry, ok := latestNativeStatus(raw); ok {
			last = entry
			state := entry.Bundles["workload"]
			inspected := entry.Plugins[extension.PluginName]
			if state.ActiveRevision == revision && !state.LastRequest.Before(after) && (state.Code != "") == wantFailure && inspected != nil && inspected.State == plugins.StateOK {
				encoded, err := json.MarshalIndent(entry, "", "  ")
				if err != nil {
					return *state, err
				}
				suffix := "-active.json"
				if wantFailure {
					suffix = "-failure.json"
				}
				return *state, s.evidence(role+"-"+revision+suffix, encoded)
			}
		}
		if time.Now().After(deadline) {
			return nativeBundleStatus{}, fmt.Errorf("native %s revision=%s failure=%v not observed: %+v", role, revision, wantFailure, last.Bundles["workload"])
		}
		select {
		case <-s.ctx.Done():
			return nativeBundleStatus{}, s.ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (s *scenario) policyProbe(id string, want int) (policyObservations, error) {
	raw, err := s.command("exec", "-n", "gateway-test", "workload", "-c", "curl", "--", "/usr/local/bin/gateway-e2e-probe", "-mode", "observe-policy", "-target", "https://"+governedHost+"/body", "-id", id, "-ca", "/cacert.pem", "-payload", `{"action":"safe"}`, "-expected-status", fmt.Sprint(want), "-interval", "200ms", "-timeout", "20s")
	var result policyObservations
	if writeErr := s.evidence(id+"-probes.json", raw); writeErr != nil {
		return result, writeErr
	}
	if err != nil {
		return result, fmt.Errorf("policy probe: %w: %s", err, raw)
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		return result, err
	}
	if len(result.Attempts) == 0 || result.Attempts[len(result.Attempts)-1].Status != want {
		return result, errors.New("missing expected policy observation")
	}
	return result, nil
}

func (s *scenario) verifyPolicyObservation(role string, result policyObservations) error {
	last := result.Attempts[len(result.Attempts)-1]
	responsible := role
	if last.Status == 200 {
		responsible = "origin"
		if !strings.Contains(last.Body, "upstream reached: /body") {
			return errors.New("new allow lacks protected operation response")
		}
	}
	if err := s.originControl(last.ID+"-after", "https"); err != nil {
		return err
	}
	if err := s.observeGovernance("workload", last.ID, responsible, last.Status, last.Body, "origin-https"); err != nil {
		return err
	}
	return s.sharedDecision(last.ID, responsible, last.Status)
}

type runtimeIdentity struct {
	UID        string            `json:"uid"`
	Containers map[string]string `json:"containers"`
	Restarts   map[string]int32  `json:"restarts"`
}

func (s *scenario) policyRuntimeIdentities() (map[string]runtimeIdentity, error) {
	result := map[string]runtimeIdentity{}
	for _, role := range []string{"workload", "egress"} {
		raw, err := s.command("get", "pods", "-n", "gateway-test", "-l", "app="+role, "-o", "json")
		if err != nil {
			return nil, err
		}
		var pods core.PodList
		if err = json.Unmarshal(raw, &pods); err != nil {
			return nil, err
		}
		if len(pods.Items) != 1 {
			return nil, fmt.Errorf("ambiguous %s runtime", role)
		}
		p := pods.Items[0]
		identity := runtimeIdentity{UID: string(p.UID), Containers: map[string]string{}, Restarts: map[string]int32{}}
		for _, status := range append(p.Status.InitContainerStatuses, p.Status.ContainerStatuses...) {
			identity.Containers[status.Name], identity.Restarts[status.Name] = status.ContainerID, status.RestartCount
		}
		if identity.UID == "" || identity.Containers["istio-proxy"] == "" {
			return nil, fmt.Errorf("missing %s runtime identity", role)
		}
		result[role] = identity
	}
	return result, nil
}

func (s *scenario) restorePublished(originals map[string][]byte) error {
	cleanup := *s
	var cancel context.CancelFunc
	cleanup.ctx, cancel = context.WithTimeout(context.WithoutCancel(s.ctx), 90*time.Second)
	defer cancel()
	for _, role := range []string{"workload", "egress"} {
		receipt, err := cleanup.publishBundle(role, "fixture-"+role, originals[role], 200)
		if err != nil {
			return err
		}
		if _, err = cleanup.waitNative(role, receipt.Revision, receipt.PublishedAt, false); err != nil {
			return err
		}
	}
	return nil
}

func denyUpdatePolicy() workload.Policy {
	return workload.Policy{RequestConstraints: []workload.Constraint{{Name: "updated-body", Match: workload.Match{Hosts: []workload.HostMatcher{{Type: workload.Exact, Value: governedHost}}, HTTP: &workload.HTTPMatch{Paths: []string{"/body"}}}, Decode: &workload.Decoder{Format: workload.JSON}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/action"), Operator: workload.In, Values: []string{"not-safe"}}}}}}
}

func (s *scenario) nativeUpdates(role string) (err error) {
	if role != "workload" && role != "egress" {
		return errors.New("invalid update role")
	}
	before, err := s.policyRuntimeIdentities()
	if err != nil {
		return err
	}
	originUID, err := s.singlePodUID("gateway-origin", "app=origin-https")
	if err != nil {
		return err
	}
	if err = s.originControl(s.id+"-before", "https"); err != nil {
		return err
	}
	originals := map[string][]byte{}
	for _, r := range []string{"workload", "egress"} {
		cm, _, _, e := s.sharedConfig(r)
		if e != nil {
			return e
		}
		originals[r] = cm.BinaryData["workload.tar.gz"]
	}
	defer func() { err = errors.Join(err, s.restorePublished(originals)) }()
	for _, r := range []string{"workload", "egress"} {
		receipt, e := s.publishPolicy(r, s.id+"-initial-"+r, workload.Policy{})
		if e != nil {
			return e
		}
		if _, e = s.waitNative(r, receipt.Revision, receipt.PublishedAt, false); e != nil {
			return e
		}
	}
	var measurements []updateMeasurement
	for cycle := range 3 {
		for _, want := range []int{403, 200} {
			opposite := 200
			if want == 200 {
				opposite = 403
			}
			if _, err = s.policyProbe(fmt.Sprintf("%s-before-%d-%d", s.id, cycle, want), opposite); err != nil {
				return err
			}
			policy := workload.Policy{}
			direction := "deny-to-allow"
			if want == 403 {
				policy = denyUpdatePolicy()
				direction = "allow-to-deny"
			}
			revision := fmt.Sprintf("%s-%s-%d-%d", s.id, role, cycle, want)
			receipt, e := s.publishPolicy(role, revision, policy)
			if e != nil {
				return e
			}
			observed, e := s.policyProbe(revision, want)
			if e != nil {
				return e
			}
			last := observed.Attempts[len(observed.Attempts)-1]
			if last.ObservedAt.Before(receipt.PublishedAt) {
				return errors.New("publisher and probe clocks are inconsistent")
			}
			native, e := s.waitNative(role, revision, receipt.PublishedAt, false)
			if e != nil {
				return e
			}
			if e = s.verifyPolicyObservation(role, observed); e != nil {
				return e
			}
			lower := receipt.PublishedAt
			if len(observed.Attempts) > 1 {
				lower = observed.Attempts[len(observed.Attempts)-2].StartedAt
			}
			measurement := updateMeasurement{Publication: receipt, Role: role, Direction: direction, NativeActivation: native.LastSuccessfulActivation, Observed: observed, Duration: last.ObservedAt.Sub(receipt.PublishedAt), ActivationDuration: native.LastSuccessfulActivation.Sub(receipt.PublishedAt), ObservationWindow: last.ObservedAt.Sub(lower), Polling: "OPA min_delay_seconds=1, max_delay_seconds=1", Clock: "publisher, OPA and application probe share the single kind node VM clock"}
			measurements = append(measurements, measurement)
		}
	}
	if err = s.nativeUpdateFailures(role); err != nil {
		return err
	}
	after, err := s.policyRuntimeIdentities()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) {
		return fmt.Errorf("policy update replaced a Pod or restarted a runtime: before=%+v after=%+v", before, after)
	}
	currentOrigin, err := s.singlePodUID("gateway-origin", "app=origin-https")
	if err != nil {
		return err
	}
	if currentOrigin != originUID {
		return errors.New("origin changed during native updates")
	}
	head, err := os.ReadFile(filepath.Join(s.env.Config.Artifacts, "code-head.txt"))
	if err != nil {
		return err
	}
	imageID, err := os.ReadFile(filepath.Join(s.env.Config.Artifacts, "gateway-image-id.txt"))
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(map[string]any{"candidate": strings.TrimSpace(string(head)), "image": s.env.Config.Image, "imageID": strings.TrimSpace(string(imageID)), "measurements": measurements, "before": before, "after": after}, "", "  ")
	if err != nil {
		return err
	}
	return s.evidence(role+"-update-duration.json", raw)
}

func (s *scenario) nativeUpdateFailures(role string) error {
	for _, failure := range []string{"download", "load", "compile"} {
		prefix := s.id + "-" + role + "-" + failure
		good, err := s.publishPolicy(role, prefix+"-good", workload.Policy{})
		if err != nil {
			return err
		}
		if _, err = s.waitNative(role, good.Revision, good.PublishedAt, false); err != nil {
			return err
		}
		body := []byte("not a bundle")
		status := 200
		if failure == "download" {
			status = 503
		}
		if failure == "compile" {
			raw, err := policybundle.BuildExecution(workload.Policy{}, prefix+"-invalid")
			if err != nil {
				return err
			}
			b, err := opabundle.NewReader(bytes.NewReader(raw)).Read()
			if err != nil {
				return err
			}
			b.Modules = append(b.Modules, opabundle.ModuleFile{URL: "invalid.rego", Path: "invalid.rego", Raw: []byte("package egress_gateway.workload.invalid\nvalue := unavailable_function()")})
			var output bytes.Buffer
			if err = opabundle.NewWriter(&output).Write(b); err != nil {
				return err
			}
			body = output.Bytes()
		}
		failed, err := s.publishBundle(role, prefix+"-invalid", body, status)
		if err != nil {
			return err
		}
		if _, err = s.waitNative(role, good.Revision, failed.PublishedAt, true); err != nil {
			return err
		}
		observed, err := s.policyProbe(prefix+"-last-good", 200)
		if err != nil {
			return err
		}
		if err = s.verifyPolicyObservation(role, observed); err != nil {
			return err
		}
		recovered, err := s.publishPolicy(role, prefix+"-recovered", denyUpdatePolicy())
		if err != nil {
			return err
		}
		if _, err = s.waitNative(role, recovered.Revision, recovered.PublishedAt, false); err != nil {
			return err
		}
		observed, err = s.policyProbe(prefix+"-recovered", 403)
		if err != nil {
			return err
		}
		if err = s.verifyPolicyObservation(role, observed); err != nil {
			return err
		}
	}
	return nil
}
