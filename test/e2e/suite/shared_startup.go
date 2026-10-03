package suite

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/artifacts"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	core "k8s.io/api/core/v1"
)

func (s *scenario) sharedConfig(role string) (core.ConfigMap, config.PolicyRuntime, workload.Policy, error) {
	var cm core.ConfigMap
	var cfg config.PolicyRuntime
	raw, err := s.command("get", "configmap", role+"-shared", "-n", "gateway-test", "-o", "json")
	if err != nil {
		return cm, cfg, workload.Policy{}, err
	}
	if err = json.Unmarshal(raw, &cm); err != nil {
		return cm, cfg, workload.Policy{}, err
	}
	cm.ResourceVersion = ""
	cm.UID = ""
	cm.ManagedFields = nil
	if err = json.Unmarshal([]byte(cm.Data["runtime.json"]), &cfg); err != nil {
		return cm, cfg, workload.Policy{}, err
	}
	dir, err := os.MkdirTemp(s.env.Config.StateDir, "shared-input-")
	if err != nil {
		return cm, cfg, workload.Policy{}, err
	}
	defer os.RemoveAll(dir)
	local := cfg
	local.Descriptors = append([]config.DescriptorFile(nil), cfg.Descriptors...)
	local.Bundle = filepath.Join(dir, filepath.Base(cfg.Bundle))
	for i := range local.Descriptors {
		local.Descriptors[i].Path = filepath.Join(dir, filepath.Base(local.Descriptors[i].Path))
	}
	for name, b := range cm.BinaryData {
		if err = os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			return cm, cfg, workload.Policy{}, err
		}
	}
	b, err := json.Marshal(local)
	if err != nil {
		return cm, cfg, workload.Policy{}, err
	}
	name := filepath.Join(dir, "runtime.json")
	if err = os.WriteFile(name, b, 0600); err != nil {
		return cm, cfg, workload.Policy{}, err
	}
	loaded, err := artifacts.LoadWorkload(name, config.Role(role))
	if err != nil {
		return cm, cfg, workload.Policy{}, err
	}
	return cm, cfg, loaded.Policy, nil
}
func (s *scenario) applyObject(name string, object any) error {
	raw, err := json.Marshal(object)
	if err != nil {
		return err
	}
	path := filepath.Join(s.env.Config.StateDir, name+".json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		return err
	}
	out, err := s.command("apply", "-f", path)
	if err != nil {
		return fmt.Errorf("apply %s: %w: %s", name, err, out)
	}
	return nil
}
func (s *scenario) sharedStartup(name string) (err error) {
	cm, cfg, p, err := s.sharedConfig("workload")
	if err != nil {
		return err
	}
	want := ""
	switch name {
	case "missing-bundle":
		delete(cm.BinaryData, "workload.tar.gz")
		want = "read workload bundle"
	case "invalid-bundle":
		cm.BinaryData["workload.tar.gz"] = []byte("not a bundle")
		want = "read workload bundle"
	case "missing-descriptor":
		delete(cm.BinaryData, "service.pb")
		want = "descriptor"
	case "wrong-digest":
		cm.BinaryData["service.pb"] = append(cm.BinaryData["service.pb"], 0)
		want = "digest mismatch"
	case "wrong-method", "missing-import":
		var set descriptorpb.FileDescriptorSet
		if err = proto.Unmarshal(cm.BinaryData["service.pb"], &set); err != nil {
			return err
		}
		if name == "wrong-method" {
			set.File[0].Service[0].Method[0].Name = new("Other")
			want = "method"
		} else {
			set.File[0].Dependency = append(set.File[0].Dependency, "unavailable.proto")
			want = "invalid descriptor definitions or imports"
		}
		raw, e := proto.Marshal(&set)
		if e != nil {
			return e
		}
		cm.BinaryData["service.pb"] = raw
		old := cfg.Descriptors[0].Digest
		digest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
		cfg.Descriptors[0].Digest = digest
		for i := range p.RequestConstraints {
			d := p.RequestConstraints[i].Decode
			if d != nil && d.DescriptorSet != nil && d.DescriptorSet.Digest == old {
				d.DescriptorSet.Digest = digest
			}
		}
		cm.BinaryData["workload.tar.gz"], err = policybundle.Build(p)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown startup case %q", name)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	cm.Data["runtime.json"] = string(raw)
	cm.Name = "startup-" + s.id
	raw, err = os.ReadFile(filepath.Join(s.env.Config.StateDir, "workload-template.json"))
	if err != nil {
		return err
	}
	var pod core.Pod
	if err = json.Unmarshal(raw, &pod); err != nil {
		return err
	}
	pod.Name = cm.Name
	for i := range pod.Spec.Volumes {
		v := &pod.Spec.Volumes[i]
		if v.Name == "gateway-shared" {
			v.ConfigMap.Name = cm.Name
		}
	}
	defer func() {
		_, e := s.command("delete", "pod,configmap", cm.Name, "-n", "gateway-test", "--ignore-not-found", "--wait=true", "--timeout=60s")
		err = errors.Join(err, e)
	}()
	if err = s.applyObject(cm.Name+"-config", cm); err != nil {
		return err
	}
	if err = s.applyObject(cm.Name+"-pod", pod); err != nil {
		return err
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		raw, err = s.command("get", "pod", pod.Name, "-n", "gateway-test", "-o", "json")
		if err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &pod); err != nil {
			return err
		}
		for _, status := range pod.Status.ContainerStatuses {
			if status.State.Running != nil {
				return errors.New("business container started with invalid shared input")
			}
		}
		failed := false
		for _, status := range pod.Status.InitContainerStatuses {
			if status.Name == "istio-proxy" {
				t := status.State.Terminated
				if t == nil {
					t = status.LastTerminationState.Terminated
				}
				failed = t != nil && t.ExitCode != 0
			}
		}
		if failed {
			log, e := s.command("logs", pod.Name, "-n", "gateway-test", "-c", "istio-proxy")
			if e != nil {
				return e
			}
			if e = s.evidence(name+"-startup.log", log); e != nil {
				return e
			}
			if !strings.Contains(string(log), want) {
				return fmt.Errorf("startup failed for wrong reason, expected %q: %s", want, log)
			}
			if e = s.evidence(name+"-pod.json", raw); e != nil {
				return e
			}
			break
		}
		if time.Now().After(deadline) {
			return errors.New("invalid shared artifact did not terminate startup")
		}
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return s.governedRequest("workload", s.id+"-healthy", contentCases()["safe"])
}
func (s *scenario) emptyShared() (err error) {
	originals := make([]core.ConfigMap, 0, 2)
	for _, role := range []string{"workload", "egress"} {
		cm, _, _, e := s.sharedConfig(role)
		if e != nil {
			return e
		}
		originals = append(originals, cm)
	}
	defer func() {
		cleanup := *s
		var cancel context.CancelFunc
		cleanup.ctx, cancel = context.WithTimeout(context.WithoutCancel(s.ctx), 3*time.Minute)
		defer cancel()
		for _, cm := range originals {
			err = errors.Join(err, cleanup.applyObject(cm.Name+"-restore", cm))
		}
		err = errors.Join(err, cleanup.restartShared())
	}()
	for _, cm := range originals {
		cm = *cm.DeepCopy()
		cm.BinaryData["workload.tar.gz"], err = policybundle.Build(workload.Policy{})
		if err != nil {
			return err
		}
		if err = s.applyObject(cm.Name+"-empty", cm); err != nil {
			return err
		}
	}
	if err = s.restartShared(); err != nil {
		return err
	}
	// This body is rejected by the normal constraints at both roles.
	if err = s.governedRequest("workload", s.id+"-empty", contentCase{scheme: "https", body: `{"action":"workload-deny"}`, role: "origin", status: 200}); err != nil {
		return err
	}
	// Independent peer admission remains enabled even with empty shared rules.
	if err = s.unadmittedSharedPeer(); err != nil {
		return err
	}
	return s.directEntrypoints()
}
func (s *scenario) restartShared() error {
	if out, err := s.command("rollout", "restart", "deployment/egress", "-n", "gateway-test"); err != nil {
		return fmt.Errorf("restart shared egress: %w: %s", err, out)
	}
	return s.mutationMode(false)
}

func (s *scenario) unadmittedSharedPeer() (err error) {
	raw, err := os.ReadFile(filepath.Join(s.env.Config.StateDir, "workload-template.json"))
	if err != nil {
		return err
	}
	var pod core.Pod
	if err = json.Unmarshal(raw, &pod); err != nil {
		return err
	}
	pod.Name = "unadmitted-" + s.id
	pod.Spec.ServiceAccountName = "egress"
	defer func() {
		_, e := s.command("delete", "pod", pod.Name, "-n", "gateway-test", "--ignore-not-found", "--wait=true", "--timeout=60s")
		err = errors.Join(err, e)
	}()
	if err = s.applyObject(pod.Name, pod); err != nil {
		return err
	}
	if out, e := s.command("wait", "pod/"+pod.Name, "-n", "gateway-test", "--for=condition=Ready", "--timeout=120s"); e != nil {
		return fmt.Errorf("unadmitted peer preparation: %w: %s", e, out)
	}
	// The normal empty-policy workload succeeds; changing only the live service
	// account presents a valid mesh certificate outside the configured peer set.
	c := contentCase{scheme: "https", body: `{"action":"safe"}`, role: "egress", status: 403, peer: "spiffe://cluster.local/ns/gateway-test/sa/egress"}
	if err = s.governedRequest(pod.Name, s.id+"-peer", c); err != nil {
		return err
	}
	return s.sharedDecision(s.id+"-peer", "egress", 403)
}
