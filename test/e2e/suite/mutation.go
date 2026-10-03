package suite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/egress-gateway/egress-gateway/config"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func (s *scenario) mutation() (err error) {
	defer func() {
		cleanup := *s
		var cancel context.CancelFunc
		cleanup.ctx, cancel = context.WithTimeout(context.WithoutCancel(s.ctx), 3*time.Minute)
		defer cancel()
		err = errors.Join(err, cleanup.mutationMode(false))
	}()
	if err = s.mutationMode(true); err != nil {
		return err
	}
	for _, role := range []string{"workload", "egress"} {
		id := s.id + "-" + role
		if err = s.governedRequest("workload", id, contentCases()[role+"-mutate"]); err != nil {
			return err
		}
		pod := "workload"
		if role == "egress" {
			pod = "deployment/egress"
		}
		log, err := s.proxyLog(pod)
		if err != nil {
			return err
		}
		entry, ok := proxyEntry(log, id)
		path, _ := entry["path"].(string)
		if !ok || entry["details"] != "lua_response" || !strings.Contains(path, "changed=true") {
			return fmt.Errorf("%s lacks a rejected authorization-response target mutation: %v", role, entry)
		}
	}
	return nil
}

func (s *scenario) mutationMode(enabled bool) error {
	raw, err := os.ReadFile(filepath.Join(s.env.Config.StateDir, "workload-template.json"))
	if err != nil {
		return err
	}
	var pod core.Pod
	if err = json.Unmarshal(raw, &pod); err != nil {
		return err
	}
	raw, err = os.ReadFile(filepath.Join(s.env.Config.Artifacts, "rendered-fixtures.yaml"))
	if err != nil {
		return err
	}
	var list struct{ Items []json.RawMessage }
	if err = yaml.Unmarshal(raw, &list); err != nil {
		return err
	}
	var deployment apps.Deployment
	for _, item := range list.Items {
		var candidate apps.Deployment
		if err = json.Unmarshal(item, &candidate); err != nil {
			return err
		}
		if candidate.Kind == "Deployment" && candidate.Name == "egress" {
			deployment = candidate
			break
		}
	}
	if deployment.Name == "" {
		return errors.New("missing saved egress template")
	}
	if enabled {
		for _, containers := range [][]core.Container{pod.Spec.InitContainers, deployment.Spec.Template.Spec.Containers} {
			for i := range containers {
				c := &containers[i]
				if c.Name != "istio-proxy" {
					continue
				}
				c.Args = []string{"--policy", "/etc/gateway/policy/policy.rego"}
				c.Env = slices.DeleteFunc(c.Env, func(e core.EnvVar) bool { return e.Name == config.EnvOPAConfig })
				c.Env = append(c.Env, core.EnvVar{Name: config.EnvOPAConfig, Value: "/etc/gateway/policy/opa.yaml"})
			}
		}
	}
	for name, object := range map[string]any{"mutation-workload.json": pod, "mutation-egress.json": deployment} {
		raw, err = json.Marshal(object)
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(s.env.Config.StateDir, name), raw, 0600); err != nil {
			return err
		}
	}
	for _, args := range [][]string{
		{"apply", "-f", filepath.Join(s.env.Config.StateDir, "mutation-egress.json")},
		{"delete", "pod", "workload", "-n", "gateway-test", "--ignore-not-found", "--wait=true", "--timeout=60s"},
		{"create", "-f", filepath.Join(s.env.Config.StateDir, "mutation-workload.json")},
		{"rollout", "status", "deployment/egress", "-n", "gateway-test", "--timeout=120s"},
		{"wait", "pod/workload", "-n", "gateway-test", "--for=condition=Ready", "--timeout=120s"},
	} {
		if output, err := s.command(args...); err != nil {
			return fmt.Errorf("mutation mode %v: %w: %s", enabled, err, output)
		}
	}
	return nil
}
