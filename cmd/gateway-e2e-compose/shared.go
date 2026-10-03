package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/extension"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/egress-gateway/egress-gateway/config"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const sharedDirectory = "/etc/gateway/shared"

// The static fixture consumer owns these inputs and the final managed mounts.
// Business Pods never select policy artifacts or configure the runtime input.
func sharedArtifacts(role config.Role) (core.ConfigMap, error) {
	cm := core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: string(role) + "-shared", Namespace: "gateway-test"}, Data: map[string]string{}, BinaryData: map[string][]byte{}}
	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{protodesc.ToFileDescriptorProto(grpc_health_v1.File_grpc_health_v1_health_proto)}}
	var refs []workload.ArtifactRef
	cfg := extension.Config{Role: string(role)}
	for _, view := range []string{"service", "alias"} {
		copy := proto.Clone(set).(*descriptorpb.FileDescriptorSet)
		if view == "alias" {
			for _, message := range copy.File[0].MessageType {
				if message.GetName() == "HealthCheckRequest" {
					message.Field[0].JsonName = new("alias")
				}
			}
		}
		raw, err := proto.Marshal(copy)
		if err != nil {
			return cm, err
		}
		name := view + ".pb"
		ref := workload.ArtifactRef{URL: "https://fixture.example/" + name, Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(raw))}
		refs = append(refs, ref)
		cfg.Descriptors = append(cfg.Descriptors, extension.DescriptorFile{URL: ref.URL, Digest: ref.Digest, Path: sharedDirectory + "/" + name})
		cm.BinaryData[name] = raw
	}
	if role == config.Egress {
		cfg.AllowedPeers = []string{"spiffe://cluster.local/ns/gateway-test/sa/workload"}
	}
	policy := sharedPolicy(role, refs)
	archive, err := policybundle.BuildExecution(policy, "fixture-"+string(role))
	if err != nil {
		return cm, err
	}
	cm.BinaryData["workload.tar.gz"] = archive
	raw, err := json.Marshal(map[string]any{
		"plugins": map[string]any{
			extension.PluginName:   cfg,
			"envoy_ext_authz_grpc": map[string]any{"path": extension.DecisionPath, "skip-request-body-parse": true},
		},
		"services": map[string]any{"fixture": map[string]any{"url": "http://policy-publisher.gateway-test.svc:8085"}},
		"bundles":  map[string]any{"workload": map[string]any{"service": "fixture", "resource": "bundles/" + string(role), "polling": map[string]any{"min_delay_seconds": 1, "max_delay_seconds": 1}}},
		"status":   map[string]any{"console": true},
	})
	if err != nil {
		return cm, err
	}
	cm.Data["opa.json"] = string(raw)
	raw, err = json.Marshal(policy)
	if err != nil {
		return cm, err
	}
	cm.Data["policy.json"] = string(raw)
	return cm, nil
}

func sharedPolicy(role config.Role, refs []workload.ArtifactRef) workload.Policy {
	hosts := []workload.HostMatcher{{Type: workload.DomainSuffix, Value: "gateway-origin.svc.cluster.local"}}
	values := []string{"safe", "egress-deny"}
	deny := workload.HostMatcher{Type: workload.Exact, Value: "blocked-workload.gateway-origin.svc.cluster.local"}
	if role == config.Egress {
		values = []string{"safe"}
		deny = workload.HostMatcher{Type: workload.DomainSuffix, Value: "blocked-egress.gateway-origin.svc.cluster.local"}
	}
	httpMatch := func(path string) workload.Match {
		return workload.Match{Hosts: hosts, HTTP: &workload.HTTPMatch{Methods: []string{"POST"}, Paths: []string{path}}}
	}
	rpc := workload.Match{Hosts: hosts, GRPC: &workload.GRPCMatch{Service: "grpc.health.v1.Health", Methods: []string{"Check"}}}
	var selectRequirements []workload.Requirement
	for _, source := range []workload.Source{workload.Header, workload.Query} {
		for _, requirement := range []workload.Requirement{
			{Source: source, Name: new("in"), Operator: workload.In, Values: []string{"good", ""}},
			{Source: source, Name: new("not"), Operator: workload.NotIn, Values: []string{"bad"}},
			{Source: source, Name: new("exists"), Operator: workload.Exists},
		} {
			if source == workload.Header {
				requirement.Name = new("x-" + *requirement.Name)
			}
			selectRequirements = append(selectRequirements, requirement)
		}
	}
	selectRequirements = append(selectRequirements,
		workload.Requirement{Source: workload.Payload, Pointer: new("/model"), Operator: workload.In, Values: []string{"good", ""}},
		workload.Requirement{Source: workload.Payload, Pointer: new("/blocked"), Operator: workload.NotIn, Values: []string{"bad"}},
		workload.Requirement{Source: workload.Payload, Pointer: new("/items/0/a~1b~0"), Operator: workload.Exists},
		workload.Requirement{Source: workload.Payload, Pointer: new("/"), Operator: workload.Exists})
	p := workload.Policy{HostDenylist: []workload.HostMatcher{deny}, RequestConstraints: []workload.Constraint{
		{Name: "http-body", Match: httpMatch("/body"), Decode: &workload.Decoder{Format: workload.JSON}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/action"), Operator: workload.In, Values: values}}},
		{Name: "http-selections", Match: httpMatch("/select"), Decode: &workload.Decoder{Format: workload.JSON}, Require: selectRequirements},
		{Name: "rpc-metadata", Match: rpc, Require: []workload.Requirement{
			{Source: workload.GRPCMetadata, Name: new("x-role"), Operator: workload.In, Values: []string{"reader", ""}},
			{Source: workload.GRPCMetadata, Name: new("x-not"), Operator: workload.NotIn, Values: []string{"bad"}},
			{Source: workload.GRPCMetadata, Name: new("x-exists"), Operator: workload.Exists}}},
		{Name: "rpc-http-carrier", Match: httpMatch("/grpc.health.v1.Health/Check"), Require: []workload.Requirement{{Source: workload.Header, Name: new("x-carrier"), Operator: workload.NotIn, Values: []string{"blocked"}}}},
		{Name: "rpc-stream", Match: workload.Match{Hosts: hosts, GRPC: &workload.GRPCMatch{Service: "grpc.health.v1.Health", Methods: []string{"Watch"}}}, Decode: &workload.Decoder{Format: workload.Protobuf, DescriptorSet: &refs[0]}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/service"), Operator: workload.Exists}}},
	}}
	for i, pointer := range []string{"/service", "/alias"} {
		p.RequestConstraints = append(p.RequestConstraints, workload.Constraint{Name: fmt.Sprintf("rpc-view-%d", i), Match: rpc, Decode: &workload.Decoder{Format: workload.Protobuf, DescriptorSet: &refs[i]}, Require: []workload.Requirement{
			{Source: workload.Payload, Pointer: new(pointer), Operator: workload.In, Values: values},
			{Source: workload.Payload, Pointer: new(pointer), Operator: workload.NotIn, Values: []string{"blocked"}},
			{Source: workload.Payload, Pointer: new(pointer), Operator: workload.Exists}}})
	}
	return p
}

func attachShared(p *core.Pod, cm core.ConfigMap) {
	p.Spec.Volumes = append(p.Spec.Volumes, core.Volume{Name: "gateway-shared", VolumeSource: core.VolumeSource{ConfigMap: &core.ConfigMapVolumeSource{LocalObjectReference: core.LocalObjectReference{Name: cm.Name}}}})
	for _, containers := range [][]core.Container{p.Spec.InitContainers, p.Spec.Containers} {
		for i := range containers {
			c := &containers[i]
			if c.Name != "istio-proxy" {
				continue
			}
			c.Args = nil
			c.Env = append(c.Env, core.EnvVar{Name: config.EnvOPAConfig, Value: sharedDirectory + "/opa.json"})
			c.VolumeMounts = append(c.VolumeMounts, core.VolumeMount{Name: "gateway-shared", MountPath: sharedDirectory, ReadOnly: true})
		}
	}
}
