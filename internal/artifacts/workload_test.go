package artifacts_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	opabundle "github.com/open-policy-agent/opa/v1/bundle"
	"os"
	"path/filepath"
	"testing"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/artifacts"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func descriptor(t *testing.T) []byte {
	t.Helper()
	b, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: new("test.proto"), Package: new("test"), Syntax: new("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: new("Request"), Field: []*descriptorpb.FieldDescriptorProto{{Name: new("model"), Number: new(int32(1)), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()}}}}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: new("Service"), Method: []*descriptorpb.MethodDescriptorProto{{Name: new("Call"), InputType: new(".test.Request"), OutputType: new(".test.Request")}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func stage(t *testing.T, p workload.Policy, files []config.DescriptorFile) string {
	t.Helper()
	dir := t.TempDir()
	b, err := policybundle.Build(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "workload.tar.gz")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(config.PolicyRuntime{Bundle: path, Descriptors: files})
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestLoadSharedBundle(t *testing.T) {
	path := stage(t, workload.Policy{}, nil)
	loaded, err := artifacts.LoadWorkload(path, config.Workload)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Archive) == 0 || len(loaded.Policy.RequestConstraints) != 0 {
		t.Fatal("lost artifact or changed empty policy")
	}
	if _, err := artifacts.LoadWorkload(path, config.Egress); err == nil {
		t.Fatal("egress accepted without trusted peer binding")
	}
}
func TestDescriptorReadiness(t *testing.T) {
	raw := descriptor(t)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	url := "https://artifact.example/test.pb"
	p := workload.Policy{RequestConstraints: []workload.Constraint{{Name: "model", Match: workload.Match{Hosts: []workload.HostMatcher{{Type: workload.Exact, Value: "api.example"}}, GRPC: &workload.GRPCMatch{Service: "test.Service", Methods: []string{"Call"}}}, Decode: &workload.Decoder{Format: workload.Protobuf, DescriptorSet: &workload.ArtifactRef{URL: url, Digest: digest}}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/model"), Operator: workload.Exists}}}}}
	file := filepath.Join(t.TempDir(), "test.pb")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	good := config.DescriptorFile{URL: url, Digest: digest, Path: file}
	if _, err := artifacts.LoadWorkload(stage(t, p, []config.DescriptorFile{good}), config.Workload); err != nil {
		t.Fatal(err)
	}
	if _, err := artifacts.LoadWorkload(stage(t, p, nil), config.Workload); err == nil {
		t.Fatal("accepted missing descriptor")
	}
	if err := os.WriteFile(file, []byte("wrong bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := artifacts.LoadWorkload(stage(t, p, []config.DescriptorFile{good}), config.Workload); err == nil {
		t.Fatal("accepted digest mismatch")
	}
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	p.RequestConstraints[0].Match.GRPC.Methods = []string{"Missing"}
	if _, err := artifacts.LoadWorkload(stage(t, p, []config.DescriptorFile{good}), config.Workload); err == nil {
		t.Fatal("accepted incompatible method")
	}
}

func TestMissingImportsAndSelectedService(t *testing.T) {
	raw := descriptor(t)
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		missingImport bool
		service       string
	}{{"missing-import", true, "test.Service"}, {"missing-service", false, "test.Other"}} {
		t.Run(tc.name, func(t *testing.T) {
			local := proto.Clone(&set).(*descriptorpb.FileDescriptorSet)
			if tc.missingImport {
				local.File[0].Dependency = []string{"unavailable.proto"}
			}
			raw, err := proto.Marshal(local)
			if err != nil {
				t.Fatal(err)
			}
			ref := workload.ArtifactRef{URL: "https://artifact.example/test.pb", Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(raw))}
			p := workload.Policy{RequestConstraints: []workload.Constraint{{Name: "model", Match: workload.Match{Hosts: []workload.HostMatcher{{Type: workload.Exact, Value: "api.example"}}, GRPC: &workload.GRPCMatch{Service: tc.service}}, Decode: &workload.Decoder{Format: workload.Protobuf, DescriptorSet: &ref}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/model"), Operator: workload.Exists}}}}}
			file := filepath.Join(t.TempDir(), "descriptor.pb")
			if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := artifacts.LoadWorkload(stage(t, p, []config.DescriptorFile{{URL: ref.URL, Digest: ref.Digest, Path: file}}), config.Workload); err == nil {
				t.Fatal("invalid dependency accepted")
			}
		})
	}
}

func TestInvalidBundleContract(t *testing.T) {
	for _, tc := range []string{"missing-policy", "wrong-version", "wrong-root", "invalid-policy", "trailing-config"} {
		t.Run(tc, func(t *testing.T) {
			path := stage(t, workload.Policy{}, nil)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var cfg config.PolicyRuntime
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			if tc == "trailing-config" {
				if err := os.WriteFile(path, append(raw, []byte(" {}")...), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				archive, err := os.ReadFile(cfg.Bundle)
				if err != nil {
					t.Fatal(err)
				}
				b, err := opabundle.NewReader(bytes.NewReader(archive)).Read()
				if err != nil {
					t.Fatal(err)
				}
				data := b.Data["egress_gateway"].(map[string]any)["workload"].(map[string]any)["config"].(map[string]any)
				switch tc {
				case "missing-policy":
					delete(data, "policy")
				case "wrong-version":
					data["version"] = "v2"
				case "wrong-root":
					b.Manifest.Roots = new([]string{"egress_gateway"})
				case "invalid-policy":
					data["policy"] = map[string]any{"hostDenylist": []any{map[string]any{"type": "Exact", "value": "*"}}, "requestConstraints": []any{}}
				}
				var buffer bytes.Buffer
				if err := opabundle.NewWriter(&buffer).Write(b); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cfg.Bundle, buffer.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := artifacts.LoadWorkload(path, config.Workload); err == nil {
				t.Fatal("incompatible configuration accepted")
			}
		})
	}
}
