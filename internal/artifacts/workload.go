package artifacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/egress-gateway/egress-gateway/config"
	opabundle "github.com/open-policy-agent/opa/v1/bundle"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Workload is an immutable startup snapshot. The archive loaded by OPA is the
// same byte slice inspected here, and decoders use these verified descriptors.
type Workload struct {
	Archive     []byte
	Policy      workload.Policy
	Runtime     config.PolicyRuntime
	Descriptors map[workload.ArtifactRef]*protoregistry.Files
}

func LoadWorkload(path string, role config.Role) (*Workload, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read workload configuration: %w", err)
	}
	var cfg config.PolicyRuntime
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("invalid workload configuration: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing workload configuration data")
	}
	if err := cfg.Validate(role); err != nil {
		return nil, err
	}
	archive, err := os.ReadFile(cfg.Bundle)
	if err != nil {
		return nil, fmt.Errorf("read workload bundle: %w", err)
	}
	loaded, err := opabundle.NewReader(bytes.NewReader(archive)).Read()
	if err != nil {
		return nil, fmt.Errorf("read workload bundle: %w", err)
	}
	if loaded.Manifest.Roots == nil || !slices.Equal(*loaded.Manifest.Roots, []string{policybundle.Root}) || loaded.Manifest.RegoVersion == nil || *loaded.Manifest.RegoVersion != 1 {
		return nil, fmt.Errorf("incompatible workload bundle manifest")
	}
	encoded, err := json.Marshal(loaded.Data)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Root struct {
			Workload struct {
				Config struct {
					Version string           `json:"version"`
					Policy  *workload.Policy `json:"policy"`
				} `json:"config"`
			} `json:"workload"`
		} `json:"egress_gateway"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return nil, fmt.Errorf("invalid workload bundle data: %w", err)
	}
	contract := envelope.Root.Workload.Config
	if contract.Version != workload.Version || contract.Policy == nil || contract.Policy.HostDenylist == nil || contract.Policy.RequestConstraints == nil {
		return nil, fmt.Errorf("missing or incompatible workload bundle data")
	}
	p := *contract.Policy
	// Bundle construction canonicalizes omitted root collections to empty arrays.
	if len(p.HostDenylist) == 0 {
		p.HostDenylist = nil
	}
	if len(p.RequestConstraints) == 0 {
		p.RequestConstraints = nil
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid workload policy: %w", err)
	}
	result := &Workload{Archive: archive, Policy: p, Runtime: cfg, Descriptors: make(map[workload.ArtifactRef]*protoregistry.Files)}
	staged := make(map[workload.ArtifactRef]string)
	for _, file := range cfg.Descriptors {
		ref := workload.ArtifactRef{URL: file.URL, Digest: file.Digest}
		if _, exists := staged[ref]; exists {
			return nil, fmt.Errorf("duplicate descriptor reference")
		}
		staged[ref] = file.Path
	}
	for _, c := range p.RequestConstraints {
		if c.Decode == nil || c.Decode.Format != workload.Protobuf {
			continue
		}
		ref := *c.Decode.DescriptorSet
		files := result.Descriptors[ref]
		if files == nil {
			path, ok := staged[ref]
			if !ok {
				return nil, fmt.Errorf("constraint %s: descriptor is not staged", c.Name)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("constraint %s: read descriptor: %w", c.Name, err)
			}
			if fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != ref.Digest {
				return nil, fmt.Errorf("constraint %s: descriptor digest mismatch", c.Name)
			}
			var set descriptorpb.FileDescriptorSet
			if err := proto.Unmarshal(raw, &set); err != nil {
				return nil, fmt.Errorf("constraint %s: invalid descriptor set", c.Name)
			}
			files, err = protodesc.NewFiles(&set)
			if err != nil {
				return nil, fmt.Errorf("constraint %s: invalid descriptor definitions or imports: %w", c.Name, err)
			}
			result.Descriptors[ref] = files
		}
		d, err := files.FindDescriptorByName(protoreflect.FullName(c.Match.GRPC.Service))
		if err != nil {
			return nil, fmt.Errorf("constraint %s: descriptor service unavailable", c.Name)
		}
		service, ok := d.(protoreflect.ServiceDescriptor)
		if !ok {
			return nil, fmt.Errorf("constraint %s: descriptor name is not a service", c.Name)
		}
		for _, method := range c.Match.GRPC.Methods {
			if service.Methods().ByName(protoreflect.Name(method)) == nil {
				return nil, fmt.Errorf("constraint %s: descriptor method unavailable", c.Name)
			}
		}
	}
	return result, nil
}
