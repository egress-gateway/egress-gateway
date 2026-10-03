package adapter

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/artifacts"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

func protoFiles(t *testing.T, jsonName string, stream bool) *protoregistry.Files {
	t.Helper()
	files, err := protodesc.NewFiles(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{Name: new("api.proto"), Package: new("test"), Syntax: new("proto3"), MessageType: []*descriptorpb.DescriptorProto{{Name: new("Request"), Field: []*descriptorpb.FieldDescriptorProto{
		{Name: new("model_name"), JsonName: new(jsonName), Number: new(int32(1)), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
		{Name: new("count"), Number: new(int32(2)), Type: descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum()},
		{Name: new("enabled"), Number: new(int32(3)), Type: descriptorpb.FieldDescriptorProto_TYPE_BOOL.Enum()},
		{Name: new("items"), Number: new(int32(4)), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), Label: descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()},
	}}}, Service: []*descriptorpb.ServiceDescriptorProto{{Name: new("Service"), Method: []*descriptorpb.MethodDescriptorProto{{Name: new("Call"), InputType: new(".test.Request"), OutputType: new(".test.Request"), ClientStreaming: new(stream)}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
func framed(body []byte) []byte {
	frame := make([]byte, 5, len(body)+5)
	binary.BigEndian.PutUint32(frame[1:], uint32(len(body)))
	return append(frame, body...)
}
func protoAdapter(t *testing.T, stream bool) *Adapter {
	ref := workload.ArtifactRef{URL: "https://example.test/api.pb", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	return New(&artifacts.Workload{Policy: workload.Policy{RequestConstraints: []workload.Constraint{{Match: workload.Match{GRPC: &workload.GRPCMatch{Service: "test.Service"}}, Decode: &workload.Decoder{Format: workload.Protobuf, DescriptorSet: &ref}}}}, Descriptors: map[workload.ArtifactRef]*protoregistry.Files{ref: protoFiles(t, "model", stream)}}, config.Workload)
}
func TestCompleteUnaryAndProtoJSON(t *testing.T) {
	a := protoAdapter(t, false)
	body := []byte{10, 4, 'g', 'o', 'o', 'd', 16, 123, 24, 1, 34, 1, 'a', 34, 1, 'b'}
	in, err := a.Normalize(request("/test.Service/Call", framed(body), &core.HeaderValue{Key: "content-type", Value: "application/grpc"}))
	if err != nil {
		t.Fatal(err)
	}
	v := in.Payloads[0]
	if v.Status != workload.Ready {
		t.Fatalf("not decoded: %+v", v)
	}
	raw, err := json.Marshal(v.Value)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"count":"123","enabled":true,"items":["a","b"],"model":"good"}` {
		t.Fatalf("wrong ProtoJSON mapping: %s", raw)
	}
	empty, err := a.Normalize(request("/test.Service/Call", framed(nil), &core.HeaderValue{Key: "content-type", Value: "application/grpc"}))
	if err != nil {
		t.Fatal(err)
	}
	if empty.Payloads[0].Status != workload.Ready || len(empty.Payloads[0].Value.(map[string]any)) != 0 {
		t.Fatal("empty message forced absent defaults")
	}
}
func TestUnaryFailures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     []byte
		encoding string
		stream   bool
		want     workload.InspectionStatus
	}{
		{"missing", nil, "", false, workload.Truncated},
		{"short-header", []byte{0, 0}, "", false, workload.Truncated},
		{"short-message", []byte{0, 0, 0, 0, 1}, "", false, workload.Truncated},
		{"extra-frame", append(framed(nil), framed(nil)...), "", false, workload.Invalid},
		{"trailing", append(framed(nil), 0), "", false, workload.Invalid},
		{"compressed", []byte{1, 0, 0, 0, 0}, "", false, workload.Unsupported},
		{"encoding", framed(nil), "gzip", false, workload.Unsupported},
		{"stream", framed(nil), "", true, workload.Unsupported},
		{"malformed-protobuf", framed([]byte{10, 255}), "", false, workload.Invalid},
		{"oversized", make([]byte, MaxBodyBytes+1), "", false, workload.Truncated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := protoAdapter(t, tc.stream)
			headers := []*core.HeaderValue{{Key: "content-type", Value: "application/grpc"}}
			if tc.encoding != "" {
				headers = append(headers, &core.HeaderValue{Key: "grpc-encoding", Value: tc.encoding})
			}
			in, err := a.Normalize(request("/test.Service/Call", tc.body, headers...))
			if err != nil {
				t.Fatal(err)
			}
			if got := in.Payloads[0].Status; got != tc.want {
				t.Fatalf("status=%s want=%s", got, tc.want)
			}
		})
	}
}
func TestDescriptorViewsStayDistinct(t *testing.T) {
	a := protoAdapter(t, false)
	ref := workload.ArtifactRef{URL: "https://example.test/other.pb", Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	a.snapshot.Descriptors[ref] = protoFiles(t, "otherModel", false)
	a.snapshot.Policy.RequestConstraints = append(a.snapshot.Policy.RequestConstraints, workload.Constraint{Decode: &workload.Decoder{Format: workload.Protobuf, DescriptorSet: &ref}})
	in, err := a.Normalize(request("/test.Service/Call", framed([]byte{10, 1, 'x'}), &core.HeaderValue{Key: "content-type", Value: "application/grpc"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Payloads) != 2 || in.Payloads[0].Value.(map[string]any)["model"] != "x" || in.Payloads[1].Value.(map[string]any)["otherModel"] != "x" {
		t.Fatalf("descriptor views merged: %+v", in.Payloads)
	}
}
func TestAllStreamingDirectionsAreUnsupported(t *testing.T) {
	for _, flags := range [][2]bool{{true, false}, {false, true}, {true, true}} {
		a := protoAdapter(t, false)
		for ref, files := range a.snapshot.Descriptors {
			var set descriptorpb.FileDescriptorSet
			files.RangeFiles(func(f protoreflect.FileDescriptor) bool {
				set.File = append(set.File, protodesc.ToFileDescriptorProto(f))
				return true
			})
			method := set.File[0].Service[0].Method[0]
			method.ClientStreaming = new(flags[0])
			method.ServerStreaming = new(flags[1])
			replacement, err := protodesc.NewFiles(&set)
			if err != nil {
				t.Fatal(err)
			}
			a.snapshot.Descriptors[ref] = replacement
		}
		in, err := a.Normalize(request("/test.Service/Call", framed(nil), &core.HeaderValue{Key: "content-type", Value: "application/grpc"}))
		if err != nil {
			t.Fatal(err)
		}
		if in.Payloads[0].Status != workload.Unsupported {
			t.Fatalf("streaming flags=%v allowed", flags)
		}
	}
}
