package adapter

import (
	"encoding/binary"
	"strings"

	"github.com/egress-gateway/egress-gateway-policy/workload"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

func (a *Adapter) decodeProto(in workload.Input, http *auth.AttributeContext_HttpRequest, headers map[string][]string, grpcType bool, decoder *workload.Decoder, body []byte) (workload.InspectionStatus, any) {
	if in.GRPC == nil {
		return workload.Unavailable, nil
	}
	if !grpcType || http.Method != "POST" || (http.Protocol != "HTTP/2" && http.Protocol != "HTTP/2.0") {
		return workload.Invalid, nil
	}
	if values := headers["grpc-encoding"]; len(values) > 0 && (len(values) != 1 || !strings.EqualFold(values[0], "identity")) {
		return workload.Unsupported, nil
	}
	if len(body) < 5 {
		return workload.Truncated, nil
	}
	if body[0] != 0 {
		return workload.Unsupported, nil
	}
	length := uint64(binary.BigEndian.Uint32(body[1:5]))
	if length > uint64(len(body)-5) {
		return workload.Truncated, nil
	}
	if length != uint64(len(body)-5) {
		return workload.Invalid, nil
	}
	files := a.snapshot.Descriptors[*decoder.DescriptorSet]
	if files == nil {
		return workload.Unavailable, nil
	}
	d, err := files.FindDescriptorByName(protoreflect.FullName(in.GRPC.Service))
	if err != nil {
		return workload.Unavailable, nil
	}
	service, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return workload.Unavailable, nil
	}
	method := service.Methods().ByName(protoreflect.Name(in.GRPC.Method))
	if method == nil {
		return workload.Unavailable, nil
	}
	if method.IsStreamingClient() || method.IsStreamingServer() {
		return workload.Unsupported, nil
	}
	message := dynamicpb.NewMessage(method.Input())
	resolver := dynamicpb.NewTypes(files)
	if err := (proto.UnmarshalOptions{Resolver: resolver}).Unmarshal(body[5:], message); err != nil {
		return workload.Invalid, nil
	}
	raw, err := (protojson.MarshalOptions{Resolver: resolver}).Marshal(message)
	if err != nil {
		return workload.Invalid, nil
	}
	value, err := decodeJSON(raw)
	if err != nil {
		return workload.Invalid, nil
	}
	return workload.Ready, value
}
