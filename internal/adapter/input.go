// Package adapter converts trusted Envoy facts into the shared workload input.
package adapter

import (
	"fmt"
	"mime"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/artifacts"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

const MaxBodyBytes = 64 * 1024

var rpcPath = regexp.MustCompile(`^/([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)/([A-Za-z_][A-Za-z0-9_]*)$`)
var metadataKey = regexp.MustCompile(`^[0-9a-z_.-]+$`)

type Adapter struct {
	snapshot *artifacts.Workload
	role     config.Role
	services map[string]bool
}

func New(snapshot *artifacts.Workload, role config.Role) *Adapter {
	a := &Adapter{snapshot: snapshot, role: role, services: make(map[string]bool)}
	for _, c := range snapshot.Policy.RequestConstraints {
		if c.Match.GRPC != nil {
			a.services[c.Match.GRPC.Service] = true
		}
	}
	return a
}

func (a *Adapter) Normalize(req *auth.CheckRequest) (workload.Input, error) {
	var zero workload.Input
	attrs := req.GetAttributes()
	http := attrs.GetRequest().GetHttp()
	if http == nil {
		return zero, fmt.Errorf("missing HTTP inspection")
	}
	if a.role == config.Egress && !slices.Contains(a.snapshot.Runtime.AllowedPeers, attrs.GetSource().GetPrincipal()) {
		return zero, fmt.Errorf("workload peer is not admitted")
	}
	host := http.GetHost()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	rawPath, rawQuery, _ := strings.Cut(http.GetPath(), "?")
	path, err := url.PathUnescape(rawPath)
	if err != nil {
		return zero, fmt.Errorf("invalid request path")
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return zero, fmt.Errorf("invalid query: %w", err)
	}
	for k, values := range query {
		if !utf8.ValidString(k) {
			return zero, fmt.Errorf("invalid query encoding")
		}
		for _, v := range values {
			if !utf8.ValidString(v) {
				return zero, fmt.Errorf("invalid query encoding")
			}
		}
	}
	// The legacy map combines duplicates. Only HeaderMap proves individual values.
	var headers map[string][]string
	if http.HeaderMap != nil {
		headers = make(map[string][]string)
		for _, h := range http.HeaderMap.Headers {
			key := strings.ToLower(h.Key)
			if strings.HasPrefix(key, ":") {
				continue
			}
			value := h.Value
			if h.RawValue != nil {
				value = string(h.RawValue)
			}
			if !utf8.ValidString(value) {
				return zero, fmt.Errorf("invalid header encoding")
			}
			headers[key] = append(headers[key], value)
		}
	}
	in := workload.Input{Version: workload.Version, Host: host, Protocol: workload.HTTP, HTTP: &workload.HTTPRequest{Method: http.Method, Path: path, Headers: headers, Query: query}}
	contentType := ""
	if len(headers["content-type"]) == 1 {
		contentType, _, _ = mime.ParseMediaType(headers["content-type"][0])
	}
	grpcType := contentType == "application/grpc" || strings.HasPrefix(contentType, "application/grpc+")
	parts := rpcPath.FindStringSubmatch(path)
	// A configured service path remains an RPC candidate even if an application
	// changes Content-Type; otherwise its constraints could become a nonmatch.
	if grpcType || (len(parts) == 3 && a.services[parts[1]]) {
		in.Protocol = workload.GRPC
		if len(parts) == 3 {
			var metadata map[string][]string
			if headers != nil {
				metadata = make(map[string][]string)
				for key, values := range headers {
					if metadataKey.MatchString(key) && !strings.HasSuffix(key, "-bin") {
						metadata[key] = values
					}
				}
			}
			in.GRPC = &workload.GRPCRequest{Service: parts[1], Method: parts[2], Metadata: metadata}
		}
	}
	body := http.RawBody
	status := workload.Ready
	if len(body) > MaxBodyBytes || http.Size > MaxBodyBytes {
		status = workload.Truncated
	}
	if http.Body != "" && body == nil {
		status = workload.Unavailable
	}
	if values := headers["x-envoy-auth-partial-body"]; slices.Contains(values, "true") {
		status = workload.Truncated
	}
	if values := headers["content-encoding"]; len(values) > 0 && (len(values) != 1 || !strings.EqualFold(values[0], "identity")) {
		status = workload.Unsupported
	}
	seen := make(map[string]bool)
	for _, constraint := range a.snapshot.Policy.RequestConstraints {
		d := constraint.Decode
		if d == nil {
			continue
		}
		view := workload.PayloadView{Format: d.Format, Status: status}
		if d.DescriptorSet != nil {
			view.DescriptorDigest = d.DescriptorSet.Digest
		}
		key := string(view.Format) + ":" + view.DescriptorDigest
		if seen[key] {
			continue
		}
		seen[key] = true
		if view.Status == workload.Ready {
			if d.Format == workload.JSON {
				value, err := decodeJSON(body)
				if err != nil {
					view.Status = workload.Invalid
				} else {
					view.Value = value
				}
			} else {
				view.Status, view.Value = a.decodeProto(in, http, headers, grpcType, d, body)
			}
		}
		in.Payloads = append(in.Payloads, view)
	}
	return in, nil
}
