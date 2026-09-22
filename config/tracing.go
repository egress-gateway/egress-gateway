package config

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
)

// Tracing is the supported startup-only OpenTelemetry input for embedded OPA.
// Nil leaves the native OPA configuration untouched. It never configures Envoy.
// Headers and the HTTP URL path remain inputs to the upstream OTLP exporter;
// they are validated here but are deliberately not copied into generated files.
type Tracing struct {
	Disabled          bool
	Protocol          string
	Address           string
	TLS               bool
	Certificate       string
	ClientCertificate string
	ClientKey         string
	ServiceName       string
	Resource          map[string]string
	SampleRatio       float64
	Batch             map[string]int
}

const otlpPrefix = "OTEL_EXPORTER_OTLP_"

// LoadTracing accepts only settings that the pinned OPA runtime can honor.
// Errors identify variable names, never their potentially sensitive values.
// Empty values have the same meaning as unset values, including at overrides.
func LoadTracing(lookup func(string) (string, bool)) (*Tracing, error) {
	get := func(name string) string { v, _ := lookup(name); return strings.TrimSpace(v) }
	effective := func(suffix string) string {
		if v := get(otlpPrefix + "TRACES_" + suffix); v != "" {
			return v
		}
		return get(otlpPrefix + suffix)
	}
	names := []string{"OTEL_SDK_DISABLED", "OTEL_TRACES_EXPORTER", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES", "OTEL_TRACES_SAMPLER", "OTEL_TRACES_SAMPLER_ARG", "OTEL_PROPAGATORS", "OTEL_BSP_SCHEDULE_DELAY", "OTEL_BSP_EXPORT_TIMEOUT", "OTEL_BSP_MAX_QUEUE_SIZE", "OTEL_BSP_MAX_EXPORT_BATCH_SIZE"}
	for _, suffix := range []string{"ENDPOINT", "PROTOCOL", "HEADERS", "CERTIFICATE", "CLIENT_CERTIFICATE", "CLIENT_KEY", "INSECURE", "TIMEOUT", "COMPRESSION"} {
		names = append(names, otlpPrefix+suffix, otlpPrefix+"TRACES_"+suffix)
	}
	configured := false
	for _, name := range names {
		configured = configured || get(name) != ""
	}
	if !configured {
		return nil, nil
	}
	c := &Tracing{SampleRatio: 1, Resource: map[string]string{}, Batch: map[string]int{}}
	if strings.EqualFold(get("OTEL_SDK_DISABLED"), "true") || strings.EqualFold(get("OTEL_TRACES_EXPORTER"), "none") {
		c.Disabled = true
		return c, nil
	}
	invalid := func(name string) error {
		return fmt.Errorf("%s: unsupported or invalid tracing setting (value omitted)", name)
	}
	if v := get("OTEL_SDK_DISABLED"); v != "" && !strings.EqualFold(v, "false") {
		return nil, invalid("OTEL_SDK_DISABLED")
	}
	if v := get("OTEL_TRACES_EXPORTER"); v != "" && !strings.EqualFold(v, "otlp") {
		return nil, invalid("OTEL_TRACES_EXPORTER")
	}
	c.Protocol = strings.ToLower(effective("PROTOCOL"))
	if c.Protocol == "" {
		c.Protocol = "http/protobuf"
	}
	if c.Protocol != "grpc" && c.Protocol != "http/protobuf" {
		return nil, invalid("OTEL_EXPORTER_OTLP[_TRACES]_PROTOCOL")
	}
	// The exporter reads both levels before applying precedence. Validate both
	// so its own parse diagnostics cannot accidentally disclose an overridden value.
	for _, prefix := range []string{otlpPrefix, otlpPrefix + "TRACES_"} {
		if v := get(prefix + "ENDPOINT"); v != "" {
			u, err := url.Parse(v)
			if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return nil, invalid(prefix + "ENDPOINT")
			}
		}
		if v := get(prefix + "HEADERS"); v != "" && !validHeaders(v) {
			return nil, invalid(prefix + "HEADERS")
		}
		if v := get(prefix + "TIMEOUT"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 || n > math.MaxInt64/1000000 {
				return nil, invalid(prefix + "TIMEOUT")
			}
		}
		if v := get(prefix + "COMPRESSION"); v != "" && v != "gzip" && v != "none" {
			return nil, invalid(prefix + "COMPRESSION")
		}
		if v := get(prefix + "INSECURE"); v != "" && !strings.EqualFold(v, "true") && !strings.EqualFold(v, "false") {
			return nil, invalid(prefix + "INSECURE")
		}
	}
	endpoint := effective("ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:4318"
		if c.Protocol == "grpc" {
			endpoint = "http://localhost:4317"
		}
	}
	u, _ := url.Parse(endpoint)
	if c.Protocol == "grpc" && u.Path != "" && u.Path != "/" {
		return nil, invalid("OTEL_EXPORTER_OTLP[_TRACES]_ENDPOINT")
	}
	c.Address, c.TLS = u.Host, u.Scheme == "https"
	// The pinned HTTP exporter applies INSECURE after the URL scheme. Refuse
	// that conflicting combination instead of silently downgrading HTTPS.
	if c.TLS && strings.EqualFold(effective("INSECURE"), "true") {
		return nil, invalid("OTEL_EXPORTER_OTLP[_TRACES]_INSECURE: conflicts with https endpoint")
	}
	c.Certificate = effective("CERTIFICATE")
	c.ClientCertificate, c.ClientKey = effective("CLIENT_CERTIFICATE"), effective("CLIENT_KEY")
	if (c.ClientCertificate == "") != (c.ClientKey == "") {
		return nil, invalid("OTEL_EXPORTER_OTLP[_TRACES]_CLIENT_CERTIFICATE/CLIENT_KEY")
	}
	if !c.TLS && (c.Certificate != "" || c.ClientCertificate != "") {
		return nil, invalid("OTEL_EXPORTER_OTLP[_TRACES]_CERTIFICATE: TLS requires an https endpoint")
	}
	for item := range strings.SplitSeq(get("OTEL_RESOURCE_ATTRIBUTES"), ",") {
		if strings.TrimSpace(item) == "" {
			continue
		}
		key, value, ok := strings.Cut(item, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok {
			return nil, invalid("OTEL_RESOURCE_ATTRIBUTES")
		}
		value, err := url.PathUnescape(value)
		if err != nil {
			return nil, invalid("OTEL_RESOURCE_ATTRIBUTES")
		}
		switch key {
		case "service.name":
			c.ServiceName = value
		case "service.version", "service.instance.id", "service.namespace", "deployment.environment":
			c.Resource[key] = value
		default:
			return nil, invalid("OTEL_RESOURCE_ATTRIBUTES: attribute not supported by pinned OPA")
		}
	}
	if v := get("OTEL_SERVICE_NAME"); v != "" {
		c.ServiceName = v
	}
	switch get("OTEL_TRACES_SAMPLER") {
	case "", "parentbased_always_on":
	case "parentbased_always_off":
		c.SampleRatio = 0
	case "parentbased_traceidratio":
		n, err := strconv.ParseFloat(get("OTEL_TRACES_SAMPLER_ARG"), 64)
		if err != nil || math.IsNaN(n) || n < 0 || n > 1 {
			return nil, invalid("OTEL_TRACES_SAMPLER_ARG")
		}
		c.SampleRatio = n
	default:
		return nil, invalid("OTEL_TRACES_SAMPLER: pinned OPA requires a parent-based sampler")
	}
	if v := get("OTEL_TRACES_SAMPLER_ARG"); v != "" && get("OTEL_TRACES_SAMPLER") != "parentbased_traceidratio" {
		return nil, invalid("OTEL_TRACES_SAMPLER_ARG: requires parentbased_traceidratio")
	}
	if get("OTEL_PROPAGATORS") != "" {
		return nil, invalid("OTEL_PROPAGATORS: OPA-Envoy uses fixed W3C and B3 propagation")
	}
	for _, suffix := range []string{"SCHEDULE_DELAY", "EXPORT_TIMEOUT", "MAX_QUEUE_SIZE", "MAX_EXPORT_BATCH_SIZE"} {
		if v := get("OTEL_BSP_" + suffix); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 || n > math.MaxInt64/1000000 {
				return nil, invalid("OTEL_BSP_" + suffix)
			}
			c.Batch[suffix] = n
		}
	}
	queue, batch := 2048, 512
	if n := c.Batch["MAX_QUEUE_SIZE"]; n != 0 {
		queue = n
	}
	if n := c.Batch["MAX_EXPORT_BATCH_SIZE"]; n != 0 {
		batch = n
	}
	if batch > queue {
		return nil, invalid("OTEL_BSP_MAX_EXPORT_BATCH_SIZE: exceeds queue size")
	}
	return c, nil
}

func validHeaders(value string) bool {
	for item := range strings.SplitSeq(value, ",") {
		key, val, ok := strings.Cut(item, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return false
		}
		for _, ch := range key {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", ch)) {
				return false
			}
		}
		decoded, err := url.PathUnescape(val)
		if err != nil {
			return false
		}
		for _, ch := range decoded {
			if ch < 0x20 && ch != '\t' || ch == 0x7f {
				return false
			}
		}
	}
	return true
}
