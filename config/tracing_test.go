package config

import (
	"strings"
	"testing"
)

func tracingEnv(values map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := values[k]; return v, ok }
}

func TestTracingInputs(t *testing.T) {
	t.Run("absent-and-empty-preserve-native", func(t *testing.T) {
		c, err := LoadTracing(tracingEnv(map[string]string{"OTEL_SERVICE_NAME": "", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": ""}))
		if err != nil || c != nil {
			t.Fatalf("%+v %v", c, err)
		}
	})
	t.Run("signal-precedence-and-service-name", func(t *testing.T) {
		c, err := LoadTracing(tracingEnv(map[string]string{
			"OTEL_EXPORTER_OTLP_PROTOCOL": "grpc", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
			"OTEL_EXPORTER_OTLP_ENDPOINT": "http://general:4317", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://traces:443/prefix/v1/traces",
			"OTEL_EXPORTER_OTLP_CERTIFICATE": "/general.pem", "OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE": "/trace.pem",
			"OTEL_RESOURCE_ATTRIBUTES": "service.name=resource,service.version=v1,service.namespace=gateway",
			"OTEL_SERVICE_NAME":        "explicit", "OTEL_TRACES_SAMPLER": "parentbased_traceidratio", "OTEL_TRACES_SAMPLER_ARG": "0.25",
			"OTEL_BSP_MAX_QUEUE_SIZE": "1024", "OTEL_BSP_MAX_EXPORT_BATCH_SIZE": "128",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if c.Protocol != "http/protobuf" || c.Address != "traces:443" || !c.TLS || c.Certificate != "/trace.pem" || c.ServiceName != "explicit" || c.Resource["service.version"] != "v1" || c.SampleRatio != .25 || c.Batch["MAX_QUEUE_SIZE"] != 1024 {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("empty-override-falls-back", func(t *testing.T) {
		c, err := LoadTracing(tracingEnv(map[string]string{"OTEL_EXPORTER_OTLP_PROTOCOL": "grpc", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "", "OTEL_EXPORTER_OTLP_ENDPOINT": "https://general:4317", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": ""}))
		if err != nil || c.Protocol != "grpc" || c.Address != "general:4317" || !c.TLS {
			t.Fatalf("%+v %v", c, err)
		}
	})
	for _, name := range []string{"OTEL_SDK_DISABLED", "OTEL_TRACES_EXPORTER"} {
		t.Run(name, func(t *testing.T) {
			v := "none"
			if name == "OTEL_SDK_DISABLED" {
				v = "TRUE"
			}
			c, err := LoadTracing(tracingEnv(map[string]string{name: v, "OTEL_EXPORTER_OTLP_ENDPOINT": "invalid-ignored-when-disabled"}))
			if err != nil || !c.Disabled {
				t.Fatalf("%+v %v", c, err)
			}
		})
	}
}

func TestTracingSafeDiagnostics(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"OTEL_EXPORTER_OTLP_ENDPOINT", "https://private-token@host:443"},
		{"OTEL_EXPORTER_OTLP_ENDPOINT", "https://host:443/?private-token"},
		{"OTEL_EXPORTER_OTLP_HEADERS", "authorization=private-token%zz"},
		{"OTEL_EXPORTER_OTLP_HEADERS", "private-token"},
		{"OTEL_EXPORTER_OTLP_HEADERS", "authorization=private-token%0a"},
		{"OTEL_EXPORTER_OTLP_TIMEOUT", "private-token"},
		{"OTEL_RESOURCE_ATTRIBUTES", "private-token=value"},
		{"OTEL_TRACES_SAMPLER", "private-token"},
		{"OTEL_PROPAGATORS", "private-token"},
		{"OTEL_TRACES_EXPORTER", "private-token"},
	} {
		t.Run(tc.name+"/"+tc.value, func(t *testing.T) {
			_, err := LoadTracing(tracingEnv(map[string]string{tc.name: tc.value}))
			if err == nil || strings.Contains(err.Error(), "private-token") {
				t.Fatalf("unsafe or missing error: %v", err)
			}
		})
	}
	for _, value := range []string{"NaN", "Inf", "-0.1", "1.01", "secret"} {
		_, err := LoadTracing(tracingEnv(map[string]string{"OTEL_TRACES_SAMPLER": "parentbased_traceidratio", "OTEL_TRACES_SAMPLER_ARG": value}))
		if err == nil {
			t.Fatalf("accepted invalid ratio %q", value)
		}
	}
}

func TestTracingTLSAndResourceEscaping(t *testing.T) {
	values := map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector:4318", "OTEL_RESOURCE_ATTRIBUTES": "service.name=hello%20world,service.version=v1%2C2", "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE": "/cert.pem", "OTEL_EXPORTER_OTLP_CLIENT_KEY": "/key.pem"}
	c, err := LoadTracing(tracingEnv(values))
	if err != nil || c.ServiceName != "hello world" || c.Resource["service.version"] != "v1,2" || c.ClientKey != "/key.pem" {
		t.Fatalf("%+v %v", c, err)
	}
	values["OTEL_EXPORTER_OTLP_INSECURE"] = "true"
	if _, err := LoadTracing(tracingEnv(values)); err == nil {
		t.Fatal("HTTPS could be silently downgraded")
	}
}
