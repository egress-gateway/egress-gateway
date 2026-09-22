package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/inspection"
	"sigs.k8s.io/yaml"
)

// prepareOPA preserves the native configuration unless standard tracing inputs
// are supplied. With those inputs, only distributed_tracing is replaced.
func prepareOPA(c config.Config) (string, error) {
	if c.Tracing == nil {
		return c.OPAConfig, nil
	}
	raw, err := os.ReadFile(c.OPAConfig)
	if err != nil {
		return "", err
	}
	var native map[string]json.RawMessage
	if err := yaml.Unmarshal(raw, &native); err != nil {
		return "", errors.New("invalid OPA configuration (content omitted)")
	}
	if native == nil {
		native = make(map[string]json.RawMessage)
	}
	tracing := map[string]any{}
	otel := c.Tracing
	if !otel.Disabled {
		protocol := "http"
		if otel.Protocol == "grpc" {
			protocol = "grpc"
		}
		encryption := "off"
		if otel.TLS {
			encryption = "tls"
		}
		if otel.ClientCertificate != "" {
			encryption = "mtls"
		}
		resource := map[string]string{}
		for k, v := range otel.Resource {
			resource[map[string]string{"service.version": "service_version", "service.instance.id": "service_instance_id", "service.namespace": "service_namespace", "deployment.environment": "deployment_environment"}[k]] = v
		}
		batch := map[string]any{"blocking": false}
		for k, v := range otel.Batch {
			batch[map[string]string{"SCHEDULE_DELAY": "batch_timeout_ms", "EXPORT_TIMEOUT": "export_timeout_ms", "MAX_QUEUE_SIZE": "max_queue_size", "MAX_EXPORT_BATCH_SIZE": "max_export_batch_size"}[k]] = v
		}
		tracing = map[string]any{
			"type": protocol, "address": otel.Address, "service_name": otel.ServiceName,
			"sample_percentage": otel.SampleRatio * 100, "encryption": encryption,
			"allow_insecure_tls": false, "tls_ca_cert_file": otel.Certificate,
			"tls_cert_file": otel.ClientCertificate, "tls_private_key_file": otel.ClientKey,
			"resource": resource, "batch_span_processor_options": batch,
		}
	}
	native["distributed_tracing"], err = json.Marshal(tracing)
	if err != nil {
		return "", err
	}
	raw, err = json.Marshal(native)
	if err != nil {
		return "", err
	}
	path := filepath.Join(c.RuntimeDir, "opa.json")
	return path, inspection.WriteAtomic(path, raw, 0o600)
}
