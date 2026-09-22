package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/inspection"
	"github.com/egress-gateway/egress-gateway/internal/request"
	"sigs.k8s.io/yaml"
)

// prepareEnvoy moves the standalone admin and named OPA cluster onto private
// sockets. Envoy validates extension schemas; preserving unknown fields here
// avoids turning the daemon into a second Envoy configuration authority.
func prepareEnvoy(c config.Config) (string, error) {
	raw, err := os.ReadFile(c.EnvoyConfig)
	if err != nil {
		return "", err
	}
	raw, err = yaml.YAMLToJSON(raw)
	if err != nil {
		return "", err
	}
	var b map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&b); err != nil {
		return "", err
	}
	if b == nil {
		return "", errors.New("empty Envoy configuration")
	}
	if b["dynamic_resources"] != nil {
		return "", errors.New("standalone bootstrap must use static resources")
	}
	admin, ok := b["admin"].(map[string]any)
	if !ok {
		admin = map[string]any{}
		b["admin"] = admin
	}
	admin["address"] = pipe(c.EnvoyAdminPath())
	static, _ := b["static_resources"].(map[string]any)
	listeners, _ := static["listeners"].([]any)
	for _, item := range listeners {
		listener, _ := item.(map[string]any)
		chains, _ := listener["filter_chains"].([]any)
		for _, item := range chains {
			chain, _ := item.(map[string]any)
			filters, _ := chain["filters"].([]any)
			for _, item := range filters {
				filter, _ := item.(map[string]any)
				if filter["name"] != "envoy.filters.network.http_connection_manager" {
					continue
				}
				hcm, _ := filter["typed_config"].(map[string]any)
				httpFilters, _ := hcm["http_filters"].([]any)
				for _, item := range httpFilters {
					filter, _ := item.(map[string]any)
					if filter["name"] == "gateway.request" || filter["name"] == "gateway.dispatch" {
						filter["typed_config"] = request.Filter(c.Role)
					}
				}
			}
		}
	}
	clusters, _ := static["clusters"].([]any)
	for _, item := range clusters {
		cluster, _ := item.(map[string]any)
		var socket string
		switch cluster["name"] {
		case "opa":
			socket = filepath.Join(c.RuntimeDir, "opa.sock")
		case "inspection_sds":
			socket = c.InspectionSDSPath()
		default:
			continue
		}
		cluster["type"] = "STATIC"
		cluster["load_assignment"] = map[string]any{"cluster_name": cluster["name"], "endpoints": []any{map[string]any{"lb_endpoints": []any{map[string]any{"endpoint": map[string]any{"address": pipe(socket)}}}}}}
	}
	raw, err = json.Marshal(b)
	if err != nil {
		return "", err
	}
	generated := filepath.Join(c.RuntimeDir, "envoy.json")
	return generated, inspection.WriteAtomic(generated, raw, 0o600)
}
func pipe(path string) any {
	return map[string]any{"pipe": map[string]any{"path": path, "mode": 0o600}}
}
