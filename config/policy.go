package config

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

const EnvWorkloadConfig = "GATEWAY_WORKLOAD_CONFIG"

// PolicyRuntime is a trusted, startup-only artifact set. It contains no rules;
// Bundle is a snapshot built by the shared policy library. Egress requires an
// exact allowed peer binding in addition to the shared workload decision.
type PolicyRuntime struct {
	Bundle       string           `json:"bundle"`
	Descriptors  []DescriptorFile `json:"descriptors,omitempty"`
	AllowedPeers []string         `json:"allowedPeers,omitempty"`
}

// DescriptorFile binds staged bytes to the policy's declared artifact reference.
// The gateway verifies the digest before decoding; it never fetches URL.
type DescriptorFile struct {
	URL    string `json:"url"`
	Digest string `json:"digest"`
	Path   string `json:"path"`
}

func (p PolicyRuntime) Validate(role Role) error {
	if !artifactPath(p.Bundle) {
		return fmt.Errorf("bundle must be a clean absolute file path")
	}
	for i, d := range p.Descriptors {
		if !artifactPath(d.Path) || d.URL == "" || d.Digest == "" {
			return fmt.Errorf("descriptors[%d] requires URL, digest and a clean absolute path", i)
		}
	}
	if role == Egress && len(p.AllowedPeers) == 0 {
		return fmt.Errorf("egress requires allowedPeers")
	}
	for i, peer := range p.AllowedPeers {
		u, err := url.Parse(peer)
		if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.ContainsAny(peer, "* \t\r\n") || u.Path == "" {
			return fmt.Errorf("allowedPeers[%d] must be an exact SPIFFE identity", i)
		}
	}
	return nil
}

func artifactPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}
