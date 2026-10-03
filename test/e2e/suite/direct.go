package suite

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/egress-gateway/egress-gateway/test/e2e/environment"
)

func (s *scenario) directEntrypoints() error {
	originUID, err := s.singlePodUID("gateway-origin", "app=origin-https")
	if err != nil {
		return err
	}
	cfg := s.env.Config
	cfg.Artifacts = filepath.Join(cfg.Artifacts, "cases", s.id)
	if err = environment.New(cfg).Operation(s.ctx, "direct-entrypoints"); err != nil {
		return err
	}
	afterUID, err := s.singlePodUID("gateway-origin", "app=origin-https")
	if err != nil {
		return err
	}
	if afterUID != originUID {
		return errors.New("origin changed during direct entrypoint probes")
	}
	dir := filepath.Join(cfg.Artifacts, "direct")
	origin, err := readText(filepath.Join(dir, "origin.log"))
	if err != nil {
		return err
	}
	for _, point := range []string{"before", "after"} {
		control, err := readText(filepath.Join(dir, "receiver-"+point+".txt"))
		if err != nil {
			return err
		}
		if !strings.Contains(control, "upstream reached: /body") || !hasRequest(origin, s.id+"-direct-"+point) {
			return errors.New("direct probe lacks healthy receiver control")
		}
	}
	for _, port := range []string{"8080", "8443"} {
		path := filepath.Join(dir, port)
		response, err := readText(filepath.Join(path, "business-response.txt"))
		if err != nil {
			return err
		}
		rc, err := readText(filepath.Join(path, "business-exit.txt"))
		if err != nil {
			return err
		}
		if strings.Contains(response, "upstream reached:") || strings.TrimSpace(rc) == "0" {
			return fmt.Errorf("direct gateway %s did not reject opaque business transport: %s", port, response)
		}
		before, err := readText(filepath.Join(path, "business-before.txt"))
		if err != nil {
			return err
		}
		after, err := readText(filepath.Join(path, "business-after.txt"))
		if err != nil {
			return err
		}
		a, err := blackholeCount(before)
		if err != nil {
			return err
		}
		b, err := blackholeCount(after)
		if err != nil {
			return err
		}
		if b <= a {
			return errors.New("direct gateway attempt lacks executed local rejection")
		}
		var unverified probeResult
		if err = readJSON(filepath.Join(path, "unverified.json"), &unverified); err != nil {
			return err
		}
		rc, err = readText(filepath.Join(path, "unverified-exit.txt"))
		if err != nil {
			return err
		}
		if !unverified.Attempted || unverified.Delivered || unverified.Error == "" || strings.TrimSpace(rc) != "1" {
			return errors.New("unverified mesh client was not rejected")
		}
		before, err = readText(filepath.Join(path, "identity-before.txt"))
		if err != nil {
			return err
		}
		after, err = readText(filepath.Join(path, "identity-after.txt"))
		if err != nil {
			return err
		}
		a, err = noCertificateCount(before)
		if err != nil {
			return err
		}
		b, err = noCertificateCount(after)
		if err != nil {
			return err
		}
		if b <= a {
			return errors.New("gateway rejection not attributable to absent client identity")
		}
		for _, kind := range []string{"business", "unverified"} {
			if hasRequest(origin, s.id+"-"+kind+"-"+port) {
				return errors.New("direct gateway request reached origin")
			}
		}
	}
	return nil
}
func noCertificateCount(text string) (uint64, error) {
	var total uint64
	found := false
	for line := range strings.SplitSeq(text, "\n") {
		name, value, ok := strings.Cut(line, ": ")
		if !ok || !strings.HasSuffix(name, ".ssl.fail_verify_no_cert") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, err
		}
		total += n
		found = true
	}
	if !found {
		return 0, errors.New("missing gateway client-certificate rejection counter")
	}
	return total, nil
}
