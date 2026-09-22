// Package daemon initializes and supervises the embedded policy runtime and its
// proxy child. It does not own Istiod's discovery or identity resources.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/inspection"
	gatewayopa "github.com/egress-gateway/egress-gateway/internal/opa"
	"github.com/open-policy-agent/opa/v1/runtime"
)

var register sync.Once

// Run treats required-service failure as terminal; container orchestration owns
// restarts. Policies are explicit local startup files; OPA_CONFIG retains bundle
// support. Arbitrary OPA CLI flags cannot override private listener ownership.
func Run(ctx context.Context, c config.Config, policies []string) (err error) {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := inspection.Directory(c.RuntimeDir, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(c.RuntimeDir, ".daemon.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("runtime directory already owned by another daemon")
	}
	if c.Role == config.Workload {
		ca, err := inspection.Open(c.StateDir, c.PublicDir, time.Now())
		if err != nil {
			return err
		}
		defer ca.Close()
	}
	register.Do(gatewayopa.RegisterPlugins)
	params := runtime.NewParams()
	params.ConfigFile = c.OPAConfig
	params.Paths = policies
	params.Addrs = new([]string{"unix://" + filepath.Join(c.RuntimeDir, "opa-api.sock")})
	params.AddrSetByUser = true
	params.UnixSocketPerm = new("0600")
	params.GracefulShutdownPeriod = 2
	params.ReadyTimeout = 20
	params.ConfigOverrides = []string{"plugins.envoy_ext_authz_grpc.addr=" + c.OPAAddress(), "plugins.envoy_ext_authz_grpc.dry-run=false", "plugins.envoy_ext_authz_grpc.enable-reflection=false"}
	embedded, err := runtime.NewRuntime(ctx, params)
	if err != nil {
		return fmt.Errorf("initialize OPA: %w", err)
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	opaDone := make(chan error, 1)
	opaExited := false
	go func() { opaDone <- embedded.Serve(runtimeCtx) }()
	defer func() {
		cancel()
		if opaExited {
			return
		}
		select {
		case <-opaDone:
		case <-time.After(5 * time.Second):
		}
	}()
	startup, cancelStartup := context.WithTimeout(ctx, 30*time.Second)
	defer cancelStartup()
	for {
		if err = checkOPA(startup, c); err == nil {
			break
		}
		select {
		case <-startup.Done():
			return fmt.Errorf("OPA startup: %w", startup.Err())
		case err = <-opaDone:
			opaExited = true
			return fmt.Errorf("OPA stopped before proxy startup: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	var proxy *exec.Cmd
	if c.ProxyMode == config.Standalone {
		generated, err := prepareEnvoy(c)
		if err != nil {
			return err
		}
		proxy = exec.Command("/usr/local/bin/envoy", "-c", generated, "--concurrency", "1")
	} else {
		role := "sidecar"
		if c.Role == config.Egress {
			role = "router"
		}
		proxy = exec.Command("/usr/local/bin/pilot-agent", "proxy", role)
	}
	proxy.Stdout, proxy.Stderr = os.Stdout, os.Stderr
	configureProcess(proxy)
	if err = proxy.Start(); err != nil {
		return fmt.Errorf("start proxy: %w", err)
	}
	defer func() {
		// Shutdown can interrupt a probe or race a service-exit notification.
		if ctx.Err() != nil {
			err = nil
		}
	}()
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- proxy.Wait() }()
	exited := false
	defer func() {
		// A process group also covers pilot-agent's Envoy child.
		_ = syscall.Kill(-proxy.Process.Pid, syscall.SIGTERM)
		if !exited {
			select {
			case <-proxyDone:
			case <-time.After(5 * time.Second):
				_ = syscall.Kill(-proxy.Process.Pid, syscall.SIGKILL)
				<-proxyDone
			}
		}
	}()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	healthy := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case err = <-opaDone:
			opaExited = true
			return fmt.Errorf("embedded OPA stopped: %v", err)
		case err = <-proxyDone:
			exited = true
			return fmt.Errorf("proxy stopped unexpectedly: %v", err)
		case <-ticker.C:
			if err = checkOPA(ctx, c); err != nil {
				return fmt.Errorf("required OPA service failed: %w", err)
			}
			err = checkProxy(ctx, c)
			if err == nil {
				healthy = true
			} else if healthy {
				return fmt.Errorf("proxy lost readiness: %w", err)
			} else if startup.Err() != nil {
				return fmt.Errorf("proxy startup timed out: %w", err)
			}
		}
	}
}

func Ready(ctx context.Context, c config.Config) error {
	if c.Role == config.Workload {
		ca, err := os.ReadFile(c.PublicCAPath())
		if err != nil {
			return err
		}
		if len(ca) == 0 {
			return errors.New("inspection CA is not published")
		}
	}
	if err := checkOPA(ctx, c); err != nil {
		return err
	}
	return checkProxy(ctx, c)
}
func checkOPA(ctx context.Context, c config.Config) error {
	if err := get(ctx, filepath.Join(c.RuntimeDir, "opa-api.sock"), "http://localhost/health?plugins&bundles"); err != nil {
		return err
	}
	// The upstream plugin may report its last healthy status after Serve fails.
	// Require its private listener to remain reachable as well.
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, "unix", filepath.Join(c.RuntimeDir, "opa.sock"))
	if err != nil {
		return err
	}
	return conn.Close()
}
func checkProxy(ctx context.Context, c config.Config) error {
	if c.ProxyMode == config.Istio {
		return get(ctx, "", "http://127.0.0.1:15021/healthz/ready")
	}
	return get(ctx, c.EnvoyAdminPath(), "http://localhost/ready")
}
func get(ctx context.Context, socket, url string) error {
	tr := &http.Transport{Proxy: nil}
	defer tr.CloseIdleConnections()
	if socket != "" {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := (&http.Client{Transport: tr, Timeout: time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("required service returned HTTP %d", res.StatusCode)
	}
	return nil
}
