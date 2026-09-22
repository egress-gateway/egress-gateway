package inspection

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestSDSNotifiesTheEvictedResourcesOwnStream(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := Open(filepath.Join(root, "private"), filepath.Join(root, "public"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ca.Close() })
	s, err := NewSecretServer(ca, 1)
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	secret.RegisterSecretDiscoveryServiceServer(server, s)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	client, err := grpc.NewClient("passthrough:///private-sds", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	api := secret.NewSecretDiscoveryServiceClient(client)
	a, err := api.DeltaSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(&discovery.DeltaDiscoveryRequest{TypeUrl: secretType, ResourceNamesSubscribe: []string{"a.test"}}); err != nil {
		t.Fatal(err)
	}
	first, err := a.Recv()
	if err != nil || len(first.GetResources()) != 1 {
		t.Fatalf("first certificate: %v", err)
	}
	b, err := api.DeltaSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Send(&discovery.DeltaDiscoveryRequest{TypeUrl: secretType, ResourceNamesSubscribe: []string{"b.test"}}); err != nil {
		t.Fatal(err)
	}
	second, err := b.Recv()
	if err != nil || len(second.GetResources()) != 1 || second.Resources[0].Name != "b.test" {
		t.Fatalf("second stream: %v", err)
	}
	removed, err := a.Recv()
	if err != nil || len(removed.GetRemovedResources()) != 1 || removed.RemovedResources[0] != "a.test" {
		t.Fatalf("eviction did not reach first stream: %v", err)
	}
}

func TestSecretCacheReuseEvictionAndReissue(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca, err := Open(filepath.Join(root, "private"), filepath.Join(root, "public"), now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ca.Close() })
	s, err := NewSecretServer(ca, 2)
	if err != nil {
		t.Fatal(err)
	}
	query := func(names ...string) *discovery.DeltaDiscoveryResponse {
		t.Helper()
		r, err := s.update(&discovery.DeltaDiscoveryRequest{ResourceNamesSubscribe: names}, now)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	first := query("a.example.test").Resources[0]
	if got := query("a.example.test").Resources[0]; got != first {
		t.Fatal("warm secret was reissued")
	}
	query("b.example.test")
	r := query("c.example.test")
	if len(r.RemovedResources) != 1 || r.RemovedResources[0] != "a.example.test" || len(s.entries) != 2 {
		t.Fatal("cache did not bound retention with SDS removal")
	}
	reissued := query("a.example.test").Resources[0]
	if reissued.Version == first.Version {
		t.Fatal("evicted certificate was not reissued")
	}
	r = query("../../sign", "*.example.test", "127.0.0.1")
	if len(r.Resources) != 0 || len(r.RemovedResources) != 3 || len(s.entries) != 2 {
		t.Fatal("invalid names entered the cache")
	}
	now = now.Add(secretTTL + time.Second)
	if got := query("a.example.test").Resources[0]; got.Version == reissued.Version {
		t.Fatal("expired certificate was reused")
	}
	if _, err := s.update(&discovery.DeltaDiscoveryRequest{ResourceNamesUnsubscribe: []string{"a.example.test", "c.example.test"}}, now); err != nil {
		t.Fatal(err)
	}
	if len(s.entries) != 0 {
		t.Fatal("unsubscribed certificates retained")
	}
}

func TestSecretBatchCannotExceedCacheBound(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca, err := Open(filepath.Join(root, "private"), filepath.Join(root, "public"), now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ca.Close() })
	s, _ := NewSecretServer(ca, 1)
	r, err := s.update(&discovery.DeltaDiscoveryRequest{ResourceNamesSubscribe: []string{"a.test", "b.test", "c.test"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Resources) != 1 || len(r.RemovedResources) != 2 || len(s.entries) != 1 {
		t.Fatal("batch exceeded bounded retention")
	}
	for _, removed := range r.RemovedResources {
		if removed == r.Resources[0].Name {
			t.Fatal("resource was added and removed in one response")
		}
	}
}
