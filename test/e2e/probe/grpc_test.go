package main

import (
	"encoding/base64"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestRPCProbeUsesTLSAndReportsRPCStatus(t *testing.T) {
	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("safe", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)
	t.Cleanup(server.Stop)
	httpServer := httptest.NewUnstartedServer(server)
	httpServer.EnableHTTP2 = true
	httpServer.StartTLS()
	t.Cleanup(httpServer.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpServer.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	request := rpcRequest{Target: strings.TrimPrefix(httpServer.URL, "https://"), CA: ca, ID: "probe", Method: "Check", Payload: "safe", Timeout: 3 * time.Second}
	result, err := probeRPC(t.Context(), request)
	if err != nil || result.Code != 0 || !result.Serving {
		t.Fatalf("successful RPC: %+v %v", result, err)
	}
	request.Payload = "missing"
	result, err = probeRPC(t.Context(), request)
	if err != nil || result.Code != 5 || result.Serving {
		t.Fatalf("application failure: %+v %v", result, err)
	}
	request.Wire, request.ContentType = true, "application/grpc"
	request.Payload = base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0, 6, 10, 4, 's', 'a', 'f', 'e'})
	result, err = probeRPC(t.Context(), request)
	if err != nil || result.Code != 0 || result.HTTPStatus != 200 || result.HTTPVersion != 2 {
		t.Fatalf("wire RPC: %+v %v", result, err)
	}
}
