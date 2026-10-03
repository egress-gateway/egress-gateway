// The local example upstream makes successful forwarding distinguishable from a proxy denial.
package main

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// main serves the fixture response used by the local gateway example.
func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("origin path=%s request_id=%s", r.URL.Path, r.Header.Get("X-Request-Id"))
		fmt.Fprintf(w, "upstream reached: %s\n", r.URL.Path)
	})
	rpc := grpc.NewServer()
	health.RegisterHealthServer(rpc, &healthServer{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			rpc.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: ":8080", Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	if certificate := os.Getenv("ORIGIN_TLS_CERT"); certificate != "" {
		go func(plain *http.Server) { log.Fatal(plain.ListenAndServe()) }(server)
		server = &http.Server{Addr: ":8443", Handler: handler, ReadHeaderTimeout: 5 * time.Second}
		log.Fatal(server.ListenAndServeTLS(certificate, os.Getenv("ORIGIN_TLS_KEY")))
	}
	log.Fatal(server.ListenAndServe())
}

// healthServer records protected operations and provides healthy RPC controls.
type healthServer struct {
	health.UnimplementedHealthServer
}

func (*healthServer) Check(ctx context.Context, req *health.HealthCheckRequest) (*health.HealthCheckResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	log.Printf("origin rpc=grpc.health.v1.Health/Check request_id=%s", strings.Join(md.Get("x-request-id"), ","))
	return &health.HealthCheckResponse{Status: health.HealthCheckResponse_SERVING}, nil
}

func (*healthServer) Watch(_ *health.HealthCheckRequest, stream grpc.ServerStreamingServer[health.HealthCheckResponse]) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	log.Printf("origin rpc=grpc.health.v1.Health/Watch request_id=%s", strings.Join(md.Get("x-request-id"), ","))
	return stream.Send(&health.HealthCheckResponse{Status: health.HealthCheckResponse_SERVING})
}
