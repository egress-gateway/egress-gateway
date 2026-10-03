package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type rpcRequest struct {
	Target, ID, CA, Method, Payload, ContentType, Encoding string
	Metadata                                               []string
	Timeout                                                time.Duration
	Wire                                                   bool
}

type rpcResult struct {
	ID          string  `json:"id"`
	Code        int     `json:"code"`
	Serving     bool    `json:"serving"`
	HTTPStatus  int     `json:"httpStatus"`
	HTTPVersion int     `json:"httpVersion"`
	ElapsedMS   float64 `json:"elapsedMs"`
}

func probeRPC(ctx context.Context, request rpcRequest) (result rpcResult, err error) {
	result.ID, result.Code = request.ID, -1
	start := time.Now()
	defer func() { result.ElapsedMS = float64(time.Since(start).Microseconds()) / 1000 }()
	ctx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	raw, err := os.ReadFile(request.CA)
	if err != nil {
		return result, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return result, errors.New("invalid RPC root")
	}
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	md := metadata.Pairs("x-request-id", request.ID)
	for _, field := range request.Metadata {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key == "" {
			return result, errors.New("metadata must be key=value")
		}
		md.Append(strings.ToLower(key), value)
	}
	if request.Wire {
		body, err := base64.StdEncoding.DecodeString(request.Payload)
		if err != nil {
			return result, err
		}
		req, err := http.NewRequestWithContext(ctx, "POST", "https://"+request.Target+"/grpc.health.v1.Health/"+request.Method, bytes.NewReader(body))
		if err != nil {
			return result, err
		}
		for key, values := range md {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		req.Header.Set("Content-Type", request.ContentType)
		if request.Encoding != "" {
			req.Header.Set("Grpc-Encoding", request.Encoding)
		}
		transport := &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}
		defer transport.CloseIdleConnections()
		response, err := (&http.Client{Transport: transport}).Do(req)
		if err != nil {
			return result, err
		}
		defer response.Body.Close()
		if _, err = io.Copy(io.Discard, response.Body); err != nil {
			return result, err
		}
		result.HTTPStatus, result.HTTPVersion = response.StatusCode, response.ProtoMajor
		code := response.Trailer.Get("Grpc-Status")
		if code == "" {
			code = response.Header.Get("Grpc-Status")
		}
		if code != "" {
			result.Code, err = strconv.Atoi(code)
		}
		return result, err
	}
	conn, err := grpc.NewClient("passthrough:///"+request.Target, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return result, err
	}
	defer conn.Close()
	ctx = metadata.NewOutgoingContext(ctx, md)
	client := health.NewHealthClient(conn)
	var reply *health.HealthCheckResponse
	switch request.Method {
	case "Check":
		reply, err = client.Check(ctx, &health.HealthCheckRequest{Service: request.Payload})
	case "Watch":
		var stream grpc.ServerStreamingClient[health.HealthCheckResponse]
		stream, err = client.Watch(ctx, &health.HealthCheckRequest{Service: request.Payload})
		if err == nil {
			reply, err = stream.Recv()
		}
	default:
		return result, errors.New("unsupported fixture RPC")
	}
	result.Code = int(status.Code(err))
	result.Serving = reply != nil && reply.Status == health.HealthCheckResponse_SERVING
	return result, nil
}
