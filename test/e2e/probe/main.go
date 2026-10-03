// gateway-e2e-probe produces identifiable traffic and healthy receiver controls.
// It is only built into the E2E client image, never the Gateway runtime image.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
	"golang.org/x/net/dns/dnsmessage"
)

type event struct {
	Kind      string `json:"kind"`
	Protocol  string `json:"protocol"`
	Target    string `json:"target,omitempty"`
	ID        string `json:"id,omitempty"`
	Local     string `json:"local,omitempty"`
	Attempted bool   `json:"attempted,omitzero"`
	Delivered bool   `json:"delivered,omitzero"`
	Sent      int64  `json:"sent,omitzero"`
	Error     string `json:"error,omitempty"`
	UID       int    `json:"uid"`
}

var logger = log.New(os.Stdout, "", 0)

func record(e event) { b, _ := json.Marshal(e); logger.Print(string(b)) }

func main() {
	bundleDir := flag.String("bundle-dir", "/policies", "fixture bundle directory")
	expectedStatus := flag.Int("expected-status", 200, "policy observation target status")
	interval := flag.Duration("interval", 200*time.Millisecond, "policy observation probe interval")
	mode := flag.String("mode", "send", "send, serve, policy-publisher or observe-policy")
	protocol := flag.String("protocol", "tcp", "tcp, udp, dns, quic, mesh, grpc or grpc-wire")
	target := flag.String("target", "", "receiver address")
	id := flag.String("id", "", "request identifier")
	ca := flag.String("ca", "/etc/receiver-trust/ca.pem", "public receiver CA")
	cert := flag.String("cert", "/tls/tls.crt", "receiver certificate")
	key := flag.String("key", "/tls/tls.key", "receiver key")
	timeout := flag.Duration("timeout", 3*time.Second, "attempt deadline")
	rpcMethod := flag.String("rpc-method", "Check", "health RPC method")
	payload := flag.String("payload", "safe", "health service value or base64 wire body")
	contentType := flag.String("content-type", "application/grpc", "wire request content type")
	encoding := flag.String("encoding", "", "wire gRPC encoding")
	var metadata []string
	flag.Func("metadata", "repeatable RPC metadata key=value", func(value string) error { metadata = append(metadata, value); return nil })
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var err error
	if *mode == "policy-publisher" {
		err = servePolicies(ctx, *bundleDir)
	} else if *mode == "observe-policy" {
		var result policyObservations
		result, err = observePolicy(ctx, *target, *id, *ca, *payload, *expectedStatus, *interval, *timeout)
		if encodeErr := json.NewEncoder(os.Stdout).Encode(result); err == nil {
			err = encodeErr
		}
	} else if *mode == "serve" {
		err = serve(ctx, *cert, *key)
	} else if *mode == "send" {
		if *protocol == "grpc" || *protocol == "grpc-wire" {
			var result rpcResult
			result, err = probeRPC(ctx, rpcRequest{Target: *target, ID: *id, CA: *ca, Timeout: *timeout, Method: *rpcMethod, Payload: *payload, Metadata: metadata, Wire: *protocol == "grpc-wire", ContentType: *contentType, Encoding: *encoding})
			if encodeErr := json.NewEncoder(os.Stdout).Encode(result); err == nil {
				err = encodeErr
			}
		} else {
			var e event
			e, err = send(ctx, *protocol, *target, *id, *ca, *timeout)
			record(e)
		}
	} else {
		err = errors.New("unknown mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func send(ctx context.Context, protocol, target, id, ca string, timeout time.Duration) (e event, err error) {
	e = event{Kind: "sender", Protocol: protocol, Target: target, ID: id, UID: os.Getuid()}
	defer func() {
		if err != nil {
			e.Error = err.Error()
		}
	}()
	if id == "" || strings.ContainsAny(id, "\n\r") {
		return e, errors.New("nonempty single-line id required")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if protocol == "mesh" {
		config, configErr := meshTLS(ca)
		if configErr != nil {
			return e, configErr
		}
		e.Attempted = true
		conn, dialErr := (&tls.Dialer{Config: config}).DialContext(ctx, "tcp4", target)
		if dialErr != nil {
			return e, dialErr
		}
		defer conn.Close()
		e.Local = conn.LocalAddr().String()
		_ = conn.SetDeadline(deadline)
		body := `{"action":"safe"}`
		request, _ := http.NewRequest("POST", "https://origin-https.gateway-origin.svc.cluster.local/body", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Request-Id", id)
		request.Close = true
		if err = request.Write(conn); err != nil {
			return e, err
		}
		reply, readErr := http.ReadResponse(bufio.NewReader(conn), request)
		if readErr != nil {
			return e, readErr
		}
		defer reply.Body.Close()
		e.Delivered = true
		return e, nil
	}
	if protocol == "quic" {
		roots := x509.NewCertPool()
		data, readErr := os.ReadFile(ca)
		if readErr != nil {
			return e, readErr
		}
		if !roots.AppendCertsFromPEM(data) {
			return e, errors.New("invalid receiver root")
		}
		remote, resolveErr := net.ResolveUDPAddr("udp4", target)
		if resolveErr != nil {
			return e, resolveErr
		}
		socket, listenErr := net.ListenPacket("udp4", "0.0.0.0:0")
		if listenErr != nil {
			return e, listenErr
		}
		defer socket.Close()
		counted := &packetCounter{PacketConn: socket}
		e.Local = socket.LocalAddr().String()
		e.Attempted = true
		defer func() { e.Sent = counted.sent.Load() }()
		conn, dialErr := quic.Dial(ctx, counted, remote, &tls.Config{RootCAs: roots, ServerName: "receiver.gateway-origin.svc.cluster.local", NextProtos: []string{"gateway-e2e"}, MinVersion: tls.VersionTLS13}, &quic.Config{HandshakeIdleTimeout: timeout, MaxIdleTimeout: timeout})
		if dialErr != nil {
			return e, dialErr
		}
		defer conn.CloseWithError(0, "complete")
		stream, streamErr := conn.OpenStreamSync(ctx)
		if streamErr != nil {
			return e, streamErr
		}
		_ = stream.SetDeadline(deadline)
		if _, err = io.WriteString(stream, id+"\n"); err != nil {
			return e, err
		}
		reply, readErr := bufio.NewReader(stream).ReadString('\n')
		if readErr != nil {
			return e, readErr
		}
		if reply != id+"\n" {
			return e, errors.New("QUIC reply mismatch")
		}
		e.Delivered = true
		return e, nil
	}
	network := protocol
	if protocol == "dns" {
		network = "udp"
	}
	if network != "tcp" && network != "udp" {
		return e, errors.New("unknown protocol")
	}
	e.Attempted = true
	conn, dialErr := (&net.Dialer{}).DialContext(ctx, network+"4", target)
	if dialErr != nil {
		return e, dialErr
	}
	defer conn.Close()
	e.Local = conn.LocalAddr().String()
	_ = conn.SetDeadline(deadline)
	payload := []byte(id + "\n")
	if protocol == "dns" {
		payload, err = dnsQuery(id)
		if err != nil {
			return e, err
		}
	}
	n, writeErr := conn.Write(payload)
	e.Sent = int64(n)
	if writeErr != nil {
		return e, writeErr
	}
	response := make([]byte, 2048)
	n, readErr := conn.Read(response)
	if readErr != nil {
		return e, readErr
	}
	if protocol == "dns" {
		var message dnsmessage.Message
		if err = message.Unpack(response[:n]); err != nil {
			return e, err
		}
		if !message.Response || message.ID != binary.BigEndian.Uint16(payload[:2]) || len(message.Questions) != 1 || message.Questions[0].Name.String() != id+".probe.test." {
			return e, errors.New("DNS reply mismatch")
		}
	} else if string(response[:n]) != string(payload) {
		return e, errors.New("receiver reply mismatch")
	}
	e.Delivered = true
	return e, nil
}

func meshTLS(ca string) (*tls.Config, error) {
	data, err := os.ReadFile(ca)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, errors.New("invalid mesh root")
	}
	// Mesh certificates identify a SPIFFE URI, not a DNS name. Replace the DNS
	// verifier with full chain verification plus the exact expected URI identity.
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "origin.gateway-origin.svc.cluster.local", InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("missing gateway certificate")
		}
		intermediates := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			intermediates.AddCert(certificate)
		}
		if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return err
		}
		for _, uri := range state.PeerCertificates[0].URIs {
			if uri.String() == "spiffe://cluster.local/ns/gateway-test/sa/egress" {
				return nil
			}
		}
		return errors.New("unexpected gateway URI identity")
	}}, nil
}

type packetCounter struct {
	net.PacketConn
	sent atomic.Int64
}

func (p *packetCounter) WriteTo(b []byte, a net.Addr) (int, error) {
	n, err := p.PacketConn.WriteTo(b, a)
	if n > 0 {
		p.sent.Add(int64(n))
	}
	return n, err
}
func dnsQuery(id string) ([]byte, error) {
	name, err := dnsmessage.NewName(id + ".probe.test.")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(id))
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(sum[:2]), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	return m.Pack()
}

func serve(ctx context.Context, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	failures := make(chan error, 6)
	start := func(fn func() error) {
		wg.Go(func() {
			if err := fn(); err != nil && ctx.Err() == nil {
				failures <- err
			}
		})
	}
	for _, port := range []string{"8081", "8444"} {
		start(func() error { return serveTCP(ctx, ":"+port) })
	}
	for _, port := range []string{"5353", "7777", "53"} {
		start(func() error { return serveUDP(ctx, ":"+port, port == "53") })
	}
	start(func() error { return serveQUIC(ctx, cert) })
	select {
	case <-ctx.Done():
	case err = <-failures:
	}
	cancel()
	wg.Wait()
	return err
}
func serveTCP(ctx context.Context, address string) error {
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				return
			}
			record(event{Kind: "receiver", Protocol: "tcp", Target: address, ID: strings.TrimSpace(line), Local: conn.RemoteAddr().String(), Delivered: true})
			_, _ = io.WriteString(conn, line)
		}()
	}
}
func serveUDP(ctx context.Context, address string, dns bool) error {
	socket, err := net.ListenPacket("udp4", address)
	if err != nil {
		return err
	}
	defer socket.Close()
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	for {
		data := make([]byte, 2048)
		n, remote, err := socket.ReadFrom(data)
		if err != nil {
			return err
		}
		data = data[:n]
		id := strings.TrimSpace(string(data))
		protocol := "udp"
		if dns {
			var m dnsmessage.Message
			if err = m.Unpack(data); err != nil || len(m.Questions) != 1 {
				continue
			}
			id = strings.TrimSuffix(m.Questions[0].Name.String(), ".probe.test.")
			protocol = "dns"
			m.Response = true
			m.RCode = dnsmessage.RCodeNameError
			data, err = m.Pack()
			if err != nil {
				return err
			}
		}
		record(event{Kind: "receiver", Protocol: protocol, Target: address, ID: id, Local: remote.String(), Delivered: true})
		_, _ = socket.WriteTo(data, remote)
	}
}
func serveQUIC(ctx context.Context, cert tls.Certificate) error {
	listener, err := quic.ListenAddr("0.0.0.0:443", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"gateway-e2e"}, MinVersion: tls.VersionTLS13}, &quic.Config{MaxIdleTimeout: 4 * time.Second})
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		go func() {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			_ = stream.SetDeadline(time.Now().Add(4 * time.Second))
			line, err := bufio.NewReader(stream).ReadString('\n')
			if err != nil {
				return
			}
			record(event{Kind: "receiver", Protocol: "quic", Target: ":443", ID: strings.TrimSpace(line), Local: conn.RemoteAddr().String(), Delivered: true})
			_, _ = io.WriteString(stream, line)
			_ = stream.Close()
		}()
	}
}
