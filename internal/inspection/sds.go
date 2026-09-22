package inspection

import (
	"container/list"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

const secretType = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
const secretTTL = 10 * time.Minute
const maxRequestNames = 128

type cachedSecret struct {
	name     string
	resource *discovery.Resource
	expires  time.Time
}

type secretWatch struct {
	names   map[string]struct{}
	updates chan *discovery.DeltaDiscoveryResponse
	errors  chan error
}

// SecretServer serves the single local Envoy over a private Unix socket. It
// owns only inspection certificates, never Istio's workload identity resources.
type SecretServer struct {
	secret.UnimplementedSecretDiscoveryServiceServer
	authority *Authority
	capacity  int
	mu        sync.Mutex
	watches   map[*secretWatch]struct{}
	entries   map[string]*list.Element
	lru       list.List
	version   uint64
	nonce     uint64
}

func NewSecretServer(authority *Authority, capacity int) (*SecretServer, error) {
	if authority == nil || capacity < 1 || capacity > maxRequestNames {
		return nil, errors.New("invalid inspection certificate capacity")
	}
	return &SecretServer{authority: authority, capacity: capacity, entries: make(map[string]*list.Element), watches: make(map[*secretWatch]struct{})}, nil
}

func (s *SecretServer) DeltaSecrets(stream secret.SecretDiscoveryService_DeltaSecretsServer) error {
	w := &secretWatch{names: make(map[string]struct{}), updates: make(chan *discovery.DeltaDiscoveryResponse, 4), errors: make(chan error, 1)}
	s.mu.Lock()
	if len(s.watches) >= 2*s.capacity {
		s.mu.Unlock()
		return status.Error(codes.ResourceExhausted, "inspection SDS subscription limit")
	}
	s.watches[w] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.watches, w); s.mu.Unlock() }()
	// SDS creates independent streams for different certificate resources. One
	// sender per stream delivers both replies and evictions caused by other names.
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				w.fail(err)
				return
			}
			if req.ErrorDetail != nil {
				w.fail(status.Error(codes.FailedPrecondition, "Envoy rejected inspection certificate configuration"))
				return
			}
			if req.TypeUrl != secretType || len(req.ResourceNamesSubscribe)+len(req.InitialResourceVersions) > maxRequestNames || len(req.ResourceNamesUnsubscribe) > maxRequestNames {
				w.fail(status.Error(codes.InvalidArgument, "unsupported inspection SDS request"))
				return
			}
			if err := s.process(w, req, time.Now()); err != nil {
				w.fail(err)
				return
			}
		}
	}()
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case err := <-w.errors:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case response := <-w.updates:
			if err := stream.Send(response); err != nil {
				return err
			}
		}
	}
}

func (w *secretWatch) fail(err error) {
	select {
	case w.errors <- err:
	default:
	}
}
func (w *secretWatch) enqueue(response *discovery.DeltaDiscoveryResponse) {
	if len(response.Resources)+len(response.RemovedResources) == 0 {
		return
	}
	select {
	case w.updates <- response:
	default:
		w.fail(status.Error(codes.ResourceExhausted, "inspection SDS consumer is not draining updates"))
	}
}

func (s *SecretServer) process(w *secretWatch, req *discovery.DeltaDiscoveryRequest, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, active := s.watches[w]; !active {
		return status.Error(codes.Canceled, "inspection subscription closed")
	}
	for _, name := range req.ResourceNamesUnsubscribe {
		delete(w.names, name)
	}
	for _, name := range req.ResourceNamesSubscribe {
		w.names[name] = struct{}{}
	}
	for name := range req.InitialResourceVersions {
		w.names[name] = struct{}{}
	}
	if len(w.names) > maxRequestNames {
		return status.Error(codes.ResourceExhausted, "inspection subscription name limit")
	}
	response, err := s.updateLocked(req, now)
	if err != nil {
		return status.Error(codes.Internal, "inspection certificate issuance failed")
	}
	for watcher := range s.watches {
		event := &discovery.DeltaDiscoveryResponse{TypeUrl: secretType, Nonce: response.Nonce, SystemVersionInfo: response.SystemVersionInfo}
		for _, resource := range response.Resources {
			if _, interested := watcher.names[resource.Name]; interested {
				event.Resources = append(event.Resources, resource)
			}
		}
		for _, name := range response.RemovedResources {
			if _, interested := watcher.names[name]; interested {
				event.RemovedResources = append(event.RemovedResources, name)
				delete(watcher.names, name)
			}
		}
		watcher.enqueue(event)
	}
	return nil
}

func (s *SecretServer) update(req *discovery.DeltaDiscoveryRequest, now time.Time) (*discovery.DeltaDiscoveryResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateLocked(req, now)
}

func (s *SecretServer) updateLocked(req *discovery.DeltaDiscoveryRequest, now time.Time) (*discovery.DeltaDiscoveryResponse, error) {
	for _, name := range req.ResourceNamesUnsubscribe {
		interested := false
		for w := range s.watches {
			if _, ok := w.names[name]; ok {
				interested = true
				break
			}
		}
		if !interested {
			s.remove(name)
		}
	}
	requested := make(map[string]struct{}, len(req.ResourceNamesSubscribe)+len(req.InitialResourceVersions))
	for _, name := range req.ResourceNamesSubscribe {
		requested[name] = struct{}{}
	}
	for name := range req.InitialResourceVersions {
		requested[name] = struct{}{}
	}
	resources := make(map[string]*discovery.Resource)
	removed := make(map[string]struct{})
	for _, name := range slices.Sorted(maps.Keys(requested)) {
		canonical, err := canonicalName(name)
		if err != nil {
			removed[name] = struct{}{}
			continue
		}
		if e, ok := s.entries[name]; ok {
			entry := e.Value.(cachedSecret)
			if now.Before(entry.expires) {
				s.lru.MoveToFront(e)
				resources[name] = entry.resource
				continue
			}
			s.remove(name)
		}
		certificate, key, err := s.authority.issue(canonical, now)
		if err != nil {
			return nil, err
		}
		value, err := anypb.New(&tlsv3.Secret{Name: name, Type: &tlsv3.Secret_TlsCertificate{TlsCertificate: &tlsv3.TlsCertificate{
			CertificateChain: &core.DataSource{Specifier: &core.DataSource_InlineBytes{InlineBytes: certificate}},
			PrivateKey:       &core.DataSource{Specifier: &core.DataSource_InlineBytes{InlineBytes: key}},
		}}})
		if err != nil {
			return nil, err
		}
		s.version++
		resource := &discovery.Resource{Name: name, Version: fmt.Sprint(s.version), Resource: value, Ttl: durationpb.New(secretTTL)}
		if s.lru.Len() == s.capacity {
			evicted := s.lru.Back().Value.(cachedSecret).name
			s.remove(evicted)
			removed[evicted] = struct{}{}
			delete(resources, evicted)
		}
		s.entries[name] = s.lru.PushFront(cachedSecret{name, resource, now.Add(secretTTL)})
		resources[name] = resource
	}
	s.nonce++
	response := &discovery.DeltaDiscoveryResponse{TypeUrl: secretType, Nonce: fmt.Sprint(s.nonce), SystemVersionInfo: "inspection"}
	for _, name := range slices.Sorted(maps.Keys(resources)) {
		response.Resources = append(response.Resources, resources[name])
	}
	response.RemovedResources = slices.Sorted(maps.Keys(removed))
	return response, nil
}

func (s *SecretServer) remove(name string) {
	if e, ok := s.entries[name]; ok {
		s.lru.Remove(e)
		delete(s.entries, name)
	}
}
