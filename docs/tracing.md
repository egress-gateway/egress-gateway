# OpenTelemetry tracing

The two consumers have separate configuration paths. A future controller may
produce both from one desired configuration; this image does not coordinate them.

| Consumer | Configuration owner and input |
| --- | --- |
| Istio Envoy (workload and egress) | External Istio `extensionProviders`, `Telemetry` and any required native `EnvoyFilter`; Istiod sends xDS through pilot-agent |
| Embedded OPA (both roles) | Standard `OTEL_*` environment variables, adapted before OPA initialization to native `distributed_tracing` |
| Standalone Envoy | The existing `ENVOY_CONFIG` native bootstrap, including tracer and exporter cluster |

OPA environment variables never generate Envoy tracing configuration. Setting them
alongside Istio configuration does not install a second Envoy exporter. Conversely,
Istio configuration does not configure OPA. Alignment is the configuration producer's
responsibility; the daemon does not read back pilot-agent or Envoy configuration.

## OPA environment contract

Empty or whitespace-only values are treated as unset. For each OTLP setting,
nonempty `OTEL_EXPORTER_OTLP_TRACES_<setting>` overrides
`OTEL_EXPORTER_OTLP_<setting>`; an empty trace-specific value falls back to the
general value. Changes take effect after restart.

With no supported nonempty tracing input, the mounted OPA configuration remains
unchanged. With environment input, only its `distributed_tracing` section is
replaced; policies, bundles, other plugins and private socket enforcement remain.
This prevents merging conflicting native and environment exporter settings.

| Variable / OTLP suffix | Supported behavior |
| --- | --- |
| `OTEL_SDK_DISABLED=true` or `OTEL_TRACES_EXPORTER=none` | Disable OPA exporter, including one previously configured in native YAML |
| `OTEL_TRACES_EXPORTER=otlp` | Enable the upstream OTLP exporter |
| `PROTOCOL` | `grpc` or `http/protobuf`; default `http/protobuf` |
| `ENDPOINT` | Absolute `http://` or `https://` URL; default localhost:4317 for gRPC or localhost:4318 for HTTP; no userinfo, query or fragment |
| `HEADERS` | Comma-separated `key=value` pairs; percent-encoded values, consumed directly by upstream; use for Collector authentication |
| `CERTIFICATE` | PEM trust root file for the Collector |
| `CLIENT_CERTIFICATE`, `CLIENT_KEY` | Paired PEM client certificate and private key for Collector mTLS |
| `INSECURE` | URL scheme determines transport; `true` with HTTPS is rejected because the pinned HTTP exporter otherwise downgrades it |
| `COMPRESSION` | `none` or `gzip`, upstream exporter |
| `TIMEOUT` | Positive milliseconds, upstream exporter |
| `OTEL_SERVICE_NAME` | Explicit service name; takes precedence over resource `service.name`; OPA default is `opa` |
| `OTEL_RESOURCE_ATTRIBUTES` | `service.name`, `service.version`, `service.instance.id`, `service.namespace`, `deployment.environment` only |
| `OTEL_TRACES_SAMPLER` | Native equivalents `parentbased_always_on`, `parentbased_always_off`, `parentbased_traceidratio` |
| `OTEL_TRACES_SAMPLER_ARG` | Ratio in [0,1], only with `parentbased_traceidratio` |
| `OTEL_BSP_SCHEDULE_DELAY`, `OTEL_BSP_EXPORT_TIMEOUT` | Positive milliseconds |
| `OTEL_BSP_MAX_QUEUE_SIZE`, `OTEL_BSP_MAX_EXPORT_BATCH_SIZE` | Positive counts; batch size must not exceed queue size |

HTTP general endpoints are base URLs: the upstream exporter appends `/v1/traces`.
Trace-specific HTTP endpoints are used as-is, including the path; use
`https://collector:4318/v1/traces`, not merely the host, for that variable. gRPC
endpoints must have no path other than `/`. TLS verification is always enabled
for HTTPS; disabling certificate verification is not exposed by this adapter.
Collector trust is separate from inspection, Istio identity and origin trust.

Malformed or unsupported settings in this supported input surface fail startup
with variable names and no supplied values. Both general and signal-specific
endpoint/header inputs are validated before the SDK reads them, including shadowed
values, to prevent upstream parse errors from exposing credentials. Resource attribute values are percent-decoded. Header values
are not written to the generated private OPA configuration. Treat certificate and
key mounts as proxy-private; never mount Collector client keys into the application.

OPA 1.20.2 fixes its sampler to a parent-based ratio sampler and constructs a
limited resource itself. Other samplers, arbitrary resource attributes (including
`deployment.environment.name`) and `OTEL_PROPAGATORS` are not supported and are
reported explicitly. The official OPA-Envoy plugin already propagates W3C trace
context/baggage and B3. This repository supplies no propagation middleware,
Trace ID generator, sampling algorithm or production sampling policy.

The upstream batch exporter remains asynchronous and bounded, with blocking
explicitly disabled. Collector outages may lose spans after the queue fills;
they do not change authorization decisions, forwarding or readiness. Native OPA
configuration without environment adaptation retains its upstream behavior.

## Configuration examples

For OPA, independently of the Envoy mode:

```sh
OTEL_TRACES_EXPORTER=otlp
OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/protobuf
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://collector.example:4318/v1/traces
OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE=/etc/collector/ca.pem
OTEL_SERVICE_NAME=workload-opa
```

Choose sampling inputs outside this repository. The tests use deterministic
sampling only to make collection assertions repeatable.

For Istio, see `test/e2e/config/istiod-values.yaml` and `tracing.yaml`. The custom
inspection listener in `https.yaml` explicitly sets the native tracing provider:
adding a listener with an EnvoyFilter requires configuring that listener, too.
For standalone, the component fixture augments its existing native bootstrap with
`envoy.tracers.opentelemetry` and an OTLP cluster. No additional runtime mode or
public configuration protocol is introduced.

## Acceptance evidence

`make smoke` includes the existing two-role HTTPS authorization fixture with:

- Disabled tracing, both OTLP transports, authenticated Collector mTLS, and
  distinct Envoy/OPA receivers to verify configuration ownership.
- Incoming W3C context and a request without context; Collector OTLP JSON must
  contain both Envoy and OPA authorization spans with matching trace IDs and
  correct parent chains.
- Collector outage with more requests than the configured OPA queue size,
  both denial paths, successful forwarding and readiness.
- Request latency and collected span/payload volumes for disabled/enabled/outage
  runs. Collection includes background OPA health probes; these are fixture
  measurements, not production performance guarantees or exact wire-byte counts.

`make e2e` uses real Istiod, CNI and the same gateway image for both roles. HTTP
and inspected HTTPS must reach the Collector with linked proxy spans while all
existing identity/TLS assertions continue to pass. OPA authorization spans remain
component assertions; the minimal kind fixture has no authorization filters.
The Collector uses an upstream image pinned by version and digest. Its structured
OTLP file output is acceptance evidence, not daemon logs or configuration parsing.

References: [OTLP environment contract](https://opentelemetry.io/docs/specs/otel/protocol/exporter/),
[OPA tracing configuration](https://www.openpolicyagent.org/docs/configuration#distributed-tracing),
[Istio OpenTelemetry tracing](https://istio.io/latest/docs/tasks/observability/distributed-tracing/opentelemetry/).
