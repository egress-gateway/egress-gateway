# syntax=docker/dockerfile:1
ARG GO_IMAGE=golang:1.26.7-bookworm
ARG ISTIO_IMAGE=istio/proxyv2:1.31.0
ARG ENVOY_IMAGE=envoyproxy/envoy:contrib-v1.39.0@sha256:7aca259c848ed1b0355d91227056155fb78ad864680efe684a0e9f5c032b857f

FROM ${ENVOY_IMAGE} AS envoy

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY config ./config
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -o /out/gateway-daemon ./cmd/gateway-daemon

FROM ${ISTIO_IMAGE}
COPY --from=envoy /usr/local/bin/envoy /usr/local/bin/envoy
COPY --from=build /out/gateway-daemon /usr/local/bin/gateway-daemon
COPY --chmod=0755 image/entrypoint.sh /usr/local/bin/gateway-entrypoint
COPY --chmod=0755 image/management-init.sh /usr/local/bin/gateway-management-init
COPY --chmod=0755 image/healthcheck.sh /usr/local/bin/gateway-healthcheck
COPY configs/opa /etc/gateway/opa
COPY image/envoy-limits.json /etc/gateway/envoy-limits.json
ENV ISTIO_BOOTSTRAP_OVERRIDE=/etc/gateway/envoy-limits.json
ENV PROXY_CONFIG='{"proxyMetadata":{"ISTIO_META_GLOBAL_DOWNSTREAM_MAX_CONNECTIONS":"64"}}'
ENV GATEWAY_ROLE=workload GATEWAY_PROXY_MODE=istio
USER root
RUN mkdir -p /var/lib/gateway/private /run/gateway/private /run/gateway/trust \
    && chown -R 1337:1337 /var/lib/gateway /run/gateway \
    && chmod 0700 /var/lib/gateway/private /run/gateway/private
USER 1337:1337
HEALTHCHECK --interval=5s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/gateway-healthcheck"]
ENTRYPOINT ["/usr/local/bin/gateway-entrypoint"]
CMD []
