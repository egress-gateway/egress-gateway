# syntax=docker/dockerfile:1
ARG GO_IMAGE=golang:1.26.7-bookworm
ARG ISTIO_IMAGE=istio/proxyv2:1.31.0

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -o /out/gateway-opa ./cmd/gateway-opa

FROM ${ISTIO_IMAGE}
COPY --from=build /out/gateway-opa /usr/local/bin/gateway-opa
COPY --chmod=0755 image/entrypoint.sh /usr/local/bin/gateway-entrypoint
COPY --chmod=0755 image/healthcheck.sh /usr/local/bin/gateway-healthcheck
COPY configs/opa /etc/gateway/opa
ENV GATEWAY_ROLE=workload GATEWAY_PROXY_MODE=istio
USER 1337:1337
HEALTHCHECK --interval=5s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/gateway-healthcheck"]
ENTRYPOINT ["/usr/local/bin/gateway-entrypoint"]
CMD []
