FROM golang:1.26.7-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY test/e2e/probe ./test/e2e/probe
RUN CGO_ENABLED=0 go build -trimpath -o /probe ./test/e2e/probe
FROM curlimages/curl:8.10.1
COPY --from=build /probe /usr/local/bin/gateway-e2e-probe
