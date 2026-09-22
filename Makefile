GO ?= go
IMAGE ?= egress-gateway:dev

.PHONY: build fmt fmt-check vet test integration check image smoke clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/gateway-daemon ./cmd/gateway-daemon
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/gateway-opa ./cmd/gateway-opa

fmt:
	$(GO) fmt ./...

fmt-check:
	@test -z "$$(gofmt -l $$(find cmd config internal test examples -name '*.go'))" || (echo 'Run make fmt'; exit 1)

vet:
	$(GO) vet ./...

test:
	$(GO) test -race ./...

integration: build
	GATEWAY_OPA_BIN="$(CURDIR)/bin/gateway-opa" $(GO) test -race -tags=integration -count=1 ./test/integration

check: fmt-check vet test integration

image:
	docker build -f image/Dockerfile -t $(IMAGE) .

smoke:
	GATEWAY_IMAGE=$(IMAGE) bash test/image/smoke.sh
	GATEWAY_IMAGE=$(IMAGE) $(GO) test -tags=image -count=1 -timeout=5m -v ./test/image/https

clean:
	rm -f bin/gateway-opa bin/gateway-daemon coverage.out
