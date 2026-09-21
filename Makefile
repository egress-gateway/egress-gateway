GO ?= go
IMAGE ?= egress-gateway:dev

.PHONY: build fmt fmt-check vet test integration check image smoke clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/gateway-opa ./cmd/gateway-opa

fmt:
	$(GO) fmt ./...

fmt-check:
	@test -z "$$(gofmt -l $$(find cmd internal test examples -name '*.go'))" || (echo 'Run make fmt'; exit 1)

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
	bash test/image/smoke.sh

clean:
	rm -f bin/gateway-opa coverage.out
