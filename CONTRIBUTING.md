# Contributing

Use English for repository content and GitHub communication, including documentation, comments, issues, and pull requests.

Use Go 1.26+ and Docker Compose v2. Run `make check` to validate Go code, and `make smoke` when changing images, startup, configuration, or plugin integration. CI uses the same entry points.

| Command | Purpose |
|---|---|
| `make build` | Build `bin/gateway-daemon` and the development OPA test utility |
| `make fmt` | Format Go files |
| `make check` | Check formatting, run vet and race detection, and test a real OPA process |
| `make image` | Build `egress-gateway:dev` |
| `make smoke` | Build and verify the image in both roles, then clean up the Compose project |

Integration tests run separately with the `integration` build tag; `go test ./...` does not run all component tests. Image smoke tests use host port 18080 by default, configurable through `GATEWAY_PORT`. If the port is occupied, choose another port rather than stopping unrelated services.

OPA extensions live under `internal/` and are explicitly registered in `internal/opa/register.go`. Do not import controller code, duplicate shared policy semantics in the gateway, or hardcode user-specific service addresses, certificates, or credentials in templates.

New plugins require a concrete use case and behavioral tests. Use the OPA Factory / Plugin lifecycle and reuse its Bundle / Discovery / Status capabilities where possible. Do not add interfaces or tests without behavior merely to fill placeholder directories.

When updating upstream dependencies, check the OPA / OPA-Envoy versions in `go.mod` together with the Go / Istio image versions in the Dockerfile, and rerun affected validation. Keep the public configuration contract in this existing module; do not add SDK modules, `go.work`, or local `replace` directives.

The project license has not yet been selected. This scaffold leaves that decision to the owner.
