# Repository guidelines

- Use English for all repository content and GitHub communication, including documentation, comments, issues, and pull requests.
- This repository owns the custom OPA runtime, Envoy integration, single image, and component validation. Public policy contracts, policy normalization/decoding, descriptor handling and the OPA policy extension belong in `egress-gateway-policy`; CRDs, bindings, and admission belong in the controller. Calico installation and platform permission validation belong in networking. Gateway owns Istio integration, trusted Pod composition, private runtime resources and governance startup ordering. This repository consumes networking through its public enrollment and installation contracts and owns its kind/Istio integration fixture.
- Read the README, relevant documentation, and existing implementation first. Preserve unrelated changes; placeholder directories do not imply new feature requirements.
- Use a single Go module with private implementation under `internal/` and the public runtime contract in `config/` and the pure Kubernetes composition boundary in `enrollment/`. Use upstream OPA extension points and register plugins in `internal/opa/register.go`.
- Run `make check` for Go changes. Run `make smoke` for image, startup, or runtime configuration changes. Run only checks relevant to the change.
- Report static, component, image, and Kubernetes / Istio validation separately. Compose success does not establish identity, injection, or bypass prevention guarantees.
- `fixture.*` policies are test-only and must not be published as the baseline. Do not add fictitious versions or local replacements for an unpublished shared library.
- Do not automatically publish images, push tags, or deploy. A pull request does not authorize these actions.
