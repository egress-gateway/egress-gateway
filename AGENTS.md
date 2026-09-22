# Repository guidelines

- Use English for all repository content and GitHub communication, including documentation, comments, issues, and pull requests.
- This repository owns the custom OPA runtime, data plane adapters, single image, and component validation. Public policy contracts belong in `egress-gateway-policy`; CRDs, bindings, and admission belong in the controller. Shared installation and enrollment belong in networking. This repository owns the minimal kind/Istio connectivity BDD fixture; comprehensive network fail-closed acceptance is a later milestone.
- Read the README, relevant documentation, and existing implementation first. Preserve unrelated changes; placeholder directories do not imply new feature requirements.
- Use a single Go module with private implementation under `internal/` and the public runtime contract in `config/`. Use upstream OPA extension points and register plugins in `internal/opa/register.go`.
- Run `make check` for Go changes. Run `make smoke` for image, startup, or runtime configuration changes. Run only checks relevant to the change.
- Report static, component, image, and Kubernetes / Istio validation separately. Compose success does not establish identity, injection, or bypass prevention guarantees.
- `fixture.*` policies are test-only and must not be published as the baseline. Do not add fictitious versions or local replacements for an unpublished shared library.
- Do not automatically publish images, push tags, or deploy. A pull request does not authorize these actions.
