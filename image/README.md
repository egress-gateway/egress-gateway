# Image

The Dockerfile builds this repository's `gateway-opa` and copies it into a pinned Istio proxyv2 image. OPA plugins and future Go dependencies on the policy library are compiled into the binary. Envoy and pilot-agent retain their upstream implementations.

The final image does not start a separate stock OPA process. It runs as UID/GID 1337 by default and listens on unprivileged ports. Deployment integration owns transparent Pod traffic interception and the permissions it requires.

`entrypoint.sh` manages startup, failure propagation, and shutdown of the OPA and proxy child processes. `healthcheck.sh` aggregates component health. Kubernetes deployments must configure corresponding probes explicitly; Kubernetes does not automatically execute Dockerfile HEALTHCHECK instructions.

`make image` builds locally; `make smoke` validates the actual image. The image contains no local test policies. Compose supplies separate fixture policies for each role through read-only mounts.
