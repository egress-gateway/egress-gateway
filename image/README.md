# Gateway image

The image contains one `gateway-daemon`, Envoy and pilot-agent. Role and mode select
startup behavior; see [the public configuration contract](../docs/configuration.md).
OPA runs inside the daemon. The shell entrypoint only `exec`s it, and the health
command delegates to `gateway-daemon ready`.

UID 1337 owns the private state/runtime directories. Deployments mounting volumes
must provide the documented ownership and permissions. Public trust is a separate
mount. The image contains no generated CA or other user secrets.

`make smoke` builds and runs both roles in a dedicated Compose project. It checks
HTTP authorization and process/private-interface/CA behavior. It does not establish
HTTPS inspection, live Istio compatibility, or network isolation. The default
Istio mode retains upstream environment and volume prerequisites.
