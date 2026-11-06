# Pilot deployment

Services (`sts`, `gateway`) serve TLS only and run on distroless `static-debian12:nonroot` (uid 65532), built from `golang:1.26`.

## Build
    docker build --build-arg TARGET=sts     -f services/Dockerfile -t registry.example.internal/ai-services/sts:0.1.0 services
    docker build --build-arg TARGET=gateway -f services/Dockerfile -t registry.example.internal/ai-services/gateway:0.1.0 services
For release pass approved digests: `--build-arg GO_IMAGE=...@sha256:... --build-arg RUN_IMAGE=...@sha256:...`, then put the pushed image digest in the manifests.
Behind an internal Go module mirror add `--build-arg GOPROXY=https://goproxy.example.internal` (used by `go mod download` and `go build`).

## Supply chain
- Pin the `ai-base` base image by digest (`BASE_IMAGE=...@sha256:...`, see `image/.gitlab-ci.yml`).
- The registry must enforce tag immutability for `ai-hardened/*`. The release job refuses to overwrite a version tag, but only the registry stops other writers.
- The image pipeline's DinD service needs a volume shared between the `dind` service and the job at `/certs`, or `DOCKER_TLS_CERTDIR=/certs` cannot hand the client its certificates.
- The image pipeline needs the internal CA: set the file-type variable `INTERNAL_CA_FILE`, or `SKIP_INTERNAL_CA=true` if the base already trusts it.

## Secrets (create out of band, never in the repo)
- sts-signing-keys (current.pem, next.pem), sts-directory-bind (bind-password), sts-tls, sts-ca
- gateway-client-cert (tls.crt, tls.key), gateway-ca, gateway-tls
- ai-services-tls (ingress front cert), ingress-backend-ca (ca.crt; the CA that signed sts-tls and gateway-tls, used by nginx proxy-ssl-verify; per ingress-nginx docs tls.crt/tls.key are only the optional client pair for authenticating to the backend. Whether a ca.crt-only secret is accepted is unverified, test in the pilot)
Serving certs need SANs for `<svc>.ai-services.svc` and the `*.example.internal` host. `gateway-ca` must trust the STS serving cert; `sts-ca` must trust GitLab and the LDAP server.

## Required env vars
- STS: STS_CONFIG, STS_SIGNING_KEYS, STS_ISSUER, STS_CA_FILE, STS_TLS_CERT, STS_TLS_KEY (STS_ADDR optional)
- Gateway: GATEWAY_CA_FILE, GATEWAY_CLIENT_CERT, GATEWAY_CLIENT_KEY, GATEWAY_STS_JWKS_URL (https), GATEWAY_STS_ISSUER, GATEWAY_AUDIENCE, GATEWAY_UPSTREAM_URL, GATEWAY_BATCH_URL, GATEWAY_TLS_CERT, GATEWAY_TLS_KEY (GATEWAY_MAX_BODY_BYTES, GATEWAY_ADDR optional)
Startup fails if TLS files are missing or a JWKS URL is not https.

## Runner manager (not included; no chart)
The GitLab Runner manager is deployed by the owner. Requirements:
- Run it in a namespace **outside** `ai-runners` (for example `ai-runner-manager`). The `ai-runners` NetworkPolicies select every pod there (`podSelector: {}`) and deny everything but the listed egress, so a manager inside it could not reach the Kubernetes API. Do not widen the job policy to select the manager.
- The manager needs egress to GitLab and the Kubernetes API. Jobs must not reach the API.
- RBAC: a Role and RoleBinding in `ai-runners` only, no cluster-wide rights, for the manager's service account. Per the GitLab Runner Kubernetes executor documentation this means `pods` (create, delete, get, list, watch), `pods/attach` and `pods/exec` (create, delete, get, patch), `pods/log` (get), `secrets` (create, delete, get, update), `configmaps` (create, delete, get, update), `services` (create, get) and `serviceaccounts` (get). Check the page for the exact runner version before applying.
- Mount `config.toml` from a secret, since it holds the runner token.

## Replace before deploy
`*.example.internal` hosts, 192.0.2.x CIDRs, ingress namespace/class/pod label, `@sha256:REPLACE_WITH_DIGEST` image digests, `runner_ids`, runner token, `AI_REVIEW_MODEL` in `templates/ai-code-review.yml` (placeholder `example-model`) and helper image tag (`x86_64-vRUNNER_VERSION`, must match the runner version), node selector/tolerations in `runner/config.toml.example`.
