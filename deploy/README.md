# Pilot deployment

Services (`sts`, `gateway`) serve TLS only and run on distroless `static-debian12:nonroot` (uid 65532), built from `golang:1.26`.

## Build
    docker build --build-arg TARGET=sts     -f services/Dockerfile -t registry.example.internal/ai-services/sts:0.1.0 services
    docker build --build-arg TARGET=gateway -f services/Dockerfile -t registry.example.internal/ai-services/gateway:0.1.0 services
For release pass approved digests: `--build-arg GO_IMAGE=...@sha256:... --build-arg RUN_IMAGE=...@sha256:...`, then put the pushed image digest in the manifests.

## Secrets (create out of band, never in the repo)
- sts-signing-keys (current.pem, next.pem), sts-directory-bind (bind-password), sts-tls, sts-ca
- gateway-client-cert (tls.crt, tls.key), gateway-ca, gateway-tls
- ai-services-tls (ingress front cert), ingress-backend-ca (ca.crt; the CA that signed sts-tls and gateway-tls, used by nginx proxy-ssl-verify; may also need a client tls.crt/tls.key pair)
Serving certs need SANs for `<svc>.ai-services.svc` and the `*.example.internal` host. `gateway-ca` must trust the STS serving cert; `sts-ca` must trust GitLab and the LDAP server.

## Required env vars
- STS: STS_CONFIG, STS_SIGNING_KEYS, STS_ISSUER, STS_CA_FILE, STS_TLS_CERT, STS_TLS_KEY (STS_ADDR optional)
- Gateway: GATEWAY_CA_FILE, GATEWAY_CLIENT_CERT, GATEWAY_CLIENT_KEY, GATEWAY_STS_JWKS_URL (https), GATEWAY_STS_ISSUER, GATEWAY_AUDIENCE, GATEWAY_UPSTREAM_URL, GATEWAY_BATCH_URL, GATEWAY_TLS_CERT, GATEWAY_TLS_KEY (GATEWAY_MAX_BODY_BYTES, GATEWAY_ADDR optional)
Startup fails if TLS files are missing or a JWKS URL is not https.

## Replace before deploy
`*.example.internal` hosts, 192.0.2.x CIDRs, ingress namespace/class/pod label, `@sha256:REPLACE_WITH_DIGEST` image digests, `runner_ids`, runner token and helper image tag (`x86_64-vRUNNER_VERSION`, must match the runner version), node selector/tolerations in `runner/config.toml.example`.
