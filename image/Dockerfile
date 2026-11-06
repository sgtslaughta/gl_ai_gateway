# Hardened AI base image (spec 8.2). Build with the approved base and mirror:
#   docker build --build-arg BASE_IMAGE=<approved-base>@sha256:<digest> \
#                --build-arg APT_MIRROR=https://mirror.example.internal/debian .
ARG BASE_IMAGE=registry.example.internal/approved/debian:bookworm-slim
FROM ${BASE_IMAGE}
ARG APT_MIRROR=

# Optional internal package mirror (deb822 and legacy formats).
RUN if [ -n "$APT_MIRROR" ]; then \
      for f in /etc/apt/sources.list.d/*.sources /etc/apt/sources.list; do \
        [ -f "$f" ] && sed -i -E "s#https?://[^ ]+#${APT_MIRROR}#g" "$f"; \
      done; \
    fi

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates curl jq git python3 \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt /root/.cache

# Internal CA certs (*.crt) go in image/ca/ at build time; never committed.
COPY ca/ /usr/local/share/ca-certificates/
RUN update-ca-certificates \
 && rm -f /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-cache /usr/bin/apt-config \
      /usr/bin/apt-key /usr/bin/apt-mark /usr/bin/apt-cdrom \
 && find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
 && echo 'ai:x:10001:10001::/home/ai:/bin/bash' >> /etc/passwd \
 && echo 'ai:x:10001:' >> /etc/group \
 && mkdir -p /home/ai && chown 10001:10001 /home/ai

COPY ai-token /usr/local/bin/ai-token
USER 10001:10001
ENV HOME=/home/ai
WORKDIR /home/ai
