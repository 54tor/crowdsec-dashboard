# Build context is the repository root: docker build -f deploy/Dockerfile .
FROM node:lts AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# vite.config.ts writes the bundle to ../backend/internal/webui/dist
RUN mkdir -p /src/backend/internal/webui/dist && npm run build

FROM golang:latest AS backend
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
COPY --from=web /src/backend/internal/webui/dist ./internal/webui/dist
RUN CGO_ENABLED=0 go build -p 4 -trimpath -ldflags="-s -w" -o /out/dashboard ./cmd/dashboard

# No Alpine package exists: built from source, integrity checked by the Go checksum database.
FROM golang:alpine AS geoipupdate-build
ARG GEOIPUPDATE_VERSION=latest
RUN CGO_ENABLED=0 GOBIN=/out go install -p 4 -trimpath -ldflags="-s -w" \
    "github.com/maxmind/geoipupdate/v8/cmd/geoipupdate@${GEOIPUPDATE_VERSION}"

# s6-overlay release archives, verified against their published SHA-256.
FROM alpine:latest AS s6
ARG S6_OVERLAY_VERSION=3.2.3.2
SHELL ["/bin/ash", "-o", "pipefail", "-c"]
RUN set -eux; \
    apk add --no-cache curl tar xz; \
    arch="$(apk --print-arch)"; \
    case "${arch}" in \
        aarch64) s6_arch="s6-overlay-aarch64.tar.xz" ;; \
        x86_64) s6_arch="s6-overlay-x86_64.tar.xz" ;; \
        *) printf 'This image supports only x86_64 and aarch64 (current: %s)\n' "${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/s6-overlay-noarch.tar.xz "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz"; \
    curl -fsSL -o /tmp/s6-overlay-arch.tar.xz "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/${s6_arch}"; \
    echo "5379750ed30a84bbd2e2dd74847ba6b5bd29cd0b2e3ea2ec58049b57eb2eda12  /tmp/s6-overlay-noarch.tar.xz" | sha256sum -c - ; \
    case "${arch}" in \
        aarch64) echo "b17f17a82e7a515c682a91edaf2ffdabb73f891981b6c1fd712115693a2f8b4c  /tmp/s6-overlay-arch.tar.xz" | sha256sum -c - ;; \
        x86_64) echo "e6befcc96a437a3831386ecfc51808c5d3e939dc5fe3c02ae9284599e8aa2408  /tmp/s6-overlay-arch.tar.xz" | sha256sum -c - ;; \
    esac; \
    mkdir -p /s6root; \
    tar -C /s6root -Jxpf /tmp/s6-overlay-noarch.tar.xz; \
    tar -C /s6root -Jxpf /tmp/s6-overlay-arch.tar.xz

FROM alpine:latest
ENV PATH="/command:${PATH}"
ENV S6_BEHAVIOUR_IF_STAGE2_FAILS=2
LABEL org.opencontainers.image.title="crowdsec-dashboard" \
      org.opencontainers.image.description="Web dashboard for a CrowdSec instance, supervised by s6-overlay and run as an unprivileged user."
RUN set -eux; \
    apk add --no-cache bash ca-certificates shadow tzdata; \
    groupadd --gid 10000 docker-user; \
    useradd --uid 10000 --gid docker-user -M --shell /bin/bash docker-user; \
    install -d -o 0 -g 0 -m 0755 /custom-scripts.d /docker-entrypoint.d
COPY --from=s6 /s6root/ /
COPY --from=geoipupdate-build /out/geoipupdate /usr/local/bin/geoipupdate
COPY --from=backend /out/dashboard /usr/local/bin/dashboard
COPY --chown=0:0 deploy/s6/rootfs/ /
EXPOSE 8080
HEALTHCHECK CMD wget -q -O /dev/null http://127.0.0.1:8080/api/healthz
ENTRYPOINT ["/init"]
