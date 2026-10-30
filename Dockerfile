# Builds the dashboard, the server, the optional separate detection service
# (xdr-detect, same image) and the Rust Linux agent that the server hands out
# to installers and agent updates.

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Static (musl) agents for amd64 and arm64, so they run on any distribution.
# arm64 is cross-compiled with cargo-zigbuild (zig is the C compiler and
# linker for ring and SQLite). AGENT_ARCHES=amd64 skips it on slow hosts.
FROM rust:1-alpine AS agent
ARG AGENT_ARCHES="amd64 arm64"
RUN apk add --no-cache musl-dev && \
    if echo "$AGENT_ARCHES" | grep -q arm64; then \
      apk add --no-cache python3 py3-pip && \
      pip install --no-cache-dir --break-system-packages ziglang==0.13.0 && \
      cargo install --locked cargo-zigbuild@0.24.0 && \
      rustup target add aarch64-unknown-linux-musl; \
    fi
# Slow or lossy links: one connection at a time, longer timeouts, more retries.
ENV CARGO_HTTP_MULTIPLEXING=false CARGO_HTTP_TIMEOUT=300 CARGO_NET_RETRY=10
WORKDIR /src
COPY agent-rs/ ./
ARG VERSION=dev
# A binary dropped in agent-rs/prebuilt/ (for hosts that can't reach
# crates.io) is used as is, and the release takes its version, so updates
# check against what it reports; otherwise the agent is compiled here.
RUN mkdir -p /out/downloads && \
    if [ -f prebuilt/xdr-agent-linux-amd64 ]; then cp prebuilt/xdr-agent-linux-* /out/downloads/ && \
      chmod 755 /out/downloads/xdr-agent-linux-* && \
      /out/downloads/xdr-agent-linux-amd64 -version > /out/downloads/VERSION; \
    else for arch in $AGENT_ARCHES; do \
        case $arch in amd64) target=x86_64-unknown-linux-musl build=build ;; arm64) target=aarch64-unknown-linux-musl build=zigbuild ;; esac; \
        XDR_VERSION=${VERSION} cargo $build --release --locked -p xdr-agent --target $target && \
        cp target/$target/release/xdr-agent /out/downloads/xdr-agent-linux-$arch || exit 1; \
      done && echo "${VERSION}" > /out/downloads/VERSION; fi && \
    cd /out/downloads && sha256sum xdr-agent-linux-* > SHA256SUMS

# .deb and .rpm packages of each binary, served next to them.
FROM goreleaser/nfpm:v2.43.1 AS pkg
COPY agent-rs/packaging/ /pkg/
COPY --from=agent /out/downloads/ /out/downloads/
RUN cd /pkg && export VERSION="$(cat /out/downloads/VERSION)" && \
    for bin in /out/downloads/xdr-agent-linux-*; do \
      ARCH="${bin##*-}"; export ARCH; cp "$bin" ./xdr-agent && \
      nfpm pkg -f nfpm.yaml -p deb -t /out/downloads/ && \
      nfpm pkg -f nfpm.yaml -p rpm -t /out/downloads/ || exit 1; \
    done && \
    cd /out/downloads && sha256sum *.deb *.rpm > PACKAGES.SHA256SUMS && ls -l

FROM golang:1.26-alpine AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w" -o /out/xdr-server ./cmd/xdr-server && \
    go build -trimpath -ldflags "-s -w" -o /out/xdr-detect ./cmd/xdr-detect

FROM alpine:3.22
RUN adduser -D -H -u 10001 xdr && mkdir /data && chown xdr /data
COPY --from=go /out/xdr-server /out/xdr-detect /usr/local/bin/
COPY --from=pkg /out/downloads /opt/xdr/downloads
COPY --from=web /src/web/dist /opt/xdr/web
ENV XDR_DATA_DIR=/data XDR_WEB_DIR=/opt/xdr/web XDR_DOWNLOADS_DIR=/opt/xdr/downloads
USER xdr
VOLUME /data
EXPOSE 8080 8443 8444
ENTRYPOINT ["/usr/local/bin/xdr-server"]
