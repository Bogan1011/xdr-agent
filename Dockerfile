# Builds the dashboard, the server, the optional separate detection service
# (xdr-detect, same image) and the Linux agent binaries that the server hands
# out to installers.

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w" -o /out/xdr-server ./cmd/xdr-server && \
    go build -trimpath -ldflags "-s -w" -o /out/xdr-detect ./cmd/xdr-detect
RUN mkdir -p /out/downloads && \
    for arch in amd64 arm64; do \
      GOOS=linux GOARCH=$arch go build -trimpath \
        -ldflags "-s -w -X github.com/Bogan1011/xdr-agent/internal/agent.Version=${VERSION}" \
        -o /out/downloads/xdr-agent-linux-$arch ./cmd/xdr-agent; \
    done && \
    cd /out/downloads && sha256sum xdr-agent-linux-* > SHA256SUMS && echo "${VERSION}" > VERSION

FROM alpine:3.22
RUN adduser -D -H -u 10001 xdr && mkdir /data && chown xdr /data
COPY --from=go /out/xdr-server /out/xdr-detect /usr/local/bin/
COPY --from=go /out/downloads /opt/xdr/downloads
COPY --from=web /src/web/dist /opt/xdr/web
ENV XDR_DATA_DIR=/data XDR_WEB_DIR=/opt/xdr/web XDR_DOWNLOADS_DIR=/opt/xdr/downloads
USER xdr
VOLUME /data
EXPOSE 8080 8443 8444
ENTRYPOINT ["/usr/local/bin/xdr-server"]
