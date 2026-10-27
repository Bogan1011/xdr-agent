VERSION ?= 0.8.0
LDFLAGS := -s -w -X github.com/Bogan1011/xdr-agent/internal/agent.Version=$(VERSION)

.PHONY: all agent agent-rs server web proto bpf test up down

all: agent server web

agent:
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "$(LDFLAGS)" -o bin/xdr-agent ./cmd/xdr-agent

# Static Rust agent in bin/xdr-agent-rs, built in Docker (no Rust toolchain needed).
agent-rs:
	docker build -t xdr-agent-rs-build -f agent-rs/Dockerfile agent-rs
	mkdir -p bin && id=$$(docker create xdr-agent-rs-build) && docker cp $$id:/xdr-agent-rs bin/xdr-agent-rs; docker rm $$id >/dev/null

server:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/xdr-server ./cmd/xdr-server

web:
	cd web && npm ci && npm run build

# Needs protoc, protoc-gen-go and protoc-gen-go-grpc on PATH.
proto:
	protoc -I proto --go_out=gen --go_opt=paths=source_relative \
		--go-grpc_out=gen --go-grpc_opt=paths=source_relative proto/xdr/v1/agent.proto

# Rebuilds the committed eBPF objects. Needs clang.
bpf:
	cd internal/agent/ebpf && go generate .

test:
	go vet ./...
	go test ./...
	cd agent-rs && cargo test

up:
	cd deploy && docker compose up -d --build

down:
	cd deploy && docker compose down
