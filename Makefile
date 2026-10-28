VERSION ?= 0.10.1

.PHONY: all agent server web proto test up down

all: agent server web

# Static Rust agent in bin/xdr-agent, built in Docker (no Rust toolchain needed).
# The console image builds its own copy for installers and updates.
agent:
	docker build -t xdr-agent-build -f agent-rs/Dockerfile agent-rs
	mkdir -p bin && id=$$(docker create xdr-agent-build) && docker cp $$id:/xdr-agent bin/xdr-agent; docker rm $$id >/dev/null

server:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/xdr-server ./cmd/xdr-server
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/xdr-detect ./cmd/xdr-detect

web:
	cd web && npm ci && npm run build

# Needs protoc, protoc-gen-go and protoc-gen-go-grpc on PATH.
proto:
	protoc -I proto --go_out=gen --go_opt=paths=source_relative \
		--go-grpc_out=gen --go-grpc_opt=paths=source_relative proto/xdr/v1/agent.proto

test:
	go vet ./...
	go test ./...
	cd agent-rs && cargo test

up:
	cd deploy && docker compose up -d --build

down:
	cd deploy && docker compose down
