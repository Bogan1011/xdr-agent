VERSION ?= 0.7.1
LDFLAGS := -s -w -X github.com/Bogan1011/xdr-agent/internal/agent.Version=$(VERSION)

.PHONY: all agent server web proto bpf test up down

all: agent server web

agent:
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "$(LDFLAGS)" -o bin/xdr-agent ./cmd/xdr-agent

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

up:
	cd deploy && docker compose up -d --build

down:
	cd deploy && docker compose down
