// Package ebpf loads the agent's CO-RE eBPF programs. The compiled objects
// are committed, so building the agent needs no clang; run `make bpf` after
// changing bpf/xdr.bpf.c.
package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -tags linux -target amd64,arm64 -cflags "-O2 -g -Wall -Werror" xdr bpf/xdr.bpf.c
