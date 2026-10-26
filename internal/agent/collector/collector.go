// Package collector holds the agent's telemetry sources.
package collector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
)

// Emit hands an event to the sender. It must not block.
type Emit func(*xdrv1.Event)

type Collector interface {
	Name() string
	Run(ctx context.Context, emit Emit) error
}

// NewEvent stamps an event with a random id and the current time.
func NewEvent(t xdrv1.EventType) *xdrv1.Event {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return &xdrv1.Event{
		Id:                hex.EncodeToString(b[:]),
		TimestampUnixNano: time.Now().UnixNano(),
		Type:              t,
	}
}
