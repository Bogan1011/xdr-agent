package pipeline

import (
	"context"

	xdrv1 "github.com/Bogan1011/xdr-agent/gen/xdr/v1"
	"github.com/Bogan1011/xdr-agent/internal/server/store"
)

// Detector runs detection and correlation on stored events and raises
// alerts. detect.Service does it in process; Remote hands it to xdr-detect.
type Detector interface {
	Process(ctx context.Context, events []store.Event)
}

// EventStore keeps the telemetry.
type EventStore interface {
	Insert(ctx context.Context, events []store.Event) error
}

// Pipeline is what an ingested batch goes through.
type Pipeline struct {
	Store    EventStore
	Enricher *Enricher
	Detector Detector
}

// Ingest normalizes, enriches and stores a batch, then hands it to detection.
// It fails only when the batch could not be stored, so the agent retries it.
func (p *Pipeline) Ingest(ctx context.Context, src Source, in []*xdrv1.Event) ([]store.Event, error) {
	rows := make([]store.Event, 0, len(in))
	for _, e := range in {
		r := Normalize(src, e)
		if p.Enricher != nil {
			p.Enricher.Enrich(&r)
		}
		rows = append(rows, r)
	}
	if err := p.Store.Insert(ctx, rows); err != nil {
		return nil, err
	}
	if p.Detector != nil {
		p.Detector.Process(ctx, rows)
	}
	return rows, nil
}
