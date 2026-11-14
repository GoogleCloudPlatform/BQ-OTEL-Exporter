// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/diag"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/metadata"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/protoenc"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
)

type logsExporter struct {
	*signalExporter
}

func newLogsExporter(set component.TelemetrySettings, cfg *Config) (*logsExporter, error) {
	if cfg == nil {
		return nil, errUnexpectedConfigType
	}
	tel, err := metadata.NewTelemetry(set.MeterProvider)
	if err != nil {
		return nil, err
	}
	se := newSignalExporter(set, cfg, cfg.Logs.Table, schema.LogsTableSchema())
	se.tel = tel
	return &logsExporter{se}, nil
}

func (e *logsExporter) start(ctx context.Context, host component.Host) error {
	return e.signalExporter.start(ctx, host)
}

func (e *logsExporter) shutdown(ctx context.Context) error {
	return e.signalExporter.shutdown(ctx)
}

func (e *logsExporter) pushLogData(ctx context.Context, ld plog.Logs) error {
	opID := diag.OperationID()

	var offloadFailedIndices []int
	var offloadFailures []offloadFailure
	opts := e.opts
	opts.Context = ctx
	opts.OnOffloadError = func(index int, err error) {
		offloadFailedIndices = append(offloadFailedIndices, index)
		offloadFailures = append(offloadFailures, offloadFailure{index: index, err: err})
	}

	var (
		encoded       [][]byte
		recordIndex   []int
		rejects       []transform.Rejection
		drops         []transform.QuarantineEntry
		rowToRecord   []int
		candidateRows []int
	)
	if wireEnc, ok := e.enc.(*protoenc.Encoder); ok && wireEnc.SupportsStreaming(schema.SignalLogs) {
		encoded, recordIndex, rejects, drops = transform.StreamLogRows(ld, opts, e.cfg.Write.MaxRowBytes, wireEnc)
		e.recordRejections(ctx, rejects, opID)
		e.recordEncodeDrops(ctx, drops, opID)
		candidateRows = recordIndex
		if len(drops) > 0 {
			dropIdx := make([]int, len(drops))
			for i, d := range drops {
				dropIdx[i] = d.Index
			}
			candidateRows = mergeSortedIndices(recordIndex, dropIdx)
		}
	} else {
		rows, rj := transform.LogRows(ld, opts)
		rejects = rj
		e.recordRejections(ctx, rejects, opID)

		var keptIndex []int
		encoded, keptIndex, drops = e.encodeRows(ctx, rows, opID)

		recordIndex = make([]int, len(keptIndex))
		rowToRecord = rowPositionToRecordIndex(len(rows), rejects, offloadFailedIndices...)
		for i, ri := range keptIndex {
			recordIndex[i] = rowToRecord[ri]
		}
		candidateRows = rowToRecord
	}

	decision := e.appendEncoded(ctx, encoded, recordIndex, opID)
	decision, retryableOffloadIndices := e.mergeOutcomeWithOffloadFailures(ctx, decision, offloadFailures, opID)
	if e.quarantine != nil {
		entries := quarantineEntries(rejects, drops, rowToRecord, decision.rowErrors)
		if len(entries) > 0 {
			qCtx, cancel := e.quarantineContext(ctx)
			qOpts := e.opts
			qOpts.Context = qCtx
			e.writeQuarantine(qCtx, entries, transform.LogQuarantineRows(ld, entries, qOpts), opID)
			cancel()
		}
	}
	if decision.err == nil {
		return nil
	}
	if decision.permanent {
		return consumererror.NewPermanent(decision.err)
	}
	if len(decision.retryableIndices) == 0 {
		return decision.err
	}
	// Acknowledged records normally stay out of the retry payload. The
	// exception is one identical to a retried record: the payload is
	// fingerprinted afresh, so a retried record keeps its intra_batch_ordinal,
	// and with it its insert_id, only if the identical records ahead of it
	// travel along.
	//
	// When synthesize_insert_id is false or every retried record carries an
	// explicit upstream insert_id, no retried record uses an ordinal hash, so
	// both the Redactor copy and peer widening are skipped.
	var retry []int
	switch {
	case !e.opts.SynthesizeInsertID:
		retry = decision.retryableIndices
	case transform.AllLogsHaveExplicitInsertID(ld, decision.retryableIndices, e.opts.InsertIDAttribute):
		retry = decision.retryableIndices
	default:
		candidates := validRecordIndices(candidateRows, decision.rowErrors)
		if len(retryableOffloadIndices) > 0 {
			candidates = mergeSortedIndices(candidates, retryableOffloadIndices)
		}
		ldForPeers := ld
		if e.opts.Redactor != nil && len(decision.retryableIndices) > 0 {
			// Peer fingerprints must see the post-redaction content that LogRows hashed,
			// without firing OnRedact twice or mutating the unredacted retry payload.
			ldForPeers = plog.NewLogs()
			ld.CopyTo(ldForPeers)
			e.opts.Redactor.RedactLogs(ldForPeers)
		}
		retry = transform.PreserveLogOrdinalPeersForContract(ldForPeers, candidates, decision.retryableIndices, e.opts)
	}
	return consumererror.NewLogs(decision.err, transform.SelectLogs(ld, retry))
}
