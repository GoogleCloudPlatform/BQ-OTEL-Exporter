// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"cloud.google.com/go/bigquery/storage/managedwriter/adapt"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/offload"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/protoenc"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/redact"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// FieldFamilyBreakdown reports average encoded ProtoRows wire bytes per row
// broken down by column family, plus percentage shares of total encoded bytes.
type FieldFamilyBreakdown struct {
	SampleRows         int     `json:"sample_rows"`
	TotalBytesPerRow   float64 `json:"total_bytes_per_row"`
	ResourceBytes      float64 `json:"resource_bytes"`
	ResourcePct        float64 `json:"resource_pct"`
	ScopeBytes         float64 `json:"instrumentation_scope_bytes"`
	ScopePct           float64 `json:"instrumentation_scope_pct"`
	BodyBytes          float64 `json:"body_bytes"`
	BodyPct            float64 `json:"body_pct"`
	AttributesBytes    float64 `json:"attributes_bytes"`
	AttributesPct      float64 `json:"attributes_pct"`
	SchemaSidecarBytes float64 `json:"schema_sidecar_bytes"`
	SchemaSidecarPct   float64 `json:"schema_sidecar_pct"`
	IdentityBytes      float64 `json:"identity_bytes"`
	IdentityPct        float64 `json:"identity_pct"`
	UnixNanoBytes      float64 `json:"unix_nano_bytes"`
	UnixNanoPct        float64 `json:"unix_nano_pct"`
	OtherBytes         float64 `json:"other_bytes"`
	OtherPct           float64 `json:"other_pct"`
}

// ByteLayersSummary reports the 5 byte layers from raw telemetry content to
// BigQuery Storage Write API wire bytes and (in live mode) stored table bytes.
type ByteLayersSummary struct {
	SourceContentBytesPerRow  float64 `json:"source_content_bytes_per_row"`
	OTLPBytesPerRow           float64 `json:"otlp_bytes_per_row"`
	ProtoRowsBytesPerRow      float64 `json:"proto_rows_bytes_per_row"`
	OTLPToProtoRowsRatio      float64 `json:"otlp_to_proto_rows_ratio"`
	SourceToProtoRowsRatio    float64 `json:"source_to_proto_rows_ratio"`
	BQLogicalBytes            int64   `json:"bq_logical_bytes,omitempty"`
	BQActivePhysicalBytes     int64   `json:"bq_active_physical_bytes,omitempty"`
	BQLongTermPhysicalBytes   int64   `json:"bq_long_term_physical_bytes,omitempty"`
	BQTimeTravelPhysicalBytes int64   `json:"bq_time_travel_physical_bytes,omitempty"`
	BQFailSafePhysicalBytes   int64   `json:"bq_fail_safe_physical_bytes,omitempty"`
	BQTotalRows               int64   `json:"bq_total_rows,omitempty"`
	BQLogicalBytesPerRow      float64 `json:"bq_logical_bytes_per_row,omitempty"`
	BQPhysicalBytesPerRow     float64 `json:"bq_physical_bytes_per_row,omitempty"`
	BQCompressionRatio        float64 `json:"bq_compression_ratio,omitempty"`
	BQStorageQueryNote        string  `json:"bq_storage_query_note,omitempty"`
}

type fieldFamilyBucket int

const (
	bucketOther fieldFamilyBucket = iota
	bucketResource
	bucketScope
	bucketBody
	bucketAttributes
	bucketSchemaSidecar
	bucketIdentity
	bucketUnixNano
)

type wireDescriptorIndex struct {
	byNumber map[protowire.Number]wireFieldInfo
}

type wireFieldInfo struct {
	name   string
	bucket fieldFamilyBucket
	nested *wireDescriptorIndex
}

func buildWireDescriptorIndex(ts *storagepb.TableSchema) (*wireDescriptorIndex, error) {
	md, err := adapt.StorageSchemaToProto2Descriptor(ts, "root")
	if err != nil {
		return nil, fmt.Errorf("deriving descriptor for wire breakdown: %w", err)
	}
	msgDesc, ok := md.(protoreflect.MessageDescriptor)
	if !ok {
		return nil, fmt.Errorf("derived descriptor is %T, want MessageDescriptor", md)
	}
	return indexWireMessage(msgDesc, ""), nil
}

func indexWireMessage(md protoreflect.MessageDescriptor, parentName string) *wireDescriptorIndex {
	fields := md.Fields()
	idx := &wireDescriptorIndex{
		byNumber: make(map[protowire.Number]wireFieldInfo, fields.Len()),
	}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		name := string(fd.Name())
		bucket := classifyWireField(name, parentName)
		var nested *wireDescriptorIndex
		if fd.Kind() == protoreflect.MessageKind && !fd.IsMap() {
			nested = indexWireMessage(fd.Message(), name)
		}
		idx.byNumber[fd.Number()] = wireFieldInfo{
			name:   name,
			bucket: bucket,
			nested: nested,
		}
	}
	return idx
}

func classifyWireField(name, parentName string) fieldFamilyBucket {
	if strings.HasSuffix(name, "_schema") {
		return bucketSchemaSidecar
	}
	if strings.HasSuffix(name, "_unix_nano") {
		return bucketUnixNano
	}
	if parentName != "" {
		return bucketOther
	}
	switch name {
	case "resource":
		return bucketResource
	case "instrumentation_scope":
		return bucketScope
	case "body":
		return bucketBody
	case "attributes":
		return bucketAttributes
	case "insert_id", "record_fingerprint":
		return bucketIdentity
	default:
		return bucketOther
	}
}

type familyByteTotals [8]int64

func (idx *wireDescriptorIndex) accumulateRow(data []byte, parentBucket fieldFamilyBucket, totals *familyByteTotals) error {
	for len(data) > 0 {
		num, wireType, tagLen := protowire.ConsumeTag(data)
		if tagLen < 0 {
			return protowire.ParseError(tagLen)
		}
		valLen := protowire.ConsumeFieldValue(num, wireType, data[tagLen:])
		if valLen < 0 {
			return protowire.ParseError(valLen)
		}
		fieldTotal := tagLen + valLen
		info, ok := idx.byNumber[num]
		if !ok {
			if parentBucket != bucketOther {
				totals[parentBucket] += int64(fieldTotal)
			} else {
				totals[bucketOther] += int64(fieldTotal)
			}
			data = data[fieldTotal:]
			continue
		}

		// Inside a parent STRUCT (e.g. resource, instrumentation_scope, events),
		// extract specific child families (*_schema sidecars and *_unix_nano)
		// into their dedicated buckets and charge the remaining bytes to the parent.
		if parentBucket != bucketOther {
			switch info.bucket {
			case bucketSchemaSidecar, bucketUnixNano:
				totals[info.bucket] += int64(fieldTotal)
			default:
				if info.nested != nil && wireType == protowire.BytesType {
					payload, hdrLen := consumeBytesPayload(data[tagLen : tagLen+valLen])
					if hdrLen >= 0 {
						totals[parentBucket] += int64(tagLen + hdrLen)
						if err := info.nested.accumulateRow(payload, parentBucket, totals); err != nil {
							return err
						}
					} else {
						totals[parentBucket] += int64(fieldTotal)
					}
				} else {
					totals[parentBucket] += int64(fieldTotal)
				}
			}
			data = data[fieldTotal:]
			continue
		}

		if info.nested != nil && wireType == protowire.BytesType {
			payload, hdrLen := consumeBytesPayload(data[tagLen : tagLen+valLen])
			if hdrLen >= 0 {
				// Attribute the outer field tag + varint length prefix to info.bucket,
				// then recursively walk the inner message.
				totals[info.bucket] += int64(tagLen + hdrLen)
				if err := info.nested.accumulateRow(payload, info.bucket, totals); err != nil {
					return err
				}
				data = data[fieldTotal:]
				continue
			}
		}

		totals[info.bucket] += int64(fieldTotal)
		data = data[fieldTotal:]
	}
	return nil
}

func consumeBytesPayload(fieldVal []byte) ([]byte, int) {
	v, n := protowire.ConsumeBytes(fieldVal)
	if n < 0 {
		return nil, n
	}
	return v, len(fieldVal) - len(v)
}

type dispatchedByteTotals struct {
	sourceBytes int64
	otlpBytes   int64
	records     int64
}

func measureByteProfile(cfg RunnerConfig, signal string, actualBytesPerRow float64) (*ByteLayersSummary, *FieldFamilyBreakdown, error) {
	return measureByteProfileWithDispatched(cfg, signal, actualBytesPerRow, nil)
}

func measureByteProfileWithDispatched(cfg RunnerConfig, signal string, actualBytesPerRow float64, dispatched *dispatchedByteTotals) (*ByteLayersSummary, *FieldFamilyBreakdown, error) {
	refRecords := cfg.BatchSize
	if refRecords <= 0 {
		refRecords = 28
	}
	refGen := NewGenerator(GeneratorConfig{
		PayloadBytes:     cfg.PayloadBytes,
		PlantSecrets:     cfg.Redaction || cfg.PlantSecrets,
		UniquePayloads:   cfg.UniquePayloads,
		WorkloadProfile:  cfg.WorkloadProfile,
		ResourceAttrs:    cfg.ResourceAttrs,
		UpstreamInsertID: cfg.UpstreamInsertID,
	})

	tOpts := transform.Options{
		Limits:             transform.DefaultLimits(),
		SynthesizeInsertID: true,
	}
	if cfg.Redaction {
		rd, err := redact.New(redact.Config{
			BlockedKeys:          redact.DefaultBlockedKeys(),
			BlockedValuePatterns: blockedSecretPatterns,
			MaskReplacement:      redact.DefaultMaskReplacement,
			RedactLogBody:        true,
		})
		if err != nil {
			return nil, nil, err
		}
		tOpts.Redactor = rd
	}

	var (
		offloader *offload.Offloader
		offErr    error
	)
	if cfg.OffloadDir != "" && (signal == "traces" || signal == "logs") {
		offloader, offErr = newMemReferenceOffloader(cfg.OffloadThresholdBytes, false)
		if offErr != nil {
			return nil, nil, offErr
		}
	} else if cfg.OffloadGCSBucket != "" && (signal == "traces" || signal == "logs") {
		offloader, offErr = newMemReferenceOffloader(cfg.OffloadThresholdBytes, true)
		if offErr != nil {
			return nil, nil, offErr
		}
		tOpts.PayloadOffloader = offloader
	}

	var (
		sourceTotalBytes int64
		otlpTotalBytes   int
		rows             []transform.Row
		ts               *storagepb.TableSchema
	)
	switch signal {
	case "traces":
		td := refGen.TracesBatch(refRecords)
		sourceTotalBytes = tracesSourceContentBytes(td)
		otlpTotalBytes = (&ptrace.ProtoMarshaler{}).TracesSize(td)
		if tOpts.Redactor != nil {
			tOpts.Redactor.RedactTraces(td)
			tOpts.Redactor = nil
		}
		if offloader != nil && tOpts.PayloadOffloader == nil {
			if err := offloadTraceBatch(context.Background(), offloader, td); err != nil {
				return nil, nil, err
			}
		}
		rows, _ = transform.SpanRows(td, tOpts)
		ts = schema.SpansTableSchema()
	case "logs":
		ld := refGen.LogsBatch(refRecords)
		sourceTotalBytes = logsSourceContentBytes(ld)
		otlpTotalBytes = (&plog.ProtoMarshaler{}).LogsSize(ld)
		if tOpts.Redactor != nil {
			tOpts.Redactor.RedactLogs(ld)
			tOpts.Redactor = nil
		}
		if offloader != nil && tOpts.PayloadOffloader == nil {
			if err := offloadLogBatch(context.Background(), offloader, ld); err != nil {
				return nil, nil, err
			}
		}
		rows, _ = transform.LogRows(ld, tOpts)
		ts = schema.LogsTableSchema()
	case "metrics":
		md := refGen.MetricsBatch(refRecords)
		sourceTotalBytes = metricsSourceContentBytes(md)
		otlpTotalBytes = (&pmetric.ProtoMarshaler{}).MetricsSize(md)
		rows, _ = transform.MetricRows(md, tOpts)
		ts = schema.MetricsTableSchema()
	default:
		return nil, nil, fmt.Errorf("unsupported signal %q", signal)
	}

	if len(rows) == 0 {
		return nil, nil, nil
	}

	enc, err := protoenc.New(ts)
	if err != nil {
		return nil, nil, err
	}
	wireIdx, err := buildWireDescriptorIndex(ts)
	if err != nil {
		return nil, nil, err
	}

	var (
		totals      familyByteTotals
		totalWire   int64
		encodedRows int
	)
	for _, r := range rows {
		b, encErr := enc.Encode(r)
		if encErr != nil {
			continue
		}
		if err := wireIdx.accumulateRow(b, bucketOther, &totals); err != nil {
			return nil, nil, err
		}
		totalWire += int64(len(b))
		encodedRows++
	}
	if encodedRows == 0 {
		return nil, nil, nil
	}

	n := float64(encodedRows)
	sourceBPR := float64(sourceTotalBytes) / float64(refRecords)
	otlpBPR := float64(otlpTotalBytes) / float64(refRecords)
	if dispatched != nil && dispatched.records > 0 {
		sourceBPR = float64(dispatched.sourceBytes) / float64(dispatched.records)
		otlpBPR = float64(dispatched.otlpBytes) / float64(dispatched.records)
	}
	measuredProtoBPR := float64(totalWire) / n
	protoBPR := measuredProtoBPR
	if actualBytesPerRow > 0 {
		protoBPR = actualBytesPerRow
	}

	var otlpRatio, sourceRatio float64
	if otlpBPR > 0 {
		otlpRatio = round2(protoBPR / otlpBPR)
	}
	if sourceBPR > 0 {
		sourceRatio = round2(protoBPR / sourceBPR)
	}

	layers := &ByteLayersSummary{
		SourceContentBytesPerRow: round2(sourceBPR),
		OTLPBytesPerRow:          round2(otlpBPR),
		ProtoRowsBytesPerRow:     round2(protoBPR),
		OTLPToProtoRowsRatio:     otlpRatio,
		SourceToProtoRowsRatio:   sourceRatio,
	}

	pct := func(v int64) float64 {
		if totalWire == 0 {
			return 0
		}
		return round2(100.0 * float64(v) / float64(totalWire))
	}
	breakdown := &FieldFamilyBreakdown{
		SampleRows:         encodedRows,
		TotalBytesPerRow:   round2(measuredProtoBPR),
		ResourceBytes:      round2(float64(totals[bucketResource]) / n),
		ResourcePct:        pct(totals[bucketResource]),
		ScopeBytes:         round2(float64(totals[bucketScope]) / n),
		ScopePct:           pct(totals[bucketScope]),
		BodyBytes:          round2(float64(totals[bucketBody]) / n),
		BodyPct:            pct(totals[bucketBody]),
		AttributesBytes:    round2(float64(totals[bucketAttributes]) / n),
		AttributesPct:      pct(totals[bucketAttributes]),
		SchemaSidecarBytes: round2(float64(totals[bucketSchemaSidecar]) / n),
		SchemaSidecarPct:   pct(totals[bucketSchemaSidecar]),
		IdentityBytes:      round2(float64(totals[bucketIdentity]) / n),
		IdentityPct:        pct(totals[bucketIdentity]),
		UnixNanoBytes:      round2(float64(totals[bucketUnixNano]) / n),
		UnixNanoPct:        pct(totals[bucketUnixNano]),
		OtherBytes:         round2(float64(totals[bucketOther]) / n),
		OtherPct:           pct(totals[bucketOther]),
	}
	return layers, breakdown, nil
}

func tracesSourceContentBytes(td ptrace.Traces) int64 {
	var total int64
	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		rs := rss.At(i)
		total += mapContentBytes(rs.Resource().Attributes()) + int64(len(rs.SchemaUrl()))
		sss := rs.ScopeSpans()
		for j := 0; j < sss.Len(); j++ {
			ss := sss.At(j)
			total += int64(len(ss.Scope().Name())+len(ss.Scope().Version())+len(ss.SchemaUrl())) + mapContentBytes(ss.Scope().Attributes())
			spans := ss.Spans()
			for k := 0; k < spans.Len(); k++ {
				sp := spans.At(k)
				total += int64(len(sp.Name()) + len(sp.TraceState().AsRaw()) + len(sp.Status().Message()))
				if !sp.TraceID().IsEmpty() {
					total += 16
				}
				if !sp.SpanID().IsEmpty() {
					total += 8
				}
				if !sp.ParentSpanID().IsEmpty() {
					total += 8
				}
				total += 16 // start + end timestamps
				total += mapContentBytes(sp.Attributes())
				evs := sp.Events()
				for e := 0; e < evs.Len(); e++ {
					ev := evs.At(e)
					total += 8 + int64(len(ev.Name())) + mapContentBytes(ev.Attributes())
				}
				links := sp.Links()
				for l := 0; l < links.Len(); l++ {
					lk := links.At(l)
					total += 24 + int64(len(lk.TraceState().AsRaw())) + mapContentBytes(lk.Attributes())
				}
			}
		}
	}
	return total
}

func logsSourceContentBytes(ld plog.Logs) int64 {
	var total int64
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		rl := rls.At(i)
		total += mapContentBytes(rl.Resource().Attributes()) + int64(len(rl.SchemaUrl()))
		sls := rl.ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			sl := sls.At(j)
			total += int64(len(sl.Scope().Name())+len(sl.Scope().Version())+len(sl.SchemaUrl())) + mapContentBytes(sl.Scope().Attributes())
			lrs := sl.LogRecords()
			for k := 0; k < lrs.Len(); k++ {
				lr := lrs.At(k)
				total += int64(len(lr.SeverityText()) + len(lr.EventName()))
				if lr.Timestamp() != 0 {
					total += 8
				}
				if lr.ObservedTimestamp() != 0 {
					total += 8
				}
				if !lr.TraceID().IsEmpty() {
					total += 16
				}
				if !lr.SpanID().IsEmpty() {
					total += 8
				}
				total += valueContentBytes(lr.Body())
				total += mapContentBytes(lr.Attributes())
			}
		}
	}
	return total
}

func metricsSourceContentBytes(md pmetric.Metrics) int64 {
	var total int64
	rms := md.ResourceMetrics()
	for i := 0; i < rms.Len(); i++ {
		rm := rms.At(i)
		total += mapContentBytes(rm.Resource().Attributes()) + int64(len(rm.SchemaUrl()))
		sms := rm.ScopeMetrics()
		for j := 0; j < sms.Len(); j++ {
			sm := sms.At(j)
			total += int64(len(sm.Scope().Name())+len(sm.Scope().Version())+len(sm.SchemaUrl())) + mapContentBytes(sm.Scope().Attributes())
			ms := sm.Metrics()
			for k := 0; k < ms.Len(); k++ {
				m := ms.At(k)
				total += int64(len(m.Name()) + len(m.Description()) + len(m.Unit()))
				switch m.Type() {
				case pmetric.MetricTypeGauge:
					total += numberDataPointsBytes(m.Gauge().DataPoints())
				case pmetric.MetricTypeSum:
					total += numberDataPointsBytes(m.Sum().DataPoints())
				case pmetric.MetricTypeHistogram:
					dps := m.Histogram().DataPoints()
					for d := 0; d < dps.Len(); d++ {
						dp := dps.At(d)
						total += 16 // start + end timestamps
						total += int64(dp.ExplicitBounds().Len()*8 + dp.BucketCounts().Len()*8 + 24)
						total += mapContentBytes(dp.Attributes())
						total += exemplarsBytes(dp.Exemplars())
					}
				case pmetric.MetricTypeExponentialHistogram:
					dps := m.ExponentialHistogram().DataPoints()
					for d := 0; d < dps.Len(); d++ {
						dp := dps.At(d)
						total += 16 + 32 // start + end timestamps + scale/counts/sum/min/max
						total += int64((dp.Positive().BucketCounts().Len() + dp.Negative().BucketCounts().Len()) * 8)
						total += mapContentBytes(dp.Attributes())
						total += exemplarsBytes(dp.Exemplars())
					}
				case pmetric.MetricTypeSummary:
					dps := m.Summary().DataPoints()
					for d := 0; d < dps.Len(); d++ {
						dp := dps.At(d)
						total += 16 + 16 // start + end timestamps + count + sum
						total += int64(dp.QuantileValues().Len() * 16)
						total += mapContentBytes(dp.Attributes())
					}
				}
			}
		}
	}
	return total
}

func numberDataPointsBytes(dps pmetric.NumberDataPointSlice) int64 {
	var total int64
	for d := 0; d < dps.Len(); d++ {
		dp := dps.At(d)
		total += 16 + 8 // start + end timestamps + numeric value
		total += mapContentBytes(dp.Attributes())
		total += exemplarsBytes(dp.Exemplars())
	}
	return total
}

func exemplarsBytes(exs pmetric.ExemplarSlice) int64 {
	var total int64
	for e := 0; e < exs.Len(); e++ {
		ex := exs.At(e)
		total += 16 + mapContentBytes(ex.FilteredAttributes())
		if !ex.TraceID().IsEmpty() {
			total += 16
		}
		if !ex.SpanID().IsEmpty() {
			total += 8
		}
	}
	return total
}

func mapContentBytes(m pcommon.Map) int64 {
	var total int64
	m.Range(func(k string, v pcommon.Value) bool {
		total += int64(len(k)) + valueContentBytes(v)
		return true
	})
	return total
}

func valueContentBytes(v pcommon.Value) int64 {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		return int64(len(v.Str()))
	case pcommon.ValueTypeBytes:
		return int64(v.Bytes().Len())
	case pcommon.ValueTypeInt:
		var buf [24]byte
		return int64(len(strconv.AppendInt(buf[:0], v.Int(), 10)))
	case pcommon.ValueTypeDouble:
		var buf [32]byte
		return int64(len(strconv.AppendFloat(buf[:0], v.Double(), 'g', -1, 64)))
	case pcommon.ValueTypeBool:
		if v.Bool() {
			return 4
		}
		return 5
	case pcommon.ValueTypeMap:
		return mapContentBytes(v.Map())
	case pcommon.ValueTypeSlice:
		var total int64
		sl := v.Slice()
		for i := 0; i < sl.Len(); i++ {
			total += valueContentBytes(sl.At(i))
		}
		return total
	default:
		return 0
	}
}

func tableStorageRegionSQL(projectID, location string) (string, error) {
	loc := strings.ToLower(strings.TrimSpace(location))
	if loc == "" {
		return "", errors.New("dataset location is empty; cannot construct INFORMATION_SCHEMA.TABLE_STORAGE region qualifier")
	}
	return fmt.Sprintf(
		"SELECT COALESCE(total_rows, 0), COALESCE(total_logical_bytes, 0), COALESCE(active_physical_bytes, 0), COALESCE(long_term_physical_bytes, 0), COALESCE(time_travel_physical_bytes, 0), COALESCE(fail_safe_physical_bytes, 0) "+
			"FROM `%s.region-%s.INFORMATION_SCHEMA.TABLE_STORAGE` "+
			"WHERE table_schema = @dataset AND table_name = @table AND deleted = FALSE",
		projectID, loc,
	), nil
}

func populateLiveTableStorage(ctx context.Context, cfg RunnerConfig, tableName string, layers *ByteLayersSummary) {
	if layers == nil || cfg.Mode != ModeLive {
		return
	}
	qCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	client, closeAll, err := newBigQueryClient(qCtx, cfg.ProjectID, cfg.ClientOptions...)
	if err != nil {
		layers.BQStorageQueryNote = fmt.Sprintf("INFORMATION_SCHEMA.TABLE_STORAGE client error: %v", err)
		return
	}
	defer closeAll()

	loc := strings.TrimSpace(cfg.Location)
	if loc == "" {
		md, mdErr := client.Dataset(cfg.DatasetID).Metadata(qCtx)
		if mdErr != nil {
			layers.BQStorageQueryNote = fmt.Sprintf("INFORMATION_SCHEMA.TABLE_STORAGE dataset metadata lookup failed: %v", mdErr)
			return
		}
		loc = strings.TrimSpace(md.Location)
	}
	sqlText, err := tableStorageRegionSQL(cfg.ProjectID, loc)
	if err != nil {
		layers.BQStorageQueryNote = err.Error()
		return
	}
	client.Location = loc

	q := client.Query(sqlText)
	q.Parameters = []bigquery.QueryParameter{
		{Name: "dataset", Value: cfg.DatasetID},
		{Name: "table", Value: tableName},
	}
	it, err := q.Read(qCtx)
	if err != nil {
		layers.BQStorageQueryNote = fmt.Sprintf("INFORMATION_SCHEMA.TABLE_STORAGE query failed: %v", err)
		return
	}
	var row []bigquery.Value
	err = it.Next(&row)
	if errors.Is(err, iterator.Done) {
		layers.BQStorageQueryNote = "INFORMATION_SCHEMA.TABLE_STORAGE returned 0 rows (storage metadata not yet materialized)"
		return
	}
	if err != nil {
		layers.BQStorageQueryNote = fmt.Sprintf("INFORMATION_SCHEMA.TABLE_STORAGE read failed: %v", err)
		return
	}
	if len(row) < 6 {
		layers.BQStorageQueryNote = fmt.Sprintf("unexpected column count %d from INFORMATION_SCHEMA.TABLE_STORAGE", len(row))
		return
	}
	totalRows, _ := row[0].(int64)
	logicalBytes, _ := row[1].(int64)
	activePhysBytes, _ := row[2].(int64)
	longTermPhysBytes, _ := row[3].(int64)
	timeTravelPhysBytes, _ := row[4].(int64)
	failSafePhysBytes, _ := row[5].(int64)

	layers.BQTotalRows = totalRows
	layers.BQLogicalBytes = logicalBytes
	layers.BQActivePhysicalBytes = activePhysBytes
	layers.BQLongTermPhysicalBytes = longTermPhysBytes
	layers.BQTimeTravelPhysicalBytes = timeTravelPhysBytes
	layers.BQFailSafePhysicalBytes = failSafePhysBytes

	// active_physical_bytes in TABLE_STORAGE includes time-travel bytes; subtract
	// time_travel_physical_bytes (clamped at 0) so tables with rewrites or
	// expired rows report current-row physical compression rather than retention overhead.
	currentPhys := max(int64(0), activePhysBytes-timeTravelPhysBytes) + longTermPhysBytes
	if totalRows > 0 {
		layers.BQLogicalBytesPerRow = round2(float64(logicalBytes) / float64(totalRows))
		layers.BQPhysicalBytesPerRow = round2(float64(currentPhys) / float64(totalRows))
	}
	if currentPhys > 0 && logicalBytes > 0 {
		layers.BQCompressionRatio = round2(float64(logicalBytes) / float64(currentPhys))
	} else {
		layers.BQCompressionRatio = 0
	}
}
