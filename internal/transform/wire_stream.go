// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package transform // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"

import (
	"crypto/sha256"
	"hash"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/otlpjson"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

// SpanWireInput carries one validated span and its pre-encoded origin fields
// for zero-map streaming protobuf encoding.
type SpanWireInput struct {
	Span                ptrace.Span
	ReceiveTimeMicros   int64
	ReceiveTimeUnixNano int64
	ServiceName         string
	ResourceWire        []byte
	ResourceSchemaURL   string
	ScopeWire           []byte
	ScopeSchemaURL      string
	Refs                []PayloadRef
}

// LogWireInput carries one validated log record and its pre-encoded origin
// fields for zero-map streaming protobuf encoding.
type LogWireInput struct {
	Record              plog.LogRecord
	TimestampMicros     int64
	TimestampSource     string
	ReceiveTimeMicros   int64
	ReceiveTimeUnixNano int64
	EventName           string
	ServiceName         string
	ResourceWire        []byte
	ResourceSchemaURL   string
	ScopeWire           []byte
	ScopeSchemaURL      string
	Refs                []PayloadRef
	LogName             string
	InsertID            string
}

// MetricWireInput carries one validated metric data point and its pre-encoded
// origin fields for zero-map streaming protobuf encoding.
type MetricWireInput struct {
	Timestamp              pcommon.Timestamp
	StartTimestamp         pcommon.Timestamp
	ReceiveTimeMicros      int64
	ReceiveTimeUnixNano    int64
	ServiceName            string
	MetricName             string
	MetricDescription      string
	MetricUnit             string
	MetricType             string
	AggregationTemporality string
	HasMonotonic           bool
	IsMonotonic            bool
	Flags                  pmetric.DataPointFlags
	Attributes             pcommon.Map
	HasMetadata            bool
	MetadataJSON           []byte
	ValueType              string
	HasValueDouble         bool
	ValueDouble            float64
	HasValueInt64          bool
	ValueInt64             int64
	HasCount               bool
	Count                  int64
	HasSum                 bool
	Sum                    float64
	HasMin                 bool
	Min                    float64
	HasMax                 bool
	Max                    float64
	ExplicitBounds         []float64
	BucketCounts           []uint64
	IsExpHistogram         bool
	ExpScale               int64
	ExpZeroCount           int64
	ExpZeroThreshold       float64
	ExpPositive            pmetric.ExponentialHistogramDataPointBuckets
	ExpNegative            pmetric.ExponentialHistogramDataPointBuckets
	IsSummary              bool
	SummaryQuantiles       pmetric.SummaryDataPointValueAtQuantileSlice
	Exemplars              pmetric.ExemplarSlice
	ResourceWire           []byte
	ResourceSchemaURL      string
	ScopeWire              []byte
	ScopeSchemaURL         string
	PointFingerprint       string
}

// SpanWireSink serializes pre-validated span batches directly to protobuf wire
// rows, caching Resource and InstrumentationScope field bytes per origin.
type SpanWireSink interface {
	EncodeSpanResource(attrs pcommon.Map, dropped uint32) []byte
	EncodeSpanScope(name, version string, attrs pcommon.Map, dropped uint32) []byte
	EncodeSpanWire(in *SpanWireInput, maxRowBytes int) (wire []byte, actualLen int, oversized bool, err error)
}

// LogWireSink serializes pre-validated log batches directly to protobuf wire
// rows, caching Resource and InstrumentationScope field bytes per origin.
type LogWireSink interface {
	EncodeLogResource(attrs pcommon.Map, dropped uint32) []byte
	EncodeLogScope(name, version string, attrs pcommon.Map, dropped uint32) []byte
	EncodeLogWire(in *LogWireInput, maxRowBytes int) (wire []byte, actualLen int, oversized bool, err error)
}

// MetricWireSink serializes pre-validated metric batches directly to protobuf
// wire rows, caching Resource and InstrumentationScope field bytes per origin.
type MetricWireSink interface {
	EncodeMetricResource(attrs pcommon.Map, dropped uint32) []byte
	EncodeMetricScope(name, version string, attrs pcommon.Map, dropped uint32) []byte
	EncodeMetricWire(in *MetricWireInput, maxRowBytes int) (wire []byte, actualLen int, oversized bool, err error)
}

// StreamSpanRows validates, redacts, offloads, and directly serializes spans
// into protobuf wire rows without allocating intermediate Row maps.
//
// keptIndex holds the 0-based batch span index for each entry in encoded.
// drops carries serialization and maxRowBytes failures indexed by batch span
// index.
func StreamSpanRows(
	td ptrace.Traces,
	opts Options,
	maxRowBytes int,
	sink SpanWireSink,
) (encoded [][]byte, keptIndex []int, rejects []Rejection, drops []QuarantineEntry) {
	td = opts.Redactor.Traces(td)
	ctx := WithBatchUploadCache(opts.context())
	received := opts.now()
	receiveMicros := received.UnixMicro()
	receiveNano := received.UnixNano()
	spanCount := td.SpanCount()
	encoded = make([][]byte, 0, spanCount)
	keptIndex = make([]int, 0, spanCount)

	var pre []preOffloadedSpan
	if opts.PayloadOffloader != nil && spanCount > 1 {
		if conc := offloadConcurrency(opts.PayloadOffloader); conc > 1 {
			pre = preOffloadSpans(ctx, td, opts, conc)
		}
	}

	eligChecker, hasEligChecker := opts.PayloadOffloader.(EligiblePayloadOffloader)
	trackedOffloader, isTracked := opts.PayloadOffloader.(TrackedPayloadOffloader)

	idx := -1
	for _, rs := range td.ResourceSpans().All() {
		resource := rs.Resource()
		resWire := sink.EncodeSpanResource(resource.Attributes(), resource.DroppedAttributesCount())
		if opts.onEncodeResource != nil {
			opts.onEncodeResource()
		}
		svc := sanitize(stringAttr(resource.Attributes(), serviceNameAttr))
		resSchemaURL := sanitize(rs.SchemaUrl())

		for _, ss := range rs.ScopeSpans().All() {
			scope := ss.Scope()
			scopeName := sanitize(scope.Name())
			scopeVer := sanitize(scope.Version())
			scopeWire := sink.EncodeSpanScope(scopeName, scopeVer, scope.Attributes(), scope.DroppedAttributesCount())
			if opts.onEncodeScope != nil {
				opts.onEncodeScope()
			}
			scopeSchemaURL := sanitize(ss.SchemaUrl())

			for _, span := range ss.Spans().All() {
				idx++
				rowSpan, rowResWire, rowScopeWire := span, resWire, scopeWire
				var refs []PayloadRef
				if opts.PayloadOffloader != nil && (!hasEligChecker || eligChecker.HasEligibleSpan(span, resource, scope)) {
					var (
						preBad     *Violation
						workSpan   ptrace.Span
						workRes    pcommon.Resource
						workScope  pcommon.InstrumentationScope
						report     OffloadReport
						offloadErr error
					)
					if pre != nil {
						p := pre[idx]
						preBad, workSpan, workRes, workScope, report, offloadErr = p.preBad, p.workSpan, p.workRes, p.workScope, p.report, p.err
					} else {
						preBad = checkSpanPreOffload(span, resource, scope, opts.Limits)
						if preBad == nil {
							workSpan = cloneSpanForOffload(span)
							workRes = cloneResourceForOffload(resource)
							workScope = cloneScopeForOffload(scope)
							if isTracked {
								report, offloadErr = trackedOffloader.OffloadSpanTracked(ctx, workSpan, workRes, workScope)
							} else {
								var r []PayloadRef
								r, offloadErr = opts.PayloadOffloader.OffloadSpan(ctx, workSpan, workRes, workScope)
								report = OffloadReport{Refs: r, Mutated: true, ResourceMutated: true, ScopeMutated: true}
							}
						}
					}
					if preBad != nil {
						rejects = append(rejects, Rejection{idx, preBad.Reason, preBad.FieldPath, preBad.Limit, preBad.Actual})
						continue
					}
					if offloadErr != nil {
						if opts.OnOffloadError != nil {
							opts.OnOffloadError(idx, offloadErr)
						}
						continue
					}
					refs = report.Refs
					if !report.Mutated {
						if bad := checkSpan(span, resource, scope, opts.Limits); bad != nil {
							rejects = append(rejects, Rejection{idx, bad.Reason, bad.FieldPath, bad.Limit, bad.Actual})
							continue
						}
					} else {
						if bad := checkSpan(workSpan, workRes, workScope, opts.Limits); bad != nil {
							rejects = append(rejects, Rejection{idx, bad.Reason, bad.FieldPath, bad.Limit, bad.Actual})
							continue
						}
						rowSpan = workSpan
						if report.ResourceMutated {
							rowResWire = sink.EncodeSpanResource(workRes.Attributes(), workRes.DroppedAttributesCount())
							if opts.onEncodeResource != nil {
								opts.onEncodeResource()
							}
						}
						if report.ScopeMutated {
							rowScopeWire = sink.EncodeSpanScope(sanitize(workScope.Name()), sanitize(workScope.Version()), workScope.Attributes(), workScope.DroppedAttributesCount())
							if opts.onEncodeScope != nil {
								opts.onEncodeScope()
							}
						}
					}
				} else if bad := checkSpan(span, resource, scope, opts.Limits); bad != nil {
					rejects = append(rejects, Rejection{idx, bad.Reason, bad.FieldPath, bad.Limit, bad.Actual})
					continue
				}

				if opts.onEncodeRecord != nil {
					opts.onEncodeRecord()
				}
				in := SpanWireInput{
					Span:                rowSpan,
					ReceiveTimeMicros:   receiveMicros,
					ReceiveTimeUnixNano: receiveNano,
					ServiceName:         svc,
					ResourceWire:        rowResWire,
					ResourceSchemaURL:   resSchemaURL,
					ScopeWire:           rowScopeWire,
					ScopeSchemaURL:      scopeSchemaURL,
					Refs:                refs,
				}
				b, actualLen, oversized, err := sink.EncodeSpanWire(&in, maxRowBytes)
				if err != nil {
					drops = append(drops, QuarantineEntry{
						Rejection: Rejection{Index: idx, Reason: ReasonSerialization},
						Detail:    err.Error(),
					})
					continue
				}
				if oversized {
					drops = append(drops, QuarantineEntry{
						Rejection: Rejection{Index: idx, Reason: ReasonRowBytes, Limit: maxRowBytes, Actual: actualLen},
					})
					continue
				}
				encoded = append(encoded, b)
				keptIndex = append(keptIndex, idx)
			}
		}
	}
	return encoded, keptIndex, rejects, drops
}

// StreamLogRows validates, redacts, offloads, fingerprints, and directly
// serializes log records into protobuf wire rows without allocating
// intermediate Row maps.
//
// Resource and InstrumentationScope nested protobuf bytes are encoded once per
// ResourceLogs / ScopeLogs and spliced into every child row (re-encoded only if
// an offload hook mutates the working resource or scope).
func StreamLogRows(
	ld plog.Logs,
	opts Options,
	maxRowBytes int,
	sink LogWireSink,
) (encoded [][]byte, keptIndex []int, rejects []Rejection, drops []QuarantineEntry) {
	ld = opts.Redactor.Logs(ld)
	ctx := WithBatchUploadCache(opts.context())
	received := opts.now()
	receiveMicros := received.UnixMicro()
	receiveNano := received.UnixNano()
	logCount := ld.LogRecordCount()
	encoded = make([][]byte, 0, logCount)
	keptIndex = make([]int, 0, logCount)

	v1Fingerprints := fingerprinterV1{}
	var v1Hash hash.Hash

	var pre []preOffloadedLog
	if opts.PayloadOffloader != nil && logCount > 1 {
		if conc := offloadConcurrency(opts.PayloadOffloader); conc > 1 {
			pre = preOffloadLogs(ctx, ld, opts, conc)
		}
	}

	eligChecker, hasEligChecker := opts.PayloadOffloader.(EligiblePayloadOffloader)
	trackedOffloader, isTracked := opts.PayloadOffloader.(TrackedPayloadOffloader)

	idx := -1
	for _, rl := range ld.ResourceLogs().All() {
		resource := rl.Resource()
		resWire := sink.EncodeLogResource(resource.Attributes(), resource.DroppedAttributesCount())
		if opts.onEncodeResource != nil {
			opts.onEncodeResource()
		}
		svc := sanitize(stringAttr(resource.Attributes(), serviceNameAttr))
		resSchemaURL := sanitize(rl.SchemaUrl())

		for _, sl := range rl.ScopeLogs().All() {
			scope := sl.Scope()
			scopeName := sanitize(scope.Name())
			scopeVer := sanitize(scope.Version())
			scopeWire := sink.EncodeLogScope(scopeName, scopeVer, scope.Attributes(), scope.DroppedAttributesCount())
			if opts.onEncodeScope != nil {
				opts.onEncodeScope()
			}
			scopeSchemaURL := sanitize(sl.SchemaUrl())
			origin := logOrigin{
				resSchemaURL:   rl.SchemaUrl(),
				scopeSchemaURL: sl.SchemaUrl(),
				svc:            svc,
				rawRes:         resource,
				rawScope:       scope,
			}

			for _, lr := range sl.LogRecords().All() {
				idx++
				rowLR := lr
				rowResWire := resWire
				rowScopeWire := scopeWire
				var refs []PayloadRef
				if opts.PayloadOffloader != nil && (!hasEligChecker || eligChecker.HasEligibleLog(lr, resource, scope)) {
					var (
						preBad     *Violation
						workLR     plog.LogRecord
						workRes    pcommon.Resource
						workScope  pcommon.InstrumentationScope
						report     OffloadReport
						offloadErr error
					)
					if pre != nil {
						p := pre[idx]
						preBad, workLR, workRes, workScope, report, offloadErr = p.preBad, p.workLR, p.workRes, p.workScope, p.report, p.err
					} else {
						preBad = checkLogPreOffload(lr, resource, scope, opts.Limits)
						if preBad == nil {
							workLR = cloneLogRecordForOffload(lr)
							workRes = cloneResourceForOffload(resource)
							workScope = cloneScopeForOffload(scope)
							if isTracked {
								report, offloadErr = trackedOffloader.OffloadLogTracked(ctx, workLR, workRes, workScope)
							} else {
								var r []PayloadRef
								r, offloadErr = opts.PayloadOffloader.OffloadLog(ctx, workLR, workRes, workScope)
								report = OffloadReport{Refs: r, Mutated: true, ResourceMutated: true, ScopeMutated: true}
							}
						}
					}
					if preBad != nil {
						rejects = append(rejects, Rejection{idx, preBad.Reason, preBad.FieldPath, preBad.Limit, preBad.Actual})
						continue
					}
					if offloadErr != nil {
						if opts.OnOffloadError != nil {
							opts.OnOffloadError(idx, offloadErr)
						}
						continue
					}
					refs = report.Refs
					if !report.Mutated {
						if bad := checkLog(lr, resource, scope, opts.Limits); bad != nil {
							rejects = append(rejects, Rejection{idx, bad.Reason, bad.FieldPath, bad.Limit, bad.Actual})
							continue
						}
					} else {
						if bad := checkLog(workLR, workRes, workScope, opts.Limits); bad != nil {
							rejects = append(rejects, Rejection{idx, bad.Reason, bad.FieldPath, bad.Limit, bad.Actual})
							continue
						}
						rowLR = workLR
						if report.ResourceMutated {
							rowResWire = sink.EncodeLogResource(workRes.Attributes(), workRes.DroppedAttributesCount())
							if opts.onEncodeResource != nil {
								opts.onEncodeResource()
							}
						}
						if report.ScopeMutated {
							rowScopeWire = sink.EncodeLogScope(sanitize(workScope.Name()), sanitize(workScope.Version()), workScope.Attributes(), workScope.DroppedAttributesCount())
							if opts.onEncodeScope != nil {
								opts.onEncodeScope()
							}
						}
					}
				} else if bad := checkLog(lr, resource, scope, opts.Limits); bad != nil {
					rejects = append(rejects, Rejection{idx, bad.Reason, bad.FieldPath, bad.Limit, bad.Actual})
					continue
				}

				// Derive identity columns (insert_id, log_name, event_name) from the
				// pre-offload record lr rather than workLR/rowLR, matching logRowV1 so
				// GCS offload placeholders do not alter logical record identity.
				resolvedInsertID := firstStringAttr(lr.Attributes(), opts.InsertIDAttribute, insertIDAttrs)
				if resolvedInsertID == "" && opts.SynthesizeInsertID {
					if v1Hash == nil {
						v1Hash = sha256.New()
					}
					if !origin.hasV1Digest {
						origin.v1Digest = hashOriginV1(v1Hash, origin.rawRes, origin.resSchemaURL, origin.rawScope, origin.scopeSchemaURL, opts.onSHA256)
						origin.hasV1Digest = true
					}
					resolvedInsertID = v1Fingerprints.nextLogInsertID(v1Hash, lr, origin.v1Digest, opts.onSHA256)
				}

				resolvedLogName := logName(lr.Attributes(), origin.svc, opts.LogNameAttribute)
				resolvedEventName := eventName(lr)

				partitionMicros := receiveMicros
				source := schema.TimestampSourceExporter
				switch {
				case rowLR.Timestamp() != 0:
					partitionMicros = micros(rowLR.Timestamp())
					source = schema.TimestampSourceEvent
				case rowLR.ObservedTimestamp() != 0:
					partitionMicros = micros(rowLR.ObservedTimestamp())
					source = schema.TimestampSourceObserved
				}

				if opts.onEncodeRecord != nil {
					opts.onEncodeRecord()
				}
				in := LogWireInput{
					Record:              rowLR,
					TimestampMicros:     partitionMicros,
					TimestampSource:     source,
					ReceiveTimeMicros:   receiveMicros,
					ReceiveTimeUnixNano: receiveNano,
					EventName:           resolvedEventName,
					ServiceName:         origin.svc,
					ResourceWire:        rowResWire,
					ResourceSchemaURL:   resSchemaURL,
					ScopeWire:           rowScopeWire,
					ScopeSchemaURL:      scopeSchemaURL,
					Refs:                refs,
					LogName:             resolvedLogName,
					InsertID:            resolvedInsertID,
				}
				b, actualLen, oversized, err := sink.EncodeLogWire(&in, maxRowBytes)
				if err != nil {
					drops = append(drops, QuarantineEntry{
						Rejection: Rejection{Index: idx, Reason: ReasonSerialization},
						Detail:    err.Error(),
					})
					continue
				}
				if oversized {
					drops = append(drops, QuarantineEntry{
						Rejection: Rejection{Index: idx, Reason: ReasonRowBytes, Limit: maxRowBytes, Actual: actualLen},
					})
					continue
				}
				encoded = append(encoded, b)
				keptIndex = append(keptIndex, idx)
			}
		}
	}
	return encoded, keptIndex, rejects, drops
}

// StreamMetricRows validates, redacts, fingerprints, and directly serializes
// metric data points into protobuf wire rows without allocating intermediate
// Row maps.
func StreamMetricRows(
	md pmetric.Metrics,
	opts Options,
	maxRowBytes int,
	sink MetricWireSink,
) (encoded [][]byte, keptIndex []int, rejects []Rejection, drops []QuarantineEntry) {
	md = opts.Redactor.Metrics(md)
	received := opts.now()
	receiveMicros := received.UnixMicro()
	receiveNano := received.UnixNano()
	pointCount := md.DataPointCount()
	encoded = make([][]byte, 0, pointCount)
	keptIndex = make([]int, 0, pointCount)
	v1Fingerprints := fingerprinterV1{}
	v1Hash := sha256.New()
	idx := -1

	emitPoint := func(
		ts, startTS pcommon.Timestamp,
		flags pmetric.DataPointFlags,
		attrs pcommon.Map,
		exemplars pmetric.ExemplarSlice,
		desc metricDescriptor,
		metaJSON []byte,
		origin metricOrigin,
		resWire, scopeWire []byte,
		resSchemaURL, scopeSchemaURL string,
		writeValue func(hash.Hash),
		in *MetricWireInput,
	) {
		fp := v1Fingerprints.nextMetricFingerprint(func(ordinal int) [32]byte {
			return hashMetricPointV1(v1Hash, ts, startTS, flags, attrs, exemplars, desc, origin, writeValue, ordinal)
		})
		in.Timestamp = ts
		in.StartTimestamp = startTS
		in.ReceiveTimeMicros = receiveMicros
		in.ReceiveTimeUnixNano = receiveNano
		in.ServiceName = origin.svc
		in.MetricName = desc.name
		in.MetricDescription = desc.desc
		in.MetricUnit = desc.unit
		in.MetricType = desc.metricType
		in.AggregationTemporality = desc.temporality
		if desc.monotonic != nil {
			in.HasMonotonic = true
			in.IsMonotonic = *desc.monotonic
		}
		in.Flags = flags
		in.Attributes = attrs
		in.HasMetadata = desc.hasMeta
		in.MetadataJSON = metaJSON
		in.Exemplars = exemplars
		in.ResourceWire = resWire
		in.ResourceSchemaURL = resSchemaURL
		in.ScopeWire = scopeWire
		in.ScopeSchemaURL = scopeSchemaURL
		in.PointFingerprint = fp

		if opts.onEncodeRecord != nil {
			opts.onEncodeRecord()
		}
		b, actualLen, oversized, err := sink.EncodeMetricWire(in, maxRowBytes)
		if err != nil {
			drops = append(drops, QuarantineEntry{
				Rejection: Rejection{Index: idx, Reason: ReasonSerialization},
				Detail:    err.Error(),
			})
			return
		}
		if oversized {
			drops = append(drops, QuarantineEntry{
				Rejection: Rejection{Index: idx, Reason: ReasonRowBytes, Limit: maxRowBytes, Actual: actualLen},
			})
			return
		}
		encoded = append(encoded, b)
		keptIndex = append(keptIndex, idx)
	}

	for _, rm := range md.ResourceMetrics().All() {
		resource := rm.Resource()
		resWire := sink.EncodeMetricResource(resource.Attributes(), resource.DroppedAttributesCount())
		if opts.onEncodeResource != nil {
			opts.onEncodeResource()
		}
		svc := sanitize(stringAttr(resource.Attributes(), serviceNameAttr))
		resSchemaURL := sanitize(rm.SchemaUrl())

		for _, sm := range rm.ScopeMetrics().All() {
			scope := sm.Scope()
			scopeWire := sink.EncodeMetricScope(sanitize(scope.Name()), sanitize(scope.Version()), scope.Attributes(), scope.DroppedAttributesCount())
			if opts.onEncodeScope != nil {
				opts.onEncodeScope()
			}
			scopeSchemaURL := sanitize(sm.SchemaUrl())
			origin := metricOrigin{
				resSchemaURL:   rm.SchemaUrl(),
				scopeSchemaURL: sm.SchemaUrl(),
				svc:            svc,
				v1Digest:       hashOriginV1(v1Hash, resource, rm.SchemaUrl(), scope, sm.SchemaUrl(), opts.onSHA256),
			}

			for _, m := range sm.Metrics().All() {
				hasMeta := m.Metadata().Len() > 0
				var metaJSON []byte
				if hasMeta {
					metaJSON = otlpjson.AppendPlainMap(nil, m.Metadata())
				}
				desc := metricDescriptor{
					name:    sanitize(m.Name()),
					rawName: m.Name(),
					desc:    sanitize(m.Description()),
					unit:    sanitize(m.Unit()),
					hasMeta: hasMeta,
					rawMeta: m.Metadata(),
				}

				switch m.Type() {
				case pmetric.MetricTypeGauge:
					desc.metricType = MetricTypeGauge
					for _, dp := range m.Gauge().DataPoints().All() {
						idx++
						if bad := checkNumberPoint(dp, desc, resource, scope, opts.Limits); bad != nil {
							rejects = append(rejects, Rejection{idx, bad.Reason, bad.FieldPath, bad.Limit, bad.Actual})
							continue
						}
						var in MetricWireInput
						if !hasNoRecordedValue(dp.Flags()) {
							switch dp.ValueType() {
							case pmetric.NumberDataPointValueTypeDouble:
								in.ValueType = ScalarValueTypeDouble
								in.HasValueDouble = true
								in.ValueDouble = dp.DoubleValue()
							case pmetric.NumberDataPointValueTypeInt:
								in.ValueType = ScalarValueTypeInt64
								in.HasValueInt64 = true
								in.ValueInt64 = dp.IntValue()
							}
						}
						emitPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, metaJSON, origin, resWire, scopeWire, resSchemaURL, scopeSchemaURL, func(hh hash.Hash) {
							writeHashNumberValueV1(hh, dp)
						}, &in)
					}

				case pmetric.MetricTypeSum:
					desc.metricType = MetricTypeSum
					desc.temporality = temporalityName(m.Sum().AggregationTemporality())
					monotonic := m.Sum().IsMonotonic()
					desc.monotonic = &monotonic
					for _, dp := range m.Sum().DataPoints().All() {
						idx++
						if bad := checkNumberPoint(dp, desc, resource, scope, opts.Limits); bad != nil {
							rejects = append(rejects, Rejection{idx, bad.Reason, bad.FieldPath, bad.Limit, bad.Actual})
							continue
						}
						var in MetricWireInput
						if !hasNoRecordedValue(dp.Flags()) {
							switch dp.ValueType() {
							case pmetric.NumberDataPointValueTypeDouble:
								in.ValueType = ScalarValueTypeDouble
								in.HasValueDouble = true
								in.ValueDouble = dp.DoubleValue()
							case pmetric.NumberDataPointValueTypeInt:
								in.ValueType = ScalarValueTypeInt64
								in.HasValueInt64 = true
								in.ValueInt64 = dp.IntValue()
							}
						}
						emitPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, metaJSON, origin, resWire, scopeWire, resSchemaURL, scopeSchemaURL, func(hh hash.Hash) {
							writeHashNumberValueV1(hh, dp)
						}, &in)
					}

				case pmetric.MetricTypeHistogram:
					desc.metricType = MetricTypeHistogram
					desc.temporality = temporalityName(m.Histogram().AggregationTemporality())
					for _, dp := range m.Histogram().DataPoints().All() {
						idx++
						if bad := checkHistogramPoint(dp, desc, resource, scope, opts.Limits); bad != nil {
							rejects = append(rejects, Rejection{idx, bad.Reason, bad.FieldPath, bad.Limit, bad.Actual})
							continue
						}
						var in MetricWireInput
						if !hasNoRecordedValue(dp.Flags()) {
							in.HasCount = true
							in.Count = int64(dp.Count())
							if dp.HasSum() {
								in.HasSum = true
								in.Sum = dp.Sum()
							}
							if dp.HasMin() {
								in.HasMin = true
								in.Min = dp.Min()
							}
							if dp.HasMax() {
								in.HasMax = true
								in.Max = dp.Max()
							}
							in.ExplicitBounds = dp.ExplicitBounds().AsRaw()
							in.BucketCounts = dp.BucketCounts().AsRaw()
						}
						emitPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, metaJSON, origin, resWire, scopeWire, resSchemaURL, scopeSchemaURL, func(hh hash.Hash) {
							writeHashHistogramValueV1(hh, dp)
						}, &in)
					}

				case pmetric.MetricTypeExponentialHistogram:
					desc.metricType = MetricTypeExponentialHistogram
					desc.temporality = temporalityName(m.ExponentialHistogram().AggregationTemporality())
					for _, dp := range m.ExponentialHistogram().DataPoints().All() {
						idx++
						if bad := checkExpHistogramPoint(dp, desc, resource, scope, opts.Limits); bad != nil {
							rejects = append(rejects, Rejection{idx, bad.Reason, bad.FieldPath, bad.Limit, bad.Actual})
							continue
						}
						var in MetricWireInput
						if !hasNoRecordedValue(dp.Flags()) {
							in.HasCount = true
							in.Count = int64(dp.Count())
							if dp.HasSum() {
								in.HasSum = true
								in.Sum = dp.Sum()
							}
							if dp.HasMin() {
								in.HasMin = true
								in.Min = dp.Min()
							}
							if dp.HasMax() {
								in.HasMax = true
								in.Max = dp.Max()
							}
							in.IsExpHistogram = true
							in.ExpScale = int64(dp.Scale())
							in.ExpZeroCount = int64(dp.ZeroCount())
							in.ExpZeroThreshold = dp.ZeroThreshold()
							in.ExpPositive = dp.Positive()
							in.ExpNegative = dp.Negative()
						}
						emitPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, metaJSON, origin, resWire, scopeWire, resSchemaURL, scopeSchemaURL, func(hh hash.Hash) {
							writeHashExpHistogramValueV1(hh, dp)
						}, &in)
					}

				case pmetric.MetricTypeSummary:
					desc.metricType = MetricTypeSummary
					for _, dp := range m.Summary().DataPoints().All() {
						idx++
						if bad := checkSummaryPoint(dp, desc, resource, scope, opts.Limits); bad != nil {
							rejects = append(rejects, Rejection{idx, bad.Reason, bad.FieldPath, bad.Limit, bad.Actual})
							continue
						}
						var in MetricWireInput
						if !hasNoRecordedValue(dp.Flags()) {
							in.HasCount = true
							in.Count = int64(dp.Count())
							in.HasSum = true
							in.Sum = dp.Sum()
							in.IsSummary = true
							in.SummaryQuantiles = dp.QuantileValues()
						}
						emitPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), pmetric.NewExemplarSlice(), desc, metaJSON, origin, resWire, scopeWire, resSchemaURL, scopeSchemaURL, func(hh hash.Hash) {
							writeHashSummaryValueV1(hh, dp)
						}, &in)
					}
				}
			}
		}
	}
	return encoded, keptIndex, rejects, drops
}
