// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package transform // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"

import (
	"crypto/sha256"
	"hash"
	"math"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/otlpjson"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

// Metric type, aggregation temporality, and scalar value type constants written
// to otel_metrics.
const (
	MetricTypeGauge                = "GAUGE"
	MetricTypeSum                  = "SUM"
	MetricTypeHistogram            = "HISTOGRAM"
	MetricTypeExponentialHistogram = "EXPONENTIAL_HISTOGRAM"
	MetricTypeSummary              = "SUMMARY"

	TemporalityUnspecified = "UNSPECIFIED"
	TemporalityDelta       = "DELTA"
	TemporalityCumulative  = "CUMULATIVE"

	ScalarValueTypeDouble = "DOUBLE"
	ScalarValueTypeInt64  = "INT64"
)

// MetricRows converts a metrics batch into rows, one per data point, dropping
// points that violate the metric contract or breach the FR8 structural limits
// and reporting them as rejections.
//
// Index in a rejection is the 0-based position of the data point in a
// flattened walk of the batch, matching MetricQuarantineRows and SelectMetrics.
func MetricRows(md pmetric.Metrics, opts Options) ([]Row, []Rejection) {
	// Step 0: redact before anything reads an attribute, metadata entry, or
	// exemplar. point_fingerprint below is taken from the redacted point.
	md = opts.Redactor.Metrics(md)
	received := opts.now()
	rows := make([]Row, 0, md.DataPointCount())
	var rejects []Rejection
	isV1 := opts.Contract == schema.ContractV1Candidate
	var fingerprints fingerprinter
	var v1Fingerprints fingerprinterV1
	var v1Hash hash.Hash
	if isV1 {
		v1Fingerprints = fingerprinterV1{}
		v1Hash = sha256.New()
	} else {
		fingerprints = fingerprinter{}
	}
	idx := -1

	for _, rm := range md.ResourceMetrics().All() {
		resource := rm.Resource()
		res := encodeBagForContract(resource.Attributes(), resource.DroppedAttributesCount(), opts.Contract)
		svc := sanitize(stringAttr(resource.Attributes(), serviceNameAttr))

		for _, sm := range rm.ScopeMetrics().All() {
			scope := sm.Scope()
			sc := encodedScope{
				name:    sanitize(scope.Name()),
				version: sanitize(scope.Version()),
				bag:     encodeBagForContract(scope.Attributes(), scope.DroppedAttributesCount(), opts.Contract),
			}
			origin := metricOrigin{
				res:            res,
				resSchemaURL:   rm.SchemaUrl(),
				scope:          sc,
				scopeSchemaURL: sm.SchemaUrl(),
				svc:            svc,
			}
			if isV1 {
				origin.v1Digest = hashOriginV1(v1Hash, resource, rm.SchemaUrl(), scope, sm.SchemaUrl())
			} else {
				origin.canonical = canonicalOrigin(res, rm.SchemaUrl(), scope, sc.bag, sm.SchemaUrl())
			}

			for _, m := range sm.Metrics().All() {
				var meta, metaSchema string
				if isV1 {
					meta = otlpjson.EncodePlainMap(m.Metadata())
				} else {
					meta, metaSchema = otlpjson.EncodeMapWithSchema(m.Metadata())
				}
				desc := metricDescriptor{
					name:       sanitize(m.Name()),
					rawName:    m.Name(),
					desc:       sanitize(m.Description()),
					unit:       sanitize(m.Unit()),
					meta:       meta,
					metaSchema: metaSchema,
					hasMeta:    m.Metadata().Len() > 0,
					rawMeta:    m.Metadata(),
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
						if isV1 {
							rows = append(rows, numberPointRowV1(dp, desc, origin, v1Fingerprints, v1Hash, received))
						} else {
							rows = append(rows, numberPointRow(dp, desc, origin, fingerprints, received))
						}
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
						if isV1 {
							rows = append(rows, numberPointRowV1(dp, desc, origin, v1Fingerprints, v1Hash, received))
						} else {
							rows = append(rows, numberPointRow(dp, desc, origin, fingerprints, received))
						}
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
						if isV1 {
							rows = append(rows, histogramPointRowV1(dp, desc, origin, v1Fingerprints, v1Hash, received))
						} else {
							rows = append(rows, histogramPointRow(dp, desc, origin, fingerprints, received))
						}
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
						if isV1 {
							rows = append(rows, expHistogramPointRowV1(dp, desc, origin, v1Fingerprints, v1Hash, received))
						} else {
							rows = append(rows, expHistogramPointRow(dp, desc, origin, fingerprints, received))
						}
					}

				case pmetric.MetricTypeSummary:
					desc.metricType = MetricTypeSummary
					for _, dp := range m.Summary().DataPoints().All() {
						idx++
						if bad := checkSummaryPoint(dp, desc, resource, scope, opts.Limits); bad != nil {
							rejects = append(rejects, Rejection{idx, bad.Reason, bad.FieldPath, bad.Limit, bad.Actual})
							continue
						}
						if isV1 {
							rows = append(rows, summaryPointRowV1(dp, desc, origin, v1Fingerprints, v1Hash, received))
						} else {
							rows = append(rows, summaryPointRow(dp, desc, origin, fingerprints, received))
						}
					}
				}
			}
		}
	}
	return rows, rejects
}

type metricOrigin struct {
	res            encodedBag
	resSchemaURL   string
	scope          encodedScope
	scopeSchemaURL string
	svc            string
	canonical      string
	v1Digest       [32]byte
}

type metricDescriptor struct {
	name        string
	rawName     string
	desc        string
	unit        string
	metricType  string
	temporality string
	monotonic   *bool
	meta        string
	metaSchema  string
	hasMeta     bool
	rawMeta     pcommon.Map
}

func temporalityName(t pmetric.AggregationTemporality) string {
	switch t {
	case pmetric.AggregationTemporalityDelta:
		return TemporalityDelta
	case pmetric.AggregationTemporalityCumulative:
		return TemporalityCumulative
	case pmetric.AggregationTemporalityUnspecified:
		return TemporalityUnspecified
	}
	return TemporalityUnspecified
}

func hasNoRecordedValue(flags pmetric.DataPointFlags) bool {
	return flags.NoRecordedValue()
}

func checkCommonPoint(
	ts, startTS pcommon.Timestamp,
	attrs pcommon.Map,
	exemplars pmetric.ExemplarSlice,
	desc metricDescriptor,
	resource pcommon.Resource,
	scope pcommon.InstrumentationScope,
	l Limits,
) *Violation {
	switch {
	case desc.rawName == "":
		return &Violation{Reason: ReasonInvalidID, FieldPath: "metric_name"}
	case ts == 0:
		return &Violation{Reason: ReasonMissingTimestamp, FieldPath: "timestamp"}
	case overflowsInt64(ts):
		return &Violation{Reason: ReasonTimestampOverflow, FieldPath: "time_unix_nano"}
	case overflowsInt64(startTS):
		return &Violation{Reason: ReasonTimestampOverflow, FieldPath: "start_time_unix_nano"}
	}
	if bad := l.checkMap(resource.Attributes(), "resource.attributes"); bad != nil {
		return bad
	}
	if bad := l.checkMap(scope.Attributes(), "instrumentation_scope.attributes"); bad != nil {
		return bad
	}
	if bad := l.checkMap(desc.rawMeta, "metric_metadata"); bad != nil {
		return bad
	}
	if bad := l.checkMap(attrs, "attributes"); bad != nil {
		return bad
	}
	if n := exemplars.Len(); n > l.MaxEventCount {
		return &Violation{ReasonEventCount, "exemplars", l.MaxEventCount, n}
	}
	for _, ex := range exemplars.All() {
		if overflowsInt64(ex.Timestamp()) {
			return &Violation{Reason: ReasonTimestampOverflow, FieldPath: "exemplars.time_unix_nano"}
		}
		if bad := l.checkMap(ex.FilteredAttributes(), "exemplars.filtered_attributes"); bad != nil {
			return bad
		}
	}
	return nil
}

func checkNumberPoint(
	dp pmetric.NumberDataPoint,
	desc metricDescriptor,
	resource pcommon.Resource,
	scope pcommon.InstrumentationScope,
	l Limits,
) *Violation {
	return checkCommonPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Attributes(), dp.Exemplars(), desc, resource, scope, l)
}

func checkHistogramPoint(
	dp pmetric.HistogramDataPoint,
	desc metricDescriptor,
	resource pcommon.Resource,
	scope pcommon.InstrumentationScope,
	l Limits,
) *Violation {
	if bad := checkCommonPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Attributes(), dp.Exemplars(), desc, resource, scope, l); bad != nil {
		return bad
	}
	if hasNoRecordedValue(dp.Flags()) {
		return nil
	}
	if dp.Count() > math.MaxInt64 {
		return &Violation{Reason: ReasonSerialization, FieldPath: "count"}
	}
	for _, c := range dp.BucketCounts().All() {
		if c > math.MaxInt64 {
			return &Violation{Reason: ReasonSerialization, FieldPath: "bucket_counts"}
		}
	}
	return nil
}

func checkExpHistogramPoint(
	dp pmetric.ExponentialHistogramDataPoint,
	desc metricDescriptor,
	resource pcommon.Resource,
	scope pcommon.InstrumentationScope,
	l Limits,
) *Violation {
	if bad := checkCommonPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Attributes(), dp.Exemplars(), desc, resource, scope, l); bad != nil {
		return bad
	}
	if hasNoRecordedValue(dp.Flags()) {
		return nil
	}
	if dp.Count() > math.MaxInt64 {
		return &Violation{Reason: ReasonSerialization, FieldPath: "count"}
	}
	if dp.ZeroCount() > math.MaxInt64 {
		return &Violation{Reason: ReasonSerialization, FieldPath: "exp_zero_count"}
	}
	for _, c := range dp.Positive().BucketCounts().All() {
		if c > math.MaxInt64 {
			return &Violation{Reason: ReasonSerialization, FieldPath: "exp_positive"}
		}
	}
	for _, c := range dp.Negative().BucketCounts().All() {
		if c > math.MaxInt64 {
			return &Violation{Reason: ReasonSerialization, FieldPath: "exp_negative"}
		}
	}
	return nil
}

func checkSummaryPoint(
	dp pmetric.SummaryDataPoint,
	desc metricDescriptor,
	resource pcommon.Resource,
	scope pcommon.InstrumentationScope,
	l Limits,
) *Violation {
	if bad := checkCommonPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Attributes(), pmetric.NewExemplarSlice(), desc, resource, scope, l); bad != nil {
		return bad
	}
	if hasNoRecordedValue(dp.Flags()) {
		return nil
	}
	if dp.Count() > math.MaxInt64 {
		return &Violation{Reason: ReasonSerialization, FieldPath: "count"}
	}
	return nil
}

func baseMetricRow(
	ts, startTS pcommon.Timestamp,
	flags pmetric.DataPointFlags,
	attrs pcommon.Map,
	exemplars pmetric.ExemplarSlice,
	desc metricDescriptor,
	origin metricOrigin,
	received time.Time,
	valueCanonical string,
	fingerprints fingerprinter,
) Row {
	attrStr, attrSchema := otlpjson.EncodeMapWithSchema(attrs)
	exRows, exCanonical := encodeExemplars(exemplars)
	fp := fingerprints.next(canonicalMetricPoint(ts, startTS, flags, attrStr, attrSchema, desc, origin, valueCanonical, exCanonical))

	r := Row{
		"timestamp":              micros(ts),
		"time_unix_nano":         int64(ts),
		"receive_time":           received.UnixMicro(),
		"receive_time_unix_nano": received.UnixNano(),
		"metric_name":            desc.name,
		"metric_type":            desc.metricType,
		"flags":                  int64(flags),
		"attributes":             attrStr,
		"attributes_schema":      attrSchema,
		"resource":               origin.res.row(),
		"instrumentation_scope":  origin.scope.row(),
		"point_fingerprint":      fp,
		"schema_version":         schema.Version,
	}
	if startTS != 0 {
		r["start_time"] = micros(startTS)
		r["start_time_unix_nano"] = int64(startTS)
	}
	putStrIfSet(r, "service_name", origin.svc)
	putStrIfSet(r, "metric_description", desc.desc)
	putStrIfSet(r, "metric_unit", desc.unit)
	putStrIfSet(r, "aggregation_temporality", desc.temporality)
	if desc.monotonic != nil {
		r["is_monotonic"] = *desc.monotonic
	}
	if desc.hasMeta {
		r["metric_metadata"] = desc.meta
		r["metric_metadata_schema"] = desc.metaSchema
	}
	putStrIfSet(r, "resource_schema_url", sanitize(origin.resSchemaURL))
	putStrIfSet(r, "scope_schema_url", sanitize(origin.scopeSchemaURL))
	if len(exRows) > 0 {
		r["exemplars"] = exRows
	}
	return r
}

func canonicalNumberValue(dp pmetric.NumberDataPoint) string {
	var valBuilder strings.Builder
	writeField(&valBuilder, "value_type", dp.ValueType().String())
	if !hasNoRecordedValue(dp.Flags()) {
		switch dp.ValueType() {
		case pmetric.NumberDataPointValueTypeDouble:
			writeField(&valBuilder, "value_double", strconv.FormatFloat(dp.DoubleValue(), 'g', -1, 64))
		case pmetric.NumberDataPointValueTypeInt:
			writeField(&valBuilder, "value_int64", strconv.FormatInt(dp.IntValue(), 10))
		}
	}
	return valBuilder.String()
}

func canonicalForNumberPoint(dp pmetric.NumberDataPoint, desc metricDescriptor, origin metricOrigin) string {
	attrStr, attrSchema := otlpjson.EncodeMapWithSchema(dp.Attributes())
	_, exCanonical := encodeExemplars(dp.Exemplars())
	return canonicalMetricPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), attrStr, attrSchema, desc, origin, canonicalNumberValue(dp), exCanonical)
}

func numberPointRow(
	dp pmetric.NumberDataPoint,
	desc metricDescriptor,
	origin metricOrigin,
	fingerprints fingerprinter,
	received time.Time,
) Row {
	r := baseMetricRow(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, origin, received, canonicalNumberValue(dp), fingerprints)
	if !hasNoRecordedValue(dp.Flags()) {
		switch dp.ValueType() {
		case pmetric.NumberDataPointValueTypeDouble:
			r["value_type"] = ScalarValueTypeDouble
			r["value_double"] = dp.DoubleValue()
		case pmetric.NumberDataPointValueTypeInt:
			r["value_type"] = ScalarValueTypeInt64
			r["value_int64"] = dp.IntValue()
		}
	}
	return r
}

func canonicalHistogramValue(dp pmetric.HistogramDataPoint) string {
	var valBuilder strings.Builder
	if !hasNoRecordedValue(dp.Flags()) {
		writeField(&valBuilder, "count", strconv.FormatUint(dp.Count(), 10))
		if dp.HasSum() {
			writeField(&valBuilder, "sum", strconv.FormatFloat(dp.Sum(), 'g', -1, 64))
		}
		if dp.HasMin() {
			writeField(&valBuilder, "min", strconv.FormatFloat(dp.Min(), 'g', -1, 64))
		}
		if dp.HasMax() {
			writeField(&valBuilder, "max", strconv.FormatFloat(dp.Max(), 'g', -1, 64))
		}
		writeField(&valBuilder, "explicit_bounds_count", strconv.Itoa(dp.ExplicitBounds().Len()))
		for _, b := range dp.ExplicitBounds().All() {
			writeField(&valBuilder, "bound", strconv.FormatFloat(b, 'g', -1, 64))
		}
		writeField(&valBuilder, "bucket_counts_count", strconv.Itoa(dp.BucketCounts().Len()))
		for _, c := range dp.BucketCounts().All() {
			writeField(&valBuilder, "bucket_count", strconv.FormatUint(c, 10))
		}
	}
	return valBuilder.String()
}

func canonicalForHistogramPoint(dp pmetric.HistogramDataPoint, desc metricDescriptor, origin metricOrigin) string {
	attrStr, attrSchema := otlpjson.EncodeMapWithSchema(dp.Attributes())
	_, exCanonical := encodeExemplars(dp.Exemplars())
	return canonicalMetricPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), attrStr, attrSchema, desc, origin, canonicalHistogramValue(dp), exCanonical)
}

func histogramPointRow(
	dp pmetric.HistogramDataPoint,
	desc metricDescriptor,
	origin metricOrigin,
	fingerprints fingerprinter,
	received time.Time,
) Row {
	r := baseMetricRow(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, origin, received, canonicalHistogramValue(dp), fingerprints)
	if !hasNoRecordedValue(dp.Flags()) {
		r["count"] = int64(dp.Count())
		if dp.HasSum() {
			r["sum"] = dp.Sum()
		}
		if dp.HasMin() {
			r["min"] = dp.Min()
		}
		if dp.HasMax() {
			r["max"] = dp.Max()
		}
		if dp.ExplicitBounds().Len() > 0 {
			bounds := make([]float64, dp.ExplicitBounds().Len())
			copy(bounds, dp.ExplicitBounds().AsRaw())
			r["explicit_bounds"] = bounds
		}
		if dp.BucketCounts().Len() > 0 {
			r["bucket_counts"] = uint64SliceToInt64(dp.BucketCounts().AsRaw())
		}
	}
	return r
}

func writeExpBucketsCanonical(b *strings.Builder, prefix string, buckets pmetric.ExponentialHistogramDataPointBuckets) {
	writeField(b, prefix+".offset", strconv.FormatInt(int64(buckets.Offset()), 10))
	writeField(b, prefix+".count", strconv.Itoa(buckets.BucketCounts().Len()))
	for _, c := range buckets.BucketCounts().All() {
		writeField(b, prefix+".bucket", strconv.FormatUint(c, 10))
	}
}

func expBucketsRow(b pmetric.ExponentialHistogramDataPointBuckets) Row {
	if b.BucketCounts().Len() == 0 && b.Offset() == 0 {
		return nil
	}
	r := Row{"offset": int64(b.Offset())}
	if b.BucketCounts().Len() > 0 {
		r["bucket_counts"] = uint64SliceToInt64(b.BucketCounts().AsRaw())
	}
	return r
}

func canonicalExpHistogramValue(dp pmetric.ExponentialHistogramDataPoint) string {
	var valBuilder strings.Builder
	if !hasNoRecordedValue(dp.Flags()) {
		writeField(&valBuilder, "count", strconv.FormatUint(dp.Count(), 10))
		writeField(&valBuilder, "exp_scale", strconv.FormatInt(int64(dp.Scale()), 10))
		writeField(&valBuilder, "exp_zero_count", strconv.FormatUint(dp.ZeroCount(), 10))
		writeField(&valBuilder, "exp_zero_threshold", strconv.FormatFloat(dp.ZeroThreshold(), 'g', -1, 64))
		if dp.HasSum() {
			writeField(&valBuilder, "sum", strconv.FormatFloat(dp.Sum(), 'g', -1, 64))
		}
		if dp.HasMin() {
			writeField(&valBuilder, "min", strconv.FormatFloat(dp.Min(), 'g', -1, 64))
		}
		if dp.HasMax() {
			writeField(&valBuilder, "max", strconv.FormatFloat(dp.Max(), 'g', -1, 64))
		}
		writeExpBucketsCanonical(&valBuilder, "exp_positive", dp.Positive())
		writeExpBucketsCanonical(&valBuilder, "exp_negative", dp.Negative())
	}
	return valBuilder.String()
}

func canonicalForExpHistogramPoint(dp pmetric.ExponentialHistogramDataPoint, desc metricDescriptor, origin metricOrigin) string {
	attrStr, attrSchema := otlpjson.EncodeMapWithSchema(dp.Attributes())
	_, exCanonical := encodeExemplars(dp.Exemplars())
	return canonicalMetricPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), attrStr, attrSchema, desc, origin, canonicalExpHistogramValue(dp), exCanonical)
}

func expHistogramPointRow(
	dp pmetric.ExponentialHistogramDataPoint,
	desc metricDescriptor,
	origin metricOrigin,
	fingerprints fingerprinter,
	received time.Time,
) Row {
	r := baseMetricRow(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, origin, received, canonicalExpHistogramValue(dp), fingerprints)
	if !hasNoRecordedValue(dp.Flags()) {
		r["count"] = int64(dp.Count())
		if dp.HasSum() {
			r["sum"] = dp.Sum()
		}
		if dp.HasMin() {
			r["min"] = dp.Min()
		}
		if dp.HasMax() {
			r["max"] = dp.Max()
		}
		r["exp_scale"] = int64(dp.Scale())
		r["exp_zero_count"] = int64(dp.ZeroCount())
		r["exp_zero_threshold"] = dp.ZeroThreshold()
		if pos := expBucketsRow(dp.Positive()); pos != nil {
			r["exp_positive"] = pos
		}
		if neg := expBucketsRow(dp.Negative()); neg != nil {
			r["exp_negative"] = neg
		}
	}
	return r
}

func canonicalSummaryValue(dp pmetric.SummaryDataPoint) string {
	var valBuilder strings.Builder
	if !hasNoRecordedValue(dp.Flags()) {
		writeField(&valBuilder, "count", strconv.FormatUint(dp.Count(), 10))
		writeField(&valBuilder, "sum", strconv.FormatFloat(dp.Sum(), 'g', -1, 64))
		writeField(&valBuilder, "summary_quantiles_count", strconv.Itoa(dp.QuantileValues().Len()))
		for _, qv := range dp.QuantileValues().All() {
			writeField(&valBuilder, "quantile", strconv.FormatFloat(qv.Quantile(), 'g', -1, 64))
			writeField(&valBuilder, "value", strconv.FormatFloat(qv.Value(), 'g', -1, 64))
		}
	}
	return valBuilder.String()
}

func canonicalForSummaryPoint(dp pmetric.SummaryDataPoint, desc metricDescriptor, origin metricOrigin) string {
	attrStr, attrSchema := otlpjson.EncodeMapWithSchema(dp.Attributes())
	return canonicalMetricPoint(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), attrStr, attrSchema, desc, origin, canonicalSummaryValue(dp), "")
}

func summaryPointRow(
	dp pmetric.SummaryDataPoint,
	desc metricDescriptor,
	origin metricOrigin,
	fingerprints fingerprinter,
	received time.Time,
) Row {
	r := baseMetricRow(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), pmetric.NewExemplarSlice(), desc, origin, received, canonicalSummaryValue(dp), fingerprints)
	if !hasNoRecordedValue(dp.Flags()) {
		r["count"] = int64(dp.Count())
		r["sum"] = dp.Sum()
		if n := dp.QuantileValues().Len(); n > 0 {
			quantiles := make([]Row, 0, n)
			for _, qv := range dp.QuantileValues().All() {
				quantiles = append(quantiles, Row{
					"quantile": qv.Quantile(),
					"value":    qv.Value(),
				})
			}
			r["summary_quantiles"] = quantiles
		}
	}
	return r
}

// PreserveMetricOrdinalPeers widens the metric data points to retry so that
// retrying them reproduces the point_fingerprints they had in the original batch.
//
// A data point's fingerprint encodes its intra_batch_ordinal: how many data
// points of the same canonical form precede it in the batch. MetricRows
// fingerprints a retry payload from scratch, so leaving out an acknowledged
// data point that is identical to a retried one shifts the retried point's
// ordinal down onto the acknowledged copy's.
func PreserveMetricOrdinalPeers(md pmetric.Metrics, candidateIndices, retryableIndices []int) []int {
	if len(retryableIndices) == 0 {
		return nil
	}
	if len(candidateIndices) == 0 {
		return retryableIndices
	}
	candidate := indexSet(candidateIndices)
	retryable := indexSet(retryableIndices)

	allCandidatesRetried := true
	for _, c := range candidateIndices {
		if !retryable[c] {
			allCandidatesRetried = false
			break
		}
	}
	if allCandidatesRetried {
		return retryableIndices
	}

	type member struct {
		idx   int
		group string
	}
	members := make([]member, 0, len(candidateIndices))
	retried := make(map[string]bool)

	idx := -1
	for _, rm := range md.ResourceMetrics().All() {
		resource := rm.Resource()
		res := encodeBag(resource.Attributes(), resource.DroppedAttributesCount())
		svc := sanitize(stringAttr(resource.Attributes(), serviceNameAttr))

		for _, sm := range rm.ScopeMetrics().All() {
			scope := sm.Scope()
			sc := encodedScope{
				name:    sanitize(scope.Name()),
				version: sanitize(scope.Version()),
				bag:     encodeBag(scope.Attributes(), scope.DroppedAttributesCount()),
			}
			origin := metricOrigin{
				res:            res,
				resSchemaURL:   rm.SchemaUrl(),
				scope:          sc,
				scopeSchemaURL: sm.SchemaUrl(),
				svc:            svc,
				canonical:      canonicalOrigin(res, rm.SchemaUrl(), scope, sc.bag, sm.SchemaUrl()),
			}

			for _, m := range sm.Metrics().All() {
				meta, metaSchema := otlpjson.EncodeMapWithSchema(m.Metadata())
				desc := metricDescriptor{
					name:       sanitize(m.Name()),
					rawName:    m.Name(),
					desc:       sanitize(m.Description()),
					unit:       sanitize(m.Unit()),
					meta:       meta,
					metaSchema: metaSchema,
					hasMeta:    m.Metadata().Len() > 0,
					rawMeta:    m.Metadata(),
				}

				switch m.Type() {
				case pmetric.MetricTypeGauge:
					desc.metricType = MetricTypeGauge
					for _, dp := range m.Gauge().DataPoints().All() {
						idx++
						if !candidate[idx] && !retryable[idx] {
							continue
						}
						group := LogFingerprint(canonicalForNumberPoint(dp, desc, origin), 0)
						members = append(members, member{idx: idx, group: group})
						if retryable[idx] {
							retried[group] = true
						}
					}

				case pmetric.MetricTypeSum:
					desc.metricType = MetricTypeSum
					desc.temporality = temporalityName(m.Sum().AggregationTemporality())
					monotonic := m.Sum().IsMonotonic()
					desc.monotonic = &monotonic
					for _, dp := range m.Sum().DataPoints().All() {
						idx++
						if !candidate[idx] && !retryable[idx] {
							continue
						}
						group := LogFingerprint(canonicalForNumberPoint(dp, desc, origin), 0)
						members = append(members, member{idx: idx, group: group})
						if retryable[idx] {
							retried[group] = true
						}
					}

				case pmetric.MetricTypeHistogram:
					desc.metricType = MetricTypeHistogram
					desc.temporality = temporalityName(m.Histogram().AggregationTemporality())
					for _, dp := range m.Histogram().DataPoints().All() {
						idx++
						if !candidate[idx] && !retryable[idx] {
							continue
						}
						group := LogFingerprint(canonicalForHistogramPoint(dp, desc, origin), 0)
						members = append(members, member{idx: idx, group: group})
						if retryable[idx] {
							retried[group] = true
						}
					}

				case pmetric.MetricTypeExponentialHistogram:
					desc.metricType = MetricTypeExponentialHistogram
					desc.temporality = temporalityName(m.ExponentialHistogram().AggregationTemporality())
					for _, dp := range m.ExponentialHistogram().DataPoints().All() {
						idx++
						if !candidate[idx] && !retryable[idx] {
							continue
						}
						group := LogFingerprint(canonicalForExpHistogramPoint(dp, desc, origin), 0)
						members = append(members, member{idx: idx, group: group})
						if retryable[idx] {
							retried[group] = true
						}
					}

				case pmetric.MetricTypeSummary:
					desc.metricType = MetricTypeSummary
					for _, dp := range m.Summary().DataPoints().All() {
						idx++
						if !candidate[idx] && !retryable[idx] {
							continue
						}
						group := LogFingerprint(canonicalForSummaryPoint(dp, desc, origin), 0)
						members = append(members, member{idx: idx, group: group})
						if retryable[idx] {
							retried[group] = true
						}
					}
				}
			}
		}
	}

	out := make([]int, 0, len(members))
	for _, m := range members {
		if retryable[m.idx] || retried[m.group] {
			out = append(out, m.idx)
		}
	}
	return out
}

func encodeExemplars(exemplars pmetric.ExemplarSlice) ([]Row, string) {
	if exemplars.Len() == 0 {
		return nil, ""
	}
	var b strings.Builder
	writeField(&b, "exemplars_count", strconv.Itoa(exemplars.Len()))
	out := make([]Row, 0, exemplars.Len())
	for _, ex := range exemplars.All() {
		fAttrs, fSchema := otlpjson.EncodeMapWithSchema(ex.FilteredAttributes())
		spanID := spanIDString(ex.SpanID())
		traceID := traceIDString(ex.TraceID())
		writeField(&b, "exemplar.time_unix_nano", strconv.FormatUint(uint64(ex.Timestamp()), 10))
		writeField(&b, "exemplar.value_type", ex.ValueType().String())
		switch ex.ValueType() {
		case pmetric.ExemplarValueTypeDouble:
			writeField(&b, "exemplar.value_double", strconv.FormatFloat(ex.DoubleValue(), 'g', -1, 64))
		case pmetric.ExemplarValueTypeInt:
			writeField(&b, "exemplar.value_int64", strconv.FormatInt(ex.IntValue(), 10))
		}
		writeField(&b, "exemplar.span_id", spanID)
		writeField(&b, "exemplar.trace_id", traceID)
		writeField(&b, "exemplar.filtered_attributes", fAttrs)
		writeField(&b, "exemplar.filtered_attributes_schema", fSchema)

		er := Row{
			"time_unix_nano":             int64(ex.Timestamp()),
			"filtered_attributes":        fAttrs,
			"filtered_attributes_schema": fSchema,
		}
		if ex.Timestamp() != 0 {
			er["time"] = micros(ex.Timestamp())
		}
		switch ex.ValueType() {
		case pmetric.ExemplarValueTypeDouble:
			er["value_double"] = ex.DoubleValue()
		case pmetric.ExemplarValueTypeInt:
			er["value_int64"] = ex.IntValue()
		}
		putStrIfSet(er, "span_id", spanID)
		putStrIfSet(er, "trace_id", traceID)
		out = append(out, er)
	}
	return out, b.String()
}

func uint64SliceToInt64(in []uint64) []int64 {
	out := make([]int64, len(in))
	for i, v := range in {
		out[i] = int64(v)
	}
	return out
}

func canonicalMetricPoint(
	ts, startTS pcommon.Timestamp,
	flags pmetric.DataPointFlags,
	attrStr, attrSchema string,
	desc metricDescriptor,
	origin metricOrigin,
	valueCanonical string,
	exemplarsCanonical string,
) string {
	var b strings.Builder
	writeField(&b, "version", schema.FingerprintPrefix)
	writeField(&b, "service_name", origin.svc)
	writeField(&b, "metric_name", desc.name)
	writeField(&b, "metric_type", desc.metricType)
	writeField(&b, "metric_unit", desc.unit)
	writeField(&b, "aggregation_temporality", desc.temporality)
	if desc.monotonic != nil {
		writeField(&b, "is_monotonic", strconv.FormatBool(*desc.monotonic))
	}
	writeField(&b, "time_unix_nano", strconv.FormatUint(uint64(ts), 10))
	writeField(&b, "start_time_unix_nano", strconv.FormatUint(uint64(startTS), 10))
	writeField(&b, "flags", strconv.FormatUint(uint64(flags), 10))
	writeField(&b, "attributes", attrStr)
	writeField(&b, "attributes_schema", attrSchema)
	writeField(&b, "metric_metadata", desc.meta)
	writeField(&b, "metric_metadata_schema", desc.metaSchema)
	b.WriteString(valueCanonical)
	b.WriteString(exemplarsCanonical)
	b.WriteString(origin.canonical)
	return b.String()
}

func hashMetricPointV1(
	h hash.Hash,
	ts, startTS pcommon.Timestamp,
	flags pmetric.DataPointFlags,
	attrs pcommon.Map,
	exemplars pmetric.ExemplarSlice,
	desc metricDescriptor,
	origin metricOrigin,
	writeValue func(hash.Hash),
	ordinal int,
) [32]byte {
	h.Reset()
	writeHashFieldStr(h, "version", schema.FingerprintPrefix)
	writeHashFieldStr(h, "service_name", origin.svc)
	writeHashFieldStr(h, "metric_name", desc.name)
	writeHashFieldStr(h, "metric_type", desc.metricType)
	writeHashFieldStr(h, "metric_unit", desc.unit)
	writeHashFieldStr(h, "aggregation_temporality", desc.temporality)
	if desc.monotonic != nil {
		if *desc.monotonic {
			writeHashFieldUint64(h, "is_monotonic", 1)
		} else {
			writeHashFieldUint64(h, "is_monotonic", 0)
		}
	}
	writeHashFieldUint64(h, "time_unix_nano", uint64(ts))
	writeHashFieldUint64(h, "start_time_unix_nano", uint64(startTS))
	writeHashFieldUint64(h, "flags", uint64(flags))
	writeHashFieldTaggedMap(h, "attributes", attrs)
	writeHashFieldTaggedMap(h, "metric_metadata", desc.rawMeta)
	if writeValue != nil {
		writeValue(h)
	}
	writeHashExemplarsV1(h, exemplars)
	writeHashFieldBytes(h, "origin_digest", origin.v1Digest[:])
	writeHashFieldInt64(h, "intra_batch_ordinal", int64(ordinal))
	return finalizeSHA256(h)
}

func writeHashNumberValueV1(h hash.Hash, dp pmetric.NumberDataPoint) {
	writeHashFieldStr(h, "value_type", dp.ValueType().String())
	if !hasNoRecordedValue(dp.Flags()) {
		switch dp.ValueType() {
		case pmetric.NumberDataPointValueTypeDouble:
			writeHashFieldFloat64(h, "value_double", dp.DoubleValue())
		case pmetric.NumberDataPointValueTypeInt:
			writeHashFieldInt64(h, "value_int64", dp.IntValue())
		}
	}
}

func writeHashHistogramValueV1(h hash.Hash, dp pmetric.HistogramDataPoint) {
	if hasNoRecordedValue(dp.Flags()) {
		return
	}
	writeHashFieldUint64(h, "count", dp.Count())
	if dp.HasSum() {
		writeHashFieldFloat64(h, "sum", dp.Sum())
	}
	if dp.HasMin() {
		writeHashFieldFloat64(h, "min", dp.Min())
	}
	if dp.HasMax() {
		writeHashFieldFloat64(h, "max", dp.Max())
	}
	writeHashFieldInt64(h, "explicit_bounds_count", int64(dp.ExplicitBounds().Len()))
	for _, b := range dp.ExplicitBounds().All() {
		writeHashFieldFloat64(h, "bound", b)
	}
	writeHashFieldInt64(h, "bucket_counts_count", int64(dp.BucketCounts().Len()))
	for _, c := range dp.BucketCounts().All() {
		writeHashFieldUint64(h, "bucket_count", c)
	}
}

func writeHashExpBucketsV1(h hash.Hash, prefix string, buckets pmetric.ExponentialHistogramDataPointBuckets) {
	writeHashFieldInt64(h, prefix+".offset", int64(buckets.Offset()))
	writeHashFieldInt64(h, prefix+".count", int64(buckets.BucketCounts().Len()))
	for _, c := range buckets.BucketCounts().All() {
		writeHashFieldUint64(h, prefix+".bucket", c)
	}
}

func writeHashExpHistogramValueV1(h hash.Hash, dp pmetric.ExponentialHistogramDataPoint) {
	if hasNoRecordedValue(dp.Flags()) {
		return
	}
	writeHashFieldUint64(h, "count", dp.Count())
	writeHashFieldInt64(h, "exp_scale", int64(dp.Scale()))
	writeHashFieldUint64(h, "exp_zero_count", dp.ZeroCount())
	writeHashFieldFloat64(h, "exp_zero_threshold", dp.ZeroThreshold())
	if dp.HasSum() {
		writeHashFieldFloat64(h, "sum", dp.Sum())
	}
	if dp.HasMin() {
		writeHashFieldFloat64(h, "min", dp.Min())
	}
	if dp.HasMax() {
		writeHashFieldFloat64(h, "max", dp.Max())
	}
	writeHashExpBucketsV1(h, "exp_positive", dp.Positive())
	writeHashExpBucketsV1(h, "exp_negative", dp.Negative())
}

func writeHashSummaryValueV1(h hash.Hash, dp pmetric.SummaryDataPoint) {
	if hasNoRecordedValue(dp.Flags()) {
		return
	}
	writeHashFieldUint64(h, "count", dp.Count())
	writeHashFieldFloat64(h, "sum", dp.Sum())
	writeHashFieldInt64(h, "summary_quantiles_count", int64(dp.QuantileValues().Len()))
	for _, qv := range dp.QuantileValues().All() {
		writeHashFieldFloat64(h, "quantile", qv.Quantile())
		writeHashFieldFloat64(h, "value", qv.Value())
	}
}

func writeHashExemplarsV1(h hash.Hash, exemplars pmetric.ExemplarSlice) {
	if exemplars.Len() == 0 {
		return
	}
	writeHashFieldInt64(h, "exemplars_count", int64(exemplars.Len()))
	for _, ex := range exemplars.All() {
		writeHashFieldUint64(h, "exemplar.time_unix_nano", uint64(ex.Timestamp()))
		writeHashFieldStr(h, "exemplar.value_type", ex.ValueType().String())
		switch ex.ValueType() {
		case pmetric.ExemplarValueTypeDouble:
			writeHashFieldFloat64(h, "exemplar.value_double", ex.DoubleValue())
		case pmetric.ExemplarValueTypeInt:
			writeHashFieldInt64(h, "exemplar.value_int64", ex.IntValue())
		}
		writeHashFieldStr(h, "exemplar.span_id", spanIDString(ex.SpanID()))
		writeHashFieldStr(h, "exemplar.trace_id", traceIDString(ex.TraceID()))
		writeHashFieldTaggedMap(h, "exemplar.filtered_attributes", ex.FilteredAttributes())
	}
}

func encodeExemplarsV1(exemplars pmetric.ExemplarSlice) []Row {
	if exemplars.Len() == 0 {
		return nil
	}
	out := make([]Row, 0, exemplars.Len())
	for _, ex := range exemplars.All() {
		er := Row{
			"time_unix_nano":      int64(ex.Timestamp()),
			"filtered_attributes": otlpjson.EncodePlainMap(ex.FilteredAttributes()),
		}
		if ex.Timestamp() != 0 {
			er["time"] = micros(ex.Timestamp())
		}
		switch ex.ValueType() {
		case pmetric.ExemplarValueTypeDouble:
			er["value_double"] = ex.DoubleValue()
		case pmetric.ExemplarValueTypeInt:
			er["value_int64"] = ex.IntValue()
		}
		putStrIfSet(er, "span_id", spanIDString(ex.SpanID()))
		putStrIfSet(er, "trace_id", traceIDString(ex.TraceID()))
		out = append(out, er)
	}
	return out
}

func baseMetricRowV1(
	ts, startTS pcommon.Timestamp,
	flags pmetric.DataPointFlags,
	attrs pcommon.Map,
	exemplars pmetric.ExemplarSlice,
	desc metricDescriptor,
	origin metricOrigin,
	received time.Time,
	writeValue func(hash.Hash),
	fingerprints fingerprinterV1,
	h hash.Hash,
) Row {
	fp := fingerprints.nextMetricFingerprint(func(ordinal int) [32]byte {
		return hashMetricPointV1(h, ts, startTS, flags, attrs, exemplars, desc, origin, writeValue, ordinal)
	})
	exRows := encodeExemplarsV1(exemplars)

	r := Row{
		"timestamp":              micros(ts),
		"time_unix_nano":         int64(ts),
		"receive_time":           received.UnixMicro(),
		"receive_time_unix_nano": received.UnixNano(),
		"metric_name":            desc.name,
		"metric_type":            desc.metricType,
		"flags":                  int64(flags),
		"attributes":             otlpjson.EncodePlainMap(attrs),
		"resource":               origin.res.rowForContract(schema.ContractV1Candidate),
		"instrumentation_scope":  origin.scope.rowForContract(schema.ContractV1Candidate),
		"point_fingerprint":      fp,
	}
	if startTS != 0 {
		r["start_time"] = micros(startTS)
		r["start_time_unix_nano"] = int64(startTS)
	}
	putStrIfSet(r, "service_name", origin.svc)
	putStrIfSet(r, "metric_description", desc.desc)
	putStrIfSet(r, "metric_unit", desc.unit)
	putStrIfSet(r, "aggregation_temporality", desc.temporality)
	if desc.monotonic != nil {
		r["is_monotonic"] = *desc.monotonic
	}
	if desc.hasMeta {
		r["metric_metadata"] = desc.meta
	}
	putStrIfSet(r, "resource_schema_url", sanitize(origin.resSchemaURL))
	putStrIfSet(r, "scope_schema_url", sanitize(origin.scopeSchemaURL))
	if len(exRows) > 0 {
		r["exemplars"] = exRows
	}
	return r
}

func numberPointRowV1(
	dp pmetric.NumberDataPoint,
	desc metricDescriptor,
	origin metricOrigin,
	fingerprints fingerprinterV1,
	h hash.Hash,
	received time.Time,
) Row {
	r := baseMetricRowV1(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, origin, received, func(hh hash.Hash) {
		writeHashNumberValueV1(hh, dp)
	}, fingerprints, h)
	if !hasNoRecordedValue(dp.Flags()) {
		switch dp.ValueType() {
		case pmetric.NumberDataPointValueTypeDouble:
			r["value_type"] = ScalarValueTypeDouble
			r["value_double"] = dp.DoubleValue()
		case pmetric.NumberDataPointValueTypeInt:
			r["value_type"] = ScalarValueTypeInt64
			r["value_int64"] = dp.IntValue()
		}
	}
	return r
}

func histogramPointRowV1(
	dp pmetric.HistogramDataPoint,
	desc metricDescriptor,
	origin metricOrigin,
	fingerprints fingerprinterV1,
	h hash.Hash,
	received time.Time,
) Row {
	r := baseMetricRowV1(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, origin, received, func(hh hash.Hash) {
		writeHashHistogramValueV1(hh, dp)
	}, fingerprints, h)
	if !hasNoRecordedValue(dp.Flags()) {
		r["count"] = int64(dp.Count())
		if dp.HasSum() {
			r["sum"] = dp.Sum()
		}
		if dp.HasMin() {
			r["min"] = dp.Min()
		}
		if dp.HasMax() {
			r["max"] = dp.Max()
		}
		if dp.ExplicitBounds().Len() > 0 {
			bounds := make([]float64, dp.ExplicitBounds().Len())
			copy(bounds, dp.ExplicitBounds().AsRaw())
			r["explicit_bounds"] = bounds
		}
		if dp.BucketCounts().Len() > 0 {
			r["bucket_counts"] = uint64SliceToInt64(dp.BucketCounts().AsRaw())
		}
	}
	return r
}

func expHistogramPointRowV1(
	dp pmetric.ExponentialHistogramDataPoint,
	desc metricDescriptor,
	origin metricOrigin,
	fingerprints fingerprinterV1,
	h hash.Hash,
	received time.Time,
) Row {
	r := baseMetricRowV1(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, origin, received, func(hh hash.Hash) {
		writeHashExpHistogramValueV1(hh, dp)
	}, fingerprints, h)
	if !hasNoRecordedValue(dp.Flags()) {
		r["count"] = int64(dp.Count())
		if dp.HasSum() {
			r["sum"] = dp.Sum()
		}
		if dp.HasMin() {
			r["min"] = dp.Min()
		}
		if dp.HasMax() {
			r["max"] = dp.Max()
		}
		r["exp_scale"] = int64(dp.Scale())
		r["exp_zero_count"] = int64(dp.ZeroCount())
		r["exp_zero_threshold"] = dp.ZeroThreshold()
		if pos := expBucketsRow(dp.Positive()); pos != nil {
			r["exp_positive"] = pos
		}
		if neg := expBucketsRow(dp.Negative()); neg != nil {
			r["exp_negative"] = neg
		}
	}
	return r
}

func summaryPointRowV1(
	dp pmetric.SummaryDataPoint,
	desc metricDescriptor,
	origin metricOrigin,
	fingerprints fingerprinterV1,
	h hash.Hash,
	received time.Time,
) Row {
	r := baseMetricRowV1(dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), pmetric.NewExemplarSlice(), desc, origin, received, func(hh hash.Hash) {
		writeHashSummaryValueV1(hh, dp)
	}, fingerprints, h)
	if !hasNoRecordedValue(dp.Flags()) {
		r["count"] = int64(dp.Count())
		r["sum"] = dp.Sum()
		if n := dp.QuantileValues().Len(); n > 0 {
			quantiles := make([]Row, 0, n)
			for _, qv := range dp.QuantileValues().All() {
				quantiles = append(quantiles, Row{
					"quantile": qv.Quantile(),
					"value":    qv.Value(),
				})
			}
			r["summary_quantiles"] = quantiles
		}
	}
	return r
}

// PreserveMetricOrdinalPeersForContract is the contract-aware counterpart of
// PreserveMetricOrdinalPeers.
func PreserveMetricOrdinalPeersForContract(
	md pmetric.Metrics,
	candidateIndices, retryableIndices []int,
	contract schema.Contract,
) []int {
	if contract != schema.ContractV1Candidate {
		return PreserveMetricOrdinalPeers(md, candidateIndices, retryableIndices)
	}
	if len(retryableIndices) == 0 {
		return nil
	}
	if len(candidateIndices) == 0 {
		return retryableIndices
	}
	candidate := indexSet(candidateIndices)
	retryable := indexSet(retryableIndices)

	allCandidatesRetried := true
	for _, c := range candidateIndices {
		if !retryable[c] {
			allCandidatesRetried = false
			break
		}
	}
	if allCandidatesRetried {
		return retryableIndices
	}

	type member struct {
		idx   int
		group [32]byte
	}
	members := make([]member, 0, len(candidateIndices))
	retried := make(map[[32]byte]bool)
	h := sha256.New()

	idx := -1
	for _, rm := range md.ResourceMetrics().All() {
		resource := rm.Resource()
		svc := sanitize(stringAttr(resource.Attributes(), serviceNameAttr))

		for _, sm := range rm.ScopeMetrics().All() {
			scope := sm.Scope()
			origin := metricOrigin{
				svc:      svc,
				v1Digest: hashOriginV1(h, resource, rm.SchemaUrl(), scope, sm.SchemaUrl()),
			}

			for _, m := range sm.Metrics().All() {
				desc := metricDescriptor{
					name:    sanitize(m.Name()),
					rawName: m.Name(),
					desc:    sanitize(m.Description()),
					unit:    sanitize(m.Unit()),
					hasMeta: m.Metadata().Len() > 0,
					rawMeta: m.Metadata(),
				}

				switch m.Type() {
				case pmetric.MetricTypeGauge:
					desc.metricType = MetricTypeGauge
					for _, dp := range m.Gauge().DataPoints().All() {
						idx++
						if !candidate[idx] && !retryable[idx] {
							continue
						}
						group := hashMetricPointV1(h, dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, origin, func(hh hash.Hash) {
							writeHashNumberValueV1(hh, dp)
						}, 0)
						members = append(members, member{idx: idx, group: group})
						if retryable[idx] {
							retried[group] = true
						}
					}

				case pmetric.MetricTypeSum:
					desc.metricType = MetricTypeSum
					desc.temporality = temporalityName(m.Sum().AggregationTemporality())
					monotonic := m.Sum().IsMonotonic()
					desc.monotonic = &monotonic
					for _, dp := range m.Sum().DataPoints().All() {
						idx++
						if !candidate[idx] && !retryable[idx] {
							continue
						}
						group := hashMetricPointV1(h, dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, origin, func(hh hash.Hash) {
							writeHashNumberValueV1(hh, dp)
						}, 0)
						members = append(members, member{idx: idx, group: group})
						if retryable[idx] {
							retried[group] = true
						}
					}

				case pmetric.MetricTypeHistogram:
					desc.metricType = MetricTypeHistogram
					desc.temporality = temporalityName(m.Histogram().AggregationTemporality())
					for _, dp := range m.Histogram().DataPoints().All() {
						idx++
						if !candidate[idx] && !retryable[idx] {
							continue
						}
						group := hashMetricPointV1(h, dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, origin, func(hh hash.Hash) {
							writeHashHistogramValueV1(hh, dp)
						}, 0)
						members = append(members, member{idx: idx, group: group})
						if retryable[idx] {
							retried[group] = true
						}
					}

				case pmetric.MetricTypeExponentialHistogram:
					desc.metricType = MetricTypeExponentialHistogram
					desc.temporality = temporalityName(m.ExponentialHistogram().AggregationTemporality())
					for _, dp := range m.ExponentialHistogram().DataPoints().All() {
						idx++
						if !candidate[idx] && !retryable[idx] {
							continue
						}
						group := hashMetricPointV1(h, dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), dp.Exemplars(), desc, origin, func(hh hash.Hash) {
							writeHashExpHistogramValueV1(hh, dp)
						}, 0)
						members = append(members, member{idx: idx, group: group})
						if retryable[idx] {
							retried[group] = true
						}
					}

				case pmetric.MetricTypeSummary:
					desc.metricType = MetricTypeSummary
					for _, dp := range m.Summary().DataPoints().All() {
						idx++
						if !candidate[idx] && !retryable[idx] {
							continue
						}
						group := hashMetricPointV1(h, dp.Timestamp(), dp.StartTimestamp(), dp.Flags(), dp.Attributes(), pmetric.NewExemplarSlice(), desc, origin, func(hh hash.Hash) {
							writeHashSummaryValueV1(hh, dp)
						}, 0)
						members = append(members, member{idx: idx, group: group})
						if retryable[idx] {
							retried[group] = true
						}
					}
				}
			}
		}
	}

	out := make([]int, 0, len(members))
	for _, m := range members {
		if retryable[m.idx] || retried[m.group] {
			out = append(out, m.idx)
		}
	}
	return out
}

// MetricQuarantineRows builds the quarantine rows for metric data points that
// will not reach the metric table: one row per entry, in batch order. An entry
// whose Index matches no data point is ignored.
func MetricQuarantineRows(md pmetric.Metrics, entries []QuarantineEntry, opts Options) []Row {
	if len(entries) == 0 {
		return nil
	}
	if err := opts.context().Err(); err != nil {
		return nil
	}
	byIndex := entriesByIndex(entries)
	builder := newQuarantineRowBuilder(opts, len(entries))
	marshaler := &pmetric.JSONMarshaler{}
	idx := -1

	for _, rm := range md.ResourceMetrics().All() {
		if builder.opts.context().Err() != nil {
			break
		}
		for _, sm := range rm.ScopeMetrics().All() {
			if builder.opts.context().Err() != nil {
				break
			}
			for _, m := range sm.Metrics().All() {
				if builder.opts.context().Err() != nil {
					break
				}
				cont := visitMetricPoints(m, func(_ int, pt metricPointRef) bool {
					if builder.opts.context().Err() != nil {
						return false
					}
					idx++
					group := byIndex[idx]
					if len(group) == 0 {
						return true
					}
					one := pmetric.NewMetrics()
					orm := one.ResourceMetrics().AppendEmpty()
					rm.Resource().CopyTo(orm.Resource())
					orm.SetSchemaUrl(rm.SchemaUrl())
					osm := orm.ScopeMetrics().AppendEmpty()
					sm.Scope().CopyTo(osm.Scope())
					osm.SetSchemaUrl(sm.SchemaUrl())
					om := osm.Metrics().AppendEmpty()
					copyMetricHeader(m, om)
					pt.copyInto(om)
					// Step 0 for the quarantine path; see SpanQuarantineRows.
					// Attributes and exemplars are read back from the redacted
					// copy, never from the visitor's view of the original.
					builder.opts.Redactor.RedactMetrics(one)
					attrs, exemplars := singleMetricPoint(om)

					payload, err := marshaler.MarshalMetrics(one)
					if err != nil {
						payload = nil
					}
					var traceID, spanID string
					for _, ex := range exemplars.All() {
						if traceID == "" {
							traceID = traceIDString(ex.TraceID())
						}
						if spanID == "" {
							spanID = spanIDString(ex.SpanID())
						}
					}
					rec := quarantinedRecord{
						signal:  schema.SignalMetrics,
						service: stringAttr(orm.Resource().Attributes(), serviceNameAttr),
						traceID: traceID,
						spanID:  spanID,
						payload: payload,
						attrs:   attrs,
					}
					return builder.add(rec, group)
				})
				if !cont {
					break
				}
			}
		}
	}
	return builder.rows()
}

// singleMetricPoint returns the attributes and exemplars of the only data
// point in a metric produced by copyInto. A summary point has no exemplars,
// and an unknown or empty metric yields empty views.
func singleMetricPoint(m pmetric.Metric) (pcommon.Map, pmetric.ExemplarSlice) {
	switch m.Type() {
	case pmetric.MetricTypeGauge:
		if dps := m.Gauge().DataPoints(); dps.Len() > 0 {
			return dps.At(0).Attributes(), dps.At(0).Exemplars()
		}
	case pmetric.MetricTypeSum:
		if dps := m.Sum().DataPoints(); dps.Len() > 0 {
			return dps.At(0).Attributes(), dps.At(0).Exemplars()
		}
	case pmetric.MetricTypeHistogram:
		if dps := m.Histogram().DataPoints(); dps.Len() > 0 {
			return dps.At(0).Attributes(), dps.At(0).Exemplars()
		}
	case pmetric.MetricTypeExponentialHistogram:
		if dps := m.ExponentialHistogram().DataPoints(); dps.Len() > 0 {
			return dps.At(0).Attributes(), dps.At(0).Exemplars()
		}
	case pmetric.MetricTypeSummary:
		if dps := m.Summary().DataPoints(); dps.Len() > 0 {
			return dps.At(0).Attributes(), pmetric.NewExemplarSlice()
		}
	}
	return pcommon.NewMap(), pmetric.NewExemplarSlice()
}

// SelectMetrics rebuilds a metrics payload containing only the data points at
// the given flattened indices, in the same walk order as MetricRows.
func SelectMetrics(md pmetric.Metrics, indices []int) pmetric.Metrics {
	keep := indexSet(indices)
	out := pmetric.NewMetrics()
	idx := -1

	for _, rm := range md.ResourceMetrics().All() {
		var destRM pmetric.ResourceMetrics
		rmStarted := false

		for _, sm := range rm.ScopeMetrics().All() {
			var destSM pmetric.ScopeMetrics
			smStarted := false

			for _, m := range sm.Metrics().All() {
				var destM pmetric.Metric
				mStarted := false

				visitMetricPoints(m, func(_ int, pt metricPointRef) bool {
					idx++
					if !keep[idx] {
						return true
					}
					if !rmStarted {
						destRM = out.ResourceMetrics().AppendEmpty()
						rm.Resource().CopyTo(destRM.Resource())
						destRM.SetSchemaUrl(rm.SchemaUrl())
						rmStarted = true
					}
					if !smStarted {
						destSM = destRM.ScopeMetrics().AppendEmpty()
						sm.Scope().CopyTo(destSM.Scope())
						destSM.SetSchemaUrl(sm.SchemaUrl())
						smStarted = true
					}
					if !mStarted {
						destM = destSM.Metrics().AppendEmpty()
						copyMetricHeader(m, destM)
						mStarted = true
					}
					pt.copyInto(destM)
					return true
				})
			}
		}
	}
	return out
}

func copyMetricHeader(src, dst pmetric.Metric) {
	dst.SetName(src.Name())
	dst.SetDescription(src.Description())
	dst.SetUnit(src.Unit())
	src.Metadata().CopyTo(dst.Metadata())
	switch src.Type() {
	case pmetric.MetricTypeGauge:
		dst.SetEmptyGauge()
	case pmetric.MetricTypeSum:
		s := dst.SetEmptySum()
		s.SetAggregationTemporality(src.Sum().AggregationTemporality())
		s.SetIsMonotonic(src.Sum().IsMonotonic())
	case pmetric.MetricTypeHistogram:
		h := dst.SetEmptyHistogram()
		h.SetAggregationTemporality(src.Histogram().AggregationTemporality())
	case pmetric.MetricTypeExponentialHistogram:
		eh := dst.SetEmptyExponentialHistogram()
		eh.SetAggregationTemporality(src.ExponentialHistogram().AggregationTemporality())
	case pmetric.MetricTypeSummary:
		dst.SetEmptySummary()
	}
}

type metricPointRef struct {
	copyInto  func(pmetric.Metric)
	attrs     pcommon.Map
	exemplars pmetric.ExemplarSlice
}

func visitMetricPoints(
	m pmetric.Metric,
	fn func(pointIdx int, item metricPointRef) bool,
) bool {
	switch m.Type() {
	case pmetric.MetricTypeGauge:
		dps := m.Gauge().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			dp := dps.At(i)
			if !fn(i, metricPointRef{
				copyInto: func(dst pmetric.Metric) {
					dp.CopyTo(dst.Gauge().DataPoints().AppendEmpty())
				},
				attrs:     dp.Attributes(),
				exemplars: dp.Exemplars(),
			}) {
				return false
			}
		}
	case pmetric.MetricTypeSum:
		dps := m.Sum().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			dp := dps.At(i)
			if !fn(i, metricPointRef{
				copyInto: func(dst pmetric.Metric) {
					dp.CopyTo(dst.Sum().DataPoints().AppendEmpty())
				},
				attrs:     dp.Attributes(),
				exemplars: dp.Exemplars(),
			}) {
				return false
			}
		}
	case pmetric.MetricTypeHistogram:
		dps := m.Histogram().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			dp := dps.At(i)
			if !fn(i, metricPointRef{
				copyInto: func(dst pmetric.Metric) {
					dp.CopyTo(dst.Histogram().DataPoints().AppendEmpty())
				},
				attrs:     dp.Attributes(),
				exemplars: dp.Exemplars(),
			}) {
				return false
			}
		}
	case pmetric.MetricTypeExponentialHistogram:
		dps := m.ExponentialHistogram().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			dp := dps.At(i)
			if !fn(i, metricPointRef{
				copyInto: func(dst pmetric.Metric) {
					dp.CopyTo(dst.ExponentialHistogram().DataPoints().AppendEmpty())
				},
				attrs:     dp.Attributes(),
				exemplars: dp.Exemplars(),
			}) {
				return false
			}
		}
	case pmetric.MetricTypeSummary:
		dps := m.Summary().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			dp := dps.At(i)
			if !fn(i, metricPointRef{
				copyInto: func(dst pmetric.Metric) {
					dp.CopyTo(dst.Summary().DataPoints().AppendEmpty())
				},
				attrs:     dp.Attributes(),
				exemplars: pmetric.NewExemplarSlice(),
			}) {
				return false
			}
		}
	}
	return true
}
