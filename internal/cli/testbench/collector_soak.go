// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	bigqueryexporter "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/redact"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testfakes/bqfake"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
)

const (
	collectorStartupTimeout          = 20 * time.Second
	collectorShutdownTimeout         = 30 * time.Second
	collectorMaxDiagBytes            = 64 * 1024
	collectorMaxPendingDiagLineBytes = 256 * 1024
	linuxUserHZ                      = 100.0
	maxCollectorEnvExpansionDepth    = 16
)

var collectorMinDrainTimeout = 15 * time.Second

type collectorEndpointOverride struct {
	otlpAddr       string
	extraOTLPAddrs []string
	healthAddr     string
	metricsHost    string
	metricsPort    int
	storageRoot    string
	useBQFake      bool
	fakeGRPCURL    string
	fakeRESTURL    string
	dryRun         bool
}

type ephemeralTableSpec struct {
	signal              string
	exporterID          string
	table               string
	provisionsDedupView bool
	destOpts            schema.DestinationOptions
}

type collectorRewriteMeta struct {
	hasHealthCheck                   bool
	healthCheckPath                  string
	activePipelineKey                string
	activeExporterID                 string
	activeExporterDiagnosticID       string
	activeExporterBodyEnvSourced     bool
	sqConfmapNullSizers              collectorSQConfmapNullSizers
	effectiveTable                   string
	effectiveEndpoint                bigqueryexporter.EndpointConfig
	effectiveCredentials             bigqueryexporter.CredentialsConfig
	effectiveKMSKeyName              string
	effectiveLabels                  map[string]string
	effectiveRedaction               bool
	effectiveRedactionConfig         bigqueryexporter.RedactionConfig
	effectiveBackpressure            bool
	effectiveStreamPoolSize          int
	effectiveConnectionPoolSize      int
	effectiveMaxInflightRequests     int
	effectiveMaxRequestBytes         int
	extraOTLPAddrs                   []string
	batchProcessorTimeout            time.Duration
	batchProcessorSendSize           int
	queueBatchFlushTimeout           time.Duration
	queueBatchMinItems               int
	effectiveLogsLogNameAttr         string
	effectiveLogsInsertIDAttr        string
	effectiveLogsSynthesizeInsertID  bool
	pipelineAltersIdentityKeys       bool
	pipelineModifiesNonIdentityAttrs bool
	canSimulateNonIdentityAttrs      bool
	nonIdentityAttrOps               []collectorAttrOp
	rawCredentialSecrets             []string
	destinationTables                []ephemeralTableSpec
	ephemeralTables                  []ephemeralTableSpec
}

func (m collectorRewriteMeta) exporterDiagnosticID() string {
	if m.activeExporterDiagnosticID != "" {
		return m.activeExporterDiagnosticID
	}
	return m.activeExporterID
}

type collectorBatchWaitConfig struct {
	batchProcTimeout       time.Duration
	batchProcSendSize      int
	queueBatchFlushTimeout time.Duration
	queueBatchMinItems     int
}

type collectorMetricsSample struct {
	Telemetry                TelemetrySnapshot
	QueueSize                int64
	InflightRequests         int64
	Sent                     int64
	HasSentMetric            bool
	HasAppendBytesMetric     bool
	SendFailed               int64
	EnqueueFailed            int64
	RejectedRequestPermanent int64
	RejectedRowError         int64
	RejectedOffloadPermanent int64
	HeapAllocBytes           uint64
}

const (
	maxDroppedPEMTailBytes    = 1024
	overlongCarryReserveBytes = 64
)

type diagOpenQuoteKind uint8

const (
	diagOpenQuoteNone diagOpenQuoteKind = iota
	diagOpenQuotePlain
	diagOpenQuoteEscaped
)

type overlongBearerPhase uint8

const (
	overlongBearerNone overlongBearerPhase = iota
	overlongBearerIntroWord
	overlongBearerSep
	overlongBearerToken
	overlongBearerFoldGap
)

type overlongBearerTracker struct {
	phase                  overlongBearerPhase
	tokenBytes             int
	minFoldBytes           int
	carry                  string
	atLineStart            bool
	startPendingBearer     bool
	startPendingBearerFold bool
	canStartBearer         bool
	canStartPendingBearer  bool
	sepAllowsPendingBearer bool
}

func (t *overlongBearerTracker) reset(pendingBearer, pendingBearerFold bool) {
	t.phase = overlongBearerNone
	t.tokenBytes = 0
	t.minFoldBytes = 8
	t.carry = ""
	t.atLineStart = true
	t.startPendingBearer = pendingBearer
	t.startPendingBearerFold = pendingBearerFold
	t.canStartBearer = true
	t.canStartPendingBearer = true
	t.sepAllowsPendingBearer = false
}

func (t *overlongBearerTracker) foldEligible() bool {
	return t.phase == overlongBearerToken && t.tokenBytes >= t.minFoldBytes
}

func (t *overlongBearerTracker) pendingBearerEligible() bool {
	if t.foldEligible() {
		return false
	}
	if t.phase == overlongBearerSep && t.minFoldBytes == 8 {
		return t.sepAllowsPendingBearer
	}
	return t.phase == overlongBearerIntroWord && t.canStartPendingBearer
}

func isHorizontalOrVerticalSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\f' || b == '\v'
}

func isASCIIWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func matchBearerEscapedSepLen(s string, allowNewline bool) int {
	if len(s) < 2 || s[0] != '\\' {
		return 0
	}
	bs := 1
	for bs < len(s) && s[bs] == '\\' {
		bs++
	}
	if bs >= len(s) {
		return 0
	}
	switch s[bs] {
	case 't', 'f', 'v':
		return bs + 1
	case 'n', 'r':
		if allowNewline {
			return bs + 1
		}
		return 0
	}
	if strings.HasPrefix(s[bs:], "u000") && bs+4 < len(s) {
		switch s[bs+4] {
		case '9', 'b', 'B', 'c', 'C':
			return bs + 5
		case 'a', 'A', 'd', 'D':
			if allowNewline {
				return bs + 5
			}
		}
	}
	return 0
}

func matchBearerFoldedNewlinePrefix(s string) int {
	switch {
	case strings.HasPrefix(s, "\r\n"):
		return 2
	case strings.HasPrefix(s, "\n"):
		return 1
	case strings.HasPrefix(s, `\\r\\n`):
		return 6
	case strings.HasPrefix(s, `\\n`):
		return 3
	case strings.HasPrefix(s, `\r\n`):
		return 4
	case strings.HasPrefix(s, `\n`):
		return 2
	case strings.HasPrefix(s, `\u000d\u000a`) || strings.HasPrefix(s, `\u000D\u000A`) ||
		strings.HasPrefix(s, `\u000d\u000A`) || strings.HasPrefix(s, `\u000D\u000a`):
		return 12
	case strings.HasPrefix(s, `\u000a`) || strings.HasPrefix(s, `\u000A`):
		return 6
	default:
		return 0
	}
}

func hasBearerFoldedGapPrefix(s string) bool {
	pos := matchBearerFoldedNewlinePrefix(s)
	if pos == 0 || pos >= len(s) {
		return false
	}
	return isHorizontalOrVerticalSpace(s[pos]) || matchBearerEscapedSepLen(s[pos:], false) > 0
}

func matchBearerIntroSepAt(s string) int {
	if len(s) == 0 {
		return 0
	}
	if isHorizontalOrVerticalSpace(s[0]) || s[0] == '\r' || s[0] == '\n' {
		return 1
	}
	if s[0] == '\\' {
		return matchBearerEscapedSepLen(s, true)
	}
	return 0
}

func (t *overlongBearerTracker) tryConsumeBearerIntro(buf string, i int, allowIntroWordAtEOF, allowFoldedGapIntro bool) (int, bool) {
	if !t.canStartBearer || len(buf)-i < 6 || !strings.EqualFold(buf[i:i+6], "Bearer") {
		return i, false
	}
	if i+6 == len(buf) {
		if !allowIntroWordAtEOF {
			return i, false
		}
		t.phase = overlongBearerIntroWord
		t.tokenBytes = 0
		t.minFoldBytes = 8
		return i + 6, true
	}
	if !allowFoldedGapIntro && hasBearerFoldedGapPrefix(buf[i+6:]) {
		return i, false
	}
	if sepLen := matchBearerIntroSepAt(buf[i+6:]); sepLen > 0 {
		t.phase = overlongBearerSep
		t.tokenBytes = 0
		t.minFoldBytes = 8
		t.sepAllowsPendingBearer = t.canStartPendingBearer
		t.canStartBearer = true
		t.canStartPendingBearer = true
		return i + 6 + sepLen, true
	}
	return i, false
}

func (t *overlongBearerTracker) feed(data []byte, atEOF bool) {
	buf := t.carry + string(data)
	t.carry = ""
	if atEOF && len(buf) > 0 && buf[len(buf)-1] == '\r' {
		buf = buf[:len(buf)-1]
	}
	if !atEOF && len(buf) <= overlongCarryReserveBytes {
		t.carry = buf
		return
	}
	limit := len(buf)
	if !atEOF {
		limit = len(buf) - overlongCarryReserveBytes
		for limit > 0 && buf[limit] == '\\' && len(buf)-limit < 128 {
			limit--
		}
		if limit > 0 && buf[limit-1] == '\\' {
			for limit > 0 && buf[limit-1] == '\\' && len(buf)-limit < 128 {
				limit--
			}
		}
	}
	if t.atLineStart && limit > 0 {
		t.atLineStart = false
		switch {
		case t.startPendingBearerFold:
			if isHorizontalOrVerticalSpace(buf[0]) {
				t.phase = overlongBearerSep
				t.minFoldBytes = 1
				t.sepAllowsPendingBearer = false
			}
		case t.startPendingBearer:
			t.phase = overlongBearerSep
			t.minFoldBytes = 8
			t.sepAllowsPendingBearer = true
		}
	}
	i := 0
	for i < limit {
		switch t.phase {
		case overlongBearerNone:
			if nextIdx, ok := t.tryConsumeBearerIntro(buf, i, true, true); ok {
				i = nextIdx
				continue
			}
			if buf[i] == '\\' {
				if escLen := matchBearerEscapedSepLen(buf[i:], true); escLen > 0 {
					t.canStartBearer = true
					t.canStartPendingBearer = true
					i += escLen
					continue
				}
			}
			c := buf[i]
			t.canStartBearer = !isASCIIWordByte(c)
			t.canStartPendingBearer = !isBearerTokenByte(c) || c == '='
			i++
		case overlongBearerIntroWord:
			if sepLen := matchBearerIntroSepAt(buf[i:]); sepLen > 0 {
				t.phase = overlongBearerSep
				t.tokenBytes = 0
				t.minFoldBytes = 8
				t.sepAllowsPendingBearer = t.canStartPendingBearer
				t.canStartBearer = true
				t.canStartPendingBearer = true
				i += sepLen
				continue
			}
			t.phase = overlongBearerNone
			t.minFoldBytes = 8
		case overlongBearerSep:
			if isHorizontalOrVerticalSpace(buf[i]) || (t.minFoldBytes == 8 && buf[i] == '\r') {
				t.canStartBearer = true
				t.canStartPendingBearer = true
				i++
				continue
			}
			if t.minFoldBytes == 8 && buf[i] == '\\' {
				if escLen := matchBearerEscapedSepLen(buf[i:], true); escLen > 0 {
					t.canStartBearer = true
					t.canStartPendingBearer = true
					i += escLen
					continue
				}
			}
			if nextIdx, ok := t.tryConsumeBearerIntro(buf, i, true, false); ok {
				i = nextIdx
				continue
			}
			if isBearerTokenByte(buf[i]) {
				t.phase = overlongBearerToken
				t.tokenBytes = 1
				t.canStartBearer = !isASCIIWordByte(buf[i])
				t.canStartPendingBearer = buf[i] == '='
				i++
				continue
			}
			t.phase = overlongBearerNone
			t.minFoldBytes = 8
		case overlongBearerToken:
			if nextIdx, ok := t.tryConsumeBearerIntro(buf, i, t.canStartPendingBearer, false); ok {
				i = nextIdx
				continue
			}
			if isBearerTokenByte(buf[i]) {
				if t.tokenBytes < 8 {
					t.tokenBytes++
				}
				t.canStartBearer = !isASCIIWordByte(buf[i])
				t.canStartPendingBearer = buf[i] == '='
				i++
				continue
			}
			if t.minFoldBytes == 8 && buf[i] == '\\' {
				if nlLen := matchBearerFoldedNewlinePrefix(buf[i:]); nlLen > 0 && hasBearerFoldedGapPrefix(buf[i:]) {
					t.phase = overlongBearerFoldGap
					t.canStartBearer = true
					t.canStartPendingBearer = true
					i += nlLen
					continue
				}
			}
			t.phase = overlongBearerNone
			t.tokenBytes = 0
			t.minFoldBytes = 8
		case overlongBearerFoldGap:
			if isHorizontalOrVerticalSpace(buf[i]) {
				t.canStartBearer = true
				t.canStartPendingBearer = true
				i++
				continue
			}
			if buf[i] == '\\' {
				if escLen := matchBearerEscapedSepLen(buf[i:], false); escLen > 0 {
					t.canStartBearer = true
					t.canStartPendingBearer = true
					i += escLen
					continue
				}
			}
			if nextIdx, ok := t.tryConsumeBearerIntro(buf, i, false, false); ok {
				i = nextIdx
				continue
			}
			if isBearerTokenByte(buf[i]) {
				t.phase = overlongBearerToken
				if t.tokenBytes < 8 {
					t.tokenBytes++
				}
				t.canStartBearer = !isASCIIWordByte(buf[i])
				t.canStartPendingBearer = buf[i] == '='
				i++
				continue
			}
			t.phase = overlongBearerNone
			t.tokenBytes = 0
			t.minFoldBytes = 8
		}
	}
	if !atEOF && i < len(buf) {
		t.carry = buf[i:]
	}
}

type boundedDiagBuffer struct {
	mu                    sync.Mutex
	retained              bytes.Buffer
	pending               bytes.Buffer
	droppingLine          bool
	droppingSawNonSpace   bool
	droppedLineSawPEM     bool
	droppedPEMTail        string
	droppedTail           string
	inPEMKeyBlock         bool
	pendingBearer         bool
	pendingBearerFold     bool
	pendingQuotedSecret   diagOpenQuoteKind
	overlongTracker       overlongBearerTracker
	truncated             bool
	droppedOverlong       bool
	preparedSecrets       []string
	redactedExporterForms []string
}

func (b *boundedDiagBuffer) SetExporterIDRedaction(exporterID string) {
	forms := buildExporterIDRedactionForms(exporterID)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.redactedExporterForms = forms
}

func (b *boundedDiagBuffer) SetCredentialRedactions(creds bigqueryexporter.CredentialsConfig, extraSecrets ...string) {
	prepared := collectCollectorCredentialSecrets(creds, extraSecrets...)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.preparedSecrets = prepared
}

func (b *boundedDiagBuffer) appendRetainedLineLocked(cleanLine string) {
	if b.truncated {
		return
	}
	if b.retained.Len()+len(cleanLine)+1 > collectorMaxDiagBytes {
		b.truncated = true
		b.pending.Reset()
		b.overlongTracker = overlongBearerTracker{}
		return
	}
	b.retained.WriteString(cleanLine)
	b.retained.WriteByte('\n')
}

func appendRollingDiagTail(prev string, data []byte, maxBytes int) string {
	if len(data) >= maxBytes {
		return string(data[len(data)-maxBytes:])
	}
	if len(prev)+len(data) <= maxBytes {
		return prev + string(data)
	}
	keepPrev := maxBytes - len(data)
	return prev[len(prev)-keepPrev:] + string(data)
}

func containsNonSpaceDiagByte(data []byte) bool {
	for _, c := range data {
		if !isHorizontalOrVerticalSpace(c) && c != '\r' {
			return true
		}
	}
	return false
}

func updatePEMStateForDroppedBytes(curInBlock bool, priorTail string, data []byte) (nextInBlock bool, sawPEM bool, nextTail string) {
	scan := priorTail + string(data)
	pos := 0
	for pos < len(scan) {
		if curInBlock {
			endLoc := reDiagPEMEnd.FindStringIndex(scan[pos:])
			if endLoc == nil {
				break
			}
			pos += endLoc[1]
			curInBlock = false
			sawPEM = true
			continue
		}
		beginLoc := reDiagPEMBegin.FindStringIndex(scan[pos:])
		if beginLoc == nil {
			break
		}
		pos += beginLoc[1]
		curInBlock = true
		sawPEM = true
	}
	rem := scan[pos:]
	if len(rem) > maxDroppedPEMTailBytes {
		rem = rem[len(rem)-maxDroppedPEMTailBytes:]
	}
	return curInBlock, sawPEM, rem
}

func collectPEMLineSpans(line string) (spans []diagSpan, nextInBlock bool) {
	pos := 0
	for pos < len(line) {
		beginLoc := reDiagPEMBegin.FindStringIndex(line[pos:])
		if beginLoc == nil {
			break
		}
		beginIdx := pos + beginLoc[0]
		afterBegin := pos + beginLoc[1]
		endLoc := reDiagPEMEnd.FindStringIndex(line[afterBegin:])
		if endLoc == nil {
			spans = append(spans, diagSpan{start: beginIdx, end: len(line), kind: diagSpanPEM, repl: "[REDACTED_PRIVATE_KEY]"})
			return spans, true
		}
		endIdx := afterBegin + endLoc[1]
		spans = append(spans, diagSpan{start: beginIdx, end: endIdx, kind: diagSpanPEM, repl: "[REDACTED_PRIVATE_KEY]"})
		pos = endIdx
	}
	return spans, false
}

func sanitizePEMLineWithExporterID(
	line string,
	inBlock bool,
	secrets []string,
	redactedExporterForms []string,
) (clean string, nextInBlock bool, suppress bool) {
	clean, nextInBlock, _, _, suppress = sanitizePEMLineWithPendingState(line, inBlock, false, false, secrets, redactedExporterForms)
	return clean, nextInBlock, suppress
}

func (b *boundedDiagBuffer) feedDroppedBearerChunkLocked(data []byte, atEOF bool) (sawPEM bool) {
	priorInBlock := b.inPEMKeyBlock
	priorPEMTail := b.droppedPEMTail
	nextInBlock, saw, nextPEMTail := updatePEMStateForDroppedBytes(priorInBlock, priorPEMTail, data)
	b.inPEMKeyBlock = nextInBlock
	b.droppedPEMTail = nextPEMTail
	if nextInBlock {
		b.overlongTracker.reset(false, false)
		return saw
	}
	if priorInBlock || saw {
		scan := priorPEMTail + string(data)
		locs := reDiagPEMEnd.FindAllStringIndex(scan, -1)
		postOffset := 0
		if len(locs) > 0 {
			postOffset = max(0, locs[len(locs)-1][1]-len(priorPEMTail))
		}
		b.overlongTracker.reset(false, false)
		b.overlongTracker.feed(data[postOffset:], atEOF)
		return saw
	}
	b.overlongTracker.feed(data, atEOF)
	return saw
}

func (b *boundedDiagBuffer) finishOverlongLineLocked(omitLineStartedInBlock, nonSpace, sawPEM bool, tailStr string) {
	foldOK := b.overlongTracker.foldEligible()
	streamPendingOK := b.overlongTracker.pendingBearerEligible()
	b.droppingLine = false
	b.droppingSawNonSpace = false
	b.droppedLineSawPEM = false
	b.droppedPEMTail = ""
	b.droppedTail = ""
	b.overlongTracker = overlongBearerTracker{}
	b.pendingQuotedSecret = diagOpenQuoteNone
	switch {
	case b.inPEMKeyBlock:
		b.pendingBearer = false
		b.pendingBearerFold = false
	case !nonSpace && !sawPEM:
		// Overlong whitespace-only lines preserve pending Bearer state.
	case foldOK:
		b.pendingBearer = false
		b.pendingBearerFold = true
	default:
		nonPEMTail := rawNonPEMTail(tailStr)
		_, _, nextPending, nextFold, _ := sanitizePEMLineWithPendingState(nonPEMTail, false, false, false, b.preparedSecrets, b.redactedExporterForms)
		if !nextPending && !nextFold && streamPendingOK && strings.TrimSpace(nonPEMTail) == "" {
			nextPending = true
		}
		b.pendingBearer = nextPending
		b.pendingBearerFold = nextFold
	}
	switch {
	case sawPEM:
		b.appendRetainedLineLocked("[REDACTED_PRIVATE_KEY] [overlong diagnostic line omitted]")
	case !omitLineStartedInBlock:
		b.appendRetainedLineLocked("[overlong diagnostic line omitted]")
	}
}

func (b *boundedDiagBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.truncated {
		return len(p), nil
	}
	rem := p
	for len(rem) > 0 && !b.truncated {
		if b.droppingLine {
			nl := bytes.IndexByte(rem, '\n')
			if nl < 0 {
				saw := b.feedDroppedBearerChunkLocked(rem, false)
				b.droppedTail = appendRollingDiagTail(b.droppedTail, rem, maxDroppedPEMTailBytes)
				b.droppedLineSawPEM = b.droppedLineSawPEM || saw
				if !b.droppingSawNonSpace {
					b.droppingSawNonSpace = containsNonSpaceDiagByte(rem)
				}
				break
			}
			seg := rem[:nl]
			saw := b.feedDroppedBearerChunkLocked(seg, true)
			b.droppedTail = appendRollingDiagTail(b.droppedTail, seg, maxDroppedPEMTailBytes)
			sawPEM := b.droppedLineSawPEM || saw
			nonSpace := b.droppingSawNonSpace || containsNonSpaceDiagByte(seg)
			tailStr := strings.TrimSuffix(b.droppedTail, "\r")
			b.finishOverlongLineLocked(b.inPEMKeyBlock, nonSpace, sawPEM, tailStr)
			rem = rem[nl+1:]
			continue
		}
		nl := bytes.IndexByte(rem, '\n')
		var chunk []byte
		hasNewline := nl >= 0
		if hasNewline {
			chunk = rem[:nl]
			rem = rem[nl+1:]
		} else {
			chunk = rem
			rem = nil
		}
		if b.pending.Len()+len(chunk) > collectorMaxPendingDiagLineBytes {
			startedInBlock := b.inPEMKeyBlock
			pendingBytes := b.pending.Bytes()
			b.droppedPEMTail = ""
			b.overlongTracker.reset(b.pendingBearer, b.pendingBearerFold)
			saw1 := b.feedDroppedBearerChunkLocked(pendingBytes, false)
			saw2 := b.feedDroppedBearerChunkLocked(chunk, hasNewline)
			tail := appendRollingDiagTail("", pendingBytes, maxDroppedPEMTailBytes)
			tail = appendRollingDiagTail(tail, chunk, maxDroppedPEMTailBytes)
			nonSpace := containsNonSpaceDiagByte(pendingBytes) || containsNonSpaceDiagByte(chunk)
			b.pending.Reset()
			b.droppedOverlong = true
			sawPEM := saw1 || saw2
			if hasNewline {
				b.finishOverlongLineLocked(startedInBlock, nonSpace, sawPEM, strings.TrimSuffix(tail, "\r"))
			} else {
				b.droppingLine = true
				b.droppedLineSawPEM = sawPEM
				b.droppingSawNonSpace = nonSpace
				b.droppedTail = tail
			}
			continue
		}
		if len(chunk) > 0 {
			_, _ = b.pending.Write(chunk)
		}
		if hasNewline {
			line := strings.TrimSuffix(b.pending.String(), "\r")
			b.pending.Reset()
			clean, nextInBlock, nextPendingBearer, nextPendingFold, nextQuotedSecret, suppress := sanitizePEMLineWithFullPendingState(line, b.inPEMKeyBlock, b.pendingBearer, b.pendingBearerFold, b.pendingQuotedSecret, b.preparedSecrets, b.redactedExporterForms)
			b.inPEMKeyBlock = nextInBlock
			b.pendingBearer = nextPendingBearer
			b.pendingBearerFold = nextPendingFold
			b.pendingQuotedSecret = nextQuotedSecret
			if !suppress {
				b.appendRetainedLineLocked(clean)
			}
		}
	}
	return len(p), nil
}

func (b *boundedDiagBuffer) String() string {
	b.mu.Lock()
	retainedRaw := b.retained.String()
	pendingRaw := b.pending.String()
	dropping := b.droppingLine
	droppingSawPEM := b.droppedLineSawPEM
	inPEMBlock := b.inPEMKeyBlock
	pendingBearer := b.pendingBearer
	pendingBearerFold := b.pendingBearerFold
	pendingQuotedSecret := b.pendingQuotedSecret
	truncated := b.truncated
	preparedSecrets := b.preparedSecrets
	redactedExporterForms := b.redactedExporterForms
	b.mu.Unlock()

	var out strings.Builder
	if retainedRaw != "" {
		out.WriteString(sanitizeCollectorDiagnosticsWithExporterID(retainedRaw, preparedSecrets, redactedExporterForms))
	}
	switch {
	case truncated:
		if out.Len() > 0 && !strings.HasSuffix(out.String(), "\n") {
			out.WriteByte('\n')
		}
		out.WriteString("[diagnostics truncated]")
	case dropping:
		if out.Len() > 0 && !strings.HasSuffix(out.String(), "\n") {
			out.WriteByte('\n')
		}
		if droppingSawPEM {
			out.WriteString("[REDACTED_PRIVATE_KEY] [overlong diagnostic line omitted]")
		} else {
			out.WriteString("[overlong diagnostic line omitted]")
		}
	case pendingRaw != "":
		cleanPending, _, _, _, _, suppress := sanitizePEMLineWithFullPendingState(strings.TrimSuffix(pendingRaw, "\r"), inPEMBlock, pendingBearer, pendingBearerFold, pendingQuotedSecret, preparedSecrets, redactedExporterForms)
		if !suppress {
			if out.Len()+len(cleanPending) <= collectorMaxDiagBytes {
				out.WriteString(cleanPending)
			} else {
				if out.Len() > 0 && !strings.HasSuffix(out.String(), "\n") {
					out.WriteByte('\n')
				}
				out.WriteString("[diagnostics truncated]")
			}
		}
	}
	return strings.TrimSpace(out.String())
}

func isBearerTokenByte(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '.' || b == '_' || b == '~' || b == '+' || b == '/' || b == '=' || b == '-'
}

func matchBearerFoldedGap(s string) int {
	pos := matchBearerFoldedNewlinePrefix(s)
	if pos == 0 {
		return 0
	}
	ws := pos
	for ws < len(s) {
		switch {
		case isHorizontalOrVerticalSpace(s[ws]):
			ws++
		case s[ws] == '\\':
			if escLen := matchBearerEscapedSepLen(s[ws:], false); escLen > 0 {
				ws += escLen
				continue
			}
			goto doneWS
		default:
			goto doneWS
		}
	}
doneWS:
	if ws == pos {
		return 0
	}
	return ws
}

func isFoldContinuationBoundary(s string, pos int) bool {
	if pos >= len(s) {
		return true
	}
	switch s[pos] {
	case '\r', '\n', '\f', '\v', '"':
		return true
	}
	if s[pos] == '\\' {
		bs := 1
		for pos+bs < len(s) && s[pos+bs] == '\\' {
			bs++
		}
		if pos+bs < len(s) {
			switch s[pos+bs] {
			case '"', 'n', 'r', 'f', 'v':
				return true
			}
			if strings.HasPrefix(s[pos+bs:], "u000") && pos+bs+4 < len(s) {
				switch s[pos+bs+4] {
				case 'a', 'A', 'b', 'B', 'c', 'C', 'd', 'D':
					return true
				}
			}
		}
	}
	return matchBearerFoldedGap(s[pos:]) > 0
}

func scanBearerTokenSpanFrom(raw string, tokStart int) (diagSpan, int, bool) {
	if tokStart >= len(raw) {
		return diagSpan{}, tokStart, false
	}
	tok1End := tokStart
	for tok1End < len(raw) && isBearerTokenByte(raw[tok1End]) {
		tok1End++
	}
	if tok1End == tokStart {
		return diagSpan{}, tokStart, false
	}
	curEnd := tok1End
	tokenBytes := tok1End - tokStart
	for curEnd < len(raw) && isFoldContinuationBoundary(raw, curEnd) {
		gap := matchBearerFoldedGap(raw[curEnd:])
		if gap == 0 {
			break
		}
		segStart := curEnd + gap
		segEnd := segStart
		for segEnd < len(raw) && isBearerTokenByte(raw[segEnd]) {
			segEnd++
		}
		if segEnd == segStart || !isFoldContinuationBoundary(raw, segEnd) {
			break
		}
		tokenBytes += segEnd - segStart
		curEnd = segEnd
	}
	if tokenBytes >= 8 {
		return diagSpan{
			start: tokStart,
			end:   curEnd,
			kind:  diagSpanCred,
			repl:  "[REDACTED]",
		}, curEnd, true
	}
	return diagSpan{}, tokStart, false
}

func collectBearerTokenSpans(raw string) []diagSpan {
	if raw == "" {
		return nil
	}
	var spans []diagSpan
	pos := 0
	for pos < len(raw) {
		loc := reDiagBearerIntro.FindStringSubmatchIndex(raw[pos:])
		if loc == nil {
			break
		}
		tokStart := pos + loc[5]
		if tokStart >= len(raw) {
			break
		}
		if sp, nextPos, ok := scanBearerTokenSpanFrom(raw, tokStart); ok {
			spans = append(spans, sp)
			pos = nextPos
			continue
		}
		pos = tokStart
	}
	return spans
}

func collectWrappedBearerSpans(line string, preparedSecrets []string) []diagSpan {
	const bearerPrefix = "Bearer\n"
	rawCombined := bearerPrefix + line
	var out []diagSpan
	for _, sp := range collectLiteralSecretSpans(rawCombined, preparedSecrets) {
		if sp.start < len(bearerPrefix) && sp.end > len(bearerPrefix) {
			out = append(out, diagSpan{
				start: 0,
				end:   sp.end - len(bearerPrefix),
				kind:  sp.kind,
				repl:  sp.repl,
			})
		}
	}
	if loc := reDiagBearerIntro.FindStringSubmatchIndex(rawCombined); loc != nil && loc[2] == 0 {
		if sp, _, ok := scanBearerTokenSpanFrom(rawCombined, loc[5]); ok && sp.end > len(bearerPrefix) {
			out = append(out, diagSpan{
				start: max(0, sp.start-len(bearerPrefix)),
				end:   sp.end - len(bearerPrefix),
				kind:  sp.kind,
				repl:  sp.repl,
			})
		}
	}
	return out
}

func collectFoldedBearerContinuationSpan(line string) (diagSpan, bool) {
	if len(line) == 0 || !isHorizontalOrVerticalSpace(line[0]) {
		return diagSpan{}, false
	}
	indent := 0
	for indent < len(line) && isHorizontalOrVerticalSpace(line[indent]) {
		indent++
	}
	if indent >= len(line) {
		return diagSpan{}, false
	}
	for i := indent; i < len(line); i++ {
		if !isBearerTokenByte(line[i]) {
			return diagSpan{}, false
		}
	}
	return diagSpan{
		start: indent,
		end:   len(line),
		kind:  diagSpanCred,
		repl:  "[REDACTED]",
	}, true
}

func rawNonPEMTail(line string) string {
	locs := reDiagPEMEnd.FindAllStringIndex(line, -1)
	if len(locs) == 0 {
		return line
	}
	return line[locs[len(locs)-1][1]:]
}

func isHTTPAuthHeaderPrefixBeforeBearer(prefix string) bool {
	p := strings.ToLower(strings.TrimRight(prefix, " \t\v\f"))
	for _, hdr := range []string{
		"proxy-authorization:",
		"authorization:",
		"authorization=",
		"auth=",
	} {
		if strings.HasSuffix(p, hdr) {
			idx := len(p) - len(hdr)
			if idx == 0 {
				return true
			}
			prev := p[idx-1]
			return !isASCIIWordByte(prev) && prev != '-'
		}
	}
	return false
}

func pendingBearerHeaderSurvives(
	rawTail, clean string,
	preparedSecrets, redactedExporterForms []string,
	extraConsumedSpans ...diagSpan,
) bool {
	if reDiagPendingBearerLine.MatchString(clean) {
		return true
	}
	m := reDiagPendingBearerLine.FindStringSubmatchIndex(rawTail)
	if len(m) < 4 {
		return false
	}
	bStart, bEnd := m[2], m[3]
	for _, sp := range extraConsumedSpans {
		if sp.start < bEnd && sp.end > bStart {
			return false
		}
	}
	for _, sp := range collectStructuralCredentialSpans(rawTail, true) {
		if sp.start < bEnd && sp.end > bStart {
			return false
		}
	}
	for _, sp := range collectLiteralSecretSpans(rawTail, preparedSecrets) {
		if sp.start >= bEnd || sp.end <= bStart {
			continue
		}
		if sp.start > bStart || sp.end < bEnd {
			return false
		}
		if sp.end > bEnd && strings.TrimSpace(rawTail[bEnd:sp.end]) != "" {
			return false
		}
		if sp.start < bStart && !isHTTPAuthHeaderPrefixBeforeBearer(rawTail[sp.start:bStart]) {
			return false
		}
		if bStart == 0 || !isHTTPAuthHeaderPrefixBeforeBearer(rawTail[:bStart]) {
			return false
		}
	}
	for _, sp := range collectExporterIDSpans(rawTail, redactedExporterForms) {
		if sp.start < bEnd && sp.end > bStart {
			return false
		}
	}
	return true
}

func sanitizePEMLineWithPendingBearer(line string, inPEMBlock, pendingBearer bool, preparedSecrets, redactedExporterForms []string) (clean string, nextInBlock, nextPendingBearer, suppress bool) {
	clean, nextInBlock, nextPendingBearer, _, suppress = sanitizePEMLineWithPendingState(line, inPEMBlock, pendingBearer, false, preparedSecrets, redactedExporterForms)
	return clean, nextInBlock, nextPendingBearer, suppress
}

func sanitizePEMLineWithPendingState(
	line string,
	inPEMBlock, pendingBearer, pendingBearerFold bool,
	preparedSecrets, redactedExporterForms []string,
) (clean string, nextInBlock, nextPendingBearer, nextPendingBearerFold, suppress bool) {
	clean, nextInBlock, nextPendingBearer, nextPendingBearerFold, _, suppress = sanitizePEMLineWithFullPendingState(
		line, inPEMBlock, pendingBearer, pendingBearerFold, diagOpenQuoteNone, preparedSecrets, redactedExporterForms,
	)
	return clean, nextInBlock, nextPendingBearer, nextPendingBearerFold, suppress
}

func sanitizePEMLineWithFullPendingState(
	line string,
	inPEMBlock, pendingBearer, pendingBearerFold bool,
	pendingQuotedSecret diagOpenQuoteKind,
	preparedSecrets, redactedExporterForms []string,
) (clean string, nextInBlock, nextPendingBearer, nextPendingBearerFold bool, nextQuotedSecret diagOpenQuoteKind, suppress bool) {
	if inPEMBlock {
		endLoc := reDiagPEMEnd.FindStringIndex(line)
		if endLoc == nil {
			return "", true, false, false, diagOpenQuoteNone, true
		}
		rem := line[endLoc[1]:]
		if rem == "" {
			return "", false, false, false, diagOpenQuoteNone, true
		}
		return sanitizePEMLineWithFullPendingState(rem, false, false, false, diagOpenQuoteNone, preparedSecrets, redactedExporterForms)
	}
	if pendingQuotedSecret != diagOpenQuoteNone {
		if isFreshDiagStructuredRecordLine(line) {
			pendingQuotedSecret = diagOpenQuoteNone
		} else {
			if strings.TrimSpace(line) == "" {
				return line, false, false, false, pendingQuotedSecret, false
			}
			contEnd := len(line)
			tailStart := -1
			nextContQuote := pendingQuotedSecret
			if pendingQuotedSecret == diagOpenQuoteEscaped {
				if endRel := findClosingJSONEscapedQuote(line); endRel >= 0 {
					contEnd = endRel
					tailStart = endRel + 2
					nextContQuote = diagOpenQuoteNone
				} else if segEnd := scanUnescapedQuoteOrEOL(line); segEnd < len(line) {
					contEnd = segEnd
					tailStart = segEnd
					nextContQuote = diagOpenQuoteNone
				}
			} else if endRel := findClosingDoubleQuoteOnLine(line); endRel >= 0 {
				contEnd = endRel
				tailStart = endRel + 1
				nextContQuote = diagOpenQuoteNone
			}
			pemSpans, pemNextIn := collectPEMLineSpans(line[:contEnd])
			var contClean string
			if len(pemSpans) > 0 {
				var cSpans []diagSpan
				if pemNextIn {
					if pemSpans[0].start > 0 {
						cSpans = append(cSpans, diagSpan{start: 0, end: pemSpans[0].start, kind: diagSpanCred, repl: "[REDACTED]"})
					}
					cSpans = append(cSpans, pemSpans...)
					contClean = applyDiagRedactionSpans(line[:contEnd], cSpans)
					return contClean, true, false, false, diagOpenQuoteNone, false
				}
				if contEnd > 0 {
					cSpans = append(cSpans, diagSpan{start: 0, end: contEnd, kind: diagSpanCred, repl: "[REDACTED]"})
				}
				cSpans = append(cSpans, pemSpans...)
				contClean = applyDiagRedactionSpans(line[:contEnd], cSpans)
			} else if contEnd > 0 {
				contClean = "[REDACTED]"
			}
			if tailStart >= 0 && tailStart <= len(line) {
				delim := line[contEnd:tailStart]
				tail := line[tailStart:]
				if tail == "" {
					return contClean + delim, false, false, false, diagOpenQuoteNone, false
				}
				tailClean, tailIn, tailPend, tailFold, tailQuote, tailSup := sanitizePEMLineWithFullPendingState(
					tail, false, false, false, diagOpenQuoteNone, preparedSecrets, redactedExporterForms,
				)
				if tailSup {
					return contClean + delim, tailIn, tailPend, tailFold, tailQuote, false
				}
				return contClean + delim + tailClean, tailIn, tailPend, tailFold, tailQuote, false
			}
			return contClean, false, false, false, nextContQuote, false
		}
	}
	if strings.TrimSpace(line) == "" {
		clean = sanitizeCollectorDiagnosticsWithExporterID(line, preparedSecrets, redactedExporterForms)
		return clean, false, pendingBearer, pendingBearerFold, diagOpenQuoteNone, false
	}

	spans, nextIn := collectPEMLineSpans(line)
	credSpans, trailingQuoteKind := collectCollectorCredentialSpansWithOpenState(line, preparedSecrets, false)
	spans = append(spans, credSpans...)
	var wrappedSpans []diagSpan
	if pendingBearer {
		wrappedSpans = collectWrappedBearerSpans(line, preparedSecrets)
		spans = append(spans, wrappedSpans...)
	} else if pendingBearerFold {
		if foldSpan, ok := collectFoldedBearerContinuationSpan(line); ok {
			wrappedSpans = append(wrappedSpans, foldSpan)
			spans = append(spans, foldSpan)
		}
	}
	spans = append(spans, collectExporterIDSpans(line, redactedExporterForms)...)
	clean = applyDiagRedactionSpans(line, spans)
	if clean == "" {
		return "", nextIn, false, false, diagOpenQuoteNone, true
	}
	if nextIn {
		return clean, true, false, false, diagOpenQuoteNone, false
	}
	tail := rawNonPEMTail(line)
	tailOffset := len(line) - len(tail)
	var tailWrappedSpans []diagSpan
	for _, sp := range wrappedSpans {
		if sp.end > tailOffset {
			tailWrappedSpans = append(tailWrappedSpans, diagSpan{
				start: max(0, sp.start-tailOffset),
				end:   sp.end - tailOffset,
				kind:  sp.kind,
				repl:  sp.repl,
			})
		}
	}
	nextPendingBearer = pendingBearerHeaderSurvives(tail, clean, preparedSecrets, redactedExporterForms, tailWrappedSpans...)
	if !nextPendingBearer {
		for _, sp := range collectBearerTokenSpans(tail) {
			if sp.end == len(tail) {
				nextPendingBearerFold = true
				break
			}
		}
		if !nextPendingBearerFold {
			for _, sp := range wrappedSpans {
				if sp.end == len(line) {
					nextPendingBearerFold = true
					break
				}
			}
		}
	}
	return clean, false, nextPendingBearer, nextPendingBearerFold, trailingQuoteKind, false
}

var (
	reDiagPEMBegin                     = regexp.MustCompile(`(?i)-----BEGIN [^\r\n-]*PRIVATE KEY-----`)
	reDiagPEMEnd                       = regexp.MustCompile(`(?i)-----END [^\r\n-]*PRIVATE KEY-----`)
	reDiagPEMBlock                     = regexp.MustCompile(`-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----`)
	reDiagPEMPrefix                    = regexp.MustCompile(`-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*`)
	reDiagBearerIntro                  = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_]|\\+[nrtfv]|\\+u000[9a-dA-D])(Bearer)((?:[ \t\v\f\r\n]|\\+[nrtfv]|\\+u000[9a-dA-D])+)`)
	reDiagJSONSecretEscapedPrefix      = regexp.MustCompile(`(\\"(?:private_key|private_key_id|client_secret|client_email|client_id|refresh_token|access_token|id_token|credentials_json|audience)\\"\s*:\s*\\")`)
	reDiagJSONSecretPlainPrefix        = regexp.MustCompile(`("(?:private_key|private_key_id|client_secret|client_email|client_id|refresh_token|access_token|id_token|credentials_json|audience)"\s*:\s*")`)
	reDiagUnsupportedTypeEscapedPrefix = regexp.MustCompile(`((?:unsupported(?:\s+credentials)?\s+type|unknown\s+credentials\s+type|has\s+unsupported\s+type)\s+)\\"`)
	reDiagUnsupportedTypePlainPrefix   = regexp.MustCompile(`((?:unsupported(?:\s+credentials)?\s+type|unknown\s+credentials\s+type|has\s+unsupported\s+type)\s+)"`)
	reDiagCredFileQuotedEscapedPrefix  = regexp.MustCompile(`((?:(?:reading|parsing|loading)\s+)?credentials(?:\s+file|\.file):?\s+)\\"`)
	reDiagCredFileQuotedPlainPrefix    = regexp.MustCompile(`((?:(?:reading|parsing|loading)\s+)?credentials(?:\s+file|\.file):?\s+)"`)
	reDiagPathOpPrefix                 = regexp.MustCompile(`(?:open|lstat|stat|CreateFile|(?:(?:reading|parsing|loading)\s+)?credentials(?:\s+file|\.file):?)\s+`)
	reDiagPendingBearerLine            = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_.~+/-]|\\+[nrtfv]|\\+u000[9a-dA-D])(Bearer)[ \t\v\f\r]*$`)
)

func collectCollectorCredentialSecrets(creds bigqueryexporter.CredentialsConfig, extraSecrets ...string) []string {
	seen := make(map[string]struct{})
	addLiteral := func(s string) {
		if len(s) < 4 {
			return
		}
		seen[s] = struct{}{}
		trimmed := strings.TrimSpace(s)
		if len(trimmed) >= 4 {
			seen[trimmed] = struct{}{}
		}
		if q := strconv.Quote(s); len(q) >= 2 {
			inner := q[1 : len(q)-1]
			if len(inner) >= 4 {
				seen[inner] = struct{}{}
				// Zap double-encodes newlines and quotes inside its JSON error strings.
				if q2 := strconv.Quote(inner); len(q2) >= 2 {
					inner2 := q2[1 : len(q2)-1]
					if len(inner2) >= 4 {
						seen[inner2] = struct{}{}
					}
				}
			}
		}
	}

	var inspectJSONValue func(key string, val any, forceSecret bool, depth int)
	inspectJSONValue = func(key string, val any, forceSecret bool, depth int) {
		if depth > 6 {
			return
		}
		switch v := val.(type) {
		case map[string]any:
			nestedForce := forceSecret || key == "credential_source" || key == "headers" || key == "format"
			for k, child := range v {
				inspectJSONValue(strings.ToLower(strings.TrimSpace(k)), child, nestedForce, depth+1)
			}
		case []any:
			for _, item := range v {
				inspectJSONValue(key, item, forceSecret, depth+1)
			}
		case string:
			if len(v) < 4 {
				return
			}
			switch key {
			case "type":
				if v != "service_account" && v != "authorized_user" && v != "external_account" {
					addLiteral(v)
				}
			case "token_uri":
				if v != "https://oauth2.googleapis.com/token" {
					addLiteral(v)
				}
			case "private_key", "private_key_id", "client_email", "client_id",
				"client_secret", "refresh_token", "access_token", "id_token",
				"audience", "subject_token_type", "service_account_impersonation_url",
				"token":
				addLiteral(v)
			default:
				if forceSecret {
					addLiteral(v)
				}
			}
		}
	}

	inspectMaybeJSON := func(raw string, allowDiskRead bool) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return
		}
		if strings.HasPrefix(trimmed, "{") {
			var doc map[string]any
			if err := json.Unmarshal([]byte(trimmed), &doc); err == nil {
				inspectJSONValue("", doc, false, 0)
			}
			return
		}
		if allowDiskRead && !strings.ContainsAny(trimmed, "\"\n\r") {
			if info, err := os.Stat(trimmed); err == nil && !info.IsDir() && info.Size() > 0 && info.Size() <= 256*1024 {
				if data, readErr := os.ReadFile(trimmed); readErr == nil {
					var doc map[string]any
					if err := json.Unmarshal(data, &doc); err == nil {
						inspectJSONValue("", doc, false, 0)
					}
				}
			}
		}
	}

	if creds.File != "" {
		addLiteral(creds.File)
		inspectMaybeJSON(creds.File, true)
	}
	if len(creds.JSON) > 0 {
		jsonStr := string(creds.JSON)
		addLiteral(jsonStr)
		inspectMaybeJSON(jsonStr, false)
	}
	if creds.ImpersonateServiceAccount != "" {
		addLiteral(creds.ImpersonateServiceAccount)
	}
	if creds.QuotaProject != "" {
		addLiteral(creds.QuotaProject)
	}
	for _, del := range creds.ImpersonateDelegates {
		if del != "" {
			addLiteral(del)
		}
	}
	for _, extra := range extraSecrets {
		if extra == "" {
			continue
		}
		addLiteral(extra)
		inspectMaybeJSON(extra, strings.HasSuffix(strings.ToLower(strings.TrimSpace(extra)), ".json"))
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b string) int {
		if c := cmp.Compare(len(b), len(a)); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
	})
	return out
}

func collectEndpointURLSecrets(ep bigqueryexporter.EndpointConfig) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string, minLen int) {
		if s == "" || len(s) < minLen {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, raw := range []string{ep.URL, ep.AdminURL} {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		// Always preserve the full URL string alongside non-trivial components.
		add(trimmed, 1)
		u, err := url.Parse(trimmed)
		if err != nil {
			continue
		}
		if u.User != nil {
			add(u.User.String(), 4)
			add(u.User.Username(), 4)
			if pass, hasPass := u.User.Password(); hasPass {
				add(pass, 4)
			}
		}
		if u.RawQuery != "" {
			if q, qErr := url.ParseQuery(u.RawQuery); qErr == nil {
				qKeys := make([]string, 0, len(q))
				for k := range q {
					qKeys = append(qKeys, k)
				}
				slices.Sort(qKeys)
				for _, k := range qKeys {
					for _, val := range q[k] {
						add(val, 4)
					}
				}
			}
			for _, part := range strings.Split(u.RawQuery, "&") {
				if eq := strings.IndexByte(part, '='); eq >= 0 {
					add(part[eq+1:], 4)
				}
			}
		}
	}
	return out
}

func findClosingJSONEscapedQuote(s string) int {
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\r' || s[i] == '\n' {
			return -1
		}
		if s[i] != '\\' {
			i++
			continue
		}
		if strings.HasPrefix(s[i:], `\\\\`) {
			i += 4
			continue
		}
		if strings.HasPrefix(s[i:], `\\\"`) {
			i += 4
			continue
		}
		if strings.HasPrefix(s[i:], `\"`) {
			return i
		}
		if i+1 < len(s) {
			i += 2
			continue
		}
		return -1
	}
	return -1
}

func scanUnescapedQuoteOrEOL(s string) int {
	escaped := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\r' || ch == '\n' {
			return i
		}
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			return i
		}
	}
	return len(s)
}

func isCredentialsProseLabelToken(tok string) bool {
	switch strings.ToLower(tok) {
	case "error", "warn", "warning", "note", "reason", "hint", "status", "details", "detail", "info", "message":
		return true
	default:
		return false
	}
}

func isCredentialsProseHyphenToken(tok string) bool {
	switch strings.ToLower(tok) {
	case "non-empty", "read-only", "utf-8":
		return true
	default:
		return false
	}
}

func looksLikePathOrQuoteOperand(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '"' || s[0] == '\'' || strings.HasPrefix(s, `\"`) {
		return true
	}
	if strings.HasPrefix(s, "/") ||
		strings.HasPrefix(s, `\`) ||
		strings.HasPrefix(s, "~/") ||
		strings.HasPrefix(s, `~\`) ||
		strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, `.\`) ||
		strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, `..\`) {
		return true
	}
	if len(s) >= 3 &&
		((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')) &&
		s[1] == ':' &&
		s[2] != ' ' && s[2] != '\t' && s[2] != '\r' && s[2] != '\n' {
		return true
	}
	end := strings.IndexAny(s, " \t\r\n:")
	tok := s
	if end >= 0 {
		tok = s[:end]
	}
	if tok == "" || strings.EqualFold(tok, "and/or") || strings.EqualFold(tok, "or/and") {
		return false
	}
	hasTrailingColon := end >= 0 && end < len(s) && s[end] == ':'
	if strings.ContainsRune(tok, '\\') {
		return true
	}
	if strings.ContainsRune(tok, '/') {
		// Accept nested/trailing-slash paths and "path: errno" error prefixes immediately,
		// while treating isolated pure-letter "word/word" tokens (such as "open/read failure"
		// or "missing/corrupt") as English prose unless they carry path markers ('.', '_', '-', digits).
		if strings.Count(tok, "/") >= 2 || strings.HasSuffix(tok, "/") || hasTrailingColon {
			return true
		}
		for i := 0; i < len(tok); i++ {
			b := tok[i]
			if b != '/' && (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') {
				return true
			}
		}
		return false
	}
	// Accept bare credential filenames (dotfiles such as ".gcp-key", names containing '_', '-', digits,
	// internal '.' like "private_sa_key.json", or single-token basenames followed by ':'), while
	// preserving plain English error prose ("and ... are mutually exclusive", "invalid JSON", "permission denied").
	if tok[0] == '.' && len(tok) > 1 {
		return true
	}
	if hasTrailingColon && !isCredentialsProseLabelToken(tok) {
		return true
	}
	if isCredentialsProseHyphenToken(tok) {
		return false
	}
	for i := 0; i < len(tok); i++ {
		b := tok[i]
		if b == '_' || b == '-' || (b >= '0' && b <= '9') {
			return true
		}
		if b == '.' && i > 0 && i < len(tok)-1 {
			return true
		}
	}
	return false
}

func collectCollectorPathErrorSpansInLine(line string, lineOffset int) []diagSpan {
	lower := strings.ToLower(line)
	hasCredContext := strings.Contains(lower, "credentials") ||
		strings.Contains(line, "open {") ||
		strings.Contains(line, `open {\"`) ||
		strings.Contains(line, "CreateFile {") ||
		strings.Contains(line, `CreateFile {\"`)
	if !hasCredContext {
		return nil
	}

	var spans []diagSpan
	cursor := 0
	for cursor < len(line) {
		loc := reDiagPathOpPrefix.FindStringIndex(line[cursor:])
		if loc == nil {
			break
		}
		op := line[cursor+loc[0] : cursor+loc[1]]
		pathStart := cursor + loc[1]
		if strings.Contains(strings.ToLower(op), "credentials") && !looksLikePathOrQuoteOperand(line[pathStart:]) {
			cursor = pathStart
			continue
		}
		if strings.HasPrefix(line[pathStart:], `\"`) {
			qStart := pathStart + 2
			endRel := findClosingJSONEscapedQuote(line[qStart:])
			if endRel >= 0 {
				if endRel > 0 {
					spans = append(spans, diagSpan{
						start: lineOffset + qStart,
						end:   lineOffset + qStart + endRel,
						kind:  diagSpanCred,
						repl:  "[REDACTED]",
					})
				}
				cursor = qStart + endRel + 2
				continue
			}
			// Fallback: unclosed JSON-escaped path has no closing delimiter yet,
			// so redact up to the next unescaped '"' or EOL without leaving filename suffixes behind.
			segEnd := qStart + scanUnescapedQuoteOrEOL(line[qStart:])
			if segEnd > qStart {
				spans = append(spans, diagSpan{
					start: lineOffset + qStart,
					end:   lineOffset + segEnd,
					kind:  diagSpanCred,
					repl:  "[REDACTED]",
				})
			}
			cursor = max(qStart+1, segEnd)
			continue
		}
		if pathStart < len(line) && line[pathStart] == '"' {
			qStart := pathStart + 1
			if endRel := findClosingDoubleQuote(line[qStart:]); endRel >= 0 {
				if endRel > 0 {
					spans = append(spans, diagSpan{
						start: lineOffset + qStart,
						end:   lineOffset + qStart + endRel,
						kind:  diagSpanCred,
						repl:  "[REDACTED]",
					})
				}
				cursor = qStart + endRel + 1
				continue
			}
			segEnd := qStart
			for segEnd < len(line) && line[segEnd] != '\r' && line[segEnd] != '\n' {
				segEnd++
			}
			if segEnd > qStart {
				spans = append(spans, diagSpan{
					start: lineOffset + qStart,
					end:   lineOffset + segEnd,
					kind:  diagSpanCred,
					repl:  "[REDACTED]",
				})
			}
			cursor = max(qStart+1, segEnd)
			continue
		}
		// Scan to the first unescaped quote (for JSON-encoded log lines) or end of line.
		segEnd := pathStart + scanUnescapedQuoteOrEOL(line[pathStart:])
		seg := line[pathStart:segEnd]
		// Strip trailing ": <os errno>" only when prefixed with ": " + ASCII letter and no JSON delimiters.
		pathEnd := segEnd
		if colonIdx := strings.LastIndex(seg, ": "); colonIdx >= 0 {
			errnoSuffix := seg[colonIdx+2:]
			if len(errnoSuffix) > 0 && ((errnoSuffix[0] >= 'a' && errnoSuffix[0] <= 'z') || (errnoSuffix[0] >= 'A' && errnoSuffix[0] <= 'Z')) &&
				!strings.ContainsAny(errnoSuffix, `{}"\`) {
				pathEnd = pathStart + colonIdx
			}
		}
		if pathEnd > pathStart {
			spans = append(spans, diagSpan{
				start: lineOffset + pathStart,
				end:   lineOffset + pathEnd,
				kind:  diagSpanCred,
				repl:  "[REDACTED]",
			})
		}
		if pathEnd <= pathStart {
			cursor = pathStart + 1
		} else {
			cursor = pathEnd
		}
	}
	return spans
}

func isComponentIDTokenChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_' || b == '-' || b == '@'
}

func hasQualifiedComponentSlash(target string) bool {
	if strings.Contains(target, "/") {
		return true
	}
	if strings.Contains(target, "%2F") || strings.Contains(target, "%2f") {
		return true
	}
	return strings.Contains(target, `\u002f`) || strings.Contains(target, `\u002F`)
}

func jsonEncodeInner(s string, escapeHTML bool) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(s); err != nil {
		return ""
	}
	trimmed := strings.TrimSpace(buf.String())
	if len(trimmed) < 2 || trimmed[0] != '"' || trimmed[len(trimmed)-1] != '"' {
		return ""
	}
	return trimmed[1 : len(trimmed)-1]
}

func lowerPercentHex(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHexByte(s[i+1]) && isHexByte(s[i+2]) {
			b.WriteByte('%')
			b.WriteByte(lowerASCIIHex(s[i+1]))
			b.WriteByte(lowerASCIIHex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func lowerASCIIHex(b byte) byte {
	if b >= 'A' && b <= 'F' {
		return b + ('a' - 'A')
	}
	return b
}

func buildExporterIDRedactionForms(id string) []string {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	seen := make(map[string]struct{}, 24)
	var forms []string
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		forms = append(forms, s)
	}
	addJSONVariants := func(s string) {
		for _, escHTML := range []bool{false, true} {
			if j1 := jsonEncodeInner(s, escHTML); j1 != "" {
				add(j1)
				for _, escHTML2 := range []bool{false, true} {
					if j2 := jsonEncodeInner(j1, escHTML2); j2 != "" && j2 != j1 {
						add(j2)
					}
				}
			}
		}
	}
	addSlashUnicodeVariants := func(s string) {
		if !strings.ContainsRune(s, '/') {
			return
		}
		for _, slashEsc := range []string{`\u002f`, `\u002F`} {
			variant := strings.ReplaceAll(s, "/", slashEsc)
			add(variant)
			addJSONVariants(variant)
		}
	}
	add(id)
	addJSONVariants(id)
	addSlashUnicodeVariants(id)
	if htmlEsc := jsonEncodeInner(id, true); htmlEsc != "" && htmlEsc != id {
		addSlashUnicodeVariants(htmlEsc)
	}
	if q := strconv.Quote(id); len(q) >= 2 {
		qInner := q[1 : len(q)-1]
		add(qInner)
		addSlashUnicodeVariants(qInner)
		if q2 := strconv.Quote(qInner); len(q2) >= 2 {
			add(q2[1 : len(q2)-1])
		}
	}
	percentBases := []string{
		url.PathEscape(id),
		url.QueryEscape(id),
	}
	if strings.ContainsRune(id, '/') {
		percentBases = append(percentBases,
			strings.ReplaceAll(id, "/", "%2F"),
			strings.ReplaceAll(id, "/", "%2f"),
		)
	}
	for _, escaped := range percentBases {
		add(escaped)
		addJSONVariants(escaped)
		if lower := lowerPercentHex(escaped); lower != escaped {
			add(lower)
			addJSONVariants(lower)
		}
	}
	slices.SortFunc(forms, func(a, b string) int {
		if len(a) != len(b) {
			return cmp.Compare(len(b), len(a))
		}
		return strings.Compare(a, b)
	})
	return forms
}

type diagSpanKind int

const (
	diagSpanExporterID diagSpanKind = iota + 1
	diagSpanCred
	diagSpanPEM
)

type diagSpan struct {
	start int
	end   int
	kind  diagSpanKind
	repl  string
}

func componentIDBoundaryOK(raw string, idx, end int, isQualified bool) bool {
	leftOK := idx == 0
	if !leftOK {
		prev := raw[idx-1]
		switch {
		case isComponentIDTokenChar(prev):
			leftOK = false
		case prev == '.':
			// Qualified type/name IDs can appear after confmap section prefixes
			// (e.g. exporters.bigquery/east), while bare type IDs stay protected
			// inside dotted hostnames.
			leftOK = isQualified
		case prev == '/':
			// Qualified type/name IDs can appear after path prefixes
			// (e.g. exporters/bigquery/east), but never directly after "://".
			leftOK = isQualified && (idx < 2 || raw[idx-2] != '/')
		default:
			leftOK = true
		}
	}
	rightOK := end == len(raw)
	if !rightOK {
		next := raw[end]
		switch {
		case isComponentIDTokenChar(next):
			rightOK = false
		case next == '.':
			// Allow trailing sentence punctuation ("... bigquery/east."), while
			// blocking dotted hostnames and dotted names ("bigquery/east.canary").
			rightOK = end+1 == len(raw) || !isComponentIDTokenChar(raw[end+1])
		case next == '/':
			// Qualified type/name IDs can precede path suffixes
			// (e.g. bigquery/east/logs), while bare type IDs stay protected
			// inside URL paths (e.g. /bigquery/v2).
			rightOK = isQualified
		default:
			rightOK = true
		}
	}
	return leftOK && rightOK
}

func collectExporterIDSpans(raw string, forms []string) []diagSpan {
	if raw == "" || len(forms) == 0 {
		return nil
	}
	var spans []diagSpan
	for _, target := range forms {
		if target == "" {
			continue
		}
		isQualified := hasQualifiedComponentSlash(target)
		pos := 0
		for pos <= len(raw)-len(target) {
			rel := strings.Index(raw[pos:], target)
			if rel < 0 {
				break
			}
			idx := pos + rel
			end := idx + len(target)
			if componentIDBoundaryOK(raw, idx, end, isQualified) {
				spans = append(spans, diagSpan{
					start: idx,
					end:   end,
					kind:  diagSpanExporterID,
					repl:  interpolatedExporterPlaceholder,
				})
				pos = end
			} else {
				pos = idx + 1
			}
		}
	}
	return spans
}

func collectLiteralSecretSpans(raw string, secrets []string) []diagSpan {
	if raw == "" || len(secrets) == 0 {
		return nil
	}
	var spans []diagSpan
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		pos := 0
		for pos <= len(raw)-len(secret) {
			rel := strings.Index(raw[pos:], secret)
			if rel < 0 {
				break
			}
			idx := pos + rel
			spans = append(spans, diagSpan{
				start: idx,
				end:   idx + len(secret),
				kind:  diagSpanCred,
				repl:  "[REDACTED]",
			})
			pos = idx + 1
		}
	}
	return spans
}

func hasISO8601TimestampPrefix(s string) bool {
	if len(s) < 19 {
		return false
	}
	isDigit := func(b byte) bool { return b >= '0' && b <= '9' }
	return isDigit(s[0]) && isDigit(s[1]) && isDigit(s[2]) && isDigit(s[3]) &&
		s[4] == '-' && isDigit(s[5]) && isDigit(s[6]) &&
		s[7] == '-' && isDigit(s[8]) && isDigit(s[9]) &&
		(s[10] == 'T' || s[10] == ' ') &&
		isDigit(s[11]) && isDigit(s[12]) && s[13] == ':' &&
		isDigit(s[14]) && isDigit(s[15]) && s[16] == ':' &&
		isDigit(s[17]) && isDigit(s[18])
}

func isFreshDiagStructuredRecordLine(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed == "" {
		return false
	}
	switch trimmed[0] {
	case '{':
		return true
	case '[':
		if strings.HasPrefix(trimmed, "[REDACTED") {
			return false
		}
		if strings.HasPrefix(trimmed, "[overlong diagnostic line omitted]") || strings.HasPrefix(trimmed, "[diagnostics truncated]") {
			return true
		}
		if len(trimmed) == 1 {
			return false
		}
		return hasISO8601TimestampPrefix(trimmed[1:]) ||
			trimmed[1] == '{' || trimmed[1] == '[' || trimmed[1] == ']' || trimmed[1] == '"' ||
			(trimmed[1] >= '0' && trimmed[1] <= '9')
	}
	if hasISO8601TimestampPrefix(trimmed) {
		return true
	}
	for _, zapLevel := range []string{"DEBUG\t", "INFO\t", "WARN\t", "ERROR\t", "DPANIC\t", "PANIC\t", "FATAL\t"} {
		if strings.HasPrefix(trimmed, zapLevel) {
			return true
		}
	}
	return false
}

func collectQuotedDiagSpansWithOpenState(raw string, prefixRe *regexp.Regexp, escapedJSON, unclosedFallback bool) ([]diagSpan, int) {
	var spans []diagSpan
	trailingOpenStart := -1
	for cursor := 0; cursor < len(raw); {
		m := prefixRe.FindStringSubmatchIndex(raw[cursor:])
		if m == nil {
			break
		}
		valStart := cursor + m[1]
		line1NL := strings.IndexByte(raw[valStart:], '\n')
		line1End := len(raw)
		if line1NL >= 0 {
			line1End = valStart + line1NL
		}
		seg1 := strings.TrimSuffix(raw[valStart:line1End], "\r")

		closedOnLine := false
		stoppedAtBareQuote := false
		if escapedJSON {
			if endRel := findClosingJSONEscapedQuote(seg1); endRel >= 0 {
				if endRel > 0 {
					spans = append(spans, diagSpan{start: valStart, end: valStart + endRel, kind: diagSpanCred, repl: "[REDACTED]"})
				}
				cursor = valStart + endRel + 2
				closedOnLine = true
			} else if bareRel := scanUnescapedQuoteOrEOL(seg1); bareRel < len(seg1) {
				stoppedAtBareQuote = true
				if unclosedFallback {
					if bareRel > 0 {
						spans = append(spans, diagSpan{start: valStart, end: valStart + bareRel, kind: diagSpanCred, repl: "[REDACTED]"})
					}
					cursor = max(valStart+1, valStart+bareRel)
				} else {
					cursor = valStart
				}
			}
		} else {
			if endRel := findClosingDoubleQuoteOnLine(seg1); endRel >= 0 {
				if endRel > 0 {
					spans = append(spans, diagSpan{start: valStart, end: valStart + endRel, kind: diagSpanCred, repl: "[REDACTED]"})
				}
				cursor = valStart + endRel + 1
				closedOnLine = true
			}
		}
		if closedOnLine || stoppedAtBareQuote {
			continue
		}

		// Line 1 reached EOL without closing; bridge continuation lines unless a fresh structured record begins.
		lastSegEnd := valStart + len(seg1)
		if line1NL < 0 {
			if unclosedFallback {
				if lastSegEnd > valStart {
					spans = append(spans, diagSpan{start: valStart, end: lastSegEnd, kind: diagSpanCred, repl: "[REDACTED]"})
				}
				trailingOpenStart = valStart
				cursor = max(valStart+1, lastSegEnd)
			} else {
				cursor = valStart
			}
			continue
		}

		resolved := false
		nextCursor := valStart
		for pos := line1End + 1; pos < len(raw); {
			nextNL := strings.IndexByte(raw[pos:], '\n')
			nextLineEnd := len(raw)
			if nextNL >= 0 {
				nextLineEnd = pos + nextNL
			}
			nextLine := strings.TrimSuffix(raw[pos:nextLineEnd], "\r")
			if isFreshDiagStructuredRecordLine(nextLine) {
				if unclosedFallback {
					if lastSegEnd > valStart {
						spans = append(spans, diagSpan{start: valStart, end: lastSegEnd, kind: diagSpanCred, repl: "[REDACTED]"})
					}
					nextCursor = max(valStart+1, pos)
				} else {
					nextCursor = max(valStart+1, pos)
				}
				resolved = true
				break
			}
			if escapedJSON {
				if endRel := findClosingJSONEscapedQuote(nextLine); endRel >= 0 {
					if pos+endRel > valStart {
						spans = append(spans, diagSpan{start: valStart, end: pos + endRel, kind: diagSpanCred, repl: "[REDACTED]"})
					}
					nextCursor = pos + endRel + 2
					resolved = true
					break
				}
				if bareRel := scanUnescapedQuoteOrEOL(nextLine); bareRel < len(nextLine) {
					if unclosedFallback {
						if pos+bareRel > valStart {
							spans = append(spans, diagSpan{start: valStart, end: pos + bareRel, kind: diagSpanCred, repl: "[REDACTED]"})
						}
						nextCursor = max(valStart+1, pos+bareRel)
					} else {
						nextCursor = pos + bareRel
					}
					resolved = true
					break
				}
			} else if endRel := findClosingDoubleQuoteOnLine(nextLine); endRel >= 0 {
				if pos+endRel > valStart {
					spans = append(spans, diagSpan{start: valStart, end: pos + endRel, kind: diagSpanCred, repl: "[REDACTED]"})
				}
				nextCursor = pos + endRel + 1
				resolved = true
				break
			}
			lastSegEnd = pos + len(nextLine)
			if nextNL < 0 {
				break
			}
			pos = nextLineEnd + 1
		}
		if resolved {
			cursor = nextCursor
			continue
		}
		if unclosedFallback {
			if lastSegEnd > valStart {
				spans = append(spans, diagSpan{start: valStart, end: lastSegEnd, kind: diagSpanCred, repl: "[REDACTED]"})
			}
			cursor = max(valStart+1, lastSegEnd)
			continue
		}
		cursor = valStart
	}
	return spans, trailingOpenStart
}

func collectStructuralCredentialSpans(raw string, includePEMRegex bool) []diagSpan {
	spans, _ := collectStructuralCredentialSpansWithOpenState(raw, includePEMRegex)
	return spans
}

func collectStructuralCredentialSpansWithOpenState(raw string, includePEMRegex bool) ([]diagSpan, diagOpenQuoteKind) {
	if raw == "" {
		return nil, diagOpenQuoteNone
	}
	var spans []diagSpan
	addCred := func(start, end int) {
		if end > start {
			spans = append(spans, diagSpan{
				start: start,
				end:   end,
				kind:  diagSpanCred,
				repl:  "[REDACTED]",
			})
		}
	}
	if includePEMRegex {
		for _, loc := range reDiagPEMBlock.FindAllStringIndex(raw, -1) {
			addCred(loc[0], loc[1])
		}
		for _, loc := range reDiagPEMPrefix.FindAllStringIndex(raw, -1) {
			addCred(loc[0], loc[1])
		}
	}
	spans = append(spans, collectBearerTokenSpans(raw)...)

	bestOpenStart := -1
	trailingQuote := diagOpenQuoteNone
	appendQuoted := func(prefixRe *regexp.Regexp, escapedJSON, unclosedFallback bool) {
		qSpans, openStart := collectQuotedDiagSpansWithOpenState(raw, prefixRe, escapedJSON, unclosedFallback)
		spans = append(spans, qSpans...)
		if openStart >= 0 && (bestOpenStart < 0 || openStart < bestOpenStart) {
			bestOpenStart = openStart
			if escapedJSON {
				trailingQuote = diagOpenQuoteEscaped
			} else {
				trailingQuote = diagOpenQuotePlain
			}
		}
	}
	appendQuoted(reDiagJSONSecretEscapedPrefix, true, true)
	appendQuoted(reDiagJSONSecretPlainPrefix, false, true)
	appendQuoted(reDiagUnsupportedTypeEscapedPrefix, true, true)
	appendQuoted(reDiagUnsupportedTypePlainPrefix, false, false)
	appendQuoted(reDiagCredFileQuotedEscapedPrefix, true, true)
	appendQuoted(reDiagCredFileQuotedPlainPrefix, false, false)

	offset := 0
	for {
		nl := strings.IndexByte(raw[offset:], '\n')
		if nl < 0 {
			spans = append(spans, collectCollectorPathErrorSpansInLine(raw[offset:], offset)...)
			break
		}
		spans = append(spans, collectCollectorPathErrorSpansInLine(raw[offset:offset+nl], offset)...)
		offset += nl + 1
	}
	return spans, trailingQuote
}

func collectCollectorCredentialSpans(raw string, secrets []string, includePEMRegex bool) []diagSpan {
	spans, _ := collectCollectorCredentialSpansWithOpenState(raw, secrets, includePEMRegex)
	return spans
}

func collectCollectorCredentialSpansWithOpenState(raw string, secrets []string, includePEMRegex bool) ([]diagSpan, diagOpenQuoteKind) {
	if raw == "" {
		return nil, diagOpenQuoteNone
	}
	spans := collectLiteralSecretSpans(raw, secrets)
	structSpans, trailingQuote := collectStructuralCredentialSpansWithOpenState(raw, includePEMRegex)
	spans = append(spans, structSpans...)
	return spans, trailingQuote
}

func applyDiagRedactionSpans(raw string, spans []diagSpan) string {
	if len(spans) == 0 {
		return raw
	}
	slices.SortFunc(spans, func(a, b diagSpan) int {
		if a.start != b.start {
			return cmp.Compare(a.start, b.start)
		}
		if a.end != b.end {
			return cmp.Compare(b.end, a.end)
		}
		return cmp.Compare(b.kind, a.kind)
	})
	merged := make([]diagSpan, 0, len(spans))
	cur := spans[0]
	for _, next := range spans[1:] {
		if next.start < cur.end {
			if next.end > cur.end {
				cur.end = next.end
			}
			if next.kind > cur.kind {
				cur.kind = next.kind
				cur.repl = next.repl
			}
			continue
		}
		merged = append(merged, cur)
		cur = next
	}
	merged = append(merged, cur)

	var b strings.Builder
	b.Grow(len(raw))
	pos := 0
	for _, sp := range merged {
		if sp.start > pos {
			b.WriteString(raw[pos:sp.start])
		}
		b.WriteString(sp.repl)
		pos = sp.end
	}
	if pos < len(raw) {
		b.WriteString(raw[pos:])
	}
	return b.String()
}

func sanitizeCollectorDiagnosticsWithExporterID(raw string, secrets, redactedExporterForms []string) string {
	spans := collectCollectorCredentialSpans(raw, secrets, true)
	spans = append(spans, collectExporterIDSpans(raw, redactedExporterForms)...)
	return applyDiagRedactionSpans(raw, spans)
}

type collectorPreparedBatch struct {
	tracesReq   ptraceotlp.ExportRequest
	logsReq     plogotlp.ExportRequest
	metricsReq  pmetricotlp.ExportRequest
	sourceBytes int64
	otlpBytes   int64
	recordCount int64
}

func reserveLoopbackAddr(ctx context.Context) (net.Listener, string, error) {
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("reserving loopback TCP port: %w", err)
	}
	return lis, lis.Addr().String(), nil
}

func ensureInlineYAMLSubmap(parent map[string]any, key, pathDesc string) (map[string]any, error) {
	raw, exists := parent[key]
	if !exists || raw == nil {
		created := make(map[string]any)
		parent[key] = created
		return created, nil
	}
	if existing, ok := raw.(map[string]any); ok {
		if existing == nil {
			created := make(map[string]any)
			parent[key] = created
			return created, nil
		}
		return existing, nil
	}
	return nil, fmt.Errorf("collector config %s must be an inline YAML map rather than a non-map or external reference (got %T)", pathDesc, raw)
}

func optionalInlineYAMLSubmap(parent map[string]any, key, pathDesc string) (map[string]any, error) {
	raw, exists := parent[key]
	if !exists || raw == nil {
		return nil, nil
	}
	existing, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("collector config %s must be an inline YAML map rather than a non-map or external reference (got %T)", pathDesc, raw)
	}
	return existing, nil
}

func parseYAMLNonNegativeInt(raw any) (int, error) {
	switch v := raw.(type) {
	case int:
		if v < 0 {
			return 0, fmt.Errorf("must be >= 0, got %d", v)
		}
		return v, nil
	case int64:
		if v < 0 || v > int64(math.MaxInt) {
			return 0, fmt.Errorf("must be in [0, %d], got %d", math.MaxInt, v)
		}
		return int(v), nil
	case uint64:
		if v > uint64(math.MaxInt) {
			return 0, fmt.Errorf("exceeds max int: %d", v)
		}
		return int(v), nil
	default:
		return 0, fmt.Errorf("expected integer, got %T", raw)
	}
}

func isValidEnvVarName(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		c := name[i]
		isAlpha := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'
		isDigit := c >= '0' && c <= '9'
		if i == 0 && !isAlpha {
			return false
		}
		if !isAlpha && !isDigit {
			return false
		}
	}
	return true
}

func collectorEnvLookup(maxProcs int) func(string) (string, bool) {
	return func(key string) (string, bool) {
		if maxProcs > 0 && (key == "GOMAXPROCS" || (runtime.GOOS == "windows" && strings.EqualFold(key, "GOMAXPROCS"))) {
			return strconv.Itoa(maxProcs), true
		}
		return os.LookupEnv(key)
	}
}

// hasUnescapedConfmapInterpolation reports whether s contains an unescaped
// confmap "${..." opening delimiter (an odd number of consecutive '$' before '{').
func hasUnescapedConfmapInterpolation(s string) bool {
	dollarRun := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '$':
			dollarRun++
		case '{':
			if dollarRun%2 == 1 {
				return true
			}
			dollarRun = 0
		default:
			dollarRun = 0
		}
	}
	return false
}

func resolveCollectorEnvStringWithLookup(raw string, lookupEnv func(string) (string, bool)) (string, error) {
	return resolveCollectorEnvStringWithOptions(raw, lookupEnv, false)
}

func resolveCollectorEnvStringWithOptions(raw string, lookupEnv func(string) (string, bool), redactValues bool) (string, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	return expandCollectorEnvSegment(raw, lookupEnv, redactValues, 0, nil)
}

func findMatchingConfmapCloseBrace(s string, contentStart int) int {
	depth := 1
	for i := contentStart; i < len(s); i++ {
		if s[i] == '$' && i+1 < len(s) {
			if s[i+1] == '$' {
				i++
				continue
			}
			if s[i+1] == '{' {
				depth++
				i++
				continue
			}
		}
		if s[i] == '}' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func expandCollectorEnvSegment(
	raw string,
	lookupEnv func(string) (string, bool),
	redactValues bool,
	depth int,
	activeVars []string,
) (string, error) {
	if depth > maxCollectorEnvExpansionDepth {
		if redactValues {
			return "", errors.New("too many recursive expansions")
		}
		return "", fmt.Errorf("too many recursive expansions in %q", raw)
	}
	if !strings.Contains(raw, "$") {
		return raw, nil
	}
	var out strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] != '$' {
			out.WriteByte(raw[i])
			i++
			continue
		}
		if i+1 < len(raw) && raw[i+1] == '$' {
			out.WriteByte('$')
			i += 2
			continue
		}
		if i+1 >= len(raw) || raw[i+1] != '{' {
			out.WriteByte('$')
			i++
			continue
		}
		closeIdx := findMatchingConfmapCloseBrace(raw, i+2)
		if closeIdx < 0 {
			if redactValues {
				return "", errors.New("unclosed ${...} reference")
			}
			return "", fmt.Errorf("unclosed ${...} reference in %q", raw)
		}
		expr := raw[i+2 : closeIdx]
		token := "${" + expr + "}"
		varName, defaultVal, hasDefault, parseErr := parseCollectorEnvExpr(expr, token, raw, redactValues)
		if parseErr != nil {
			return "", parseErr
		}
		if slices.Contains(activeVars, varName) {
			if redactValues {
				return "", errors.New("too many recursive expansions")
			}
			return "", fmt.Errorf("too many recursive expansions in %q (cycle at %q)", token, varName)
		}
		val, ok := lookupEnv(varName)
		if hasDefault && ok && strings.Contains(defaultVal, "${") {
			if _, err := expandCollectorEnvSegment(defaultVal, lookupEnv, redactValues, depth+1, activeVars); err != nil {
				return "", err
			}
		}
		if hasDefault && !ok {
			expandedDefault, err := expandCollectorEnvSegment(defaultVal, lookupEnv, redactValues, depth+1, activeVars)
			if err != nil {
				return "", err
			}
			out.WriteString(expandedDefault)
		} else if ok {
			nextActive := make([]string, len(activeVars)+1)
			copy(nextActive, activeVars)
			nextActive[len(activeVars)] = varName
			expandedVal, err := expandCollectorEnvSegment(val, lookupEnv, redactValues, depth+1, nextActive)
			if err != nil {
				return "", err
			}
			out.WriteString(expandedVal)
		}
		i = closeIdx + 1
	}
	return out.String(), nil
}

func parseCollectorEnvExpr(expr, token, raw string, redactValues bool) (varName, defaultVal string, hasDefault bool, err error) {
	if expr == "" {
		if redactValues {
			return "", "", false, errors.New("empty ${} reference")
		}
		return "", "", false, fmt.Errorf("empty ${} reference in %q", raw)
	}
	beforeDefault, defaultVal, hasDefault := strings.Cut(expr, ":-")
	if strings.Contains(beforeDefault, "${") {
		if redactValues {
			return "", "", false, errors.New("nested ${ reference is not supported")
		}
		return "", "", false, fmt.Errorf("nested ${ reference in %q is not supported", raw)
	}
	var hasEnvScheme bool
	if colonIdx := strings.IndexByte(beforeDefault, ':'); colonIdx >= 0 {
		scheme := beforeDefault[:colonIdx]
		rest := beforeDefault[colonIdx+1:]
		if scheme == "" {
			if redactValues {
				return "", "", false, errors.New("empty provider scheme in ${...} reference")
			}
			return "", "", false, fmt.Errorf("empty provider scheme in %q", token)
		}
		if scheme != "env" {
			if redactValues {
				return "", "", false, errors.New("unsupported collector config provider in ${...} reference (only env is supported)")
			}
			return "", "", false, fmt.Errorf("unsupported collector config provider %q in %q (only env is supported)", scheme, token)
		}
		hasEnvScheme = true
		varName = rest
	} else {
		varName = beforeDefault
	}
	if hasDefault && !hasEnvScheme {
		if redactValues {
			return "", "", false, errors.New("default syntax :- requires explicit env: scheme")
		}
		return "", "", false, fmt.Errorf("default syntax :- requires explicit env: scheme in %q", token)
	}
	if varName == "" {
		if redactValues {
			return "", "", false, errors.New("empty environment variable name")
		}
		return "", "", false, fmt.Errorf("empty environment variable name in %q", token)
	}
	if strings.ContainsRune(varName, ':') {
		if redactValues {
			return "", "", false, errors.New("invalid ':' in environment variable name")
		}
		return "", "", false, fmt.Errorf("invalid ':' in environment variable name %q in %q", varName, token)
	}
	if !isValidEnvVarName(varName) {
		if redactValues {
			return "", "", false, errors.New("invalid environment variable name")
		}
		return "", "", false, fmt.Errorf("invalid environment variable name %q in %q", varName, token)
	}
	return varName, defaultVal, hasDefault, nil
}

func escapeCollectorConfmapDollars(s string) string {
	if !strings.ContainsRune(s, '$') {
		return s
	}
	return strings.ReplaceAll(s, "$", "$$")
}

func validateRedactedValuePatternCombination(patterns []string, exporterPath string) error {
	if len(patterns) == 0 {
		return nil
	}
	parts := make([]string, 0, len(patterns))
	for _, p := range patterns {
		parts = append(parts, "(?:"+p+")")
	}
	if _, err := regexp.Compile(strings.Join(parts, "|")); err != nil {
		return fmt.Errorf("%s.redaction.blocked_value_patterns: patterns cannot be combined into a valid regular expression", exporterPath)
	}
	return nil
}

func describeYAMLValueKind(raw any) string {
	switch raw.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case int, int64, uint64, float64:
		return "number"
	case []any, []string:
		return "sequence"
	case map[string]any, map[any]any:
		return "map"
	default:
		return fmt.Sprintf("%T", raw)
	}
}

const (
	collectorInlineConfmapScheme = "tbinline"
	collectorEnvConfmapScheme    = "env"
)

type redactedConfmapError struct {
	msg string
}

func (e redactedConfmapError) Error() string {
	return e.msg
}

type inlineConfmapProvider struct {
	scheme string
	uri    string
	data   map[string]any
	used   bool
}

func (p *inlineConfmapProvider) Retrieve(_ context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if p.used || uri != p.uri {
		return nil, redactedConfmapError{msg: "unexpected inline configuration retrieval"}
	}
	p.used = true
	return confmap.NewRetrieved(p.data)
}

func (p *inlineConfmapProvider) Scheme() string {
	return p.scheme
}

func (*inlineConfmapProvider) Shutdown(context.Context) error {
	return nil
}

type lookupEnvConfmapProvider struct {
	lookupEnv func(string) (string, bool)
}

func (*lookupEnvConfmapProvider) Scheme() string {
	return collectorEnvConfmapScheme
}

func (*lookupEnvConfmapProvider) Shutdown(context.Context) error {
	return nil
}

func isBlankOrYAMLCommentLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}

func isYAMLDocStartLine(line string) bool {
	return line == "---" || strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "---\t")
}

func isYAMLDocEndLine(line string) bool {
	if line == "..." {
		return true
	}
	if !strings.HasPrefix(line, "...") {
		return false
	}
	rest := line[3:]
	if rest[0] != ' ' && rest[0] != '\t' {
		return false
	}
	return isBlankOrYAMLCommentLine(rest)
}

func isYAMLDirectiveLine(line string) bool {
	return strings.HasPrefix(line, "%YAML ") ||
		strings.HasPrefix(line, "%YAML\t") ||
		strings.HasPrefix(line, "%TAG ") ||
		strings.HasPrefix(line, "%TAG\t")
}

type yamlLineWithOffset struct {
	startByte int
	text      string
}

func splitYAMLLinesWithOffsets(val string) []yamlLineWithOffset {
	var lines []yamlLineWithOffset
	lineStart := 0
	var cur strings.Builder
	for i := 0; i < len(val); {
		b := val[i]
		if b == '\r' {
			lines = append(lines, yamlLineWithOffset{startByte: lineStart, text: cur.String()})
			cur.Reset()
			i++
			if i < len(val) && val[i] == '\n' {
				i++
			}
			lineStart = i
			continue
		}
		if b == '\n' {
			lines = append(lines, yamlLineWithOffset{startByte: lineStart, text: cur.String()})
			cur.Reset()
			i++
			lineStart = i
			continue
		}
		// Unicode line breaks accepted by YAML 1.2: NEL (U+0085), LS (U+2028), PS (U+2029).
		if strings.HasPrefix(val[i:], "\u0085") {
			lines = append(lines, yamlLineWithOffset{startByte: lineStart, text: cur.String()})
			cur.Reset()
			i += len("\u0085")
			lineStart = i
			continue
		}
		if strings.HasPrefix(val[i:], "\u2028") || strings.HasPrefix(val[i:], "\u2029") {
			lines = append(lines, yamlLineWithOffset{startByte: lineStart, text: cur.String()})
			cur.Reset()
			i += len("\u2028")
			lineStart = i
			continue
		}
		cur.WriteByte(b)
		i++
	}
	lines = append(lines, yamlLineWithOffset{startByte: lineStart, text: cur.String()})
	return lines
}

func inspectEnvYAMLDocMarkersWithEndOffset(val string) (multiDoc bool, validDocEndTriviaOnly bool, docEndStartByte int, seenContentBeforeEnd bool) {
	lines := splitYAMLLinesWithOffsets(val)

	docStartCount := 0
	seenContent := false
	sawDocEnd := false
	docEndStartByte = -1
	for i, entry := range lines {
		line := entry.text
		// Strip optional UTF-8 BOM only at stream start or directly before a
		// YAML document boundary marker ("---" or "...").
		if i == 0 {
			line = strings.TrimPrefix(line, "\uFEFF")
		} else if trimmed, hasBOM := strings.CutPrefix(line, "\uFEFF"); hasBOM && (isYAMLDocStartLine(trimmed) || isYAMLDocEndLine(trimmed)) {
			line = trimmed
		}
		if sawDocEnd {
			// After explicit document end ("..."), allow leading horizontal
			// whitespace and repeated UTF-8 BOMs before a trailing comment or blank line.
			trimmed := strings.TrimLeft(line, " \t\uFEFF")
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				return true, false, -1, seenContent
			}
			continue
		}
		if isYAMLDocStartLine(line) {
			docStartCount++
			if docStartCount > 1 || seenContent {
				return true, false, -1, seenContent
			}
			if !isBlankOrYAMLCommentLine(strings.TrimPrefix(line, "---")) {
				seenContent = true
			}
			continue
		}
		if isYAMLDocEndLine(line) {
			sawDocEnd = true
			docEndStartByte = entry.startByte
			seenContentBeforeEnd = seenContent
			continue
		}
		if isBlankOrYAMLCommentLine(line) {
			continue
		}
		if docStartCount == 0 && !seenContent && isYAMLDirectiveLine(line) {
			continue
		}
		seenContent = true
	}
	return false, sawDocEnd, docEndStartByte, seenContentBeforeEnd
}

func inspectEnvYAMLDocMarkers(val string) (multiDoc bool, validDocEndTriviaOnly bool) {
	multiDoc, validDocEndTriviaOnly, _, _ = inspectEnvYAMLDocMarkersWithEndOffset(val)
	return multiDoc, validDocEndTriviaOnly
}

func hasMultiDocumentYAMLMarkers(val string) bool {
	multiDoc, _ := inspectEnvYAMLDocMarkers(val)
	return multiDoc
}

func validateSingleDocEnvYAML(val string) error {
	dec := yaml.NewDecoder(strings.NewReader(val))
	var firstDoc any
	err1 := dec.Decode(&firstDoc)
	if err1 == nil {
		var extraDoc any
		if err2 := dec.Decode(&extraDoc); !errors.Is(err2, io.EOF) {
			if err2 == nil {
				return redactedConfmapError{msg: "multi-document YAML in environment variable is not allowed"}
			}
			// Waive trailing decode errors only when a standalone explicit "..."
			// document-end marker actually closed the valid first document and is
			// followed exclusively by whitespace, BOMs, or YAML comments.
			multiDoc, validDocEndTriviaOnly, docEndStartByte, seenContentBeforeEnd := inspectEnvYAMLDocMarkersWithEndOffset(val)
			if multiDoc || !validDocEndTriviaOnly || docEndStartByte < 0 {
				return redactedConfmapError{msg: "multi-document YAML in environment variable is not allowed"}
			}
			decBefore := yaml.NewDecoder(strings.NewReader(val[:docEndStartByte]))
			var preDoc any
			preErr1 := decBefore.Decode(&preDoc)
			if errors.Is(preErr1, io.EOF) && !seenContentBeforeEnd {
				return nil
			}
			if preErr1 != nil {
				return redactedConfmapError{msg: "multi-document YAML in environment variable is not allowed"}
			}
			var preExtra any
			if preErr2 := decBefore.Decode(&preExtra); !errors.Is(preErr2, io.EOF) {
				return redactedConfmapError{msg: "multi-document YAML in environment variable is not allowed"}
			}
		}
		return nil
	}
	if !errors.Is(err1, io.EOF) && hasMultiDocumentYAMLMarkers(val) {
		return redactedConfmapError{msg: "multi-document YAML in environment variable is not allowed"}
	}
	return nil
}

func (p *lookupEnvConfmapProvider) Retrieve(_ context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if !strings.HasPrefix(uri, collectorEnvConfmapScheme+":") {
		return nil, redactedConfmapError{msg: "unsupported collector config provider (only env is supported)"}
	}
	envVarName, defaultVal, hasDefault := strings.Cut(uri[len(collectorEnvConfmapScheme)+1:], ":-")
	if envVarName == "" {
		return nil, redactedConfmapError{msg: "empty environment variable name"}
	}
	if !isValidEnvVarName(envVarName) {
		return nil, redactedConfmapError{msg: "invalid environment variable name"}
	}
	val, exists := p.lookupEnv(envVarName)
	if !exists {
		if !hasDefault {
			return confmap.NewRetrievedFromYAML(nil)
		}
		if defaultVal == "" {
			return confmap.NewRetrieved("")
		}
		val = defaultVal
	}
	if err := validateSingleDocEnvYAML(val); err != nil {
		return nil, err
	}
	var envDoc any
	dec := yaml.NewDecoder(strings.NewReader(val))
	if decErr := dec.Decode(&envDoc); decErr == nil {
		if err := rejectCollidingYAMLMapKeys(envDoc, "environment variable YAML", false); err != nil {
			return nil, redactedConfmapError{msg: "ambiguous duplicate map keys in environment variable YAML"}
		}
	}
	ret, err := confmap.NewRetrievedFromYAML([]byte(val))
	if err != nil {
		return nil, redactedConfmapError{msg: "invalid environment variable YAML value"}
	}
	return ret, nil
}

const yamlDiagAnchoredPrefix = `^(?:yaml:[ \t]*)?(?:line[ \t]+(\d+):[ \t]*)?`

var (
	confmapDecodePatternIndexPattern    = regexp.MustCompile(`blocked_value_patterns\[(\d+)\]`)
	confmapURISchemeOpaquePattern       = regexp.MustCompile(`(?s:^([A-Za-z][A-Za-z0-9+.-]+):(.*)$)`)
	yamlErrorLinePrefixPattern          = regexp.MustCompile(`^(?:yaml:[ \t]*)?line[ \t]+(\d+):`)
	yamlInvalidMapKeyDiagPattern        = regexp.MustCompile(`(?s)` + yamlDiagAnchoredPrefix + `invalid map key:.*$`)
	yamlDuplicateMappingKeyDiagPattern  = regexp.MustCompile(`(?s)` + yamlDiagAnchoredPrefix + `mapping key "(?:[^"\\]|\\.)*" already defined at line[ \t]+(\d+)\s*$`)
	yamlBinaryInvalidBase64DiagPattern  = regexp.MustCompile(`(?s)` + yamlDiagAnchoredPrefix + `!!binary value contains invalid base64 data\s*$`)
	yamlMappingKeyAlreadyDefinedPattern = regexp.MustCompile(`(?s)` + yamlDiagAnchoredPrefix + `mapping key\b.*(?i:already defined)`)
	yamlCannotDecodeDiagPattern         = regexp.MustCompile(`(?s)` + yamlDiagAnchoredPrefix + `cannot decode\b`)
	yamlCannotUnmarshalDiagPattern      = regexp.MustCompile(`(?s)` + yamlDiagAnchoredPrefix + `cannot unmarshal\b`)
	yamlUnknownAnchorDiagPattern        = regexp.MustCompile(`(?s)` + yamlDiagAnchoredPrefix + `unknown anchor\b`)
	yamlAnchorCycleDiagPattern          = regexp.MustCompile(`(?s)` + yamlDiagAnchoredPrefix + `anchor\b.*\bcontains itself\b`)
)

// sanitizeCollectorYAMLDiagnostic sanitizes a single YAML parser diagnostic as a
// whole (without splitting on newlines) and rebuilds it strictly from fixed
// value-free reason strings plus validated line numbers, failing closed on any
// unrecognized diagnostic.
func sanitizeCollectorYAMLDiagnostic(diag string) string {
	linePrefix := ""
	if m := yamlErrorLinePrefixPattern.FindStringSubmatch(diag); len(m) == 2 {
		linePrefix = "line " + m[1] + ":"
	}
	withLinePrefix := func(reason string) string {
		if linePrefix != "" {
			return linePrefix + " " + reason
		}
		return reason
	}

	if yamlInvalidMapKeyDiagPattern.MatchString(diag) {
		return withLinePrefix("invalid mapping key")
	}
	if m := yamlDuplicateMappingKeyDiagPattern.FindStringSubmatch(diag); len(m) == 3 {
		reason := "mapping key already defined at line " + m[2]
		if m[1] != "" {
			return "line " + m[1] + ": " + reason
		}
		return reason
	}
	if yamlBinaryInvalidBase64DiagPattern.MatchString(diag) {
		return withLinePrefix("!!binary value contains invalid base64 data")
	}
	if yamlCannotDecodeDiagPattern.MatchString(diag) {
		return withLinePrefix("invalid YAML scalar value")
	}
	if yamlCannotUnmarshalDiagPattern.MatchString(diag) {
		return withLinePrefix("invalid YAML structure")
	}
	if yamlUnknownAnchorDiagPattern.MatchString(diag) {
		return withLinePrefix("unknown YAML anchor")
	}
	if yamlAnchorCycleDiagPattern.MatchString(diag) {
		return withLinePrefix("invalid YAML anchor reference")
	}
	if yamlMappingKeyAlreadyDefinedPattern.MatchString(diag) {
		return withLinePrefix("mapping key already defined")
	}
	return withLinePrefix("invalid YAML syntax")
}

func sanitizeCollectorYAMLParseError(err error) error {
	if err == nil {
		return nil
	}
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		sanitized := make([]string, len(typeErr.Errors))
		for i, diag := range typeErr.Errors {
			sanitized[i] = sanitizeCollectorYAMLDiagnostic(diag)
		}
		return &yaml.TypeError{Errors: sanitized}
	}
	return errors.New(sanitizeCollectorYAMLDiagnostic(err.Error()))
}

func sanitizeCollectorConfmapError(err error) error {
	if err == nil {
		return nil
	}
	var redErr redactedConfmapError
	if errors.As(err, &redErr) {
		return errors.New(redErr.msg)
	}
	msg := err.Error()
	if strings.Contains(msg, "too many recursive expansions") {
		return errors.New("too many recursive expansions")
	}
	if strings.Contains(msg, "is not supported") || strings.Contains(msg, "unsupported scheme on URI") {
		return errors.New("unsupported collector config provider (only env is supported)")
	}
	if strings.Contains(msg, "contains unsupported characters ('$')") {
		return errors.New("collector config reference contains unsupported '$' character")
	}
	if strings.Contains(msg, "does not have unambiguous string representation") {
		return errors.New("embedded collector config reference must resolve to a string")
	}
	if strings.Contains(msg, "cannot be used as a Conf") || strings.Contains(msg, "unsupported type=") {
		return errors.New("resolved collector config value has an unsupported type")
	}
	return errors.New("invalid collector config reference")
}

// preEscapeExpandedValue mirrors confmap's internal.ExpandedValue in
// go.opentelemetry.io/collector/confmap@v1.71.0 before Resolver.Resolve invokes
// escapeDollarSigns (resolver.go), preserving YAML-decoded scalar escapes (such
// as \u0024\u0024 -> $$) and cross-substitution $$ pairs so unclosed, unescaped
// ${ references can be detected without false positives on $$ escapes.
type preEscapeExpandedValue struct {
	value    any
	original string
}

// preEscapeConfmapExpander mirrors the scalar/container expansion passes of
// go.opentelemetry.io/collector/confmap@v1.71.0 (expand.go: expandValueRecursively,
// expandValue, findURI, findAndExpandURI, expandURI) up to the point right before
// resolver.go's escapeDollarSigns rewrites "$$" to "$".
type preEscapeConfmapExpander struct {
	ctx      context.Context
	provider *lookupEnvConfmapProvider
	closers  []confmap.CloseFunc
}

func (e *preEscapeConfmapExpander) closeAll() {
	for _, fn := range e.closers {
		if fn != nil {
			_ = fn(e.ctx)
		}
	}
	e.closers = nil
}

func (e *preEscapeConfmapExpander) findURI(input string) string {
	closeIndex := strings.Index(input, "}")
	if closeIndex < 0 {
		return ""
	}
	remaining := input[closeIndex+1:]
	openIndex := strings.LastIndex(input[:closeIndex+1], "${")
	if openIndex < 0 {
		if !strings.Contains(remaining, "}") {
			return ""
		}
		return e.findURI(remaining)
	}

	index := openIndex - 1
	count := 0
	for index >= 0 && input[index] == '$' {
		count++
		index--
	}
	if count%2 == 1 {
		if !strings.Contains(remaining, "}") {
			return ""
		}
		return e.findURI(remaining)
	}
	return input[openIndex : closeIndex+1]
}

func (e *preEscapeConfmapExpander) expandURI(input string) (*confmap.Retrieved, error) {
	uri := input[2 : len(input)-1]
	if !strings.Contains(uri, ":") {
		uri = collectorEnvConfmapScheme + ":" + uri
	}
	m := confmapURISchemeOpaquePattern.FindStringSubmatch(uri)
	if len(m) != 3 {
		return nil, redactedConfmapError{msg: "invalid collector config reference"}
	}
	scheme, opaque := m[1], m[2]
	if strings.Contains(opaque, "$") {
		return nil, redactedConfmapError{msg: "collector config reference contains unsupported '$' character"}
	}
	if scheme != collectorEnvConfmapScheme {
		return nil, redactedConfmapError{msg: "unsupported collector config provider (only env is supported)"}
	}
	ret, err := e.provider.Retrieve(e.ctx, uri, nil)
	if err != nil {
		return nil, err
	}
	e.closers = append(e.closers, ret.Close)
	return ret, nil
}

func (e *preEscapeConfmapExpander) findAndExpandURI(input string) (any, bool, error) {
	uri := e.findURI(input)
	if uri == "" {
		return input, false, nil
	}
	if uri == input {
		ret, err := e.expandURI(input)
		if err != nil {
			return input, false, err
		}
		val, err := ret.AsRaw()
		if err != nil {
			return input, false, err
		}
		if asStr, err2 := ret.AsString(); err2 == nil {
			return preEscapeExpandedValue{
				value:    val,
				original: asStr,
			}, true, nil
		}
		return val, true, nil
	}
	expanded, err := e.expandURI(uri)
	if err != nil {
		return input, false, err
	}
	repl, err := expanded.AsString()
	if err != nil {
		return input, false, redactedConfmapError{msg: "embedded collector config reference must resolve to a string"}
	}
	return strings.ReplaceAll(input, uri, repl), true, nil
}

func (e *preEscapeConfmapExpander) expandValue(value any) (any, bool, error) {
	switch v := value.(type) {
	case preEscapeExpandedValue:
		expanded, changed, err := e.expandValue(v.value)
		if err != nil {
			return nil, false, err
		}
		switch exp := expanded.(type) {
		case preEscapeExpandedValue, string:
			return exp, changed, nil
		}
		originalExpanded, originalChanged, err := e.expandValue(v.original)
		if err != nil {
			return expanded, changed, nil
		}
		if origStr, ok := originalExpanded.(string); ok {
			return preEscapeExpandedValue{
				value:    expanded,
				original: origStr,
			}, changed || originalChanged, nil
		}
		return expanded, changed, nil
	case string:
		if !strings.Contains(v, "${") || !strings.Contains(v, "}") {
			return value, false, nil
		}
		return e.findAndExpandURI(v)
	case []any:
		nslice := make([]any, 0, len(v))
		nchanged := false
		for _, elem := range v {
			val, changed, err := e.expandValue(elem)
			if err != nil {
				return nil, false, err
			}
			nslice = append(nslice, val)
			nchanged = nchanged || changed
		}
		return nslice, nchanged, nil
	case map[string]any:
		nmap := make(map[string]any, len(v))
		nchanged := false
		for _, mk := range slices.Sorted(maps.Keys(v)) {
			val, changed, err := e.expandValue(v[mk])
			if err != nil {
				return nil, false, err
			}
			nmap[mk] = val
			nchanged = nchanged || changed
		}
		return nmap, nchanged, nil
	case map[any]any:
		items, _ := sortedAnyYAMLMapEntries(v)
		nmap := make(map[string]any, len(items))
		nchanged := false
		for _, item := range items {
			val, changed, err := e.expandValue(item.val)
			if err != nil {
				return nil, false, err
			}
			nmap[item.strKey] = val
			nchanged = nchanged || changed
		}
		return nmap, nchanged, nil
	}
	return value, false, nil
}

func (e *preEscapeConfmapExpander) expandRecursively(value any) (any, error) {
	for range 1000 {
		val, changed, err := e.expandValue(value)
		if err != nil {
			return nil, err
		}
		if !changed {
			return val, nil
		}
		value = val
	}
	return nil, errors.New("too many recursive expansions")
}

func expandBlockedPatternsPreservingEscapedDollars(inlineRoot any, lookupEnv func(string) (string, bool)) (any, error) {
	expander := &preEscapeConfmapExpander{
		ctx:      context.Background(),
		provider: &lookupEnvConfmapProvider{lookupEnv: lookupEnv},
	}
	defer expander.closeAll()
	return expander.expandRecursively(inlineRoot)
}

// hasUnclosedUnescapedConfmapInterpolation reports whether an assembled
// pre-escapeDollarSigns scalar retains an unclosed, unescaped confmap "${"
// reference. Following confmap@v1.71.0 expand.go findURI semantics, bare
// literal "{" characters (for example regex classes like "[{]") do not participate
// in "${...}" nesting, whereas escaped "$${...}" placeholders inside an open
// interpolation track their paired "}" so balanced defaults remain accepted and
// truncated defaults remain rejected.
func hasUnclosedUnescapedConfmapInterpolation(s string) bool {
	openDepth := 0
	for i := 0; i < len(s); {
		if s[i] == '$' {
			start := i
			for i < len(s) && s[i] == '$' {
				i++
			}
			if i < len(s) && s[i] == '{' {
				if (i-start)%2 == 1 || openDepth > 0 {
					openDepth++
				}
				i++
			}
			continue
		}
		if s[i] == '}' && openDepth > 0 {
			openDepth--
		}
		i++
	}
	return openDepth > 0
}

func preEscapeContainerAsValue(v any) any {
	if exp, ok := v.(preEscapeExpandedValue); ok {
		return exp.value
	}
	return v
}

func preEscapeElementAsString(v any) (string, bool) {
	switch x := v.(type) {
	case preEscapeExpandedValue:
		return x.original, true
	case string:
		return x, true
	default:
		return "", false
	}
}

func resolveInlineConfmap(
	confKey string,
	inlineRoot any,
	lookupEnv func(string) (string, bool),
) (*confmap.Conf, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	rootURI := collectorInlineConfmapScheme + ":" + confKey
	rootFactory := confmap.NewProviderFactory(func(confmap.ProviderSettings) confmap.Provider {
		return &inlineConfmapProvider{
			scheme: collectorInlineConfmapScheme,
			uri:    rootURI,
			data:   map[string]any{confKey: inlineRoot},
		}
	})
	envFactory := confmap.NewProviderFactory(func(confmap.ProviderSettings) confmap.Provider {
		return &lookupEnvConfmapProvider{lookupEnv: lookupEnv}
	})

	resolver, err := confmap.NewResolver(confmap.ResolverSettings{
		URIs:              []string{rootURI},
		ProviderFactories: []confmap.ProviderFactory{rootFactory, envFactory},
		DefaultScheme:     collectorEnvConfmapScheme,
	})
	if err != nil {
		return nil, sanitizeCollectorConfmapError(err)
	}
	ctx := context.Background()
	defer func() {
		_ = resolver.Shutdown(ctx)
	}()

	resolvedConf, err := resolver.Resolve(ctx)
	if err != nil {
		if _, preErr := expandBlockedPatternsPreservingEscapedDollars(map[string]any{confKey: inlineRoot}, lookupEnv); preErr != nil {
			return nil, sanitizeCollectorConfmapError(preErr)
		}
		return nil, sanitizeCollectorConfmapError(err)
	}
	return resolvedConf, nil
}

func unwrapConfmapValueTracked(v any, pathDesc string, preserveStrings bool, nilPaths map[string]struct{}) any {
	switch tv := v.(type) {
	case nil, string, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, time.Time, []string:
		return v
	case map[string]any:
		if tv == nil {
			return nil
		}
		out := make(map[string]any, len(tv))
		for _, k := range slices.Sorted(maps.Keys(tv)) {
			childPath := k
			if pathDesc != "" {
				childPath = pathDesc + "." + k
			}
			out[k] = unwrapConfmapValueTracked(tv[k], childPath, preserveStrings, nilPaths)
		}
		return out
	case map[any]any:
		if tv == nil {
			return nil
		}
		items, _ := sortedAnyYAMLMapEntries(tv)
		out := make(map[string]any, len(items))
		for _, item := range items {
			childPath := item.strKey
			if pathDesc != "" {
				childPath = pathDesc + "." + item.strKey
			}
			out[item.strKey] = unwrapConfmapValueTracked(item.val, childPath, preserveStrings, nilPaths)
		}
		return out
	case []any:
		if tv == nil {
			return nil
		}
		out := make([]any, len(tv))
		for i, elem := range tv {
			out[i] = unwrapConfmapValueTracked(elem, fmt.Sprintf("%s[%d]", pathDesc, i), preserveStrings, nilPaths)
		}
		return out
	default:
		// Public confmap.Conf.Get() stops unwrapping after the outer
		// internal.ExpandedValue when a whole-map env var itself contains nested
		// env expressions; decode through confmap to unwrap all nested levels
		// while preserving original strings on declared string fields.
		var rawHolder struct {
			V any `mapstructure:"v"`
		}
		if err := confmap.NewFromStringMap(map[string]any{"v": v}).Unmarshal(&rawHolder); err != nil {
			return v
		}
		if preserveStrings && preserveResolvedCollectorStringPath(pathDesc) {
			var strHolder struct {
				V string `mapstructure:"v"`
			}
			if strErr := confmap.NewFromStringMap(map[string]any{"v": v}).Unmarshal(&strHolder); strErr == nil {
				return strHolder.V
			}
		}
		res := unwrapConfmapValueTracked(rawHolder.V, pathDesc, preserveStrings, nilPaths)
		if res == nil && nilPaths != nil && pathDesc != "" {
			nilPaths[pathDesc] = struct{}{}
		}
		return res
	}
}

type collectorSQConfmapNullSizers struct {
	sizer      bool
	batchSizer bool
}

func (s collectorSQConfmapNullSizers) merge(other collectorSQConfmapNullSizers) collectorSQConfmapNullSizers {
	return collectorSQConfmapNullSizers{
		sizer:      s.sizer || other.sizer,
		batchSizer: s.batchSizer || other.batchSizer,
	}
}

func extractSQNullSizers(nilPaths map[string]struct{}, basePrefix string) collectorSQConfmapNullSizers {
	if len(nilPaths) == 0 {
		return collectorSQConfmapNullSizers{}
	}
	_, sizer := nilPaths[basePrefix+"sending_queue.sizer"]
	_, batchSizer := nilPaths[basePrefix+"sending_queue.batch.sizer"]
	return collectorSQConfmapNullSizers{
		sizer:      sizer,
		batchSizer: batchSizer,
	}
}

func rawSendingQueueBatchHasExplicitSizer(resolvedSQ any) bool {
	sqMap, ok := resolvedSQ.(map[string]any)
	if !ok || sqMap == nil {
		return false
	}
	batchMap, ok := sqMap["batch"].(map[string]any)
	if !ok || batchMap == nil {
		return false
	}
	_, exists := batchMap["sizer"]
	return exists
}

func applyConfmapNullSizersToQueue(
	qs *configoptional.Optional[exporterhelper.QueueBatchConfig],
	resolvedSQ any,
	sizers collectorSQConfmapNullSizers,
) {
	if qs == nil || (!sizers.sizer && !sizers.batchSizer) {
		return
	}
	q := qs.Get()
	if q == nil {
		return
	}
	if sizers.sizer {
		q.Sizer = exporterhelper.RequestSizerType{}
	}
	b := q.Batch.Get()
	if b == nil {
		return
	}
	if sizers.batchSizer {
		b.Sizer = exporterhelper.RequestSizerType{}
		return
	}
	if sizers.sizer && !rawSendingQueueBatchHasExplicitSizer(resolvedSQ) {
		b.Sizer = exporterhelper.RequestSizerType{}
	}
}

func interpolatedKeyTargetsStorage(k string, lookupEnv func(string) (string, bool)) bool {
	if !hasUnescapedConfmapInterpolation(k) {
		return false
	}
	resolvedConf, err := resolveInlineConfmap("key", k, lookupEnv)
	if err != nil || resolvedConf == nil {
		return true
	}
	resolvedVal := unwrapConfmapValueTracked(resolvedConf.Get("key"), "sending_queue_key", false, nil)
	if resolvedVal == nil {
		return true
	}
	return strings.TrimSpace(fmt.Sprint(resolvedVal)) == "storage"
}

func normalizeSendingQueueStorageWithConfmap(
	rawSQNode any,
	resolvedSQNode any,
	diagExporterID string,
	bodyFromEnv bool,
	lookupEnv func(string) (string, bool),
) (bool, error) {
	interpolated := bodyFromEnv
	if rawSQStr, isStr := rawSQNode.(string); isStr && hasUnescapedConfmapInterpolation(rawSQStr) {
		interpolated = true
	}
	hasInterpStorageKey := false
	rawSQMap, ok := rawSQNode.(map[string]any)
	if !ok || rawSQMap == nil {
		if rawSQAnyMap, isAny := rawSQNode.(map[any]any); isAny && rawSQAnyMap != nil {
			if normRaw, normErr := normalizeNestedMapsToStringKeys(rawSQAnyMap); normErr == nil {
				rawSQMap, _ = normRaw.(map[string]any)
			} else {
				for k := range rawSQAnyMap {
					if interpolatedKeyTargetsStorage(fmt.Sprint(k), lookupEnv) {
						hasInterpStorageKey = true
						break
					}
				}
			}
		}
	}
	if !hasInterpStorageKey && rawSQMap != nil {
		for k := range rawSQMap {
			if interpolatedKeyTargetsStorage(k, lookupEnv) {
				hasInterpStorageKey = true
				break
			}
		}
	}
	if hasInterpStorageKey {
		interpolated = true
	}
	var stVal any
	hasResolved := false
	if resolvedSQMap, isResMap := resolvedSQNode.(map[string]any); isResMap && resolvedSQMap != nil {
		if v, exists := resolvedSQMap["storage"]; exists {
			stVal = v
			hasResolved = true
		}
	}
	if rawSQMap != nil {
		rawStorage, hasStorage := rawSQMap["storage"]
		if !hasStorage && hasResolved {
			interpolated = true
		}
		if hasStorage {
			if origStID, isStr := rawStorage.(string); isStr && hasUnescapedConfmapInterpolation(origStID) {
				interpolated = true
				resolvedStorageConf, stErr := resolveInlineConfmap("storage", origStID, lookupEnv)
				if stErr != nil {
					return true, fmt.Errorf("resolving collector exporter %q sending_queue.storage: %w", diagExporterID, stErr)
				}
				if resolvedStorageConf != nil {
					stVal = unwrapConfmapValueTracked(
						resolvedStorageConf.Get("storage"),
						"exporters."+diagExporterID+".sending_queue.storage",
						false,
						nil,
					)
				} else {
					stVal = nil
				}
				normStVal, normErr := normalizeNestedMapsToStringKeys(stVal)
				if normErr != nil {
					return true, normErr
				}
				stVal = normStVal
				hasResolved = true
				if resolvedSQMap, ok := resolvedSQNode.(map[string]any); ok && resolvedSQMap != nil {
					resolvedSQMap["storage"] = stVal
				}
			} else if !hasResolved {
				stVal = rawStorage
				hasResolved = true
			}
		}
	} else if hasResolved {
		interpolated = true
	}
	if !hasResolved || stVal == nil {
		return interpolated, nil
	}
	stStr, isStr := stVal.(string)
	if !isStr {
		if interpolated {
			return true, fmt.Errorf("collector exporter %q sending_queue.storage must be a string extension ID, got %s", diagExporterID, describeYAMLValueKind(stVal))
		}
		return false, fmt.Errorf("collector exporter %q sending_queue.storage must be a string extension ID, got %T", diagExporterID, stVal)
	}
	if strings.TrimSpace(stStr) == "" {
		return interpolated, fmt.Errorf("collector exporter %q sending_queue.storage must not be empty", diagExporterID)
	}
	var stID component.ID
	if idErr := stID.UnmarshalText([]byte(stStr)); idErr != nil {
		if interpolated {
			return true, fmt.Errorf("collector exporter %q sending_queue.storage is not a valid extension ID", diagExporterID)
		}
		return false, fmt.Errorf("collector exporter %q sending_queue.storage %q is not a valid extension ID: %w", diagExporterID, stStr, idErr)
	}
	return interpolated, nil
}

func extractSanitizedConfmapExporter(resolvedConf *confmap.Conf, confKey, diagPath string) (*confmap.Conf, any, collectorSQConfmapNullSizers) {
	if resolvedConf == nil {
		return nil, nil, collectorSQConfmapNullSizers{}
	}
	rawVal := resolvedConf.Get(confKey)
	if rawVal == nil {
		return nil, nil, collectorSQConfmapNullSizers{}
	}
	nilPaths := make(map[string]struct{})
	plainVal := unwrapConfmapValueTracked(rawVal, diagPath, true, nilPaths)
	nullSizers := extractSQNullSizers(nilPaths, diagPath+".")
	subConf, subErr := resolvedConf.Sub(confKey)
	if subErr != nil {
		return nil, plainVal, nullSizers
	}
	return subConf, plainVal, nullSizers
}

func resolveCollectorScalarWithConfmap(raw string, lookupEnv func(string) (string, bool)) (string, error) {
	resolvedConf, err := resolveInlineConfmap("value", raw, lookupEnv)
	if err != nil {
		return "", err
	}
	container := resolvedConf.Get("value")
	resolvedStr, ok := container.(string)
	if !ok {
		return "", fmt.Errorf("expected string, got %s", describeYAMLValueKind(container))
	}
	if strings.Contains(resolvedStr, "${") {
		preExpanded, preErr := expandBlockedPatternsPreservingEscapedDollars(raw, lookupEnv)
		if preErr != nil {
			return "", sanitizeCollectorConfmapError(preErr)
		}
		preStr, preOK := preEscapeElementAsString(preExpanded)
		if !preOK || hasUnclosedUnescapedConfmapInterpolation(preStr) {
			return "", errors.New("unclosed ${...} reference")
		}
	}
	return resolvedStr, nil
}

func resolveCollectorStringSliceWithConfmap(raw string, lookupEnv func(string) (string, bool)) ([]string, error) {
	resolvedConf, err := resolveInlineConfmap("exporters", raw, lookupEnv)
	if err != nil {
		return nil, err
	}
	container := resolvedConf.Get("exporters")
	if container == nil {
		return nil, nil
	}
	if resolvedStr, isStr := container.(string); isStr {
		if strings.Contains(resolvedStr, "${") {
			preExpanded, preErr := expandBlockedPatternsPreservingEscapedDollars(raw, lookupEnv)
			if preErr != nil {
				return nil, sanitizeCollectorConfmapError(preErr)
			}
			preStr, preOK := preEscapeElementAsString(preExpanded)
			if !preOK || hasUnclosedUnescapedConfmapInterpolation(preStr) {
				return nil, errors.New("unclosed ${...} reference")
			}
		}
		return nil, errors.New("expected YAML sequence of strings, got string")
	}
	list, err := extractYAMLStringSlice(container)
	if err != nil {
		return nil, err
	}
	for _, elem := range list {
		if !strings.Contains(elem, "${") {
			continue
		}
		preExpanded, preErr := expandBlockedPatternsPreservingEscapedDollars(raw, lookupEnv)
		if preErr != nil {
			return nil, sanitizeCollectorConfmapError(preErr)
		}
		preSeq, isSeq := preEscapeContainerAsValue(preExpanded).([]any)
		if !isSeq || len(preSeq) != len(list) {
			return nil, errors.New("unclosed ${...} reference")
		}
		for i, resolvedElem := range list {
			if !strings.Contains(resolvedElem, "${") {
				continue
			}
			preStr, ok := preEscapeElementAsString(preSeq[i])
			if !ok || hasUnclosedUnescapedConfmapInterpolation(preStr) {
				return nil, errors.New("unclosed ${...} reference")
			}
		}
		break
	}
	return list, nil
}

func resolveBlockedPatternsWithConfmap(
	inlineRoot any,
	exporterPath string,
	lookupEnv func(string) (string, bool),
) (any, []any, []string, error) {
	resolvedConf, err := resolveInlineConfmap("blocked_value_patterns", inlineRoot, lookupEnv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: %w", exporterPath, err)
	}

	container := resolvedConf.Get("blocked_value_patterns")
	if container == nil {
		return nil, nil, nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: expected YAML sequence of strings, got null", exporterPath)
	}
	rawSeq, isSeq := container.([]any)
	if !isSeq {
		return container, nil, nil, nil
	}
	if len(rawSeq) == 0 {
		return container, rawSeq, []string{}, nil
	}

	var decoded struct {
		Patterns []string `mapstructure:"blocked_value_patterns"`
	}
	if err := resolvedConf.Unmarshal(&decoded); err != nil {
		if m := confmapDecodePatternIndexPattern.FindStringSubmatch(err.Error()); len(m) == 2 {
			if idx, pErr := strconv.Atoi(m[1]); pErr == nil && idx >= 0 && idx < len(rawSeq) {
				return nil, nil, nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: expected string, got %s", exporterPath, idx, describeYAMLValueKind(rawSeq[idx]))
			}
		}
		for i, elem := range rawSeq {
			switch elem.(type) {
			case string, []any, map[string]any, map[any]any:
			default:
				return nil, nil, nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: expected string, got %s", exporterPath, i, describeYAMLValueKind(elem))
			}
		}
		for i, elem := range rawSeq {
			if _, ok := elem.(string); !ok {
				return nil, nil, nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: expected string, got %s", exporterPath, i, describeYAMLValueKind(elem))
			}
		}
		return nil, nil, nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: expected YAML sequence of strings", exporterPath)
	}
	if len(decoded.Patterns) != len(rawSeq) {
		return nil, nil, nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: expected YAML sequence of strings", exporterPath)
	}
	return container, rawSeq, decoded.Patterns, nil
}

func resolveAndValidateCollectorBlockedValuePatterns(rawPatterns any, exporterPath string, lookupEnv func(string) (string, bool)) ([]string, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	var inlineRoot any
	switch v := rawPatterns.(type) {
	case nil:
		return nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: expected YAML sequence of strings, got null", exporterPath)
	case string:
		inlineRoot = v
	case []string:
		seq := make([]any, len(v))
		for i, s := range v {
			seq[i] = s
		}
		inlineRoot = seq
	case []any:
		for i, elem := range v {
			if _, ok := elem.(string); !ok {
				return nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: expected string, got %s", exporterPath, i, describeYAMLValueKind(elem))
			}
		}
		inlineRoot = slices.Clone(v)
	default:
		return nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: expected YAML sequence of strings, got %s", exporterPath, describeYAMLValueKind(rawPatterns))
	}

	container, rawSeq, decodedPatterns, err := resolveBlockedPatternsWithConfmap(inlineRoot, exporterPath, lookupEnv)
	if err != nil {
		return nil, err
	}

	if rawSeq == nil {
		if containerStr, ok := container.(string); ok && strings.Contains(containerStr, "${") {
			preExpanded, preErr := expandBlockedPatternsPreservingEscapedDollars(inlineRoot, lookupEnv)
			if preErr != nil {
				return nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: unclosed collector config reference", exporterPath)
			}
			if preStr, preOK := preEscapeElementAsString(preExpanded); preOK && hasUnclosedUnescapedConfmapInterpolation(preStr) {
				return nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: unclosed collector config reference", exporterPath)
			}
		}
		return nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: expected YAML sequence of strings, got %s", exporterPath, describeYAMLValueKind(container))
	}
	if len(rawSeq) == 0 {
		return []string{}, nil
	}

	var preSeq []any
	var preErr error
	hasCheckedUnclosed := false
	for _, p := range decodedPatterns {
		if strings.Contains(p, "${") {
			var preExpanded any
			preExpanded, preErr = expandBlockedPatternsPreservingEscapedDollars(inlineRoot, lookupEnv)
			if preErr == nil {
				var isSeq bool
				preSeq, isSeq = preEscapeContainerAsValue(preExpanded).([]any)
				if !isSeq {
					preErr = errors.New("expected YAML sequence")
				}
			}
			hasCheckedUnclosed = true
			break
		}
	}

	patterns := make([]string, 0, len(decodedPatterns))
	for i, resolvedElem := range decodedPatterns {
		if rawSeq[i] == nil && strings.TrimSpace(resolvedElem) == "" {
			return nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: expected string, got null", exporterPath, i)
		}
		if hasCheckedUnclosed && strings.Contains(resolvedElem, "${") {
			if preErr != nil || i >= len(preSeq) {
				return nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: unclosed collector config reference", exporterPath, i)
			}
			if preStr, ok := preEscapeElementAsString(preSeq[i]); !ok || hasUnclosedUnescapedConfmapInterpolation(preStr) {
				return nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: unclosed collector config reference", exporterPath, i)
			}
		}
		if strings.TrimSpace(resolvedElem) == "" {
			return nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: pattern must not be empty", exporterPath, i)
		}
		re, compErr := regexp.Compile(resolvedElem)
		if compErr != nil {
			return nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: invalid regular expression", exporterPath, i)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: pattern matches empty strings", exporterPath, i)
		}
		patterns = append(patterns, resolvedElem)
	}
	if err := validateRedactedValuePatternCombination(patterns, exporterPath); err != nil {
		return nil, err
	}
	return patterns, nil
}

func resolveCollectorYAMLBoolWithLookup(raw any, fieldPath string, lookupEnv func(string) (string, bool)) (bool, error) {
	return resolveCollectorYAMLBoolWithLookupWithOptions(raw, fieldPath, lookupEnv, false)
}

func resolveCollectorYAMLBoolWithLookupWithOptions(raw any, fieldPath string, lookupEnv func(string) (string, bool), forceRedact bool) (bool, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	if raw == nil {
		return false, nil
	}
	switch v := raw.(type) {
	case bool:
		return v, nil
	case string:
		hasInterpolated := forceRedact || hasUnescapedConfmapInterpolation(v)
		resolved, err := resolveCollectorEnvStringWithOptions(v, lookupEnv, hasInterpolated)
		if err != nil {
			return false, fmt.Errorf("resolving %s: %w", fieldPath, err)
		}
		standalone := isSingleStandaloneConfmapExpr(v)
		if !standalone && strings.TrimSpace(resolved) != resolved {
			if hasInterpolated {
				return false, fmt.Errorf("parsing %s boolean: %w", fieldPath, strconv.ErrSyntax)
			}
			return false, fmt.Errorf("parsing %s boolean %q: %w", fieldPath, resolved, strconv.ErrSyntax)
		}
		trimmed := strings.TrimSpace(resolved)
		if trimmed == "" {
			if !standalone {
				return false, fmt.Errorf("parsing %s boolean %q: %w", fieldPath, resolved, strconv.ErrSyntax)
			}
			return false, nil
		}
		parsed, err := strconv.ParseBool(trimmed)
		if err != nil {
			if hasInterpolated {
				return false, fmt.Errorf("parsing %s boolean: %w", fieldPath, strconv.ErrSyntax)
			}
			return false, fmt.Errorf("parsing %s boolean %q: %w", fieldPath, trimmed, err)
		}
		return parsed, nil
	default:
		return false, fmt.Errorf("%s must be a boolean, got %T", fieldPath, raw)
	}
}

func preserveResolvedCollectorStringPath(pathDesc string) bool {
	for _, suffix := range []string{
		".table",
		".project",
		".dataset",
		".location",
		".partition_granularity",
		".kms_key_name",
		".max_staleness",
		".log_name_attribute",
		".insert_id_attribute",
		".search_index.analyzer",
		".credentials.file",
		".credentials.json",
		".credentials.impersonate_service_account",
		".credentials.quota_project",
		".credentials.universe_domain",
		".endpoint.url",
		".endpoint.admin_url",
		".write.compression",
		".redaction.mask_replacement",
		".offload.bucket",
		".offload.prefix",
		".offload.authorizer",
		".path",
		".format",
		".compression",
		".group_by.resource_attribute",
		".directory_permissions",
	} {
		if pathDesc == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(pathDesc, suffix) {
			return true
		}
	}
	for _, elemSub := range []string{
		".credentials.impersonate_delegates[",
		".clustering[",
		".search_index.columns[",
		".sending_queue.batch.partition.metadata_keys[",
		".redaction.blocked_keys[",
		".redaction.blocked_key_patterns[",
		".redaction.blocked_value_patterns[",
		".output_paths[",
	} {
		if idx := strings.Index(pathDesc, elemSub); idx >= 0 && strings.HasSuffix(pathDesc, "]") {
			return true
		}
	}
	return strings.Contains(pathDesc, ".labels.")
}

func appendResolvedYAMLChildPath(parentPath, key string) string {
	if parentPath == "" {
		return key
	}
	if hasUnescapedConfmapInterpolation(key) {
		return parentPath + ".*"
	}
	return parentPath + "." + key
}

func resolveCollectorEnvYAMLValueWithOptions(raw any, pathDesc string, lookupEnv func(string) (string, bool), redactValues bool) (any, error) {
	return resolveCollectorEnvYAMLValueTracked(raw, pathDesc, lookupEnv, redactValues, nil)
}

func resolveCollectorEnvYAMLValueTracked(raw any, pathDesc string, lookupEnv func(string) (string, bool), redactValues bool, nilPaths map[string]struct{}) (any, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	switch v := raw.(type) {
	case map[string]any:
		if v == nil {
			return nil, nil
		}
		cloned := make(map[string]any, len(v))
		for _, k := range slices.Sorted(maps.Keys(v)) {
			val := v[k]
			childPath := appendResolvedYAMLChildPath(pathDesc, k)
			resolvedVal, err := resolveCollectorEnvYAMLValueTracked(val, childPath, lookupEnv, redactValues, nilPaths)
			if err != nil {
				return nil, err
			}
			cloned[k] = resolvedVal
		}
		return cloned, nil
	case map[any]any:
		if v == nil {
			return nil, nil
		}
		if err := rejectCollidingYAMLMapKeys(v, pathDesc, false); err != nil {
			return nil, err
		}
		entries, err := sortedAnyYAMLMapEntries(v)
		if err != nil {
			return nil, err
		}
		cloned := make(map[any]any, len(v))
		for _, item := range entries {
			childPath := appendResolvedYAMLChildPath(pathDesc, item.strKey)
			resolvedVal, err := resolveCollectorEnvYAMLValueTracked(item.val, childPath, lookupEnv, redactValues, nilPaths)
			if err != nil {
				return nil, err
			}
			cloned[item.rawKey] = resolvedVal
		}
		return cloned, nil
	case []any:
		if v == nil {
			return nil, nil
		}
		cloned := make([]any, len(v))
		for idx, val := range v {
			childPath := fmt.Sprintf("%s[%d]", pathDesc, idx)
			resolvedVal, err := resolveCollectorEnvYAMLValueTracked(val, childPath, lookupEnv, redactValues, nilPaths)
			if err != nil {
				return nil, err
			}
			cloned[idx] = resolvedVal
		}
		return cloned, nil
	case string:
		if !strings.Contains(v, "$") {
			return v, nil
		}
		resolved, err := resolveCollectorEnvStringWithOptions(v, lookupEnv, redactValues)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", pathDesc, err)
		}
		if preserveResolvedCollectorStringPath(pathDesc) {
			return resolved, nil
		}
		if isSingleStandaloneConfmapExpr(v) {
			resolvedConf, confErr := resolveInlineConfmap("value", v, lookupEnv)
			if confErr == nil {
				var unwrapped any
				if resolvedConf != nil {
					unwrapped = unwrapConfmapValueTracked(resolvedConf.Get("value"), pathDesc, true, nilPaths)
				}
				switch unwrapped.(type) {
				case map[string]any, map[any]any, []any:
					if err := rejectCollidingYAMLMapKeys(unwrapped, pathDesc, false); err != nil {
						return nil, err
					}
				}
				if unwrapped == nil && nilPaths != nil && pathDesc != "" {
					nilPaths[pathDesc] = struct{}{}
				}
				return unwrapped, nil
			}
			if strings.Contains(confErr.Error(), "multi-document YAML") ||
				strings.Contains(confErr.Error(), "ambiguous duplicate map keys") {
				return nil, fmt.Errorf("resolving %s: %w", pathDesc, confErr)
			}
			// Fall back to yaml.Unmarshal only when confmap YAML retrieval fails
			// (such as integer-keyed YAML maps) so whitespace-padded scalars that
			// confmap accepts directly retain exact collector semantics.
			var parsed any
			if yamlErr := yaml.Unmarshal([]byte(resolved), &parsed); yamlErr == nil {
				if err := rejectCollidingYAMLMapKeys(parsed, pathDesc, false); err != nil {
					return nil, err
				}
				if parsed == nil && nilPaths != nil && pathDesc != "" {
					nilPaths[pathDesc] = struct{}{}
				}
				return parsed, nil
			}
			return nil, fmt.Errorf("resolving %s: %w", pathDesc, confErr)
		}
		return resolved, nil
	default:
		return raw, nil
	}
}

func decodeCollectorCredentialsMap(
	exporterID, exporterPath string,
	resolvedCredMap map[string]any,
	dst *bigqueryexporter.CredentialsConfig,
	forceRedactKeys bool,
) error {
	keys := make([]string, 0, len(resolvedCredMap))
	for k := range resolvedCredMap {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		val := resolvedCredMap[k]
		if val == nil {
			continue
		}
		switch k {
		case "file", "json", "impersonate_service_account", "quota_project", "universe_domain":
			if _, ok := val.(string); !ok {
				return fmt.Errorf("decoding collector exporter %q credentials config: %s.credentials.%s must be a string, got %T", exporterID, exporterPath, k, val)
			}
		case "impersonate_delegates":
			if _, err := extractYAMLStringSlice(val); err != nil {
				return fmt.Errorf("decoding collector exporter %q credentials config: %s.credentials.%s: %w", exporterID, exporterPath, k, err)
			}
		default:
			if forceRedactKeys {
				return fmt.Errorf("decoding collector exporter %q credentials config: unsupported key in %s.credentials", exporterID, exporterPath)
			}
			return fmt.Errorf("decoding collector exporter %q credentials config: unsupported key %q in %s.credentials", exporterID, k, exporterPath)
		}
	}
	if err := confmap.NewFromStringMap(resolvedCredMap).Unmarshal(dst); err != nil {
		return fmt.Errorf("decoding collector exporter %q credentials config: invalid %s.credentials configuration", exporterID, exporterPath)
	}
	return nil
}

func decodeCollectorEndpointMap(
	exporterID, exporterPath string,
	resolvedEPMap map[string]any,
	dst *bigqueryexporter.EndpointConfig,
	forceRedactKeys bool,
) error {
	keys := make([]string, 0, len(resolvedEPMap))
	for k := range resolvedEPMap {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		val := resolvedEPMap[k]
		if val == nil {
			continue
		}
		switch k {
		case "url", "admin_url":
			if _, ok := val.(string); !ok {
				return fmt.Errorf("decoding collector exporter %q endpoint config: %s.endpoint.%s must be a string, got %T", exporterID, exporterPath, k, val)
			}
		case "insecure", "without_authentication":
			if _, ok := val.(bool); !ok {
				return fmt.Errorf("decoding collector exporter %q endpoint config: %s.endpoint.%s must be a boolean, got %T", exporterID, exporterPath, k, val)
			}
		default:
			if forceRedactKeys {
				return fmt.Errorf("decoding collector exporter %q endpoint config: unsupported key in %s.endpoint", exporterID, exporterPath)
			}
			return fmt.Errorf("decoding collector exporter %q endpoint config: unsupported key %q in %s.endpoint", exporterID, k, exporterPath)
		}
	}
	if err := confmap.NewFromStringMap(resolvedEPMap).Unmarshal(dst); err != nil {
		return fmt.Errorf("decoding collector exporter %q endpoint config: invalid %s.endpoint configuration", exporterID, exporterPath)
	}
	return nil
}

func extractYAMLStringSlice(raw any) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	switch v := raw.(type) {
	case []string:
		out := make([]string, len(v))
		copy(out, v)
		return out, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("expected string item in YAML sequence, got %T", item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected YAML sequence of strings, got %T", raw)
	}
}

func parseComponentID(raw string) (component.ID, bool) {
	var parsed component.ID
	if err := parsed.UnmarshalText([]byte(raw)); err != nil {
		return component.ID{}, false
	}
	return parsed, true
}

func canonicalComponentID(raw string) (string, bool) {
	parsed, ok := parseComponentID(raw)
	if !ok {
		return "", false
	}
	return parsed.String(), true
}

func sameComponentID(a, b string) bool {
	if a == b {
		return true
	}
	pa, okA := parseComponentID(a)
	pb, okB := parseComponentID(b)
	return okA && okB && pa == pb
}

func isBigQueryComponentID(id string) bool {
	parsed, ok := parseComponentID(id)
	return ok && parsed.Type().String() == "bigquery"
}

// exporterRequiresNonEmptyConfig reports whether id is excluded from the
// allowlist of exporter types known to have valid empty default configs when a
// non-canonical exporters: key misses conf.Sub(id.String()) during collector
// unmarshaling.
//
// Custom distribution allowlist contract:
//   - Canonical unused keys (e.g. "custom/a": {}) pass non-canonical validation
//     and are pruned before launching otelcol-bq.
//   - Non-canonical keys of unfamiliar types (e.g. "custom /a": {}, "kafka /a": {})
//     are rejected fail-closed.
//   - Non-canonical keys of explicitly allowlisted empty-default types ("debug /a": {},
//     "nop /a": {}) are permitted and pruned.
//
// Bundled stock exporters with strict field validation ("file", plus "debug" when
// canonical) are validated before pruning.
func exporterRequiresNonEmptyConfig(id component.ID) bool {
	switch id.Type().String() {
	case "debug", "nop":
		return false
	default:
		return true
	}
}

type debugTelemetryLevel int32

const (
	debugLevelNone debugTelemetryLevel = iota - 1
	debugLevelBasic
	debugLevelNormal
	debugLevelDetailed
)

func (l debugTelemetryLevel) String() string {
	switch l {
	case debugLevelNone:
		return "None"
	case debugLevelBasic:
		return "Basic"
	case debugLevelNormal:
		return "Normal"
	case debugLevelDetailed:
		return "Detailed"
	default:
		return ""
	}
}

func (l debugTelemetryLevel) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}

func (l *debugTelemetryLevel) UnmarshalText(text []byte) error {
	if l == nil {
		return errors.New("cannot unmarshal to a nil *debugTelemetryLevel")
	}
	str := strings.ToLower(string(text))
	switch str {
	case "none":
		*l = debugLevelNone
		return nil
	case "basic":
		*l = debugLevelBasic
		return nil
	case "normal":
		*l = debugLevelNormal
		return nil
	case "detailed":
		*l = debugLevelDetailed
		return nil
	default:
		return fmt.Errorf("unknown metrics level %q", str)
	}
}

type debugExporterConfig struct {
	Verbosity          debugTelemetryLevel `mapstructure:"verbosity,omitempty"`
	SamplingInitial    int                 `mapstructure:"sampling_initial"`
	SamplingThereafter int                 `mapstructure:"sampling_thereafter"`
	UseInternalLogger  bool                `mapstructure:"use_internal_logger"`
	OutputPaths        []string            `mapstructure:"output_paths"`
	SendingQueue       any                 `mapstructure:"sending_queue"`
}

func (c *debugExporterConfig) Validate() error {
	if c.Verbosity != debugLevelBasic && c.Verbosity != debugLevelNormal && c.Verbosity != debugLevelDetailed {
		return fmt.Errorf("verbosity level %q is not supported", c.Verbosity.String())
	}
	if c.UseInternalLogger && c.OutputPaths != nil {
		return errors.New("output_paths is not supported when use_internal_logger is true")
	}
	if !c.UseInternalLogger && c.OutputPaths != nil && len(c.OutputPaths) == 0 {
		return errors.New("output_paths must not be empty when use_internal_logger is false")
	}
	return nil
}

type fileExporterRotationConfig struct {
	MaxMegabytes int  `mapstructure:"max_megabytes"`
	MaxDays      int  `mapstructure:"max_days"`
	MaxBackups   int  `mapstructure:"max_backups"`
	LocalTime    bool `mapstructure:"localtime"`
}

type fileExporterGroupByConfig struct {
	Enabled           bool   `mapstructure:"enabled"`
	ResourceAttribute string `mapstructure:"resource_attribute"`
	MaxOpenFiles      int    `mapstructure:"max_open_files"`
}

type fileExporterCompressionParams struct {
	Level int `mapstructure:"level"`
}

type fileExporterConfig struct {
	Path                 string                        `mapstructure:"path"`
	Append               bool                          `mapstructure:"append"`
	Rotation             *fileExporterRotationConfig   `mapstructure:"rotation"`
	FormatType           string                        `mapstructure:"format"`
	Encoding             *component.ID                 `mapstructure:"encoding"`
	Compression          string                        `mapstructure:"compression"`
	CompressionParams    fileExporterCompressionParams `mapstructure:"compression_params"`
	FlushInterval        time.Duration                 `mapstructure:"flush_interval"`
	GroupBy              *fileExporterGroupByConfig    `mapstructure:"group_by"`
	CreateDirectory      bool                          `mapstructure:"create_directory"`
	DirectoryPermissions string                        `mapstructure:"directory_permissions"`
}

func (c *fileExporterConfig) Validate() error {
	if c.Path == "" {
		return errors.New("path must be non-empty")
	}
	if c.Append && c.Rotation != nil {
		return errors.New("append and rotation enabled at the same time is not supported")
	}
	if c.Rotation != nil && (c.Rotation.MaxMegabytes < 0 || c.Rotation.MaxDays < 0 || c.Rotation.MaxBackups < 0) {
		return errors.New("rotation max_megabytes, max_days and max_backups must not be negative")
	}
	if c.FormatType != "json" && c.FormatType != "proto" {
		return errors.New("format type is not supported")
	}
	if c.Compression != "" && c.Compression != "zstd" {
		return errors.New("compression is not supported")
	}
	if c.FlushInterval < 0 {
		return errors.New("flush_interval must be larger than zero")
	}
	if c.GroupBy != nil && c.GroupBy.Enabled {
		if strings.Count(c.Path, "*") != 1 {
			return errors.New("path must contain exactly one * when group_by is enabled")
		}
		if strings.HasPrefix(c.Path, "*") {
			return errors.New("path must not start with * when group_by is enabled")
		}
		if c.GroupBy.ResourceAttribute == "" {
			return errors.New("resource_attribute must not be empty when group_by is enabled")
		}
		if c.GroupBy.MaxOpenFiles <= 0 {
			return errors.New("max_open_files must be positive when group_by is enabled")
		}
	}
	if c.CreateDirectory {
		if c.DirectoryPermissions != "" {
			permissions, err := strconv.ParseInt(c.DirectoryPermissions, 8, 32)
			if err != nil {
				return errors.New("directory_permissions value must be a valid octal representation")
			}
			if permissions&int64(os.ModePerm) != permissions {
				return errors.New("directory_permissions contain invalid bits for file access")
			}
		}
	} else if c.DirectoryPermissions != "" {
		return errors.New("directory_permissions requires create_directory to be true")
	}
	return nil
}

func validateBundledInactiveExporterConfig(
	expID component.ID,
	diagKey string,
	rawExp any,
	bodyFromEnv bool,
	envConf *confmap.Conf,
	envNullSizers collectorSQConfmapNullSizers,
	lookupEnv func(string) (string, bool),
) error {
	typ := expID.Type().String()
	if typ != "debug" && typ != "file" {
		return nil
	}
	var (
		resolvedMap  map[string]any
		rawForScrub  any
		decodeConf   *confmap.Conf
		sqNullSizers = envNullSizers
	)
	if bodyFromEnv {
		if rawExp == nil {
			resolvedMap = map[string]any{}
		} else {
			normAny, err := normalizeNestedMapsToStringKeys(rawExp)
			if err != nil {
				return err
			}
			m, ok := normAny.(map[string]any)
			if !ok {
				return fmt.Errorf("collector exporter %q must be a YAML map or null", diagKey)
			}
			resolvedMap = m
		}
		rawForScrub = map[string]any{}
		decodeConf = envConf
		if decodeConf == nil {
			decodeConf = confmap.NewFromStringMap(resolvedMap)
		}
	} else {
		rawNode := rawExp
		if rawNode == nil {
			rawNode = map[string]any{}
		}
		nilPaths := make(map[string]struct{})
		resolvedAny, err := resolveCollectorEnvYAMLValueTracked(rawNode, "exporters."+diagKey, lookupEnv, true, nilPaths)
		if err != nil {
			return err
		}
		sqNullSizers = sqNullSizers.merge(extractSQNullSizers(nilPaths, "exporters."+diagKey+"."))
		normAny, err := normalizeNestedMapsToStringKeys(resolvedAny)
		if err != nil {
			return err
		}
		m, ok := normAny.(map[string]any)
		if !ok {
			return fmt.Errorf("collector exporter %q must be a YAML map or null", diagKey)
		}
		resolvedMap = m
		rawForScrub = rawNode
		decodeConf = confmap.NewFromStringMap(resolvedMap)
	}

	if err := rejectExporterBodyDelimiterKeysWithOptions(resolvedMap, diagKey, "exporters."+diagKey, []string{"exporters", diagKey}, true); err != nil {
		return err
	}

	switch typ {
	case "debug":
		dbgCfg := debugExporterConfig{
			Verbosity:          debugLevelBasic,
			SamplingInitial:    2,
			SamplingThereafter: 1,
			UseInternalLogger:  true,
		}
		if err := decodeConf.Unmarshal(&dbgCfg); err != nil {
			return fmt.Errorf("decoding collector exporter %q config: %w", diagKey, scrubInterpolatedErrorWithScopeAndForceLookup(nil, rawForScrub, resolvedMap, err, bodyFromEnv, lookupEnv))
		}
		if sqVal, hasSQ := resolvedMap["sending_queue"]; hasSQ && sqVal != nil {
			var rawSQNode any
			if rawMap, ok := rawForScrub.(map[string]any); ok && rawMap != nil {
				rawSQNode = rawMap["sending_queue"]
			}
			if _, stErr := normalizeSendingQueueStorageWithConfmap(rawSQNode, sqVal, diagKey, bodyFromEnv, lookupEnv); stErr != nil {
				return stErr
			}
			bqCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config)
			if !ok {
				return errors.New("unexpected exporter config type")
			}
			if err := confmap.NewFromStringMap(map[string]any{"sending_queue": sqVal}).Unmarshal(bqCfg); err != nil {
				return fmt.Errorf("decoding collector exporter %q config: %w", diagKey, scrubInterpolatedErrorWithScopeAndForceLookup(nil, rawForScrub, resolvedMap, err, bodyFromEnv, lookupEnv))
			}
			applyConfmapNullSizersToQueue(&bqCfg.QueueSettings, sqVal, sqNullSizers)
			if q := bqCfg.QueueSettings.Get(); q != nil {
				if err := confmap.Validate(q); err != nil {
					return fmt.Errorf("validating collector exporter %q sending_queue: %w", diagKey, scrubInterpolatedErrorWithScopeAndForceLookup([]string{"sending_queue"}, rawForScrub, resolvedMap, err, bodyFromEnv, lookupEnv))
				}
			}
		}
		if err := dbgCfg.Validate(); err != nil {
			return fmt.Errorf("validating collector exporter %q config: %w", diagKey, err)
		}
	case "file":
		fileCfg := fileExporterConfig{
			FormatType:    "json",
			FlushInterval: time.Second,
		}
		if gbVal, hasGB := resolvedMap["group_by"]; hasGB && gbVal != nil {
			fileCfg.GroupBy = &fileExporterGroupByConfig{
				ResourceAttribute: "fileexporter.path_segment",
				MaxOpenFiles:      100,
			}
		}
		if err := decodeConf.Unmarshal(&fileCfg); err != nil {
			return fmt.Errorf("decoding collector exporter %q config: %w", diagKey, scrubInterpolatedErrorWithScopeAndForceLookup(nil, rawForScrub, resolvedMap, err, bodyFromEnv, lookupEnv))
		}
		if err := fileCfg.Validate(); err != nil {
			return fmt.Errorf("validating collector exporter %q config: %w", diagKey, err)
		}
	}
	return nil
}

func escapeConfmapDollarsInYAMLValue(v any) any {
	switch tv := v.(type) {
	case string:
		return escapeCollectorConfmapDollars(tv)
	case []any:
		out := make([]any, len(tv))
		for i, elem := range tv {
			out[i] = escapeConfmapDollarsInYAMLValue(elem)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(tv))
		for k, val := range tv {
			out[k] = escapeConfmapDollarsInYAMLValue(val)
		}
		return out
	default:
		return v
	}
}

func isOTLPComponentID(id string) bool {
	return id == "otlp" || strings.HasPrefix(id, "otlp/")
}

func isHealthCheckComponentID(id string) bool {
	return id == "health_check" || strings.HasPrefix(id, "health_check/")
}

func isFileStorageComponentID(id string) bool {
	return id == "file_storage" || strings.HasPrefix(id, "file_storage/")
}

func sanitizeExtensionDirName(id string) string {
	if id == "" {
		return "_empty"
	}
	var b strings.Builder
	b.Grow(len(id) * 2)
	for i := 0; i < len(id); i++ {
		c := id[i]
		// Percent-encode uppercase ASCII as well so distinct extension IDs like
		// file_storage/A and file_storage/a never share a directory on
		// case-insensitive filesystems.
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteByte(c)
		} else {
			_, _ = fmt.Fprintf(&b, "_%02x", c)
		}
	}
	return b.String()
}

func signalTableSchema(signal string) *storagepb.TableSchema {
	switch signal {
	case "traces":
		return schema.SpansTableSchema()
	case "metrics":
		return schema.MetricsTableSchema()
	default:
		return schema.LogsTableSchema()
	}
}

func rejectCollectorHealthCheckTLS(hc map[string]any, extID string, lookupEnv func(string) (string, bool)) error {
	rawTLS, hasTLS := hc["tls"]
	if !hasTLS || rawTLS == nil {
		return nil
	}
	if tlsStr, isStr := rawTLS.(string); isStr && hasUnescapedConfmapInterpolation(tlsStr) {
		resolvedTLS, rErr := resolveCollectorEnvYAMLValueWithOptions(tlsStr, "extensions."+extID+".tls", lookupEnv, true)
		if rErr != nil {
			return fmt.Errorf("resolving collector extension %q tls: %w", extID, rErr)
		}
		if resolvedTLS == nil {
			return nil
		}
		if s, ok := resolvedTLS.(string); ok && strings.TrimSpace(s) == "" {
			return nil
		}
	}
	return fmt.Errorf("collector extension %q configures tls, which is not supported by plaintext loopback health probes", extID)
}

func countActiveSignalOTLPReceivers(rawYAML []byte, signal string) int {
	var doc map[string]any
	if err := yaml.Unmarshal(rawYAML, &doc); err != nil || len(doc) == 0 {
		return 1
	}
	if signal == "" {
		signal = "logs"
	}
	svc, _ := doc["service"].(map[string]any)
	pipelines, _ := svc["pipelines"].(map[string]any)
	var matched []string
	for k := range pipelines {
		if k == signal || strings.HasPrefix(k, signal+"/") {
			matched = append(matched, k)
		}
	}
	if len(matched) != 1 {
		return 1
	}
	pipe, _ := pipelines[matched[0]].(map[string]any)
	recvIDs, err := extractYAMLStringSlice(pipe["receivers"])
	if err != nil || len(recvIDs) == 0 {
		return 1
	}
	return len(recvIDs)
}

func formatCollectorExitErr(prefix string, waitErr error, diag *boundedDiagBuffer) error {
	var diagStr string
	if diag != nil {
		diagStr = diag.String()
	}
	if waitErr == nil {
		return fmt.Errorf("%s (exit status 0): %s", prefix, diagStr)
	}
	return fmt.Errorf("%s (%w): %s", prefix, waitErr, diagStr)
}

var collectorTableIDPattern = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func rewriteBigQueryExporterMapWithLookup(bq map[string]any, exporterID, signal string, cfg RunnerConfig, ep collectorEndpointOverride, meta *collectorRewriteMeta, lookupEnv func(string) (string, bool)) error {
	if lookupEnv == nil {
		lookupEnv = collectorEnvLookup(cfg.MaxProcs)
	}
	exporterPath := "exporters." + exporterID
	bq["project"] = cfg.ProjectID
	bq["dataset"] = cfg.DatasetID
	bq["location"] = cfg.Location

	sigMap, err := ensureInlineYAMLSubmap(bq, signal, exporterPath+"."+signal)
	if err != nil {
		return err
	}
	var (
		effectiveTable   string
		hasExplicitTable bool
	)
	if rawTable, exists := sigMap["table"]; exists {
		// Match exporter Config.Validate() strictly: explicit blank or null table under
		// the active signal is a hard error instead of falling back to the default table.
		if rawTable == nil {
			return fmt.Errorf("collector exporter %s.table must not be empty", signal)
		}
		rawStr, ok := rawTable.(string)
		if !ok {
			return fmt.Errorf("collector exporter %s.table must be a string, got %T", signal, rawTable)
		}
		hasExplicitTable = true
		hasInterpolatedTable := meta.activeExporterBodyEnvSourced || hasUnescapedConfmapInterpolation(rawStr)
		resolvedTable, resErr := resolveCollectorEnvStringWithOptions(rawStr, lookupEnv, hasInterpolatedTable)
		if resErr != nil {
			return fmt.Errorf("resolving collector exporter %s.table: %w", signal, resErr)
		}
		effectiveTable = strings.TrimSpace(resolvedTable)
		if effectiveTable == "" {
			if hasInterpolatedTable {
				return fmt.Errorf("collector exporter %s.table resolved to an empty table name", signal)
			}
			return fmt.Errorf("collector exporter %s.table %q resolved to an empty table name", signal, rawStr)
		}
		if !collectorTableIDPattern.MatchString(effectiveTable) {
			if hasInterpolatedTable {
				return fmt.Errorf("collector exporter %s.table must contain only letters, numbers and underscores", signal)
			}
			return fmt.Errorf("collector exporter %s.table %q (%q) must contain only letters, numbers and underscores", signal, effectiveTable, rawStr)
		}
	}
	if !hasExplicitTable {
		effectiveTable = collectorTargetTable(signal)
		sigMap["table"] = effectiveTable
	}
	meta.effectiveTable = effectiveTable

	writeCfg, err := ensureInlineYAMLSubmap(bq, "write", exporterPath+".write")
	if err != nil {
		return err
	}
	if cfg.StreamPoolSize > 0 {
		writeCfg["stream_pool_size"] = cfg.StreamPoolSize
	}
	if cfg.ConnectionPoolSize > 0 {
		writeCfg["connection_pool_size"] = cfg.ConnectionPoolSize
	}
	if cfg.MaxInflightRequests > 0 {
		writeCfg["max_inflight_requests"] = cfg.MaxInflightRequests
	}
	if cfg.MaxRequestBytes > 0 {
		writeCfg["max_request_bytes"] = cfg.MaxRequestBytes
	}
	if cfg.Compression != "" {
		writeCfg["compression"] = cfg.Compression
	}

	bpMap, err := optionalInlineYAMLSubmap(writeCfg, "backpressure", exporterPath+".write.backpressure")
	if err != nil {
		return err
	}
	var yamlBackpressure bool
	if bpMap != nil {
		yamlBackpressure, err = resolveCollectorYAMLBoolWithLookupWithOptions(bpMap["enabled"], exporterPath+".write.backpressure.enabled", lookupEnv, meta.activeExporterBodyEnvSourced)
		if err != nil {
			return err
		}
	}
	if cfg.Backpressure {
		bp, bpErr := ensureInlineYAMLSubmap(writeCfg, "backpressure", exporterPath+".write.backpressure")
		if bpErr != nil {
			return bpErr
		}
		bp["enabled"] = true
		if cfg.SimulateAckDelay > 0 {
			lt := max(time.Millisecond, cfg.SimulateAckDelay/2)
			bp["latency_threshold"] = lt.String()
		}
	}
	meta.effectiveBackpressure = cfg.Backpressure || yamlBackpressure

	writeMask := inspectCollectorWriteInterpMaskWithForce(writeCfg, meta.activeExporterBodyEnvSourced)
	resolvedWriteAny, err := resolveCollectorEnvYAMLValueWithOptions(writeCfg, exporterPath+".write", lookupEnv, true)
	if err != nil {
		return err
	}
	resolvedWriteRaw, err := normalizeNestedMapsToStringKeys(resolvedWriteAny)
	if err != nil {
		return err
	}
	resolvedWriteMap, _ := resolvedWriteRaw.(map[string]any)
	defaultExpCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config)
	if !ok {
		return errors.New("unexpected exporter config type")
	}
	if resolvedWriteMap != nil {
		if err := confmap.NewFromStringMap(resolvedWriteMap).Unmarshal(&defaultExpCfg.Write); err != nil {
			return fmt.Errorf("decoding collector exporter %q write config: %w", exporterID, scrubInterpolatedErrorWithScopeAndForceLookup([]string{"write"}, writeCfg, resolvedWriteMap, err, meta.activeExporterBodyEnvSourced, lookupEnv))
		}
	}
	if err := validateCollectorWriteLimits(defaultExpCfg.Write, writeMask); err != nil {
		return fmt.Errorf("validating collector exporter %q write config: %w", exporterID, err)
	}
	meta.effectiveStreamPoolSize = defaultExpCfg.Write.StreamPoolSize
	meta.effectiveConnectionPoolSize = defaultExpCfg.Write.ConnectionPoolSize
	meta.effectiveMaxInflightRequests = defaultExpCfg.Write.MaxInflightRequests
	meta.effectiveMaxRequestBytes = defaultExpCfg.Write.MaxRequestBytes

	if _, err := optionalInlineYAMLSubmap(bq, "retry_on_failure", exporterPath+".retry_on_failure"); err != nil {
		return err
	}
	if ep.useBQFake && (cfg.SimulateThrottleEvery > 0 || cfg.SimulateAckDelay > 0) {
		retryCfg, rErr := ensureInlineYAMLSubmap(bq, "retry_on_failure", exporterPath+".retry_on_failure")
		if rErr != nil {
			return rErr
		}
		retryCfg["enabled"] = true
		retryCfg["initial_interval"] = "10ms"
		retryCfg["max_interval"] = "50ms"
	}

	redMap, err := optionalInlineYAMLSubmap(bq, "redaction", exporterPath+".redaction")
	if err != nil {
		return err
	}
	var (
		yamlRedaction    bool
		existingPatterns []string
		hasUserPatterns  bool
	)
	if redMap != nil {
		yamlRedaction, err = resolveCollectorYAMLBoolWithLookupWithOptions(redMap["enabled"], exporterPath+".redaction.enabled", lookupEnv, meta.activeExporterBodyEnvSourced)
		if err != nil {
			return err
		}
		if rawPatterns, hasPatterns := redMap["blocked_value_patterns"]; hasPatterns && rawPatterns != nil {
			parsed, pErr := resolveAndValidateCollectorBlockedValuePatterns(rawPatterns, exporterPath, lookupEnv)
			if pErr != nil {
				return pErr
			}
			existingPatterns = parsed
			hasUserPatterns = true
		}
	}
	if cfg.Redaction {
		red, redErr := ensureInlineYAMLSubmap(bq, "redaction", exporterPath+".redaction")
		if redErr != nil {
			return redErr
		}
		red["enabled"] = true
		red["redact_log_body"] = true
		seen := make(map[string]struct{}, len(existingPatterns)+len(blockedSecretPatterns))
		mergedRaw := make([]string, 0, len(existingPatterns)+len(blockedSecretPatterns))
		mergedYAML := make([]any, 0, len(existingPatterns)+len(blockedSecretPatterns))
		appendPattern := func(p string) {
			if _, dup := seen[p]; dup {
				return
			}
			seen[p] = struct{}{}
			mergedRaw = append(mergedRaw, p)
			mergedYAML = append(mergedYAML, escapeCollectorConfmapDollars(p))
		}
		for _, p := range existingPatterns {
			appendPattern(p)
		}
		for _, p := range blockedSecretPatterns {
			appendPattern(p)
		}
		if err := validateRedactedValuePatternCombination(mergedRaw, exporterPath); err != nil {
			return err
		}
		red["blocked_value_patterns"] = mergedYAML
	} else if hasUserPatterns {
		escaped := make([]any, len(existingPatterns))
		for i, p := range existingPatterns {
			escaped[i] = escapeCollectorConfmapDollars(p)
		}
		redMap["blocked_value_patterns"] = escaped
	}
	meta.effectiveRedaction = cfg.Redaction || yamlRedaction
	if rawRed, hasRed := bq["redaction"].(map[string]any); hasRed && rawRed != nil {
		if resolvedRedAny, resErr := resolveCollectorEnvYAMLValueWithOptions(rawRed, exporterPath+".redaction", lookupEnv, true); resErr == nil {
			if resolvedRedMap, isMap := resolvedRedAny.(map[string]any); isMap && resolvedRedMap != nil {
				if err := confmap.NewFromStringMap(resolvedRedMap).Unmarshal(&defaultExpCfg.Redaction); err == nil {
					meta.effectiveRedactionConfig = defaultExpCfg.Redaction
					meta.effectiveRedaction = defaultExpCfg.Redaction.Enabled
				}
			}
		}
	}

	if cfg.OffloadGCSBucket != "" {
		off, offErr := ensureInlineYAMLSubmap(bq, "offload", exporterPath+".offload")
		if offErr != nil {
			return offErr
		}
		off["enabled"] = true
		off["bucket"] = cfg.OffloadGCSBucket
		off["min_bytes"] = cfg.OffloadThresholdBytes
	}
	offMap, err := optionalInlineYAMLSubmap(bq, "offload", exporterPath+".offload")
	if err != nil {
		return err
	}
	if offMap != nil {
		offEnabled, offBoolErr := resolveCollectorYAMLBoolWithLookupWithOptions(offMap["enabled"], exporterPath+".offload.enabled", lookupEnv, meta.activeExporterBodyEnvSourced)
		if offBoolErr != nil {
			return offBoolErr
		}
		if ep.useBQFake && offEnabled {
			return errors.New("collector offload.enabled requires --collector-allow-live (payload offload writes to live Cloud Storage)")
		}
	}
	if ep.useBQFake {
		bq["offload"] = map[string]any{"enabled": false}
	}

	quarantineMap, err := optionalInlineYAMLSubmap(bq, "quarantine", exporterPath+".quarantine")
	if err != nil {
		return err
	}
	if quarantineMap != nil {
		if _, err := resolveCollectorYAMLBoolWithLookupWithOptions(quarantineMap["enabled"], exporterPath+".quarantine.enabled", lookupEnv, meta.activeExporterBodyEnvSourced); err != nil {
			return err
		}
	}

	if ep.useBQFake {
		bq["endpoint"] = map[string]any{
			"url":                    ep.fakeGRPCURL,
			"admin_url":              ep.fakeRESTURL,
			"insecure":               true,
			"without_authentication": true,
		}
		meta.effectiveEndpoint = bigqueryexporter.EndpointConfig{
			URL:                   ep.fakeGRPCURL,
			AdminURL:              ep.fakeRESTURL,
			Insecure:              true,
			WithoutAuthentication: true,
		}
		delete(bq, "credentials")
		bq["auto_create"] = map[string]any{
			"dataset":         false,
			"tables":          false,
			"companion_views": false,
			"search_indexes":  false,
		}
	} else {
		epMap, epErr := optionalInlineYAMLSubmap(bq, "endpoint", exporterPath+".endpoint")
		if epErr != nil {
			return epErr
		}
		if epMap != nil {
			var rawEP bigqueryexporter.EndpointConfig
			if s, ok := epMap["url"].(string); ok {
				rawEP.URL = s
			}
			if s, ok := epMap["admin_url"].(string); ok {
				rawEP.AdminURL = s
			}
			meta.rawCredentialSecrets = append(meta.rawCredentialSecrets, collectEndpointURLSecrets(rawEP)...)
			resolvedEPAny, resErr := resolveCollectorEnvYAMLValueWithOptions(epMap, exporterPath+".endpoint", lookupEnv, true)
			if resErr != nil {
				return resErr
			}
			resolvedEPMap, _ := resolvedEPAny.(map[string]any)
			if resolvedEPMap != nil {
				if err := decodeCollectorEndpointMap(exporterID, exporterPath, resolvedEPMap, &defaultExpCfg.Endpoint, meta.activeExporterBodyEnvSourced); err != nil {
					return err
				}
			}
			meta.effectiveEndpoint = defaultExpCfg.Endpoint
		}
		credMap, credErr := optionalInlineYAMLSubmap(bq, "credentials", exporterPath+".credentials")
		if credErr != nil {
			return credErr
		}
		if credMap != nil {
			resolvedCredAny, resCredErr := resolveCollectorEnvYAMLValueWithOptions(credMap, exporterPath+".credentials", lookupEnv, true)
			if resCredErr != nil {
				return resCredErr
			}
			resolvedCredMap, _ := resolvedCredAny.(map[string]any)
			if resolvedCredMap != nil {
				if err := decodeCollectorCredentialsMap(exporterID, exporterPath, resolvedCredMap, &defaultExpCfg.Credentials, meta.activeExporterBodyEnvSourced); err != nil {
					return err
				}
			}
			meta.effectiveCredentials = defaultExpCfg.Credentials
		}
		parentProvisionsTables := cfg.EphemeralDataset && meta.effectiveEndpoint.WithoutAuthentication
		bq["auto_create"] = map[string]any{
			"dataset":         false,
			"tables":          cfg.EphemeralDataset && !parentProvisionsTables,
			"companion_views": cfg.EphemeralDataset && !parentProvisionsTables,
			"search_indexes":  false,
		}
		if cfg.EphemeralDataset {
			quarantine, qErr := ensureInlineYAMLSubmap(bq, "quarantine", exporterPath+".quarantine")
			if qErr != nil {
				return qErr
			}
			quarantine["enabled"] = true
		}

		collectCredentialMapSecrets := func(m map[string]any) {
			for _, k := range []string{"file", "json", "impersonate_service_account", "quota_project"} {
				if s, ok := m[k].(string); ok && s != "" {
					meta.rawCredentialSecrets = append(meta.rawCredentialSecrets, s)
				}
			}
			if dels, err := extractYAMLStringSlice(m["impersonate_delegates"]); err == nil {
				for _, d := range dels {
					if d != "" {
						meta.rawCredentialSecrets = append(meta.rawCredentialSecrets, d)
					}
				}
			}
		}
		if rawCredMap, ok := bq["credentials"].(map[string]any); ok && rawCredMap != nil {
			collectCredentialMapSecrets(rawCredMap)
			if resolvedAny, resErr := resolveCollectorEnvYAMLValueWithOptions(rawCredMap, exporterPath+".credentials", lookupEnv, true); resErr == nil {
				if resolvedMap, isMap := resolvedAny.(map[string]any); isMap && resolvedMap != nil {
					collectCredentialMapSecrets(resolvedMap)
				}
			}
		}
		if adcPath, ok := lookupEnv("GOOGLE_APPLICATION_CREDENTIALS"); ok && strings.TrimSpace(adcPath) != "" {
			meta.rawCredentialSecrets = append(meta.rawCredentialSecrets, adcPath)
		}
		if adcEnv := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); strings.TrimSpace(adcEnv) != "" {
			meta.rawCredentialSecrets = append(meta.rawCredentialSecrets, adcEnv)
		}
	}
	return nil
}

type collectorWriteInterpMask struct {
	streamPoolSize      bool
	connectionPoolSize  bool
	maxInflightRequests bool
	maxRequestBytes     bool
	compression         bool
}

func inspectCollectorWriteInterpMaskWithForce(rawWrite map[string]any, forceAll bool) collectorWriteInterpMask {
	if forceAll {
		return collectorWriteInterpMask{
			streamPoolSize:      true,
			connectionPoolSize:  true,
			maxInflightRequests: true,
			maxRequestBytes:     true,
			compression:         true,
		}
	}
	return inspectCollectorWriteInterpMask(rawWrite)
}

func inspectCollectorWriteInterpMask(rawWrite map[string]any) collectorWriteInterpMask {
	var mask collectorWriteInterpMask
	if rawWrite == nil {
		return mask
	}
	hasEnvRef := func(key string) bool {
		s, ok := rawWrite[key].(string)
		return ok && hasUnescapedConfmapInterpolation(s)
	}
	mask.streamPoolSize = hasEnvRef("stream_pool_size")
	mask.connectionPoolSize = hasEnvRef("connection_pool_size")
	mask.maxInflightRequests = hasEnvRef("max_inflight_requests")
	mask.maxRequestBytes = hasEnvRef("max_request_bytes")
	mask.compression = hasEnvRef("compression")
	return mask
}

type interpolatedFieldRedaction struct {
	parts        []string
	fieldPath    string
	leafKey      string
	replacements []string
	isMapKey     bool
}

type invalidKeyACNode struct {
	termSegs int
	fail     *invalidKeyACNode
	dictFail *invalidKeyACNode
	children map[string]*invalidKeyACNode
}

type newlineInvalidKeyEntry struct {
	lines []string
}

type interpolatedInvalidKeyGroup struct {
	parts                []string
	keySet               map[string]struct{}
	multiAC              *invalidKeyACNode
	maxCommaSpan         int
	newlineEntries       []newlineInvalidKeyEntry
	bridgeNewlineEntries []newlineInvalidKeyEntry
	maxKeyNewlines       int
}

var bigQueryConfigTopLevelSections = map[string]struct{}{
	"auto_create":      {},
	"credentials":      {},
	"dataset":          {},
	"endpoint":         {},
	"kms_key_name":     {},
	"labels":           {},
	"limits":           {},
	"location":         {},
	"logs":             {},
	"metrics":          {},
	"offload":          {},
	"project":          {},
	"quarantine":       {},
	"redaction":        {},
	"retry_on_failure": {},
	"sending_queue":    {},
	"timeout":          {},
	"traces":           {},
	"write":            {},
}

func newPairAdder(pairs *[]string, seen map[string]struct{}) func(string, string) {
	return func(target, replacement string) {
		if target == "" {
			return
		}
		if _, dup := seen[target]; dup {
			return
		}
		seen[target] = struct{}{}
		*pairs = append(*pairs, target, replacement)
	}
}

func appendNumericErrorRedactions(formatted, rawTrimmed string, addPair func(string, string)) {
	for _, tok := range []string{formatted, rawTrimmed} {
		if tok == "" {
			continue
		}
		addPair("("+tok+")", "([REDACTED])")
		addPair("got "+tok, "got [REDACTED]")
		addPair("found "+tok, "found [REDACTED]")
		addPair("'"+tok+"'", "'[REDACTED]'")
	}
}

func appendFloatNumericRedactions(f float64, formatted, rawTrimmed string, addPair func(string, string)) {
	appendNumericErrorRedactions(formatted, rawTrimmed, addPair)
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return
	}
	trunc := math.Trunc(f)
	// float64(math.MaxInt64) rounds up to 2^63, which overflows int64 on conversion.
	const minInt64Float = -0x1p63
	const maxInt64FloatExclusive = 0x1p63
	if trunc >= minInt64Float && trunc < maxInt64FloatExclusive {
		appendNumericErrorRedactions(strconv.FormatInt(int64(trunc), 10), "", addPair)
	}
}

func appendFormattedScalarTokens(s string, addPair func(string, string)) {
	if s == "" {
		return
	}
	addPair(strconv.Quote(s), "[REDACTED]")
	addPair("'"+s+"'", "'[REDACTED]'")
	addPair("("+s+")", "([REDACTED])")
	addPair("got "+s, "got [REDACTED]")
	addPair("found "+s, "found [REDACTED]")
}

func appendResolvedScalarRedactions(resolvedNode any, addPair func(string, string)) {
	switch rv := resolvedNode.(type) {
	case nil:
		appendFormattedScalarTokens("<nil>", addPair)
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(rv)) {
			appendResolvedScalarRedactions(rv[k], addPair)
		}
	case map[any]any:
		items, _ := sortedAnyYAMLMapEntries(rv)
		for _, item := range items {
			appendResolvedScalarRedactions(item.val, addPair)
		}
	case []any:
		for _, elem := range rv {
			appendResolvedScalarRedactions(elem, addPair)
		}
	case []string:
		for _, elem := range rv {
			appendResolvedScalarRedactions(elem, addPair)
		}
	case string:
		addQuotedForms := func(tok string) {
			if tok == "" {
				return
			}
			addPair(strconv.Quote(tok), "[REDACTED]")
			addPair("'"+tok+"'", "'[REDACTED]'")
			if strings.ContainsAny(tok, "\r\n") {
				// Go's time.ParseDuration quotes strings with raw newlines/CRs rather
				// than backslash escapes, so register raw-quoted tokens for multiline scrubbing.
				addPair(`"`+tok+`"`, "[REDACTED]")
			}
		}
		addStringVariants := func(s string) {
			addQuotedForms(s)
			if trimmedTok := strings.TrimSpace(s); trimmedTok != "" && trimmedTok != s {
				addQuotedForms(trimmedTok)
			}
			if lowerTok := strings.ToLower(s); lowerTok != s {
				addQuotedForms(lowerTok)
				if trimmedLower := strings.TrimSpace(lowerTok); trimmedLower != "" && trimmedLower != lowerTok {
					addQuotedForms(trimmedLower)
				}
			}
		}
		addStringVariants(rv)
		if beforeSlash, afterSlash, hasSlash := strings.Cut(rv, "/"); hasSlash {
			// Register component.ID UnmarshalText type/name segments (e.g.
			// "'encoding' in \"route alpha\" id: invalid character(s) in name \"route alpha\"").
			addStringVariants(beforeSlash)
			addStringVariants(afterSlash)
		}
		trimmed := strings.TrimSpace(rv)
		if trimmed == "" {
			return
		}
		if d, err := time.ParseDuration(trimmed); err == nil {
			ds := d.String()
			addPair("("+ds+")", "([REDACTED])")
			addPair("got "+ds, "got [REDACTED]")
			addPair("found "+ds, "found [REDACTED]")
			appendNumericErrorRedactions(strconv.FormatInt(int64(d), 10), "", addPair)
		}
		if n, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			appendNumericErrorRedactions(strconv.FormatInt(n, 10), trimmed, addPair)
		} else if u, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
			appendNumericErrorRedactions(strconv.FormatUint(u, 10), trimmed, addPair)
		} else if f, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			appendFloatNumericRedactions(f, strconv.FormatFloat(f, 'g', -1, 64), trimmed, addPair)
		}
	case int, int32, int64, uint, uint32, uint64:
		appendNumericErrorRedactions(fmt.Sprint(rv), "", addPair)
	case float32:
		appendFloatNumericRedactions(float64(rv), fmt.Sprint(rv), "", addPair)
	case float64:
		appendFloatNumericRedactions(rv, fmt.Sprint(rv), "", addPair)
	case bool:
		addPair("("+strconv.FormatBool(rv)+")", "([REDACTED])")
	case time.Time:
		appendFormattedScalarTokens(rv.String(), addPair)
	default:
		appendFormattedScalarTokens(fmt.Sprint(rv), addPair)
	}
}

func normalizeSliceAny(v any) ([]any, bool) {
	switch s := v.(type) {
	case []any:
		return s, true
	case []string:
		out := make([]any, len(s))
		for i, item := range s {
			out[i] = item
		}
		return out, true
	default:
		return nil, false
	}
}

type yamlAnyKeyEntry struct {
	rawKey  any
	strKey  string
	typeStr string
	val     any
}

func sortedAnyYAMLMapEntries(m map[any]any) ([]yamlAnyKeyEntry, error) {
	items := make([]yamlAnyKeyEntry, 0, len(m))
	for k, val := range m {
		items = append(items, yamlAnyKeyEntry{
			rawKey:  k,
			strKey:  fmt.Sprint(k),
			typeStr: fmt.Sprintf("%T", k),
			val:     val,
		})
	}
	slices.SortFunc(items, func(a, b yamlAnyKeyEntry) int {
		if c := strings.Compare(a.strKey, b.strKey); c != 0 {
			return c
		}
		if c := strings.Compare(a.typeStr, b.typeStr); c != 0 {
			return c
		}
		return strings.Compare(fmt.Sprintf("%v", a.val), fmt.Sprintf("%v", b.val))
	})
	return items, nil
}

// rejectCollidingYAMLMapKeys walks v deterministically and fails closed if any
// map[any]any contains distinct keys whose string representations collide (for
// example int(1) and float64(1.0), or multiple NaN keys). Errors are value-free.
func rejectCollidingYAMLMapKeys(v any, pathDesc string, includeChildPaths bool) error {
	switch tv := v.(type) {
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(tv)) {
			childPath := pathDesc
			if includeChildPaths && !hasUnescapedConfmapInterpolation(k) {
				if childPath == "" {
					childPath = k
				} else {
					childPath += "." + k
				}
			}
			if err := rejectCollidingYAMLMapKeys(tv[k], childPath, includeChildPaths); err != nil {
				return err
			}
		}
	case map[any]any:
		items, _ := sortedAnyYAMLMapEntries(tv)
		seen := make(map[string]struct{}, len(items))
		for _, item := range items {
			if _, dup := seen[item.strKey]; dup {
				if pathDesc != "" && pathDesc != "collector YAML config" {
					return fmt.Errorf("collector config at %s contains ambiguous duplicate map keys", pathDesc)
				}
				return errors.New("collector YAML config contains ambiguous duplicate map keys")
			}
			seen[item.strKey] = struct{}{}
		}
		for _, item := range items {
			childPath := pathDesc
			if includeChildPaths && !hasUnescapedConfmapInterpolation(item.strKey) {
				if childPath == "" {
					childPath = item.strKey
				} else {
					childPath += "." + item.strKey
				}
			}
			if err := rejectCollidingYAMLMapKeys(item.val, childPath, includeChildPaths); err != nil {
				return err
			}
		}
	case []any:
		for idx, elem := range tv {
			childPath := pathDesc
			if includeChildPaths {
				childPath = fmt.Sprintf("%s[%d]", pathDesc, idx)
			}
			if err := rejectCollidingYAMLMapKeys(elem, childPath, includeChildPaths); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizeMapStringAny(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			strKey := fmt.Sprint(k)
			if _, dup := out[strKey]; dup {
				// Never silently collapse colliding non-string YAML keys.
				return nil, false
			}
			out[strKey] = val
		}
		return out, true
	default:
		return nil, false
	}
}

func containsInterpolation(node any) bool {
	if node == nil {
		return false
	}
	if s, ok := node.(string); ok {
		return hasUnescapedConfmapInterpolation(s)
	}
	if sl, ok := normalizeSliceAny(node); ok {
		return slices.ContainsFunc(sl, containsInterpolation)
	}
	switch mp := node.(type) {
	case map[string]any:
		for k, v := range mp {
			if hasUnescapedConfmapInterpolation(k) || containsInterpolation(v) {
				return true
			}
		}
	case map[any]any:
		for k, v := range mp {
			if hasUnescapedConfmapInterpolation(fmt.Sprint(k)) || containsInterpolation(v) {
				return true
			}
		}
	}
	return false
}

func addInterpolatedEntry(pathParts []string, entries *[]interpolatedFieldRedaction, isMapKey bool, collect func(func(string, string))) {
	var pairs []string
	if collect != nil {
		seen := make(map[string]struct{})
		collect(newPairAdder(&pairs, seen))
	}
	if len(pairs) == 0 {
		return
	}
	var parts []string
	var fieldPath, leafKey string
	if len(pathParts) > 0 {
		parts = slices.Clone(pathParts)
		fieldPath = strings.Join(parts, ".")
		leafKey = parts[len(parts)-1]
	}
	*entries = append(*entries, interpolatedFieldRedaction{
		parts:        parts,
		fieldPath:    fieldPath,
		leafKey:      leafKey,
		replacements: pairs,
		isMapKey:     isMapKey,
	})
}

func appendMapKeySegments(key string, dst []string) []string {
	dst = append(dst, key)
	if strings.Contains(key, "::") {
		for _, seg := range appendNonEmptyConfmapSegments(nil, key) {
			if seg != "" && seg != key {
				dst = append(dst, seg)
			}
		}
	}
	return dst
}

func appendMapKeyBracketEntry(pathParts []string, mapKey string, entries *[]interpolatedFieldRedaction) {
	if mapKey == "" {
		return
	}
	parentPath := strings.Join(pathParts, ".")
	childParts := append(slices.Clone(pathParts), mapKey)
	keyForms := appendMapKeySegments(mapKey, nil)
	addInterpolatedEntry(childParts, entries, true, func(addPair func(string, string)) {
		for _, ik := range keyForms {
			if parentPath != "" {
				addPair(parentPath+"["+ik+"]", parentPath+"[[REDACTED]]")
			}
			addPair("["+ik+"]", "[[REDACTED]]")
			addPair(strconv.Quote(ik), "[REDACTED]")
			addPair("'"+ik+"'", "'[REDACTED]'")
		}
	})
}

func buildInvalidKeyACFailLinks(root *invalidKeyACNode) {
	if root == nil || len(root.children) == 0 {
		return
	}
	queue := make([]*invalidKeyACNode, 0, len(root.children))
	for _, seg := range slices.Sorted(maps.Keys(root.children)) {
		child := root.children[seg]
		child.fail = root
		queue = append(queue, child)
	}
	for head := 0; head < len(queue); head++ {
		u := queue[head]
		for _, seg := range slices.Sorted(maps.Keys(u.children)) {
			v := u.children[seg]
			f := u.fail
			for f != nil && f.children[seg] == nil {
				f = f.fail
			}
			if f == nil {
				v.fail = root
			} else {
				v.fail = f.children[seg]
			}
			if v.fail.termSegs > 0 {
				v.dictFail = v.fail
			} else {
				v.dictFail = v.fail.dictFail
			}
			queue = append(queue, v)
		}
	}
}

func appendInvalidKeyGroup(pathParts []string, keys []string, groups *[]interpolatedInvalidKeyGroup) {
	appendInvalidKeyGroupWithBridgeKeys(pathParts, keys, nil, groups)
}

func appendInvalidKeyGroupWithBridgeKeys(pathParts []string, keys, bridgeKeys []string, groups *[]interpolatedInvalidKeyGroup) {
	if len(keys) == 0 {
		return
	}
	keySet := make(map[string]struct{}, len(keys))
	var multiAC *invalidKeyACNode
	maxCommaSpan := 1
	var newlineKeys []string
	maxKeyNewlines := 0
	for _, k := range keys {
		if k == "" {
			continue
		}
		if _, dup := keySet[k]; dup {
			continue
		}
		keySet[k] = struct{}{}
		if strings.Contains(k, ", ") {
			segCount := strings.Count(k, ", ") + 1
			maxCommaSpan = max(maxCommaSpan, segCount)
			if multiAC == nil {
				multiAC = &invalidKeyACNode{}
			}
			node := multiAC
			for seg := range strings.SplitSeq(k, ", ") {
				if node.children == nil {
					node.children = make(map[string]*invalidKeyACNode)
				}
				child := node.children[seg]
				if child == nil {
					child = &invalidKeyACNode{}
					node.children[seg] = child
				}
				node = child
			}
			node.termSegs = segCount
		}
		if strings.ContainsRune(k, '\n') {
			newlineKeys = append(newlineKeys, k)
			maxKeyNewlines = max(maxKeyNewlines, strings.Count(k, "\n"))
		}
	}
	if len(keySet) == 0 {
		return
	}
	var bridgeNewlineKeys []string
	var bridgeSeen map[string]struct{}
	for _, bk := range bridgeKeys {
		if bk == "" || !strings.ContainsRune(bk, '\n') {
			continue
		}
		if _, isSecret := keySet[bk]; isSecret {
			continue
		}
		if bridgeSeen == nil {
			bridgeSeen = make(map[string]struct{})
		}
		if _, dup := bridgeSeen[bk]; dup {
			continue
		}
		bridgeSeen[bk] = struct{}{}
		bridgeNewlineKeys = append(bridgeNewlineKeys, bk)
		maxKeyNewlines = max(maxKeyNewlines, strings.Count(bk, "\n"))
	}
	buildInvalidKeyACFailLinks(multiAC)
	newlineEntries := make([]newlineInvalidKeyEntry, len(newlineKeys))
	for i, nk := range newlineKeys {
		newlineEntries[i] = newlineInvalidKeyEntry{lines: strings.Split(nk, "\n")}
	}
	bridgeNewlineEntries := make([]newlineInvalidKeyEntry, len(bridgeNewlineKeys))
	for i, bk := range bridgeNewlineKeys {
		bridgeNewlineEntries[i] = newlineInvalidKeyEntry{lines: strings.Split(bk, "\n")}
	}
	*groups = append(*groups, interpolatedInvalidKeyGroup{
		parts:                slices.Clone(pathParts),
		keySet:               keySet,
		multiAC:              multiAC,
		maxCommaSpan:         maxCommaSpan,
		newlineEntries:       newlineEntries,
		bridgeNewlineEntries: bridgeNewlineEntries,
		maxKeyNewlines:       maxKeyNewlines,
	})
}

func normalizeNestedMapsToStringKeys(v any) (any, error) {
	switch tv := v.(type) {
	case map[string]any:
		if tv == nil {
			return nil, nil
		}
		out := make(map[string]any, len(tv))
		for _, k := range slices.Sorted(maps.Keys(tv)) {
			normVal, err := normalizeNestedMapsToStringKeys(tv[k])
			if err != nil {
				return nil, err
			}
			out[k] = normVal
		}
		return out, nil
	case map[any]any:
		if tv == nil {
			return nil, nil
		}
		items, _ := sortedAnyYAMLMapEntries(tv)
		out := make(map[string]any, len(items))
		for _, item := range items {
			if _, dup := out[item.strKey]; dup {
				return nil, errors.New("collector config contains ambiguous duplicate map keys")
			}
			normVal, err := normalizeNestedMapsToStringKeys(item.val)
			if err != nil {
				return nil, err
			}
			out[item.strKey] = normVal
		}
		return out, nil
	case []any:
		if tv == nil {
			return nil, nil
		}
		out := make([]any, len(tv))
		for i, elem := range tv {
			normElem, err := normalizeNestedMapsToStringKeys(elem)
			if err != nil {
				return nil, err
			}
			out[i] = normElem
		}
		return out, nil
	default:
		return v, nil
	}
}

func collectOrderedYAMLMapBuckets(node any) (keys []string, buckets map[string][]any, ok bool) {
	switch m := node.(type) {
	case map[string]any:
		keys = slices.Sorted(maps.Keys(m))
		buckets = make(map[string][]any, len(m))
		for _, k := range keys {
			buckets[k] = []any{m[k]}
		}
		return keys, buckets, true
	case map[any]any:
		items, _ := sortedAnyYAMLMapEntries(m)
		buckets = make(map[string][]any, len(items))
		for _, item := range items {
			if _, exists := buckets[item.strKey]; !exists {
				keys = append(keys, item.strKey)
			}
			buckets[item.strKey] = append(buckets[item.strKey], item.val)
		}
		return keys, buckets, true
	default:
		return nil, nil, false
	}
}

func appendFormattedContainerRedactions(resolvedNode any, addPair func(string, string)) {
	if resolvedNode == nil {
		return
	}
	cands := []any{resolvedNode}
	if norm, err := normalizeNestedMapsToStringKeys(resolvedNode); err == nil {
		cands = append(cands, norm)
	}
	for _, cand := range cands {
		formatted := fmt.Sprint(cand)
		if formatted == "" {
			continue
		}
		addPair(strconv.Quote(formatted), "[REDACTED]")
		addPair("'"+formatted+"'", "'[REDACTED]'")
	}
}

func isCSVStringToSlicePath(pathParts []string) bool {
	if len(pathParts) == 0 {
		return false
	}
	if slices.Contains(pathParts[:len(pathParts)-1], "labels") {
		return false
	}
	leaf := pathParts[len(pathParts)-1]
	parent := ""
	if len(pathParts) >= 2 {
		parent = pathParts[len(pathParts)-2]
	}
	switch leaf {
	case "clustering":
		return parent == "traces" || parent == "logs" || parent == "metrics"
	case "columns":
		return parent == "search_index"
	case "impersonate_delegates":
		return parent == "credentials"
	case "blocked_keys", "blocked_key_patterns", "blocked_value_patterns":
		return parent == "redaction"
	case "metadata_keys":
		return parent == "partition"
	case "output_paths":
		return true
	default:
		return false
	}
}

func appendSliceStringElemRedactions(s string, addPair func(string, string)) {
	if s == "" {
		return
	}
	addQuotedForms := func(tok string) {
		if tok == "" {
			return
		}
		addPair(strconv.Quote(tok), "[REDACTED]")
		addPair("'"+tok+"'", "'[REDACTED]'")
		if strings.ContainsAny(tok, "\r\n") {
			addPair(`"`+tok+`"`, "[REDACTED]")
		}
	}
	addVariants := func(val string) {
		addQuotedForms(val)
		if trimmedTok := strings.TrimSpace(val); trimmedTok != "" && trimmedTok != val {
			addQuotedForms(trimmedTok)
		}
		if lowerTok := strings.ToLower(val); lowerTok != val {
			addQuotedForms(lowerTok)
			if trimmedLower := strings.TrimSpace(lowerTok); trimmedLower != "" && trimmedLower != lowerTok {
				addQuotedForms(trimmedLower)
			}
		}
	}
	addVariants(s)
	if beforeSlash, afterSlash, hasSlash := strings.Cut(s, "/"); hasSlash {
		addVariants(beforeSlash)
		addVariants(afterSlash)
	}
}

func parseConfmapTemplateParts(raw string) (lits, exprs []string, ok bool) {
	var curLit strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] != '$' {
			curLit.WriteByte(raw[i])
			i++
			continue
		}
		if i+1 < len(raw) && raw[i+1] == '$' {
			curLit.WriteByte('$')
			i += 2
			continue
		}
		if i+1 < len(raw) && raw[i+1] == '{' {
			closeIdx := findMatchingConfmapCloseBrace(raw, i+2)
			if closeIdx < 0 {
				return nil, nil, false
			}
			lits = append(lits, curLit.String())
			curLit.Reset()
			exprs = append(exprs, raw[i:closeIdx+1])
			i = closeIdx + 1
			continue
		}
		curLit.WriteByte('$')
		i++
	}
	lits = append(lits, curLit.String())
	return lits, exprs, true
}

func computeEnvTaintedBytes(rawStr, resolvedStr string, forceAll bool, lookupEnv func(string) (string, bool)) []bool {
	tainted := make([]bool, len(resolvedStr))
	if len(tainted) == 0 {
		return tainted
	}
	fillRange := func(start, end int) {
		for i := max(0, start); i < min(len(tainted), end); i++ {
			tainted[i] = true
		}
	}
	if forceAll {
		fillRange(0, len(tainted))
		return tainted
	}
	lits, exprs, ok := parseConfmapTemplateParts(rawStr)
	if !ok || len(exprs) == 0 {
		if hasUnescapedConfmapInterpolation(rawStr) {
			fillRange(0, len(tainted))
		}
		return tainted
	}
	if lookupEnv != nil {
		pos := 0
		matched := strings.HasPrefix(resolvedStr, lits[0])
		if matched {
			pos = len(lits[0])
			for j, expr := range exprs {
				expVal, err := resolveCollectorEnvStringWithOptions(expr, lookupEnv, true)
				if err != nil || !strings.HasPrefix(resolvedStr[pos:], expVal) ||
					!strings.HasPrefix(resolvedStr[pos+len(expVal):], lits[j+1]) {
					matched = false
					break
				}
				fillRange(pos, pos+len(expVal))
				pos += len(expVal) + len(lits[j+1])
			}
		}
		if matched && pos == len(resolvedStr) {
			return tainted
		}
		clear(tainted)
	}
	if len(exprs) == 1 &&
		strings.HasPrefix(resolvedStr, lits[0]) &&
		strings.HasSuffix(resolvedStr, lits[1]) &&
		len(lits[0])+len(lits[1]) <= len(resolvedStr) {
		fillRange(len(lits[0]), len(resolvedStr)-len(lits[1]))
		return tainted
	}
	startBound := 0
	if strings.HasPrefix(resolvedStr, lits[0]) {
		startBound = len(lits[0])
	}
	endBound := len(resolvedStr)
	if lastLit := lits[len(lits)-1]; lastLit != "" && len(resolvedStr)-startBound >= len(lastLit) && strings.HasSuffix(resolvedStr, lastLit) {
		endBound = len(resolvedStr) - len(lastLit)
	}
	if len(exprs) >= 2 && startBound <= endBound {
		pos := startBound
		var midAnchors [][2]int
		anchorsOK := true
		for j := 1; j < len(lits)-1; j++ {
			mid := lits[j]
			if mid == "" {
				continue
			}
			idx := strings.Index(resolvedStr[pos:endBound], mid)
			if idx < 0 {
				anchorsOK = false
				break
			}
			absIdx := pos + idx
			// Require uniqueness in the remaining window so env content cannot spoof a literal anchor.
			if strings.Contains(resolvedStr[absIdx+1:endBound], mid) {
				anchorsOK = false
				break
			}
			midAnchors = append(midAnchors, [2]int{absIdx, absIdx + len(mid)})
			pos = absIdx + len(mid)
		}
		if anchorsOK {
			cur := startBound
			for _, a := range midAnchors {
				fillRange(cur, a[0])
				cur = a[1]
			}
			fillRange(cur, endBound)
			return tainted
		}
	}
	fillRange(startBound, endBound)
	return tainted
}

func maskTaintedStringRuns(resolvedStr string, tainted []bool) string {
	var b strings.Builder
	b.Grow(len(resolvedStr))
	for i := 0; i < len(resolvedStr); {
		if i < len(tainted) && tainted[i] {
			b.WriteString("[REDACTED]")
			for i < len(resolvedStr) && i < len(tainted) && tainted[i] {
				i++
			}
			continue
		}
		start := i
		for i < len(resolvedStr) && (i >= len(tainted) || !tainted[i]) {
			i++
		}
		b.WriteString(resolvedStr[start:i])
	}
	return b.String()
}

func splitCSVElementsWithEnvMask(rawStr, resolvedStr string, forceAll bool, lookupEnv func(string) (string, bool)) (cols []string, envMask []bool, envMaskedStr string) {
	tainted := computeEnvTaintedBytes(rawStr, resolvedStr, forceAll, lookupEnv)
	envMaskedStr = maskTaintedStringRuns(resolvedStr, tainted)
	pos := 0
	for {
		rel := strings.IndexByte(resolvedStr[pos:], ',')
		var end int
		if rel < 0 {
			end = len(resolvedStr)
		} else {
			end = pos + rel
		}
		cols = append(cols, resolvedStr[pos:end])
		isEnv := false
		for bi := pos; bi < end && bi < len(tainted); bi++ {
			if tainted[bi] {
				isEnv = true
				break
			}
		}
		envMask = append(envMask, isEnv)
		if rel < 0 {
			break
		}
		pos = end + 1
	}
	return cols, envMask, envMaskedStr
}

func appendCSVStringToSliceRedactions(raw string, addPair func(string, string)) {
	cols := strings.Split(raw, ",")
	envMask := make([]bool, len(cols))
	for i := range envMask {
		envMask[i] = true
	}
	appendCSVStringToSliceRedactionsMasked(cols, envMask, addPair)
}

func appendCSVStringToSliceRedactionsMasked(cols []string, envMask []bool, addPair func(string, string)) {
	if len(cols) == 0 {
		return
	}
	hasEnv := false
	allEnv := true
	for i := range cols {
		if i < len(envMask) && envMask[i] {
			hasEnv = true
		} else {
			allEnv = false
		}
	}
	if !hasEnv {
		return
	}
	fullBracketed := "[" + strings.Join(cols, " ") + "]"
	if allEnv {
		addPair("("+fullBracketed+")", "([REDACTED])")
		addPair(strconv.Quote(fullBracketed), "[REDACTED]")
		addPair("'"+fullBracketed+"'", "'[REDACTED]'")
		addPair(fullBracketed, "[REDACTED]")
	} else {
		maskedCols := make([]string, len(cols))
		for i, col := range cols {
			if i < len(envMask) && envMask[i] {
				maskedCols[i] = "[REDACTED]"
			} else {
				maskedCols[i] = col
			}
		}
		maskedBracketed := "[" + strings.Join(maskedCols, " ") + "]"
		addPair("("+fullBracketed+")", "("+maskedBracketed+")")
		addPair(strconv.Quote(fullBracketed), strconv.Quote(maskedBracketed))
		addPair("'"+fullBracketed+"'", "'"+maskedBracketed+"'")
		addPair(fullBracketed, maskedBracketed)
	}
	for i, col := range cols {
		if i >= len(envMask) || !envMask[i] || col == "" {
			continue
		}
		appendSliceStringElemRedactions(col, addPair)
		if trimmed := strings.TrimSpace(col); trimmed != "" && trimmed != col {
			appendSliceStringElemRedactions(trimmed, addPair)
		}
	}
}

func appendInterpolatedSliceEntries(rawSlice []any, resolvedNode any, pathParts []string, entries *[]interpolatedFieldRedaction, invalidGroups *[]interpolatedInvalidKeyGroup, forceAll bool, lookupEnv func(string) (string, bool)) {
	resSlice, hasResSlice := normalizeSliceAny(resolvedNode)
	if !hasResSlice {
		return
	}
	if len(resSlice) > 0 && (forceAll || slices.ContainsFunc(rawSlice, containsInterpolation)) {
		sliceVariants := [][]any{resSlice}
		if normAny, normErr := normalizeNestedMapsToStringKeys(resSlice); normErr == nil {
			if normSlice, ok := normalizeSliceAny(normAny); ok && normSlice != nil {
				sliceVariants = append(sliceVariants, normSlice)
			}
		}
		addInterpolatedEntry(pathParts, entries, false, func(addPair func(string, string)) {
			for _, variant := range sliceVariants {
				fullParts := make([]string, len(variant))
				for i, elem := range variant {
					fullParts[i] = fmt.Sprint(elem)
				}
				fullBracketed := "[" + strings.Join(fullParts, " ") + "]"
				if forceAll || rawSlice == nil || len(rawSlice) != len(variant) {
					addPair("("+fullBracketed+")", "([REDACTED])")
					addPair(strconv.Quote(fullBracketed), "[REDACTED]")
					addPair("'"+fullBracketed+"'", "'[REDACTED]'")
					addPair(fullBracketed, "[REDACTED]")
					continue
				}
				maskedParts := make([]string, len(variant))
				changed := false
				for i := range variant {
					if containsInterpolation(rawSlice[i]) {
						maskedParts[i] = "[REDACTED]"
						changed = true
					} else {
						maskedParts[i] = fullParts[i]
					}
				}
				if !changed {
					continue
				}
				maskedBracketed := "[" + strings.Join(maskedParts, " ") + "]"
				addPair("("+fullBracketed+")", "("+maskedBracketed+")")
				addPair(strconv.Quote(fullBracketed), strconv.Quote(maskedBracketed))
				addPair("'"+fullBracketed+"'", "'"+maskedBracketed+"'")
				addPair(fullBracketed, maskedBracketed)
			}
		})
	}
	if forceAll || rawSlice == nil {
		for _, resElem := range resSlice {
			appendInterpolatedErrorEntriesWithOptions(nil, resElem, pathParts, entries, invalidGroups, true, true, lookupEnv)
		}
		return
	}
	for i, rawElem := range rawSlice {
		var resElem any
		if i < len(resSlice) {
			resElem = resSlice[i]
		}
		appendInterpolatedErrorEntriesWithOptions(rawElem, resElem, pathParts, entries, invalidGroups, false, true, lookupEnv)
	}
}

func appendInterpolatedErrorEntriesWithOptions(rawNode, resolvedNode any, pathParts []string, entries *[]interpolatedFieldRedaction, invalidGroups *[]interpolatedInvalidKeyGroup, forceAll, fromSlice bool, lookupEnv func(string) (string, bool)) {
	if rawNode == nil && !forceAll {
		return
	}
	if rawKeys, rawBuckets, ok := collectOrderedYAMLMapBuckets(rawNode); ok {
		resKeys, resBuckets, isResMap := collectOrderedYAMLMapBuckets(resolvedNode)
		if len(pathParts) > 0 && isResMap && len(resBuckets) > 0 && (forceAll || containsInterpolation(rawNode)) {
			addInterpolatedEntry(pathParts, entries, false, func(addPair func(string, string)) {
				appendFormattedContainerRedactions(resolvedNode, addPair)
			})
		}
		rawHasInterpKey := false
		for _, k := range rawKeys {
			if hasUnescapedConfmapInterpolation(k) {
				rawHasInterpKey = true
				break
			}
		}
		var groupInvalidKeys []string
		var groupBridgeKeys []string
		matchedResKeys := make(map[string]struct{}, len(rawKeys))
		for _, k := range rawKeys {
			rawVals := rawBuckets[k]
			keyIsInterp := hasUnescapedConfmapInterpolation(k)
			childForceAll := forceAll || keyIsInterp
			isCollidingBucket := len(rawVals) > 1 || len(resBuckets[k]) > 1
			bucketHasInterp := childForceAll || slices.ContainsFunc(rawVals, containsInterpolation)
			resVals, found := resBuckets[k]
			if found {
				matchedResKeys[k] = struct{}{}
				if (childForceAll || (isCollidingBucket && bucketHasInterp)) && k != "" {
					groupInvalidKeys = appendMapKeySegments(k, groupInvalidKeys)
					appendMapKeyBracketEntry(pathParts, k, entries)
				} else if strings.ContainsRune(k, '\n') {
					groupBridgeKeys = appendMapKeySegments(k, groupBridgeKeys)
				}
			}
			childParts := append(slices.Clone(pathParts), k)
			// Never silently collapse colliding non-string keys: iterate every
			// raw/resolved value in the bucket and propagate bucket-level
			// interpolation across colliding entries so literal siblings never mask
			// interpolated siblings.
			if isCollidingBucket {
				if bucketHasInterp && len(pathParts) > 0 && len(resVals) > 0 {
					addInterpolatedEntry(pathParts, entries, false, func(addPair func(string, string)) {
						for _, resChild := range resVals {
							appendResolvedScalarRedactions(resChild, addPair)
						}
					})
				}
				for _, rv := range rawVals {
					for _, resChild := range resVals {
						appendInterpolatedErrorEntriesWithOptions(rv, resChild, childParts, entries, invalidGroups, bucketHasInterp, false, lookupEnv)
					}
					if len(resVals) == 0 {
						appendInterpolatedErrorEntriesWithOptions(rv, nil, childParts, entries, invalidGroups, bucketHasInterp, false, lookupEnv)
					}
				}
				continue
			}
			var resChild any
			if len(resVals) == 1 {
				resChild = resVals[0]
			}
			appendInterpolatedErrorEntriesWithOptions(rawVals[0], resChild, childParts, entries, invalidGroups, childForceAll, false, lookupEnv)
		}
		if isResMap && (forceAll || rawHasInterpKey) {
			for _, rk := range resKeys {
				if _, seen := matchedResKeys[rk]; seen {
					continue
				}
				if rk != "" {
					groupInvalidKeys = appendMapKeySegments(rk, groupInvalidKeys)
					appendMapKeyBracketEntry(pathParts, rk, entries)
				}
				childParts := append(slices.Clone(pathParts), rk)
				for _, resChild := range resBuckets[rk] {
					appendInterpolatedErrorEntriesWithOptions(nil, resChild, childParts, entries, invalidGroups, true, false, lookupEnv)
				}
			}
		}
		appendInvalidKeyGroupWithBridgeKeys(pathParts, groupInvalidKeys, groupBridgeKeys, invalidGroups)
		return
	}
	if rawSlice, ok := normalizeSliceAny(rawNode); ok {
		appendInterpolatedSliceEntries(rawSlice, resolvedNode, pathParts, entries, invalidGroups, forceAll, lookupEnv)
		return
	}
	var rawStrVal string
	if rawVal, ok := rawNode.(string); ok {
		rawStrVal = rawVal
		if !forceAll && !hasUnescapedConfmapInterpolation(rawVal) {
			return
		}
	} else if !forceAll {
		return
	}
	if _, resBuckets, isMap := collectOrderedYAMLMapBuckets(resolvedNode); isMap {
		if len(resBuckets) > 0 {
			addInterpolatedEntry(pathParts, entries, false, func(addPair func(string, string)) {
				appendFormattedContainerRedactions(resolvedNode, addPair)
			})
		}
		appendInterpolatedErrorEntriesWithOptions(map[string]any{}, resolvedNode, pathParts, entries, invalidGroups, true, false, lookupEnv)
		return
	}
	if _, isSlice := normalizeSliceAny(resolvedNode); isSlice {
		appendInterpolatedSliceEntries(nil, resolvedNode, pathParts, entries, invalidGroups, true, lookupEnv)
		return
	}
	addInterpolatedEntry(pathParts, entries, false, func(addPair func(string, string)) {
		if isCSVStringToSlicePath(pathParts) {
			if resStr, ok := resolvedNode.(string); ok {
				if !fromSlice && resStr != "" {
					cols, envMask, envMaskedStr := splitCSVElementsWithEnvMask(rawStrVal, resStr, forceAll, lookupEnv)
					if envMaskedStr != resStr {
						addPair(strconv.Quote(resStr), strconv.Quote(envMaskedStr))
						addPair("'"+resStr+"'", "'"+envMaskedStr+"'")
					}
					appendCSVStringToSliceRedactionsMasked(cols, envMask, addPair)
				} else if fromSlice {
					appendSliceStringElemRedactions(resStr, addPair)
				}
				return
			}
			if fromSlice && resolvedNode != nil {
				appendSliceStringElemRedactions(fmt.Sprint(resolvedNode), addPair)
				return
			}
		}
		appendResolvedScalarRedactions(resolvedNode, addPair)
	})
}

func isPathIdentOrDotByte(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_' ||
		b == '.'
}

func containsExactPathToken(line, token string) bool {
	if token == "" {
		return false
	}
	start := 0
	for {
		idx := strings.Index(line[start:], token)
		if idx < 0 {
			return false
		}
		absIdx := start + idx
		endIdx := absIdx + len(token)
		leftOK := absIdx == 0 || !isPathIdentOrDotByte(line[absIdx-1])
		rightOK := endIdx == len(line) || !isPathIdentOrDotByte(line[endIdx])
		if leftOK && rightOK {
			return true
		}
		start = absIdx + 1
	}
}

func cutExporterErrorPrefix(s string) (string, bool) {
	s = strings.TrimPrefix(s, "Error: ")
	rest, ok := strings.CutPrefix(s, "exporters::")
	if !ok {
		return s, false
	}
	idxDouble := strings.Index(rest, "::")
	idxColonSpace := strings.Index(rest, ": ")
	switch {
	case idxDouble >= 0 && (idxColonSpace < 0 || idxDouble < idxColonSpace):
		return rest[idxDouble+2:], true
	case idxColonSpace >= 0:
		return rest[idxColonSpace+2:], true
	default:
		return s, false
	}
}

func extractLeadingTopLevelPath(s string) []string {
	end := 0
	for end < len(s) && isPathIdentOrDotByte(s[end]) {
		end++
	}
	if end == 0 {
		return nil
	}
	if end < len(s) {
		switch s[end] {
		case ' ', ':', '[':
		default:
			return nil
		}
	}
	pathStr := strings.TrimSuffix(s[:end], ".")
	parts := strings.Split(pathStr, ".")
	if len(parts) == 0 {
		return nil
	}
	if _, ok := bigQueryConfigTopLevelSections[parts[0]]; !ok {
		return nil
	}
	if parts[0] == "sending_queue" {
		if _, afterColon, hasColon := strings.Cut(s[end:], ":"); hasColon {
			afterColon = strings.TrimSpace(afterColon)
			if sub, _, ok := strings.Cut(afterColon, ":"); ok && isSubScopeToken(sub) {
				return []string{"sending_queue", sub}
			}
		}
	}
	return parts
}

func isSubScopeToken(tok string) bool {
	if tok == "" {
		return false
	}
	for i := 0; i < len(tok); i++ {
		b := tok[i]
		if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '_' {
			return false
		}
	}
	return true
}

func isKnownDirectSectionChild(tok string) bool {
	switch tok {
	case "batch", "backpressure", "keepalive", "search_index":
		return true
	default:
		return false
	}
}

func updateErrorBlockAndLineScope(line string, initialScope, blockScope []string) ([]string, []string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return blockScope, blockScope
	}
	if rest, ok := cutExporterErrorPrefix(trimmed); ok {
		trimmed = strings.TrimSpace(rest)
	} else {
		trimmed = strings.TrimPrefix(trimmed, "Error: ")
	}
	if afterBullet, ok := strings.CutPrefix(trimmed, "*"); ok && (afterBullet == "" || afterBullet[0] == ' ' || afterBullet[0] == '\t') {
		trimmed = strings.TrimSpace(afterBullet)
	}
	base := slices.Clone(initialScope)

	if len(trimmed) > 0 && trimmed[0] == '\'' {
		if endQuote := strings.IndexByte(trimmed[1:], '\''); endQuote >= 0 {
			sec := trimmed[1 : 1+endQuote]
			after := trimmed[2+endQuote:]
			if sec == "" {
				return blockScope, blockScope
			}
			if sec == "exporters" {
				return base, base
			}
			isContainer := strings.Contains(after, "decoding failed due to the following error(s):")
			secParts := strings.Split(sec, ".")
			if _, isTop := bigQueryConfigTopLevelSections[secParts[0]]; isTop {
				var next []string
				if len(base) > 0 && len(secParts) >= len(base) && slices.Equal(secParts[:len(base)], base) {
					next = slices.Clone(secParts)
				} else {
					next = append(slices.Clone(base), secParts...)
				}
				if isContainer {
					return next, next
				}
				return base, next
			}
			parentScope := blockScope
			if isContainer && isKnownDirectSectionChild(secParts[0]) && len(parentScope) > 1 {
				parentScope = parentScope[:1]
			}
			next := append(slices.Clone(parentScope), secParts...)
			if isContainer {
				return next, next
			}
			return blockScope, next
		}
	}

	if topParts := extractLeadingTopLevelPath(trimmed); len(topParts) > 0 {
		afterTop := strings.TrimPrefix(trimmed, strings.Join(topParts, "."))
		if !strings.HasPrefix(afterTop, ":") || !strings.Contains(trimmed, "' value expected ") {
			// Keep section block scope for top-level Validate() lines so indented/following
			// sub-section lines (e.g. "batch: ..." after "sending_queue: ...") stay scoped.
			sectionDepth := 1
			if topParts[0] == "sending_queue" && len(topParts) >= 2 && topParts[1] == "batch" {
				sectionDepth = 2
			}
			var nextBlock, nextLine []string
			if len(base) > 0 && slices.Equal(topParts[:1], base[:1]) {
				nextBlock = slices.Clone(topParts[:sectionDepth])
				nextLine = slices.Clone(topParts)
			} else {
				nextBlock = append(slices.Clone(base), topParts[:sectionDepth]...)
				nextLine = append(slices.Clone(base), topParts...)
			}
			return nextBlock, nextLine
		}
	}

	if !strings.Contains(trimmed, "' value expected ") {
		if subKey, _, ok := strings.Cut(trimmed, ":"); ok && isSubScopeToken(subKey) {
			if len(blockScope) > 0 {
				next := append(slices.Clone(blockScope[:1]), subKey)
				return next, next
			}
		}
	}

	return blockScope, blockScope
}

func ancestorsMatchScope(ancestors []string, line string, lineScope []string) bool {
	if len(ancestors) >= 2 && containsExactPathToken(line, strings.Join(ancestors, ".")) {
		return true
	}
	for _, anc := range ancestors {
		if slices.Contains(lineScope, anc) || containsExactPathToken(line, anc) {
			continue
		}
		return false
	}
	return true
}

type lineTokenMatchSets struct {
	quotedUnq    map[string]struct{}
	brackets     map[string]struct{}
	singleQuotes map[string]struct{}
	exactRuns    map[string]struct{}
	ancestorsOK  map[string]bool
}

func ancestorsMatchScopeCached(ancestors []string, line string, lineScope []string, cache map[string]bool) bool {
	if len(ancestors) == 0 {
		return true
	}
	if cache != nil {
		key := strings.Join(ancestors, "\x00")
		if ok, hit := cache[key]; hit {
			return ok
		}
		ok := ancestorsMatchScope(ancestors, line, lineScope)
		cache[key] = ok
		return ok
	}
	return ancestorsMatchScope(ancestors, line, lineScope)
}

func entryMatchesLineWithSets(entry interpolatedFieldRedaction, line string, lineScope []string, sets *lineTokenMatchSets) bool {
	if len(entry.parts) == 0 {
		return true
	}
	var ancCache map[string]bool
	if sets != nil {
		ancCache = sets.ancestorsOK
		if _, ok := sets.exactRuns[entry.fieldPath]; ok {
			return true
		}
		if len(entry.parts) >= 2 && ancestorsMatchScopeCached(entry.parts[:len(entry.parts)-1], line, lineScope, ancCache) {
			if _, ok := sets.exactRuns[entry.leafKey]; ok {
				ancestors := entry.parts[:len(entry.parts)-1]
				if len(lineScope) > len(ancestors) &&
					slices.Equal(lineScope[:len(ancestors)], ancestors) &&
					isKnownDirectSectionChild(lineScope[len(ancestors)]) {
					return false
				}
				return true
			}
			if _, ok := sets.quotedUnq[entry.leafKey]; ok {
				return true
			}
			if _, ok := sets.brackets[entry.leafKey]; ok {
				return true
			}
			if entry.isMapKey {
				if _, ok := sets.singleQuotes[entry.leafKey]; ok {
					return true
				}
			}
		}
	}
	if containsExactPathToken(line, entry.fieldPath) {
		return true
	}
	if len(entry.parts) >= 2 && entry.leafKey == "columns" {
		parentPath := strings.Join(entry.parts[:len(entry.parts)-1], ".")
		if containsExactPathToken(line, parentPath) {
			return true
		}
		if containsExactPathToken(line, "search_index") && ancestorsMatchScopeCached(entry.parts[:len(entry.parts)-2], line, lineScope, ancCache) {
			return true
		}
	}
	if containsExactPathToken(line, entry.leafKey) && ancestorsMatchScopeCached(entry.parts[:len(entry.parts)-1], line, lineScope, ancCache) {
		ancestors := entry.parts[:len(entry.parts)-1]
		if len(lineScope) > len(ancestors) &&
			slices.Equal(lineScope[:len(ancestors)], ancestors) &&
			isKnownDirectSectionChild(lineScope[len(ancestors)]) {
			return false
		}
		return true
	}
	if len(entry.parts) >= 2 {
		parentAncestors := entry.parts[:len(entry.parts)-1]
		if ancestorsMatchScopeCached(parentAncestors, line, lineScope, ancCache) {
			keyFirstLine, _, _ := strings.Cut(entry.leafKey, "\n")
			if strings.Contains(line, strconv.Quote(entry.leafKey)) ||
				(keyFirstLine != "" && strings.Contains(line, "["+keyFirstLine)) ||
				(entry.isMapKey && keyFirstLine != "" && strings.Contains(line, "'"+keyFirstLine+"'")) {
				return true
			}
		}
	}
	return false
}

func invalidKeyLastLineMatches(line, lastPattern string) bool {
	return line == lastPattern || strings.HasPrefix(line, lastPattern+", ")
}

func isNewlineInvalidKeyBridging(lines []string, li, end int, groups []interpolatedInvalidKeyGroup) bool {
	if end+1 >= len(lines) {
		return false
	}
	nextLine := lines[end+1]
	matchesEntry := func(entry newlineInvalidKeyEntry) bool {
		nkLines := entry.lines
		L := len(nkLines)
		if L < 2 {
			return false
		}
		lastIdx := L - 1
		for m := range lastIdx {
			if m+1 == lastIdx {
				if !invalidKeyLastLineMatches(nextLine, nkLines[lastIdx]) {
					continue
				}
			} else if nextLine != nkLines[m+1] {
				continue
			}
			startIdx := end - m
			endIdx := startIdx + lastIdx
			if startIdx < li || endIdx >= len(lines) {
				continue
			}
			if !strings.HasSuffix(lines[startIdx], nkLines[0]) {
				continue
			}
			allInteriorMatch := true
			for k := 1; k < lastIdx; k++ {
				if lines[startIdx+k] != nkLines[k] {
					allInteriorMatch = false
					break
				}
			}
			if allInteriorMatch && (m+1 == lastIdx || invalidKeyLastLineMatches(lines[endIdx], nkLines[lastIdx])) {
				return true
			}
		}
		return false
	}
	for _, grp := range groups {
		for _, entry := range grp.newlineEntries {
			if matchesEntry(entry) {
				return true
			}
		}
		for _, entry := range grp.bridgeNewlineEntries {
			if matchesEntry(entry) {
				return true
			}
		}
	}
	return false
}

type invalidKeyBridgeMatch struct {
	groupIdx int
	endIdx   int
}

type invalidKeyLineIndex struct {
	baseOffset     int
	isBoundary     []bool
	matchesByStart [][]invalidKeyBridgeMatch
}

// buildInvalidKeyLineIndex precomputes confmap boundary flags and multiline
// invalid-key bridge spans across lines[baseOffset:] in a single O(N) pass so
// callers processing many headers avoid repeated full-tail scans. Groups with
// maxKeyNewlines <= 0 contribute no bridge spans; non-boundary continuations
// are still tracked via isBoundary.
func buildInvalidKeyLineIndex(lines []string, baseOffset int, groups []interpolatedInvalidKeyGroup) *invalidKeyLineIndex {
	if baseOffset < 0 || baseOffset+1 >= len(lines) {
		return nil
	}
	nLines := len(lines) - baseOffset
	isBoundary := make([]bool, nLines)
	nextNonBlankHeader := true
	for p := len(lines) - 1; p > baseOffset; p-- {
		if strings.TrimSpace(lines[p]) != "" {
			nextNonBlankHeader = isStrictConfmapErrorHeaderLine(lines[p])
		}
		isBoundary[p-baseOffset] = nextNonBlankHeader
	}

	hasNewlineGroup := false
	for _, grp := range groups {
		if grp.maxKeyNewlines > 0 {
			hasNewlineGroup = true
			break
		}
	}
	if !hasNewlineGroup {
		return &invalidKeyLineIndex{
			baseOffset: baseOffset,
			isBoundary: isBoundary,
		}
	}

	var matchesByStart [][]invalidKeyBridgeMatch
	recordMatch := func(startIdx, groupIdx, endIdx int) {
		if matchesByStart == nil {
			matchesByStart = make([][]invalidKeyBridgeMatch, nLines)
		}
		rel := startIdx - baseOffset
		existing := matchesByStart[rel]
		for i := range existing {
			if existing[i].groupIdx == groupIdx {
				if endIdx > existing[i].endIdx {
					existing[i].endIdx = endIdx
				}
				return
			}
		}
		matchesByStart[rel] = append(existing, invalidKeyBridgeMatch{
			groupIdx: groupIdx,
			endIdx:   endIdx,
		})
	}

	markEntry := func(groupIdx int, entry newlineInvalidKeyEntry) {
		nkLines := entry.lines
		L := len(nkLines)
		if L < 2 || L > nLines {
			return
		}
		lastIdx := L - 1
		if L == 2 {
			for s := baseOffset; s < len(lines)-1; s++ {
				if strings.HasSuffix(lines[s], nkLines[0]) && invalidKeyLastLineMatches(lines[s+1], nkLines[lastIdx]) {
					recordMatch(s, groupIdx, s+1)
				}
			}
			return
		}
		interior := nkLines[1:lastIdx]
		M := len(interior)
		lps := make([]int, M)
		j := 0
		for i := 1; i < M; i++ {
			for j > 0 && interior[i] != interior[j] {
				j = lps[j-1]
			}
			if interior[i] == interior[j] {
				j++
			}
			lps[i] = j
		}
		j = 0
		for p := baseOffset + 1; p < len(lines)-1; p++ {
			line := lines[p]
			for j > 0 && line != interior[j] {
				j = lps[j-1]
			}
			if line == interior[j] {
				j++
			}
			if j == M {
				startIdx := p - M
				endIdx := p + 1
				if strings.HasSuffix(lines[startIdx], nkLines[0]) && invalidKeyLastLineMatches(lines[endIdx], nkLines[lastIdx]) {
					recordMatch(startIdx, groupIdx, endIdx)
				}
				j = lps[j-1]
			}
		}
	}

	for gIdx, grp := range groups {
		if grp.maxKeyNewlines <= 0 {
			continue
		}
		for _, entry := range grp.newlineEntries {
			markEntry(gIdx, entry)
		}
		for _, entry := range grp.bridgeNewlineEntries {
			markEntry(gIdx, entry)
		}
	}

	return &invalidKeyLineIndex{
		baseOffset:     baseOffset,
		isBoundary:     isBoundary,
		matchesByStart: matchesByStart,
	}
}

func findInvalidKeySpanEndWithIndex(lines []string, li int, idx *invalidKeyLineIndex, allowedMask []uint64, allowedGen uint64) int {
	if idx == nil || li < idx.baseOffset || li+1 >= len(lines) {
		return li
	}
	bridgedUntil := li
	advanceBridges := func(pos int) {
		if len(idx.matchesByStart) == 0 {
			return
		}
		for _, m := range idx.matchesByStart[pos-idx.baseOffset] {
			if allowedMask == nil || allowedMask[m.groupIdx] == allowedGen {
				if m.endIdx > bridgedUntil {
					bridgedUntil = m.endIdx
				}
			}
		}
	}
	advanceBridges(li)
	end := li
	for end+1 < len(lines) {
		if idx.isBoundary[end+1-idx.baseOffset] && end >= bridgedUntil {
			break
		}
		end++
		advanceBridges(end)
	}
	return end
}

// findInvalidKeySpanEnd extends li across non-boundary continuation lines and
// newline-containing invalid keys in amortized O(N) time across lines[li:] via
// a backward non-blank boundary pass and KMP interior line matching.
func findInvalidKeySpanEnd(lines []string, li int, groups []interpolatedInvalidKeyGroup) int {
	idx := buildInvalidKeyLineIndex(lines, li, groups)
	return findInvalidKeySpanEndWithIndex(lines, li, idx, nil, 0)
}

type invalidKeySegOffset struct {
	start int
	end   int
}

// collectMultiCommaKeyMatchStarts records, for each segment index r, the earliest
// starting segment (1-indexed as startSeg+1, or 0 for none) of any registered
// multi-comma invalid key ending at r. Because every shorter suffix ending at r
// lies strictly inside that longest match, interval union avoids walking dictFail.
func collectMultiCommaKeyMatchStarts(listStr string, segOffsets []invalidKeySegOffset, groups []interpolatedInvalidKeyGroup) []int {
	var bestStartPlus1ByEnd []int
	for _, grp := range groups {
		root := grp.multiAC
		if root == nil {
			continue
		}
		node := root
		for segIdx, off := range segOffsets {
			seg := listStr[off.start:off.end]
			for node != root && node.children[seg] == nil {
				node = node.fail
			}
			if next := node.children[seg]; next != nil {
				node = next
			}
			best := node
			if best.termSegs == 0 {
				best = best.dictFail
			}
			if best != nil && best.termSegs > 0 {
				startPlus1 := (segIdx + 1 - best.termSegs) + 1
				if bestStartPlus1ByEnd == nil {
					bestStartPlus1ByEnd = make([]int, len(segOffsets))
				}
				if bestStartPlus1ByEnd[segIdx] == 0 || startPlus1 < bestStartPlus1ByEnd[segIdx] {
					bestStartPlus1ByEnd[segIdx] = startPlus1
				}
			}
		}
	}
	return bestStartPlus1ByEnd
}

func redactInvalidKeyListSpan(lines []string, li int, groups []interpolatedInvalidKeyGroup) (newLine string, consumedExtra int, matched bool) {
	return redactInvalidKeyListSpanWithIndex(lines, li, groups, nil, nil, 0)
}

func redactInvalidKeyListSpanWithIndex(
	lines []string,
	li int,
	groups []interpolatedInvalidKeyGroup,
	idx *invalidKeyLineIndex,
	allowedMask []uint64,
	allowedGen uint64,
) (newLine string, consumedExtra int, matched bool) {
	if li < 0 || li >= len(lines) || len(groups) == 0 {
		return "", 0, false
	}
	maxCommaSpan := 1
	maxNL := 0
	for _, grp := range groups {
		maxCommaSpan = max(maxCommaSpan, grp.maxCommaSpan)
		maxNL = max(maxNL, grp.maxKeyNewlines)
	}
	end := li
	if maxNL > 0 {
		if idx != nil {
			end = findInvalidKeySpanEndWithIndex(lines, li, idx, allowedMask, allowedGen)
		} else {
			end = findInvalidKeySpanEnd(lines, li, groups)
		}
	}
	spanLine := lines[li]
	if end > li {
		spanLine = strings.Join(lines[li:end+1], "\n")
	}
	invalidIdx := findUnquotedInvalidKeysMarker(spanLine)
	if invalidIdx < 0 {
		return "", 0, false
	}
	head := spanLine[:invalidIdx]
	tail := spanLine[invalidIdx+len(invalidKeysMarker):]
	lead := ""
	listStr := tail
	if afterSp, hasSp := strings.CutPrefix(tail, " "); hasSp {
		lead = " "
		listStr = afterSp
	}
	keyExists := func(cand string) bool {
		for _, grp := range groups {
			if _, hit := grp.keySet[cand]; hit {
				return true
			}
		}
		return false
	}

	var out strings.Builder
	changed := false
	lastCopied := 0
	if maxCommaSpan <= 1 {
		for pos, hasSeg := 0, true; hasSeg; {
			var segEnd, nextPos int
			var nextHasSeg bool
			if rel := strings.Index(listStr[pos:], ", "); rel < 0 {
				segEnd = len(listStr)
				nextHasSeg = false
			} else {
				segEnd = pos + rel
				nextPos = segEnd + 2
				nextHasSeg = true
			}
			if keyExists(listStr[pos:segEnd]) {
				if !changed {
					out.Grow(len(listStr))
					changed = true
				}
				out.WriteString(listStr[lastCopied:pos])
				out.WriteString("[REDACTED]")
				if nextHasSeg {
					out.WriteString(", ")
					lastCopied = nextPos
				} else {
					lastCopied = len(listStr)
				}
			}
			pos = nextPos
			hasSeg = nextHasSeg
		}
	} else {
		var segOffsets []invalidKeySegOffset
		for pos, hasSeg := 0, true; hasSeg; {
			if rel := strings.Index(listStr[pos:], ", "); rel < 0 {
				segOffsets = append(segOffsets, invalidKeySegOffset{start: pos, end: len(listStr)})
				hasSeg = false
			} else {
				segOffsets = append(segOffsets, invalidKeySegOffset{start: pos, end: pos + rel})
				pos = pos + rel + 2
			}
		}
		bestStartPlus1ByEnd := collectMultiCommaKeyMatchStarts(listStr, segOffsets, groups)
		type invalidKeySegInterval struct {
			start int
			end   int
		}
		var merged []invalidKeySegInterval
		for segIdx, off := range segOffsets {
			var startSeg int
			switch {
			case bestStartPlus1ByEnd != nil && bestStartPlus1ByEnd[segIdx] > 0:
				startSeg = bestStartPlus1ByEnd[segIdx] - 1
			case keyExists(listStr[off.start:off.end]):
				startSeg = segIdx
			default:
				continue
			}
			for len(merged) > 0 && startSeg <= merged[len(merged)-1].end {
				if merged[len(merged)-1].start < startSeg {
					startSeg = merged[len(merged)-1].start
				}
				merged = merged[:len(merged)-1]
			}
			merged = append(merged, invalidKeySegInterval{start: startSeg, end: segIdx})
		}
		if len(merged) > 0 {
			out.Grow(len(listStr))
			changed = true
			for _, iv := range merged {
				segStartByte := segOffsets[iv.start].start
				if segStartByte > lastCopied {
					out.WriteString(listStr[lastCopied:segStartByte])
				}
				out.WriteString("[REDACTED]")
				if iv.end+1 < len(segOffsets) {
					out.WriteString(", ")
					lastCopied = segOffsets[iv.end+1].start
				} else {
					lastCopied = len(listStr)
				}
			}
		}
	}
	if !changed {
		return "", 0, false
	}
	if lastCopied < len(listStr) {
		out.WriteString(listStr[lastCopied:])
	}
	return head + invalidKeysMarker + lead + out.String(), end - li, true
}

func isStrictConfmapErrorHeaderLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	if rest, ok := cutExporterErrorPrefix(trimmed); ok {
		trimmed = strings.TrimSpace(rest)
	} else {
		trimmed = strings.TrimPrefix(trimmed, "Error: ")
	}
	if strings.HasPrefix(trimmed, "* ") ||
		strings.HasPrefix(trimmed, "error decoding '") ||
		strings.HasPrefix(trimmed, "error unmarshaling ") {
		return true
	}
	if len(trimmed) > 0 && trimmed[0] == '\'' {
		if endQuote := strings.IndexByte(trimmed[1:], '\''); endQuote >= 0 {
			sec := trimmed[1 : 1+endQuote]
			after := trimmed[2+endQuote:]
			if strings.HasPrefix(after, " ") || strings.HasPrefix(after, ": ") {
				return true
			}
			secParts := strings.Split(sec, ".")
			if sec == "" || sec == "exporters" || isKnownDirectSectionChild(secParts[0]) {
				if strings.Contains(after, "': got '") || strings.Contains(after, "decoding failed") || strings.Contains(after, "unexpected ") || strings.Contains(after, "has invalid keys:") {
					return true
				}
			}
			if _, isTop := bigQueryConfigTopLevelSections[secParts[0]]; isTop {
				if strings.Contains(after, "': got '") || strings.Contains(after, "decoding failed") || strings.Contains(after, "unexpected ") || strings.Contains(after, "has invalid keys:") {
					return true
				}
			}
		}
	}
	return false
}

func isConfmapSpanBoundaryAt(lines []string, idx int) bool {
	if idx < 0 || idx >= len(lines) {
		return true
	}
	if strings.TrimSpace(lines[idx]) == "" {
		for m := idx + 1; m < len(lines); m++ {
			if strings.TrimSpace(lines[m]) == "" {
				continue
			}
			return isStrictConfmapErrorHeaderLine(lines[m])
		}
		return true
	}
	return isStrictConfmapErrorHeaderLine(lines[idx])
}

func redactConfmapGotExpectedLinesFrom(firstLine string, lines []string, contStartIdx int, leafKeys []string) (collapsed string, endLineIdx int, matched bool, ambiguous bool) {
	line := firstLine
	for _, leaf := range leafKeys {
		if leaf == "" {
			continue
		}
		needle := "for '" + leaf + "': got '"
		idx := strings.Index(line, needle)
		if idx < 0 {
			continue
		}
		valStart := idx + len(needle)
		hasBest := false
		bestEndLine := contStartIdx - 1
		bestEndOffset := -1
		if endRel := strings.LastIndex(line[valStart:], "' value expected "); endRel >= 0 {
			hasBest = true
			bestEndOffset = valStart + endRel
		}
		for k := contStartIdx; k < len(lines); k++ {
			if hasBest && isConfmapSpanBoundaryAt(lines, k) {
				break
			}
			if endRel := strings.LastIndex(lines[k], "' value expected "); endRel >= 0 {
				hasBest = true
				bestEndLine = k
				bestEndOffset = endRel
			}
		}
		if !hasBest {
			// Ambiguous or unclosed multiline "got '" boundary: fail closed rather
			// than leaving trailing lines unredacted.
			return line[:valStart] + "[REDACTED]'", len(lines) - 1, true, true
		}
		var suffix string
		if bestEndLine < contStartIdx {
			suffix = line[bestEndOffset:]
		} else {
			suffix = lines[bestEndLine][bestEndOffset:]
		}
		return line[:valStart] + "[REDACTED]" + suffix, bestEndLine, true, false
	}
	return line, contStartIdx - 1, false, false
}

// findClosingDoubleQuote returns the index in s of the first unescaped '"',
// tracking backslash escapes ('\\' and '\"') so escaped quotes inside Go-quoted
// errors (such as time.ParseDuration) are not mistaken for closing delimiters.
func findClosingDoubleQuote(s string) int {
	return findClosingDoubleQuoteWithLineLimit(s, false)
}

func findClosingDoubleQuoteOnLine(s string) int {
	return findClosingDoubleQuoteWithLineLimit(s, true)
}

func findClosingDoubleQuoteWithLineLimit(s string, stopOnNewline bool) int {
	escaped := false
	for i := 0; i < len(s); i++ {
		if stopOnNewline && (s[i] == '\r' || s[i] == '\n') {
			return -1
		}
		if escaped {
			escaped = false
			continue
		}
		switch s[i] {
		case '\\':
			escaped = true
		case '"':
			return i
		}
	}
	return -1
}

func redactEarliestDurationClause(line string, searchFrom int) (out string, nextSearch int, matched bool, ambiguous bool) {
	const (
		unknownUnitPrefix         = `time: unknown unit "`
		unknownUnitRedactedPrefix = `time: unknown unit [REDACTED] in duration "`
		inDurationPrefix          = ` in duration "`
		inDurationRedactedPrefix  = ` in duration [REDACTED]`
		redactedUnknownClause     = `[REDACTED] in duration [REDACTED]`
	)
	bestIdx := -1
	bestKind := ""
	for _, cand := range []string{
		unknownUnitPrefix,
		unknownUnitRedactedPrefix,
		`time: invalid duration "`,
		`time: missing unit in duration "`,
	} {
		if rel := strings.Index(line[searchFrom:], cand); rel >= 0 {
			pos := searchFrom + rel
			if bestIdx < 0 || pos < bestIdx {
				bestIdx = pos
				bestKind = cand
			}
		}
	}
	if bestIdx < 0 {
		return line, len(line), false, false
	}
	valStart := bestIdx + len(bestKind)
	switch bestKind {
	case unknownUnitPrefix:
		unitEndRel := findClosingDoubleQuote(line[valStart:])
		if unitEndRel < 0 {
			return line[:valStart-1] + "[REDACTED]", len(line), true, true
		}
		afterUnit := line[valStart+unitEndRel+1:]
		if strings.HasPrefix(afterUnit, inDurationRedactedPrefix) {
			out = line[:valStart-1] + redactedUnknownClause + afterUnit[len(inDurationRedactedPrefix):]
			return out, valStart - 1 + len(redactedUnknownClause), true, false
		}
		if !strings.HasPrefix(afterUnit, inDurationPrefix) {
			return line[:valStart-1] + "[REDACTED]", len(line), true, true
		}
		origStart := valStart + unitEndRel + 1 + len(inDurationPrefix)
		origEndRel := findClosingDoubleQuote(line[origStart:])
		if origEndRel < 0 {
			return line[:valStart-1] + "[REDACTED]", len(line), true, true
		}
		out = line[:valStart-1] + redactedUnknownClause + line[origStart+origEndRel+1:]
		return out, valStart - 1 + len(redactedUnknownClause), true, false
	case unknownUnitRedactedPrefix:
		origEndRel := findClosingDoubleQuote(line[valStart:])
		if origEndRel < 0 {
			return line[:bestIdx+len("time: unknown unit ")] + redactedUnknownClause, len(line), true, true
		}
		out = line[:valStart-1] + "[REDACTED]" + line[valStart+origEndRel+1:]
		return out, valStart - 1 + len("[REDACTED]"), true, false
	default:
		endRel := findClosingDoubleQuote(line[valStart:])
		if endRel < 0 {
			// Go's time.quote never emits raw newlines, so an unclosed quote here means
			// upstream error truncation (e.g. mapstructure wrapTimeParseDurationError) or
			// an unexpected span; fail closed immediately instead of scanning sibling lines.
			return line[:valStart-1] + "[REDACTED]", len(line), true, true
		}
		out = line[:valStart-1] + "[REDACTED]" + line[valStart+endRel+1:]
		return out, valStart - 1 + len("[REDACTED]"), true, false
	}
}

func redactConfmapDurationLine(cur string) (collapsed string, matched bool, ambiguous bool) {
	anyMatched := false
	for searchFrom := 0; searchFrom < len(cur); {
		next, nextPos, hit, ambig := redactEarliestDurationClause(cur, searchFrom)
		if !hit {
			break
		}
		anyMatched = true
		cur = next
		if ambig {
			return cur, true, true
		}
		searchFrom = nextPos
	}
	return cur, anyMatched, false
}

func redactConfmapDurationLines(lines []string, startIdx int) (collapsed string, consumedExtra int, matched bool, ambiguous bool) {
	if startIdx < 0 || startIdx >= len(lines) {
		return "", 0, false, false
	}
	collapsed, matched, ambiguous = redactConfmapDurationLine(lines[startIdx])
	return collapsed, 0, matched, ambiguous
}

func scrubInterpolatedError(rawNode, resolvedNode any, err error) error {
	return scrubInterpolatedErrorWithScope(nil, rawNode, resolvedNode, err)
}

// scrubInterpolatedErrorWithScope redacts env-resolved operands inside err
// while scoping replacements to the matching config section and path.
// Validator diagnostics are expected to render user-controlled values quoted
// or in parentheses; validators formatting bare "%s" values for interpolated
// strings must handle suppression explicitly at the call site.
func scrubInterpolatedErrorWithScope(scopePrefix []string, rawNode, resolvedNode any, err error) error {
	return scrubInterpolatedErrorWithScopeAndForceLookup(scopePrefix, rawNode, resolvedNode, err, false, nil)
}

func scrubInterpolatedErrorWithScopeAndForce(scopePrefix []string, rawNode, resolvedNode any, err error, forceAll bool) error {
	return scrubInterpolatedErrorWithScopeAndForceLookup(scopePrefix, rawNode, resolvedNode, err, forceAll, nil)
}

func emitPathIdentAndDotTokensWithSets(s string, start int, exactRuns map[string]struct{}, visit func(string)) int {
	i := start
	for i < len(s) && isPathIdentOrDotByte(s[i]) {
		i++
	}
	run := strings.Trim(s[start:i], ".")
	if run != "" {
		visit(run)
		if exactRuns != nil {
			exactRuns[run] = struct{}{}
		}
		if strings.ContainsRune(run, '.') {
			for _, seg := range strings.Split(run, ".") {
				if seg != "" {
					visit(seg)
				}
			}
		}
	}
	return i
}

func visitQuotedTokenBodyWithSets(inner string, sets *lineTokenMatchSets, recordExactRuns bool, visit func(string)) {
	var exactRuns map[string]struct{}
	if sets != nil && recordExactRuns {
		exactRuns = sets.exactRuns
	}
	nextCloseBracket := -2
	for j := 0; j < len(inner); {
		if isPathIdentOrDotByte(inner[j]) {
			j = emitPathIdentAndDotTokensWithSets(inner, j, exactRuns, visit)
			continue
		}
		if inner[j] == '[' {
			if nextCloseBracket != -1 && nextCloseBracket <= j {
				if rel := strings.IndexByte(inner[j+1:], ']'); rel >= 0 {
					nextCloseBracket = j + 1 + rel
				} else {
					nextCloseBracket = -1
				}
			}
			if nextCloseBracket >= 0 {
				if endRel := nextCloseBracket - (j + 1); endRel > 0 {
					bracketed := inner[j+1 : j+1+endRel]
					visit(bracketed)
					if sets != nil && recordExactRuns {
						sets.brackets[bracketed] = struct{}{}
					}
					if trimmed := strings.TrimSpace(bracketed); trimmed != "" && trimmed != bracketed {
						visit(trimmed)
					}
					if strings.HasPrefix(bracketed, `"`) && strings.HasSuffix(bracketed, `"`) {
						if unq, err := strconv.Unquote(bracketed); err == nil && unq != "" {
							visit(unq)
						}
					}
					for k := 0; k < len(bracketed); {
						if isPathIdentOrDotByte(bracketed[k]) {
							k = emitPathIdentAndDotTokensWithSets(bracketed, k, exactRuns, visit)
							continue
						}
						k++
					}
					j += 1 + endRel + 1
					continue
				}
			}
		}
		j++
	}
}

const invalidKeysMarker = "has invalid keys:"

func findUnquotedInvalidKeysMarker(s string) int {
	if !strings.Contains(s, invalidKeysMarker) {
		return -1
	}
	nextCloseBracket := -2
	noMoreDoubleQuote := false
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], invalidKeysMarker) {
			return i
		}
		switch s[i] {
		case '"':
			if noMoreDoubleQuote {
				i++
				continue
			}
			if endRel := findClosingDoubleQuote(s[i+1:]); endRel >= 0 {
				i += 1 + endRel + 1
				continue
			}
			noMoreDoubleQuote = true
			i++
		case '[':
			if nextCloseBracket != -1 && nextCloseBracket <= i {
				if rel := strings.IndexByte(s[i+1:], ']'); rel >= 0 {
					nextCloseBracket = i + 1 + rel
				} else {
					nextCloseBracket = -1
				}
			}
			if nextCloseBracket >= 0 {
				i = nextCloseBracket + 1
				continue
			}
			i++
		case '\'', '`':
			q := s[i]
			j := i + 1
			innerNextClose := nextCloseBracket
			for j < len(s) {
				if s[j] == '[' {
					if innerNextClose != -1 && innerNextClose <= j {
						if rel := strings.IndexByte(s[j+1:], ']'); rel >= 0 {
							innerNextClose = j + 1 + rel
						} else {
							innerNextClose = -1
						}
					}
					if innerNextClose >= 0 {
						j = innerNextClose + 1
						continue
					}
				}
				if s[j] == q {
					break
				}
				j++
			}
			if j < len(s) && s[j] == q {
				nextCloseBracket = innerNextClose
				i = j + 1
				continue
			}
			i++
		default:
			i++
		}
	}
	return -1
}

func extractLineLookupTokens(s string, visit func(string)) {
	extractLineLookupTokensWithSets(s, nil, visit)
}

func extractLineLookupTokensWithSets(s string, sets *lineTokenMatchSets, visit func(string)) {
	var topExactRuns map[string]struct{}
	if sets != nil {
		topExactRuns = sets.exactRuns
	}
	nextCloseBracket := -2
	nextOpenBracket := -2
	noMoreDoubleQuote := false
	for i := 0; i < len(s); {
		if isPathIdentOrDotByte(s[i]) {
			i = emitPathIdentAndDotTokensWithSets(s, i, topExactRuns, visit)
			continue
		}
		switch s[i] {
		case '[':
			if nextCloseBracket != -1 && nextCloseBracket <= i {
				if rel := strings.IndexByte(s[i+1:], ']'); rel >= 0 {
					nextCloseBracket = i + 1 + rel
				} else {
					nextCloseBracket = -1
				}
			}
			if nextOpenBracket != -1 && nextOpenBracket <= i {
				if rel := strings.IndexByte(s[i+1:], '['); rel >= 0 {
					nextOpenBracket = i + 1 + rel
				} else {
					nextOpenBracket = -1
				}
			}
			if nextCloseBracket >= 0 {
				if endRel := nextCloseBracket - (i + 1); endRel > 0 {
					hasNestedOpen := nextOpenBracket > i && nextOpenBracket < nextCloseBracket
					// Skip hashing long nested unclosed '[' prefixes while always
					// emitting innermost brackets and normal bracketed keys in O(N).
					if !hasNestedOpen || endRel <= 128 {
						bracketed := s[i+1 : i+1+endRel]
						visit(bracketed)
						if sets != nil {
							sets.brackets[bracketed] = struct{}{}
						}
						if trimmed := strings.TrimSpace(bracketed); trimmed != "" && trimmed != bracketed {
							visit(trimmed)
						}
					}
				}
			}
			i++
		case '"':
			if noMoreDoubleQuote {
				i++
				continue
			}
			if endRel := findClosingDoubleQuote(s[i+1:]); endRel >= 0 {
				rawTok := s[i : i+1+endRel+1]
				inner := s[i+1 : i+1+endRel]
				if inner != "" {
					visit(inner)
					visitQuotedTokenBodyWithSets(inner, sets, true, visit)
					if strings.ContainsRune(inner, '\\') {
						if unq, err := strconv.Unquote(rawTok); err == nil && unq != "" && unq != inner {
							visit(unq)
							if sets != nil && strconv.Quote(unq) == rawTok {
								sets.quotedUnq[unq] = struct{}{}
							}
							visitQuotedTokenBodyWithSets(unq, sets, false, visit)
						}
					} else if sets != nil && strconv.Quote(inner) == rawTok {
						sets.quotedUnq[inner] = struct{}{}
					}
				}
				i += 1 + endRel + 1
				continue
			}
			noMoreDoubleQuote = true
			i++
		case '\'', '`':
			q := s[i]
			if endRel := strings.IndexByte(s[i+1:], q); endRel >= 0 {
				inner := s[i+1 : i+1+endRel]
				if inner != "" {
					visit(inner)
					if sets != nil && q == '\'' {
						sets.singleQuotes[inner] = struct{}{}
					}
					visitQuotedTokenBodyWithSets(inner, sets, true, visit)
				}
				i += 1 + endRel + 1
				continue
			}
			i++
		default:
			if s[i] != ' ' && s[i] != '\t' && s[i] != ':' && s[i] != ',' && s[i] != '(' && s[i] != ')' && s[i] != ']' {
				start := i
				for i < len(s) && !isPathIdentOrDotByte(s[i]) && s[i] != ' ' && s[i] != '\t' && s[i] != '\'' && s[i] != '"' && s[i] != '`' && s[i] != '[' && s[i] != ']' && s[i] != ',' && s[i] != ':' && s[i] != '(' && s[i] != ')' {
					i++
				}
				if i > start {
					visit(s[start:i])
				} else {
					i++
				}
				continue
			}
			i++
		}
	}
	if idx := findUnquotedInvalidKeysMarker(s); idx >= 0 {
		tail := strings.TrimPrefix(s[idx+len(invalidKeysMarker):], " ")
		if tail != "" {
			for part := range strings.SplitSeq(tail, ", ") {
				if part != "" {
					visit(part)
					if trimmed := strings.TrimSpace(part); trimmed != "" && trimmed != part {
						visit(trimmed)
					}
				}
			}
		}
	}
}

func scrubInterpolatedErrorWithScopeAndForceLookup(scopePrefix []string, rawNode, resolvedNode any, err error, forceAll bool, lookupEnv func(string) (string, bool)) error {
	if err == nil {
		return nil
	}
	var entries []interpolatedFieldRedaction
	var invalidGroups []interpolatedInvalidKeyGroup
	appendInterpolatedErrorEntriesWithOptions(rawNode, resolvedNode, scopePrefix, &entries, &invalidGroups, forceAll, false, lookupEnv)
	if len(entries) == 0 && len(invalidGroups) == 0 {
		return err
	}

	var (
		rootIndices     []int
		columnsIndices  []int
		fallbackIndices []int
	)
	byLeafKey := make(map[string][]int, len(entries))
	for i, e := range entries {
		switch {
		case len(e.parts) == 0:
			rootIndices = append(rootIndices, i)
		case len(e.parts) >= 2 && e.leafKey == "columns":
			columnsIndices = append(columnsIndices, i)
		case e.leafKey == "" ||
			strings.ContainsAny(e.leafKey, "\n'\"[],") ||
			!utf8.ValidString(e.leafKey) ||
			strings.TrimSpace(e.leafKey) == "":
			fallbackIndices = append(fallbackIndices, i)
		default:
			byLeafKey[e.leafKey] = append(byLeafKey[e.leafKey], i)
			if trimmedKey := strings.TrimSpace(e.leafKey); trimmedKey != "" && trimmedKey != e.leafKey {
				byLeafKey[trimmedKey] = append(byLeafKey[trimmedKey], i)
			}
		}
	}

	type replacementPair struct {
		target string
		repl   string
	}
	lines := strings.Split(err.Error(), "\n")
	blockScope := slices.Clone(scopePrefix)
	outLines := make([]string, 0, len(lines))
	changed := false
	var (
		keyLineIdx     *invalidKeyLineIndex
		groupMask      []uint64
		groupMaskGen   uint64
		matchingGroups []interpolatedInvalidKeyGroup
	)
	if len(invalidGroups) > 0 {
		groupMask = make([]uint64, len(invalidGroups))
	}
	for li := 0; li < len(lines); li++ {
		line := lines[li]
		nextContIdx := li + 1
		var lineScope []string
		blockScope, lineScope = updateErrorBlockAndLineScope(line, scopePrefix, blockScope)

		origLine := line
		multiConsumed := false
		searchLine := line
		if invalidIdx := findUnquotedInvalidKeysMarker(line); invalidIdx >= 0 && strings.HasSuffix(strings.TrimSpace(line[:invalidIdx]), "'") {
			invalidHead := line[:invalidIdx]
			groupMaskGen++
			matchingGroups = matchingGroups[:0]
			anyGroupMaxNL := false
			for gi, grp := range invalidGroups {
				if ancestorsMatchScope(grp.parts, invalidHead, lineScope) {
					matchingGroups = append(matchingGroups, grp)
					groupMask[gi] = groupMaskGen
					if grp.maxKeyNewlines > 0 {
						anyGroupMaxNL = true
					}
				}
			}
			if anyGroupMaxNL && keyLineIdx == nil {
				keyLineIdx = buildInvalidKeyLineIndex(lines, 0, invalidGroups)
			}
			if replacedSpan, extraLines, hitInvalid := redactInvalidKeyListSpanWithIndex(lines, li, matchingGroups, keyLineIdx, groupMask, groupMaskGen); hitInvalid {
				// Group matching already redacted the invalid-key span in O(K);
				// restrict token lookup to the header so thousands of keys never trigger O(K^2) scans.
				searchLine = invalidHead
				line = replacedSpan
				changed = true
				if extraLines > 0 {
					multiConsumed = true
					nextContIdx = li + 1 + extraLines
				}
			}
		}

		var sets *lineTokenMatchSets
		if searchLine == line && len(line) > 0 {
			sets = &lineTokenMatchSets{
				quotedUnq:    make(map[string]struct{}),
				brackets:     make(map[string]struct{}),
				singleQuotes: make(map[string]struct{}),
				exactRuns:    make(map[string]struct{}),
				ancestorsOK:  make(map[string]bool),
			}
		}
		candSet := make(map[int]struct{})
		var candIndices []int
		recordCandidate := func(idx int) {
			if _, dup := candSet[idx]; dup {
				return
			}
			candSet[idx] = struct{}{}
			candIndices = append(candIndices, idx)
		}
		for _, idx := range rootIndices {
			recordCandidate(idx)
		}
		for _, idx := range columnsIndices {
			recordCandidate(idx)
		}
		for _, idx := range fallbackIndices {
			recordCandidate(idx)
		}
		extractLineLookupTokensWithSets(searchLine, sets, func(tok string) {
			for _, idx := range byLeafKey[tok] {
				recordCandidate(idx)
			}
		})
		var matchedIndices []int
		for _, idx := range candIndices {
			if entryMatchesLineWithSets(entries[idx], line, lineScope, sets) {
				matchedIndices = append(matchedIndices, idx)
			}
		}
		slices.Sort(matchedIndices)

		seenTargets := make(map[string]struct{})
		seenLeaves := make(map[string]struct{})
		var matchedPairs []replacementPair
		var matchedLeafKeys []string
		for _, idx := range matchedIndices {
			entry := entries[idx]
			if entry.leafKey != "" {
				if _, dup := seenLeaves[entry.leafKey]; !dup {
					seenLeaves[entry.leafKey] = struct{}{}
					matchedLeafKeys = append(matchedLeafKeys, entry.leafKey)
				}
			}
			for i := 0; i < len(entry.replacements); i += 2 {
				tgt := entry.replacements[i]
				if _, dup := seenTargets[tgt]; dup {
					continue
				}
				seenTargets[tgt] = struct{}{}
				matchedPairs = append(matchedPairs, replacementPair{
					target: tgt,
					repl:   entry.replacements[i+1],
				})
			}
		}

		slices.SortFunc(matchedPairs, func(a, b replacementPair) int {
			if len(a.target) != len(b.target) {
				return cmp.Compare(len(b.target), len(a.target))
			}
			return strings.Compare(a.target, b.target)
		})
		var multilinePairs []replacementPair
		var singleLinePairs []replacementPair
		for _, p := range matchedPairs {
			if strings.Contains(p.target, "\n") {
				multilinePairs = append(multilinePairs, p)
			} else {
				singleLinePairs = append(singleLinePairs, p)
			}
		}

		// Run exact multiline and single-line replacements first so spoofed markers
		// inside a known interpolated value (such as "' value expected ",
		// "for '<leaf>': got '...' value expected ", or "time: unknown unit / invalid duration")
		// are consumed cleanly before structural span redactors run.
		if len(multilinePairs) > 0 && nextContIdx < len(lines) {
			maxSpan := 0
			for _, p := range multilinePairs {
				firstLine, _, _ := strings.Cut(p.target, "\n")
				if strings.Contains(line, firstLine) {
					maxSpan = max(maxSpan, strings.Count(p.target, "\n"))
				}
			}
			if maxSpan > 0 {
				spanEnd := min(len(lines), nextContIdx+maxSpan)
				orderedMulti := make([]string, 0, len(multilinePairs)*2)
				for _, p := range multilinePairs {
					orderedMulti = append(orderedMulti, p.target, p.repl)
				}
				joinedSpan := line + "\n" + strings.Join(lines[nextContIdx:spanEnd], "\n")
				replacedSpan := strings.NewReplacer(orderedMulti...).Replace(joinedSpan)
				if replacedSpan != joinedSpan {
					changed = true
					multiConsumed = true
					replacedParts := strings.Split(replacedSpan, "\n")
					line = replacedParts[0]
					if len(replacedParts) == 1 {
						nextContIdx = spanEnd
					} else {
						tail := make([]string, 0, len(replacedParts)+len(lines)-spanEnd)
						tail = append(tail, replacedParts...)
						tail = append(tail, lines[spanEnd:]...)
						lines = append(lines[:li:li], tail...)
						nextContIdx = li + 1
						keyLineIdx = nil
					}
				}
			}
		}

		if len(singleLinePairs) > 0 {
			ordered := make([]string, 0, len(singleLinePairs)*2)
			for _, p := range singleLinePairs {
				ordered = append(ordered, p.target, p.repl)
			}
			if replaced := strings.NewReplacer(ordered...).Replace(line); replaced != line {
				line = replaced
				changed = true
			}
		}

		// Collapse remaining confmap "got '...' value expected " and
		// "time: ... duration \"...\"" spans within genuine confmap error blocks.
		collapsed, endLineIdx, matchedGot, ambiguousGot := redactConfmapGotExpectedLinesFrom(line, lines, nextContIdx, matchedLeafKeys)
		if ambiguousGot {
			return errors.New("decoding collector config failed (redacted interpolated value)")
		}
		if matchedGot && endLineIdx >= nextContIdx {
			changed = true
			multiConsumed = true
			line = collapsed
			nextContIdx = endLineIdx + 1
		} else if matchedGot {
			line = collapsed
		}

		if len(matchedPairs) > 0 || len(matchedLeafKeys) > 0 {
			durCollapsed, durMatched, durAmbig := redactConfmapDurationLine(line)
			if durAmbig || (!durMatched && len(multilinePairs) > 0 && strings.HasSuffix(strings.TrimSpace(line), "time: invalid duration")) {
				return errors.New("decoding collector config failed (redacted interpolated value)")
			}
			if durMatched {
				line = durCollapsed
			}
		}

		if line != origLine || multiConsumed {
			changed = true
		}
		outLines = append(outLines, line)
		li = nextContIdx - 1
	}
	if !changed {
		return err
	}
	return errors.New(strings.Join(outLines, "\n"))
}

func validateCollectorWriteLimits(w bigqueryexporter.WriteConfig, mask collectorWriteInterpMask) error {
	if w.StreamPoolSize < 1 || w.StreamPoolSize > 16 {
		if mask.streamPoolSize {
			return errors.New("effective write.stream_pool_size must be between 1 and 16")
		}
		return fmt.Errorf("effective write.stream_pool_size %d must be between 1 and 16", w.StreamPoolSize)
	}
	if w.ConnectionPoolSize < 1 || w.ConnectionPoolSize > 16 {
		if mask.connectionPoolSize {
			return errors.New("effective write.connection_pool_size must be between 1 and 16")
		}
		return fmt.Errorf("effective write.connection_pool_size %d must be between 1 and 16", w.ConnectionPoolSize)
	}
	if w.MaxInflightRequests < 1 || w.MaxInflightRequests > MaxBenchmarkInflightRequests {
		if mask.maxInflightRequests {
			return fmt.Errorf("effective write.max_inflight_requests must be between 1 and %d", MaxBenchmarkInflightRequests)
		}
		return fmt.Errorf("effective write.max_inflight_requests %d must be between 1 and %d", w.MaxInflightRequests, MaxBenchmarkInflightRequests)
	}
	if w.MaxRequestBytes <= 0 {
		if mask.maxRequestBytes {
			return errors.New("effective write.max_request_bytes must be > 0")
		}
		return fmt.Errorf("effective write.max_request_bytes %d must be > 0", w.MaxRequestBytes)
	}
	if w.Compression != "" && w.Compression != "gzip" {
		if mask.compression {
			return errors.New(`write.compression must be empty or "gzip"`)
		}
		return fmt.Errorf(`write.compression %q must be empty or "gzip"`, w.Compression)
	}
	return nil
}

const (
	invalidExporterIDPlaceholder    = "<invalid-exporter-id>"
	interpolatedExporterPlaceholder = "<interpolated-exporter>"
)

func isExporterRedactionSubtree(parts []string) bool {
	return len(parts) == 3 &&
		strings.EqualFold(parts[0], "exporters") &&
		strings.EqualFold(parts[2], "redaction")
}

func isExporterBlockedValuePatternsSubtree(parts []string) bool {
	return len(parts) == 4 &&
		strings.EqualFold(parts[0], "exporters") &&
		strings.EqualFold(parts[2], "redaction") &&
		strings.EqualFold(parts[3], "blocked_value_patterns")
}

func safeExporterIDLabel(rawID string) string {
	if canonical, ok := canonicalComponentID(rawID); ok {
		return canonical
	}
	return invalidExporterIDPlaceholder
}

func safeExporterRedactionPath(parts []string) string {
	return "exporters." + safeExporterIDLabel(parts[1]) + ".redaction"
}

func safeExporterBlockedValuePatternsPath(parts []string) string {
	return safeExporterRedactionPath(parts) + ".blocked_value_patterns"
}

func appendNonEmptyConfmapSegments(parts []string, key string) []string {
	flat := make([]string, 0, len(parts)+4)
	flat = append(flat, parts...)
	for _, seg := range strings.Split(key, "::") {
		if seg != "" {
			flat = append(flat, seg)
		}
	}
	return flat
}

func rejectDelimiterKeyWithOptions(parts []string, key, redactionErrPrefix string, redactKeys bool) error {
	if !strings.Contains(key, "::") {
		return nil
	}
	// Check whether splitting non-empty confmap "::" segments lands inside or on an
	// exporter's blocked_value_patterns subtree (case-insensitively, including an empty
	// exporter ID such as "exporters::::redaction::blocked_value_patterns::SECRET")
	// and redact any key names.
	flat := appendNonEmptyConfmapSegments(parts, key)
	if len(flat) >= 4 && isExporterBlockedValuePatternsSubtree(flat[:4]) {
		blockedPath := safeExporterBlockedValuePatternsPath(flat[:4])
		if redactionErrPrefix != "" {
			blockedPath = redactionErrPrefix + ".blocked_value_patterns"
		}
		return fmt.Errorf("collector config at %s contains unsupported confmap path delimiter \"::\"", blockedPath)
	}
	if len(flat) >= 3 &&
		strings.EqualFold(flat[0], "exporters") &&
		strings.EqualFold(flat[1], "redaction") &&
		strings.EqualFold(flat[2], "blocked_value_patterns") {
		return fmt.Errorf("collector config at exporters.%s.redaction.blocked_value_patterns contains unsupported confmap path delimiter \"::\"", invalidExporterIDPlaceholder)
	}
	if redactKeys {
		if redactionErrPrefix != "" {
			return fmt.Errorf("collector config at %s contains unsupported confmap path delimiter \"::\"", redactionErrPrefix)
		}
		return fmt.Errorf("collector config at %s contains unsupported confmap path delimiter \"::\"", strings.Join(parts, "."))
	}
	if redactionErrPrefix != "" {
		return fmt.Errorf("collector config key %q (at %s.%s) contains unsupported confmap path delimiter \"::\"", key, redactionErrPrefix, key)
	}
	childParts := appendConfigPathComponent(parts, key)
	return fmt.Errorf("collector config key %q (at %s) contains unsupported confmap path delimiter \"::\"", key, strings.Join(childParts, "."))
}

type yamlMapEntry struct {
	key string
	val any
}

func sortedYAMLMapEntries(node any) ([]yamlMapEntry, bool) {
	switch m := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		entries := make([]yamlMapEntry, len(keys))
		for i, k := range keys {
			entries[i] = yamlMapEntry{key: k, val: m[k]}
		}
		return entries, true
	case map[any]any:
		items, _ := sortedAnyYAMLMapEntries(m)
		entries := make([]yamlMapEntry, len(items))
		for i, item := range items {
			entries[i] = yamlMapEntry{key: item.strKey, val: item.val}
		}
		return entries, true
	default:
		return nil, false
	}
}

func rejectBlockedValuePatternsConfmapDelimiterKeys(node any, safePath string) error {
	if entries, isMap := sortedYAMLMapEntries(node); isMap {
		for _, e := range entries {
			if strings.Contains(e.key, "::") {
				return fmt.Errorf("collector config at %s contains unsupported confmap path delimiter \"::\"", safePath)
			}
			if err := rejectBlockedValuePatternsConfmapDelimiterKeys(e.val, safePath); err != nil {
				return err
			}
		}
		return nil
	}
	if seq, isSeq := node.([]any); isSeq {
		for i, elem := range seq {
			if err := rejectBlockedValuePatternsConfmapDelimiterKeys(elem, fmt.Sprintf("%s[%d]", safePath, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectExporterBlockedPatternsNodeDelimiterKeys(node any, exporterID, safePath string) error {
	if exporterID == "" || !isBigQueryComponentID(exporterID) {
		// Preserve non-BigQuery exporter shape relaxation while never echoing
		// map keys from blocked_value_patterns subtrees in delimiter errors.
		return rejectBlockedValuePatternsConfmapDelimiterKeys(node, safePath)
	}
	switch m := node.(type) {
	case map[string]any, map[any]any:
		return fmt.Errorf("reading %s: expected YAML sequence of strings, got map", safePath)
	case []any:
		for i, elem := range m {
			if _, ok := elem.(string); !ok {
				return fmt.Errorf("%s[%d]: expected string, got %s", safePath, i, describeYAMLValueKind(elem))
			}
		}
		return nil
	default:
		return nil
	}
}

func rejectRedactionNodeDelimiterKeysWithOptions(node any, rawExporterID, safeRedactionPath string, partsFallback []string, allowExporterNamedRedaction, redactKeys bool) error {
	if entries, isMap := sortedYAMLMapEntries(node); isMap {
		for _, e := range entries {
			if strings.Contains(e.key, "::") {
				segs := appendNonEmptyConfmapSegments(nil, e.key)
				if len(segs) >= 1 && strings.EqualFold(segs[0], "blocked_value_patterns") {
					return fmt.Errorf("collector config at %s.blocked_value_patterns contains unsupported confmap path delimiter \"::\"", safeRedactionPath)
				}
				if allowExporterNamedRedaction && len(segs) >= 2 && strings.EqualFold(segs[0], "redaction") && strings.EqualFold(segs[1], "blocked_value_patterns") {
					return fmt.Errorf("collector config at %s.redaction.blocked_value_patterns contains unsupported confmap path delimiter \"::\"", safeRedactionPath)
				}
				if redactKeys {
					return fmt.Errorf("collector config at %s contains unsupported confmap path delimiter \"::\"", safeRedactionPath)
				}
				return fmt.Errorf("collector config key %q (at %s.%s) contains unsupported confmap path delimiter \"::\"", e.key, safeRedactionPath, e.key)
			}
			nextParts := partsFallback
			nextRedactionPath := safeRedactionPath
			if !redactKeys {
				nextParts = appendConfigPathComponent(partsFallback, e.key)
				nextRedactionPath = safeRedactionPath + "." + e.key
			}
			if strings.EqualFold(e.key, "blocked_value_patterns") {
				if err := rejectExporterBlockedPatternsNodeDelimiterKeys(e.val, rawExporterID, safeRedactionPath+".blocked_value_patterns"); err != nil {
					return err
				}
				continue
			}
			if allowExporterNamedRedaction && strings.EqualFold(e.key, "redaction") {
				if err := rejectRedactionNodeDelimiterKeysWithOptions(e.val, "redaction", safeRedactionPath+".redaction", appendConfigPathComponent(partsFallback, "redaction"), false, redactKeys); err != nil {
					return err
				}
				continue
			}
			if redactKeys {
				nextRedactionPath = safeRedactionPath
			}
			_ = nextRedactionPath
			if err := rejectConfmapDelimiterKeysWithOptions(e.val, nextParts, redactKeys); err != nil {
				return err
			}
		}
		return nil
	}
	if seq, isSeq := node.([]any); isSeq {
		for i, elem := range seq {
			nextFallback := slices.Clone(partsFallback)
			if len(nextFallback) > 0 && !redactKeys {
				nextFallback[len(nextFallback)-1] = fmt.Sprintf("%s[%d]", nextFallback[len(nextFallback)-1], i)
			}
			nextPath := safeRedactionPath
			if !redactKeys {
				nextPath = fmt.Sprintf("%s[%d]", safeRedactionPath, i)
			}
			if err := rejectRedactionNodeDelimiterKeysWithOptions(elem, rawExporterID, nextPath, nextFallback, allowExporterNamedRedaction, redactKeys); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectExporterBodyDelimiterKeys(node any, rawExporterID, safeExporterPath string, partsPrefix []string) error {
	return rejectExporterBodyDelimiterKeysWithOptions(node, rawExporterID, safeExporterPath, partsPrefix, false)
}

func rejectExporterBodyDelimiterKeysWithOptions(node any, rawExporterID, safeExporterPath string, partsPrefix []string, redactKeys bool) error {
	if entries, isMap := sortedYAMLMapEntries(node); isMap {
		for _, e := range entries {
			if strings.Contains(e.key, "::") {
				segs := appendNonEmptyConfmapSegments(nil, e.key)
				if len(segs) >= 2 && strings.EqualFold(segs[0], "redaction") && strings.EqualFold(segs[1], "blocked_value_patterns") {
					return fmt.Errorf("collector config at %s.redaction.blocked_value_patterns contains unsupported confmap path delimiter \"::\"", safeExporterPath)
				}
				if redactKeys {
					return fmt.Errorf("collector config at %s contains unsupported confmap path delimiter \"::\"", safeExporterPath)
				}
				return fmt.Errorf("collector config key %q (at %s.%s) contains unsupported confmap path delimiter \"::\"", e.key, safeExporterPath, e.key)
			}
			if strings.EqualFold(e.key, "redaction") {
				if err := rejectRedactionNodeDelimiterKeysWithOptions(e.val, rawExporterID, safeExporterPath+".redaction", appendConfigPathComponent(partsPrefix, "redaction"), false, redactKeys); err != nil {
					return err
				}
				continue
			}
			nextParts := partsPrefix
			if !redactKeys {
				nextParts = appendConfigPathComponent(partsPrefix, e.key)
			}
			if err := rejectConfmapDelimiterKeysWithOptions(e.val, nextParts, redactKeys); err != nil {
				return err
			}
		}
		return nil
	}
	if seq, isSeq := node.([]any); isSeq {
		for i, elem := range seq {
			nextParts := slices.Clone(partsPrefix)
			if len(nextParts) > 0 && !redactKeys {
				nextParts[len(nextParts)-1] = fmt.Sprintf("%s[%d]", nextParts[len(nextParts)-1], i)
			}
			nextPath := safeExporterPath
			if !redactKeys {
				nextPath = fmt.Sprintf("%s[%d]", safeExporterPath, i)
			}
			if err := rejectExporterBodyDelimiterKeysWithOptions(elem, rawExporterID, nextPath, nextParts, redactKeys); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectExportersListDelimiterKeys(node any, pathPrefix string) error {
	if entries, isMap := sortedYAMLMapEntries(node); isMap {
		for _, e := range entries {
			if strings.Contains(e.key, "::") {
				segs := appendNonEmptyConfmapSegments(nil, e.key)
				switch {
				case len(segs) >= 2 && strings.EqualFold(segs[0], "redaction") && strings.EqualFold(segs[1], "blocked_value_patterns"):
					return fmt.Errorf("collector config at %s.redaction.blocked_value_patterns contains unsupported confmap path delimiter \"::\"", pathPrefix)
				case len(segs) >= 3 && strings.EqualFold(segs[1], "redaction") && strings.EqualFold(segs[2], "blocked_value_patterns"):
					return fmt.Errorf("collector config at %s.%s.redaction.blocked_value_patterns contains unsupported confmap path delimiter \"::\"", pathPrefix, safeExporterIDLabel(segs[0]))
				case len(segs) >= 1 && strings.EqualFold(segs[0], "blocked_value_patterns"):
					return fmt.Errorf("collector config at %s.blocked_value_patterns contains unsupported confmap path delimiter \"::\"", pathPrefix)
				default:
					return fmt.Errorf("collector config key %q (at %s.%s) contains unsupported confmap path delimiter \"::\"", e.key, pathPrefix, e.key)
				}
			}
			switch {
			case strings.EqualFold(e.key, "redaction"):
				expLabel := safeExporterIDLabel(e.key)
				if err := rejectRedactionNodeDelimiterKeysWithOptions(e.val, "", pathPrefix+"."+expLabel, []string{pathPrefix, expLabel}, true, false); err != nil {
					return err
				}
			case strings.EqualFold(e.key, "blocked_value_patterns"):
				if err := rejectBlockedValuePatternsConfmapDelimiterKeys(e.val, pathPrefix+".blocked_value_patterns"); err != nil {
					return err
				}
			default:
				expLabel := safeExporterIDLabel(e.key)
				if err := rejectExporterBodyDelimiterKeys(e.val, e.key, pathPrefix+"."+expLabel, []string{pathPrefix, expLabel}); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if seq, isSeq := node.([]any); isSeq {
		for i, elem := range seq {
			if err := rejectExportersListDelimiterKeys(elem, fmt.Sprintf("%s[%d]", pathPrefix, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendConfigPathComponent(parts []string, component string) []string {
	next := make([]string, len(parts)+1)
	copy(next, parts)
	next[len(parts)] = component
	return next
}

func rejectConfmapDelimiterKeys(node any, parts []string) error {
	return rejectConfmapDelimiterKeysWithOptions(node, parts, false)
}

func rejectConfmapDelimiterKeysWithOptions(node any, parts []string, redactKeys bool) error {
	if isExporterBlockedValuePatternsSubtree(parts) {
		return rejectExporterBlockedPatternsNodeDelimiterKeys(node, parts[1], safeExporterBlockedValuePatternsPath(parts))
	}
	if entries, isMap := sortedYAMLMapEntries(node); isMap {
		for _, e := range entries {
			if err := rejectDelimiterKeyWithOptions(parts, e.key, "", redactKeys); err != nil {
				return err
			}
			nextParts := parts
			if !redactKeys {
				nextParts = appendConfigPathComponent(parts, e.key)
			}
			if err := rejectConfmapDelimiterKeysWithOptions(e.val, nextParts, redactKeys); err != nil {
				return err
			}
		}
		return nil
	}
	if seq, isSeq := node.([]any); isSeq {
		if len(parts) == 1 && strings.EqualFold(parts[0], "exporters") {
			return rejectExportersListDelimiterKeys(seq, "exporters")
		}
		if isExporterRedactionSubtree(parts) {
			safeRedactionBase := safeExporterRedactionPath(parts)
			for i, elem := range seq {
				elemParts := slices.Clone(parts)
				if len(elemParts) > 0 && !redactKeys {
					elemParts[len(elemParts)-1] = fmt.Sprintf("%s[%d]", parts[len(parts)-1], i)
				}
				nextPath := safeRedactionBase
				if !redactKeys {
					nextPath = fmt.Sprintf("%s[%d]", safeRedactionBase, i)
				}
				if err := rejectRedactionNodeDelimiterKeysWithOptions(elem, parts[1], nextPath, elemParts, false, redactKeys); err != nil {
					return err
				}
			}
			return nil
		}
		for i, elem := range seq {
			elemParts := slices.Clone(parts)
			if !redactKeys {
				if len(elemParts) == 0 {
					elemParts = []string{fmt.Sprintf("[%d]", i)}
				} else {
					elemParts[len(elemParts)-1] = fmt.Sprintf("%s[%d]", elemParts[len(elemParts)-1], i)
				}
			}
			if err := rejectConfmapDelimiterKeysWithOptions(elem, elemParts, redactKeys); err != nil {
				return err
			}
		}
	}
	return nil
}

func rewriteCollectorLoopbackConfig(rawYAML []byte, cfg RunnerConfig, signal string, ep collectorEndpointOverride) ([]byte, collectorRewriteMeta, error) {
	var meta collectorRewriteMeta
	lookupEnv := collectorEnvLookup(cfg.MaxProcs)
	var rawDoc any
	if err := yaml.Unmarshal(rawYAML, &rawDoc); err != nil {
		return nil, meta, fmt.Errorf("parsing collector YAML config: %w", sanitizeCollectorYAMLParseError(err))
	}
	if err := rejectCollidingYAMLMapKeys(rawDoc, "collector YAML config", false); err != nil {
		return nil, meta, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(rawYAML, &doc); err != nil {
		return nil, meta, fmt.Errorf("parsing collector YAML config: %w", sanitizeCollectorYAMLParseError(err))
	}
	if len(doc) == 0 {
		return nil, meta, errors.New("collector YAML config is empty")
	}
	if err := rejectConfmapDelimiterKeys(doc, nil); err != nil {
		return nil, meta, err
	}
	if signal == "" {
		signal = "logs"
	}

	svc, err := ensureInlineYAMLSubmap(doc, "service", "service")
	if err != nil {
		return nil, meta, err
	}
	pipelines, err := ensureInlineYAMLSubmap(svc, "pipelines", "service.pipelines")
	if err != nil {
		return nil, meta, err
	}
	procMap, err := optionalInlineYAMLSubmap(doc, "processors", "processors")
	if err != nil {
		return nil, meta, err
	}

	var matched []string
	for k := range pipelines {
		if k == signal || strings.HasPrefix(k, signal+"/") {
			matched = append(matched, k)
		}
	}
	slices.Sort(matched)

	switch len(matched) {
	case 0:
		if len(pipelines) > 0 {
			found := make([]string, 0, len(pipelines))
			for k := range pipelines {
				found = append(found, k)
			}
			slices.Sort(found)
			return nil, meta, fmt.Errorf("collector config defines no %q pipeline (found %v)", signal, found)
		}
		return nil, meta, fmt.Errorf("collector config defines no %q pipeline (service.pipelines is empty)", signal)
	case 1:
		meta.activePipelineKey = matched[0]
		for k := range pipelines {
			if k != meta.activePipelineKey {
				delete(pipelines, k)
			}
		}
	default:
		return nil, meta, fmt.Errorf("collector config defines multiple %q pipelines (%v); keep a single pipeline for the benchmarked signal", signal, matched)
	}

	activePipe, err := ensureInlineYAMLSubmap(pipelines, meta.activePipelineKey, "service.pipelines."+meta.activePipelineKey)
	if err != nil {
		return nil, meta, err
	}
	procIDs, err := extractYAMLStringSlice(activePipe["processors"])
	if err != nil {
		return nil, meta, fmt.Errorf("reading processors for collector pipeline %q: %w", meta.activePipelineKey, err)
	}
	if len(procIDs) > 0 {
		if procMap == nil {
			return nil, meta, fmt.Errorf("collector pipeline %q references undefined processor %q (processors section is missing)", meta.activePipelineKey, procIDs[0])
		}
		for _, id := range procIDs {
			if _, exists := procMap[id]; !exists {
				defined := make([]string, 0, len(procMap))
				for k := range procMap {
					defined = append(defined, k)
				}
				slices.Sort(defined)
				return nil, meta, fmt.Errorf("collector pipeline %q references undefined processor %q (defined processors: %v)", meta.activePipelineKey, id, defined)
			}
		}
	}
	sawBatch := false
	for _, id := range procIDs {
		if id != "batch" && !strings.HasPrefix(id, "batch/") {
			continue
		}
		procTimeout := 200 * time.Millisecond
		procSendSize := 8192
		if rawProcCfg, hasProcCfg := procMap[id]; hasProcCfg && rawProcCfg != nil {
			procCfg, ok := rawProcCfg.(map[string]any)
			if !ok {
				return nil, meta, fmt.Errorf("collector processor %q must be an inline YAML map, got %T", id, rawProcCfg)
			}
			if rawT, hasT := procCfg["timeout"]; hasT && rawT != nil {
				tStr, isStr := rawT.(string)
				if !isStr {
					return nil, meta, fmt.Errorf("collector processor %q timeout must be a duration string, got %T", id, rawT)
				}
				hasInterpolatedT := hasUnescapedConfmapInterpolation(tStr)
				if strings.Contains(tStr, "$") {
					resolvedT, rErr := resolveCollectorEnvStringWithOptions(tStr, lookupEnv, hasInterpolatedT)
					if rErr != nil {
						return nil, meta, fmt.Errorf("resolving collector processor %q timeout: %w", id, rErr)
					}
					tStr = resolvedT
				}
				parsedT, pErr := time.ParseDuration(strings.TrimSpace(tStr))
				if pErr != nil {
					if hasInterpolatedT {
						return nil, meta, fmt.Errorf("parsing collector processor %q timeout: invalid duration", id)
					}
					return nil, meta, fmt.Errorf("parsing collector processor %q timeout %q: %w", id, tStr, pErr)
				}
				if parsedT < 0 {
					if hasInterpolatedT {
						return nil, meta, fmt.Errorf("collector processor %q timeout must be >= 0", id)
					}
					return nil, meta, fmt.Errorf("collector processor %q timeout %q must be >= 0", id, tStr)
				}
				procTimeout = parsedT
			}
			if rawS, hasS := procCfg["send_batch_size"]; hasS && rawS != nil {
				if sStr, isStr := rawS.(string); isStr && hasUnescapedConfmapInterpolation(sStr) {
					resolvedS, rErr := resolveCollectorEnvStringWithOptions(sStr, lookupEnv, true)
					if rErr != nil {
						return nil, meta, fmt.Errorf("resolving collector processor %q send_batch_size: %w", id, rErr)
					}
					n, sErr := strconv.Atoi(strings.TrimSpace(resolvedS))
					if sErr != nil || n < 0 {
						return nil, meta, fmt.Errorf("parsing collector processor %q send_batch_size: expected non-negative integer", id)
					}
					procSendSize = n
				} else {
					parsedS, sErr := parseYAMLNonNegativeInt(rawS)
					if sErr != nil {
						return nil, meta, fmt.Errorf("parsing collector processor %q send_batch_size: %w", id, sErr)
					}
					procSendSize = parsedS
				}
			}
		}
		meta.batchProcessorTimeout = max(meta.batchProcessorTimeout, procTimeout)
		if !sawBatch {
			meta.batchProcessorSendSize = procSendSize
			sawBatch = true
		} else if procSendSize > meta.batchProcessorSendSize {
			meta.batchProcessorSendSize = procSendSize
		}
	}

	if procMap != nil {
		activeProcs := make(map[string]struct{}, len(procIDs))
		for _, id := range procIDs {
			activeProcs[id] = struct{}{}
		}
		for k := range procMap {
			if _, used := activeProcs[k]; !used {
				delete(procMap, k)
			}
		}
		if len(procMap) == 0 {
			delete(doc, "processors")
		}
	}

	var (
		exporterIDs                 []string
		hasListInterpolatedExporter bool
	)
	if rawExpStr, isStr := activePipe["exporters"].(string); isStr && hasUnescapedConfmapInterpolation(rawExpStr) {
		hasListInterpolatedExporter = true
		exporterIDs, err = resolveCollectorStringSliceWithConfmap(rawExpStr, lookupEnv)
		if err != nil {
			return nil, meta, fmt.Errorf("reading exporters for collector pipeline %q: %w", meta.activePipelineKey, err)
		}
	} else {
		exporterIDs, err = extractYAMLStringSlice(activePipe["exporters"])
		if err != nil {
			return nil, meta, fmt.Errorf("reading exporters for collector pipeline %q: %w", meta.activePipelineKey, err)
		}
	}
	if len(exporterIDs) != 1 {
		safeIDs := make([]string, len(exporterIDs))
		for i, id := range exporterIDs {
			if hasListInterpolatedExporter || hasUnescapedConfmapInterpolation(id) {
				safeIDs[i] = interpolatedExporterPlaceholder
			} else {
				safeIDs[i] = id
			}
		}
		return nil, meta, fmt.Errorf("collector pipeline %q must configure exactly 1 bigquery exporter for single-sink accounting, got %d (%v)", meta.activePipelineKey, len(exporterIDs), safeIDs)
	}
	rawExporterID := exporterIDs[0]
	hasInterpolatedExporter := hasListInterpolatedExporter || hasUnescapedConfmapInterpolation(rawExporterID)
	resolvedExporterID := rawExporterID
	if !hasListInterpolatedExporter && (hasInterpolatedExporter || strings.Contains(rawExporterID, "$$")) {
		var rErr error
		resolvedExporterID, rErr = resolveCollectorScalarWithConfmap(rawExporterID, lookupEnv)
		if rErr != nil {
			return nil, meta, fmt.Errorf("resolving exporter for collector pipeline %q: %w", meta.activePipelineKey, rErr)
		}
	}
	activeExpID, validExpID := parseComponentID(resolvedExporterID)
	if !validExpID || activeExpID.Type().String() != "bigquery" {
		if hasInterpolatedExporter {
			return nil, meta, fmt.Errorf("collector pipeline %q references unsupported or invalid bigquery exporter", meta.activePipelineKey)
		}
		return nil, meta, fmt.Errorf("collector pipeline %q references unsupported non-bigquery exporter %q", meta.activePipelineKey, resolvedExporterID)
	}
	meta.activeExporterID = activeExpID.String()
	diagExporterID := meta.activeExporterID
	if hasInterpolatedExporter {
		diagExporterID = interpolatedExporterPlaceholder
	}
	meta.activeExporterDiagnosticID = diagExporterID

	exportersMap, err := optionalInlineYAMLSubmap(doc, "exporters", "exporters")
	if err != nil {
		return nil, meta, err
	}
	if exportersMap == nil {
		if hasInterpolatedExporter {
			return nil, meta, fmt.Errorf("collector pipeline %q references undefined exporter %s (exporters section is missing)", meta.activePipelineKey, interpolatedExporterPlaceholder)
		}
		return nil, meta, fmt.Errorf("collector pipeline %q references undefined exporter %q (exporters section is missing)", meta.activePipelineKey, meta.activeExporterID)
	}
	exporterDiagLabel := func(rawKey string) string {
		if hasInterpolatedExporter && sameComponentID(rawKey, meta.activeExporterID) {
			return interpolatedExporterPlaceholder
		}
		return rawKey
	}
	seenExporterIDs := make(map[component.ID]string, len(exportersMap))
	envSourcedExporters := make(map[string]bool)
	envSourcedConfs := make(map[string]*confmap.Conf)
	envSQNullSizers := make(map[string]collectorSQConfmapNullSizers)
	expandedExporters := make(map[string]any, len(exportersMap))
	exporterKeys := make([]string, 0, len(exportersMap))
	for k := range exportersMap {
		exporterKeys = append(exporterKeys, k)
	}
	slices.Sort(exporterKeys)
	for _, k := range exporterKeys {
		diagKey := exporterDiagLabel(k)
		expID, valid := parseComponentID(k)
		if !valid {
			return nil, meta, fmt.Errorf("collector exporter %q has invalid component ID", diagKey)
		}
		canonical := expID.String()
		diagCanonical := exporterDiagLabel(canonical)
		if prev, dup := seenExporterIDs[expID]; dup {
			return nil, meta, fmt.Errorf("collector config defines duplicate exporters (%q and %q) normalizing to %q", exporterDiagLabel(prev), diagKey, diagCanonical)
		}
		seenExporterIDs[expID] = k
		rawExp := exportersMap[k]
		bodyFromEnv := false
		if rawStr, isStr := rawExp.(string); isStr && hasUnescapedConfmapInterpolation(rawStr) {
			resolvedConf, confErr := resolveInlineConfmap("exporter", rawStr, lookupEnv)
			if confErr != nil {
				return nil, meta, fmt.Errorf("resolving collector exporter %q: %w", diagKey, confErr)
			}
			var (
				subConf   *confmap.Conf
				nullSizer collectorSQConfmapNullSizers
			)
			subConf, rawExp, nullSizer = extractSanitizedConfmapExporter(resolvedConf, "exporter", "exporters."+diagKey)
			if strVal, isResStr := rawExp.(string); isResStr && strings.Contains(strVal, "${") {
				preExpanded, preErr := expandBlockedPatternsPreservingEscapedDollars(rawStr, lookupEnv)
				if preErr != nil {
					return nil, meta, fmt.Errorf("resolving collector exporter %q: %w", diagKey, sanitizeCollectorConfmapError(preErr))
				}
				if preStr, preOK := preEscapeElementAsString(preExpanded); !preOK || hasUnclosedUnescapedConfmapInterpolation(preStr) {
					return nil, meta, fmt.Errorf("resolving collector exporter %q: unclosed ${...} reference", diagKey)
				}
			}
			envSourcedConfs[k] = subConf
			envSQNullSizers[k] = nullSizer
			bodyFromEnv = true
		}
		if rawExp != nil {
			switch rawExp.(type) {
			case map[string]any, map[any]any:
			default:
				return nil, meta, fmt.Errorf("collector exporter %q must be a YAML map or null, got %s", diagKey, describeYAMLValueKind(rawExp))
			}
		}
		envSourcedExporters[k] = bodyFromEnv
		expandedExporters[k] = rawExp
	}
	for _, k := range exporterKeys {
		expID, _ := parseComponentID(k)
		canonical := expID.String()
		// Collector decodes exporters into map[component.ID]map[string]any and looks up
		// each entry via conf.Sub(id.String()), so any key under exporters: differing
		// from id.String() yields an empty component config. Canonical unused keys (such
		// as "custom/a": {}) pass and are pruned below; non-canonical unfamiliar types
		// (such as "custom /a": {}) fail closed, while empty-default types ("debug /a",
		// "nop /a") are permitted and pruned.
		if k != canonical && exporterRequiresNonEmptyConfig(expID) {
			return nil, meta, fmt.Errorf("collector exporter %q must use canonical component ID %q", exporterDiagLabel(k), exporterDiagLabel(canonical))
		}
		// Validate canonical bundled stock exporters (debug, file) before pruning so
		// invalid or env-expanded configurations fail preflight identically to otelcol-bq.
		if k == canonical && !sameComponentID(k, meta.activeExporterID) {
			if vErr := validateBundledInactiveExporterConfig(expID, exporterDiagLabel(k), expandedExporters[k], envSourcedExporters[k], envSourcedConfs[k], envSQNullSizers[k], lookupEnv); vErr != nil {
				return nil, meta, vErr
			}
		}
	}
	if _, exists := exportersMap[meta.activeExporterID]; !exists {
		defined := make([]string, 0, len(exportersMap))
		for k := range exportersMap {
			defined = append(defined, k)
		}
		slices.Sort(defined)
		if hasInterpolatedExporter {
			return nil, meta, fmt.Errorf("collector pipeline %q references undefined exporter %s (defined exporters: %v)", meta.activePipelineKey, interpolatedExporterPlaceholder, defined)
		}
		return nil, meta, fmt.Errorf("collector pipeline %q references undefined exporter %q (defined exporters: %v)", meta.activePipelineKey, meta.activeExporterID, defined)
	}
	if hasListInterpolatedExporter || rawExporterID != meta.activeExporterID {
		activePipe["exporters"] = []string{meta.activeExporterID}
	}
	if envSourcedExporters[meta.activeExporterID] {
		meta.activeExporterBodyEnvSourced = true
		meta.sqConfmapNullSizers = envSQNullSizers[meta.activeExporterID]
		activeExpRaw := expandedExporters[meta.activeExporterID]
		var expandedMap map[string]any
		if activeExpRaw == nil {
			expandedMap = map[string]any{}
		} else {
			normAny, normErr := normalizeNestedMapsToStringKeys(activeExpRaw)
			if normErr != nil {
				return nil, meta, normErr
			}
			var isMap bool
			expandedMap, isMap = normAny.(map[string]any)
			if !isMap || expandedMap == nil {
				return nil, meta, fmt.Errorf("collector exporter %q must be a YAML map or null", diagExporterID)
			}
		}
		if err := rejectExporterBodyDelimiterKeysWithOptions(expandedMap, diagExporterID, "exporters."+diagExporterID, []string{"exporters", diagExporterID}, true); err != nil {
			return nil, meta, err
		}
		exportersMap[meta.activeExporterID] = escapeConfmapDollarsInYAMLValue(expandedMap)
	}
	bq, err := ensureInlineYAMLSubmap(exportersMap, meta.activeExporterID, "exporters."+diagExporterID)
	if err != nil {
		return nil, meta, err
	}
	if err := rewriteBigQueryExporterMapWithLookup(bq, diagExporterID, signal, cfg, ep, &meta, lookupEnv); err != nil {
		return nil, meta, err
	}
	meta.effectiveLogsSynthesizeInsertID = true
	if defaultCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config); ok {
		meta.effectiveLogsSynthesizeInsertID = defaultCfg.Logs.SynthesizeInsertID
		if rawLogs, hasLogs := bq["logs"]; hasLogs && rawLogs != nil {
			logsMap, isMap := rawLogs.(map[string]any)
			if !isMap {
				return nil, meta, fmt.Errorf("collector exporter %q logs must be an inline YAML map, got %T", diagExporterID, rawLogs)
			}
			resolvedLogsAny, resLogsErr := resolveCollectorEnvYAMLValueWithOptions(logsMap, "exporters."+diagExporterID+".logs", lookupEnv, true)
			if resLogsErr != nil {
				return nil, meta, resLogsErr
			}
			resolvedLogsRaw, normErr := normalizeNestedMapsToStringKeys(resolvedLogsAny)
			if normErr != nil {
				return nil, meta, normErr
			}
			if resolvedLogsMap, ok := resolvedLogsRaw.(map[string]any); ok && resolvedLogsMap != nil {
				if err := confmap.NewFromStringMap(resolvedLogsMap).Unmarshal(&defaultCfg.Logs); err != nil {
					return nil, meta, fmt.Errorf("decoding collector exporter %q logs config: %w", diagExporterID, scrubInterpolatedErrorWithScopeAndForceLookup([]string{"logs"}, logsMap, resolvedLogsMap, err, meta.activeExporterBodyEnvSourced, lookupEnv))
				}
				meta.effectiveLogsLogNameAttr = defaultCfg.Logs.LogNameAttribute
				meta.effectiveLogsInsertIDAttr = defaultCfg.Logs.InsertIDAttribute
				meta.effectiveLogsSynthesizeInsertID = defaultCfg.Logs.SynthesizeInsertID
			}
		}
	}
	impact := collectorPipelineIdentityEffectWithLookup(
		signal, procIDs, procMap, meta.effectiveLogsLogNameAttr, meta.effectiveLogsInsertIDAttr, lookupEnv,
	)
	meta.pipelineAltersIdentityKeys = impact.altersIdentityKeys
	meta.pipelineModifiesNonIdentityAttrs = impact.modifiesNonIdentityAttrs
	meta.canSimulateNonIdentityAttrs = impact.canSimulate
	meta.nonIdentityAttrOps = impact.ops

	for k := range exportersMap {
		if k != meta.activeExporterID {
			delete(exportersMap, k)
		}
	}

	activeExts, err := extractYAMLStringSlice(svc["extensions"])
	if err != nil {
		return nil, meta, fmt.Errorf("reading collector service.extensions: %w", err)
	}
	activeExtSet := make(map[string]struct{}, len(activeExts))
	dedupExts := make([]string, 0, len(activeExts))
	for _, extID := range activeExts {
		if _, seen := activeExtSet[extID]; !seen {
			activeExtSet[extID] = struct{}{}
			dedupExts = append(dedupExts, extID)
		}
	}

	sqMap, err := optionalInlineYAMLSubmap(bq, "sending_queue", "exporters."+diagExporterID+".sending_queue")
	if err != nil {
		return nil, meta, err
	}
	if sqMap != nil {
		if _, err := optionalInlineYAMLSubmap(sqMap, "batch", "exporters."+diagExporterID+".sending_queue.batch"); err != nil {
			return nil, meta, err
		}
		sqNilPaths := make(map[string]struct{})
		resolvedSQAny, resSQErr := resolveCollectorEnvYAMLValueTracked(sqMap, "exporters."+diagExporterID+".sending_queue", lookupEnv, true, sqNilPaths)
		if resSQErr != nil {
			return nil, meta, resSQErr
		}
		meta.sqConfmapNullSizers = meta.sqConfmapNullSizers.merge(extractSQNullSizers(sqNilPaths, "exporters."+diagExporterID+"."))
		resolvedSQNormalized, normErr := normalizeNestedMapsToStringKeys(resolvedSQAny)
		if normErr != nil {
			return nil, meta, normErr
		}
		storageInterpolated, stErr := normalizeSendingQueueStorageWithConfmap(sqMap, resolvedSQNormalized, diagExporterID, meta.activeExporterBodyEnvSourced, lookupEnv)
		if stErr != nil {
			return nil, meta, stErr
		}
		hasInterpolatedStorage := meta.activeExporterBodyEnvSourced || storageInterpolated
		sqExpCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config)
		if !ok {
			return nil, meta, errors.New("unexpected exporter config type")
		}
		if err := confmap.NewFromStringMap(map[string]any{"sending_queue": resolvedSQNormalized}).Unmarshal(sqExpCfg); err != nil {
			return nil, meta, fmt.Errorf("decoding collector exporter %q sending_queue config: %w", diagExporterID, scrubInterpolatedErrorWithScopeAndForceLookup([]string{"sending_queue"}, sqMap, resolvedSQNormalized, err, meta.activeExporterBodyEnvSourced, lookupEnv))
		}
		applyConfmapNullSizersToQueue(&sqExpCfg.QueueSettings, resolvedSQNormalized, meta.sqConfmapNullSizers)
		if q := sqExpCfg.QueueSettings.Get(); q != nil && q.StorageID != nil {
			stID := strings.TrimSpace(q.StorageID.String())
			if !isFileStorageComponentID(stID) {
				if hasInterpolatedStorage {
					return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage is unsupported; only file_storage* extensions are supported", diagExporterID)
				}
				return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage %q is unsupported; only file_storage* extensions are supported", diagExporterID, stID)
			}
			if _, isActive := activeExtSet[stID]; !isActive {
				if hasInterpolatedStorage {
					return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage is not enabled in service.extensions", diagExporterID)
				}
				return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage %q is not enabled in service.extensions", diagExporterID, stID)
			}
		}
		if sqExpCfg.QueueSettings.HasValue() {
			q := sqExpCfg.QueueSettings.Get()
			if q != nil && q.Batch.HasValue() {
				qb := q.Batch.Get()
				if qb != nil && qb.MinSize > 0 && qb.FlushTimeout > 0 {
					meta.queueBatchFlushTimeout = qb.FlushTimeout
					effectiveSizer := qb.Sizer
					if strings.TrimSpace(effectiveSizer.String()) == "" {
						effectiveSizer = q.Sizer
					}
					if s := strings.ToLower(strings.TrimSpace(effectiveSizer.String())); s == "" || s == "items" {
						meta.queueBatchMinItems = int(min(qb.MinSize, int64(math.MaxInt)))
					} else {
						meta.queueBatchMinItems = 0
					}
				}
			}
		}
	}

	extMap, extErr := optionalInlineYAMLSubmap(doc, "extensions", "extensions")
	if extErr != nil {
		return nil, meta, extErr
	}
	if len(dedupExts) > 0 {
		if extMap == nil {
			return nil, meta, fmt.Errorf("collector service.extensions references undefined extension %q (extensions section is missing)", dedupExts[0])
		}
		healthCheckCount := 0
		usedStorageDirs := make(map[string]string)
		for _, extID := range dedupExts {
			if _, exists := extMap[extID]; !exists {
				defined := make([]string, 0, len(extMap))
				for k := range extMap {
					defined = append(defined, k)
				}
				slices.Sort(defined)
				return nil, meta, fmt.Errorf("collector service.extensions references undefined extension %q (defined extensions: %v)", extID, defined)
			}
			switch {
			case isHealthCheckComponentID(extID):
				healthCheckCount++
				if healthCheckCount > 1 {
					return nil, meta, fmt.Errorf("collector service.extensions enables multiple health_check extensions (%v); at most one is supported", dedupExts)
				}
				hc, hcErr := ensureInlineYAMLSubmap(extMap, extID, "extensions."+extID)
				if hcErr != nil {
					return nil, meta, hcErr
				}
				if err := rejectCollectorHealthCheckTLS(hc, extID, lookupEnv); err != nil {
					return nil, meta, err
				}
				hc["endpoint"] = ep.healthAddr
				var rawPath string
				if rawVal, hasPath := hc["path"]; hasPath && rawVal != nil {
					pStr, ok := rawVal.(string)
					if !ok {
						return nil, meta, fmt.Errorf("collector config extensions.%s.path must be a string, got %T", extID, rawVal)
					}
					if strings.Contains(pStr, "$") {
						resolvedPath, rErr := resolveCollectorEnvStringWithOptions(pStr, lookupEnv, hasUnescapedConfmapInterpolation(pStr))
						if rErr != nil {
							return nil, meta, fmt.Errorf("resolving collector config extensions.%s.path: %w", extID, rErr)
						}
						pStr = resolvedPath
					}
					rawPath = pStr
				}
				meta.hasHealthCheck = true
				meta.healthCheckPath = normalizeHealthCheckPath(rawPath)
			case isFileStorageComponentID(extID):
				if strings.TrimSpace(ep.storageRoot) == "" {
					return nil, meta, fmt.Errorf("collector extension %q requires an isolated storageRoot directory", extID)
				}
				safeExtName := sanitizeExtensionDirName(extID)
				storageKey := strings.ToLower(safeExtName)
				if prevExt, collided := usedStorageDirs[storageKey]; collided {
					return nil, meta, fmt.Errorf("collector file_storage extensions %q and %q map to the same storage directory %q", prevExt, extID, safeExtName)
				}
				usedStorageDirs[storageKey] = extID
				queueDir := filepath.Join(ep.storageRoot, safeExtName, "queue")
				compactionDir := filepath.Join(ep.storageRoot, safeExtName, "compaction")
				if !ep.dryRun {
					if mkErr := os.MkdirAll(queueDir, 0o700); mkErr != nil {
						return nil, meta, fmt.Errorf("creating isolated file_storage queue directory for %q: %w", extID, mkErr)
					}
					if mkErr := os.MkdirAll(compactionDir, 0o700); mkErr != nil {
						return nil, meta, fmt.Errorf("creating isolated file_storage compaction directory for %q: %w", extID, mkErr)
					}
				}
				fsCfg, fsErr := ensureInlineYAMLSubmap(extMap, extID, "extensions."+extID)
				if fsErr != nil {
					return nil, meta, fsErr
				}
				fsCfg["directory"] = queueDir
				compactionCfg, compErr := ensureInlineYAMLSubmap(fsCfg, "compaction", "extensions."+extID+".compaction")
				if compErr != nil {
					return nil, meta, compErr
				}
				compactionCfg["directory"] = compactionDir
			default:
				return nil, meta, fmt.Errorf("collector service.extensions references unsupported active extension %q", extID)
			}
		}
		for k := range extMap {
			if _, used := activeExtSet[k]; !used {
				delete(extMap, k)
			}
		}
		if len(extMap) == 0 {
			delete(doc, "extensions")
		}
	} else {
		delete(doc, "extensions")
	}

	receiverIDs, err := extractYAMLStringSlice(activePipe["receivers"])
	if err != nil {
		return nil, meta, fmt.Errorf("reading receivers for collector pipeline %q: %w", meta.activePipelineKey, err)
	}
	if len(receiverIDs) == 0 {
		return nil, meta, fmt.Errorf("collector pipeline %q must configure at least 1 otlp receiver", meta.activePipelineKey)
	}
	activeReceivers := make(map[string]struct{}, len(receiverIDs))
	dedupReceivers := make([]string, 0, len(receiverIDs))
	for _, recvID := range receiverIDs {
		if !isOTLPComponentID(recvID) {
			return nil, meta, fmt.Errorf("collector pipeline %q references unsupported non-otlp receiver %q", meta.activePipelineKey, recvID)
		}
		if _, seen := activeReceivers[recvID]; !seen {
			activeReceivers[recvID] = struct{}{}
			dedupReceivers = append(dedupReceivers, recvID)
		}
	}

	receiversMap, err := optionalInlineYAMLSubmap(doc, "receivers", "receivers")
	if err != nil {
		return nil, meta, err
	}
	if receiversMap == nil {
		return nil, meta, fmt.Errorf("collector pipeline %q references undefined receiver %q (receivers section is missing)", meta.activePipelineKey, dedupReceivers[0])
	}
	for _, recvID := range dedupReceivers {
		if _, exists := receiversMap[recvID]; !exists {
			defined := make([]string, 0, len(receiversMap))
			for k := range receiversMap {
				defined = append(defined, k)
			}
			slices.Sort(defined)
			return nil, meta, fmt.Errorf("collector pipeline %q references undefined receiver %q (defined receivers: %v)", meta.activePipelineKey, recvID, defined)
		}
	}
	usedAddrs := make(map[string]struct{}, len(dedupReceivers))
	if ep.otlpAddr != "" {
		usedAddrs[ep.otlpAddr] = struct{}{}
	}
	for i, recvID := range dedupReceivers {
		otlpRecv, rErr := ensureInlineYAMLSubmap(receiversMap, recvID, "receivers."+recvID)
		if rErr != nil {
			return nil, meta, rErr
		}
		protocols, pErr := ensureInlineYAMLSubmap(otlpRecv, "protocols", "receivers."+recvID+".protocols")
		if pErr != nil {
			return nil, meta, pErr
		}
		delete(protocols, "http")
		grpcCfg, gErr := ensureInlineYAMLSubmap(protocols, "grpc", "receivers."+recvID+".protocols.grpc")
		if gErr != nil {
			return nil, meta, gErr
		}
		if rawTLS, hasTLS := grpcCfg["tls"]; hasTLS && rawTLS != nil {
			return nil, meta, fmt.Errorf("collector receiver %q configures protocols.grpc.tls, which is not supported by loopback plaintext mode", recvID)
		}
		if i == 0 {
			grpcCfg["endpoint"] = ep.otlpAddr
			continue
		}
		addr := "127.0.0.1:0"
		if i-1 < len(ep.extraOTLPAddrs) && strings.TrimSpace(ep.extraOTLPAddrs[i-1]) != "" {
			candidate := strings.TrimSpace(ep.extraOTLPAddrs[i-1])
			if candidate != "127.0.0.1:0" {
				if _, dup := usedAddrs[candidate]; dup {
					return nil, meta, fmt.Errorf("duplicate OTLP receiver endpoint %q assigned to receiver %q", candidate, recvID)
				}
				usedAddrs[candidate] = struct{}{}
			}
			addr = candidate
		}
		grpcCfg["endpoint"] = addr
		meta.extraOTLPAddrs = append(meta.extraOTLPAddrs, addr)
	}
	for k := range receiversMap {
		if _, used := activeReceivers[k]; !used {
			delete(receiversMap, k)
		}
	}

	existingTelem, err := optionalInlineYAMLSubmap(svc, "telemetry", "service.telemetry")
	if err != nil {
		return nil, meta, err
	}
	var (
		existingMetrics map[string]any
		existingLogs    map[string]any
	)
	if existingTelem != nil {
		if existingMetrics, err = optionalInlineYAMLSubmap(existingTelem, "metrics", "service.telemetry.metrics"); err != nil {
			return nil, meta, err
		}
		if existingLogs, err = optionalInlineYAMLSubmap(existingTelem, "logs", "service.telemetry.logs"); err != nil {
			return nil, meta, err
		}
		if _, err = optionalInlineYAMLSubmap(existingTelem, "traces", "service.telemetry.traces"); err != nil {
			return nil, meta, err
		}
	}
	if ep.useBQFake {
		telem, tErr := ensureInlineYAMLSubmap(svc, "telemetry", "service.telemetry")
		if tErr != nil {
			return nil, meta, tErr
		}
		delete(telem, "traces")
		sanitizedLogs := map[string]any{
			"output_paths":       []any{"stderr"},
			"error_output_paths": []any{"stderr"},
		}
		if existingLogs != nil {
			for _, scalarKey := range []string{"level", "encoding"} {
				if rawVal, ok := existingLogs[scalarKey]; ok && rawVal != nil {
					s, ok := rawVal.(string)
					if !ok {
						return nil, meta, fmt.Errorf("collector service.telemetry.logs.%s must be a string, got %T", scalarKey, rawVal)
					}
					if _, rErr := resolveCollectorEnvStringWithOptions(s, lookupEnv, true); rErr != nil {
						return nil, meta, fmt.Errorf("resolving collector service.telemetry.logs.%s: %w", scalarKey, rErr)
					}
					sanitizedLogs[scalarKey] = s
				}
			}
		}
		telem["logs"] = sanitizedLogs
		if existingMetrics != nil {
			delete(existingMetrics, "readers")
			delete(existingMetrics, "address")
		}
	}
	if ep.metricsHost != "" && ep.metricsPort > 0 {
		telem, tErr := ensureInlineYAMLSubmap(svc, "telemetry", "service.telemetry")
		if tErr != nil {
			return nil, meta, tErr
		}
		metricsCfg, mErr := ensureInlineYAMLSubmap(telem, "metrics", "service.telemetry.metrics")
		if mErr != nil {
			return nil, meta, mErr
		}
		metricsCfg["level"] = "detailed"
		metricsCfg["readers"] = []any{
			map[string]any{
				"pull": map[string]any{
					"exporter": map[string]any{
						"prometheus": map[string]any{
							"host":                ep.metricsHost,
							"port":                ep.metricsPort,
							"without_scope_info":  true,
							"without_type_suffix": true,
							"without_units":       true,
						},
					},
				},
			},
		}
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, meta, fmt.Errorf("marshaling rewritten collector YAML: %w", err)
	}
	return out, meta, nil
}

var (
	ottlDeleteMatchingKeysStmtPattern = regexp.MustCompile(`^\s*delete_matching_keys\(\s*attributes\s*,\s*("(?:[^"\\]|\\.)*")\s*\)\s*$`)
	ottlDeleteKeyStmtPattern          = regexp.MustCompile(`^\s*delete_key\(\s*attributes\s*,\s*("(?:[^"\\]|\\.)*")\s*\)\s*$`)
	ottlSetAttrStmtPattern            = regexp.MustCompile(`^\s*set\(\s*attributes\[\s*("(?:[^"\\]|\\.)*")\s*\]\s*,\s*(.+)\)\s*$`)
)

type collectorPipelineIdentityImpact struct {
	altersIdentityKeys       bool
	modifiesNonIdentityAttrs bool
	canSimulate              bool
	ops                      []collectorAttrOp
}

func isScalarAttrLiteral(val any) bool {
	switch val.(type) {
	case string, bool, int, int64, uint64, float64:
		return true
	default:
		return false
	}
}

func parseOTTLAttrLiteral(rhs string) (any, bool) {
	s := strings.TrimSpace(rhs)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u, true
		}
		return nil, false
	}
	if s == "true" {
		return true, true
	}
	if s == "false" {
		return false, true
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, true
	}
	if !strings.ContainsAny(s, "nNiI") {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f, true
		}
	}
	return nil, false
}

func isSingleStandaloneConfmapExpr(raw string) bool {
	if !strings.HasPrefix(raw, "${") || !strings.HasSuffix(raw, "}") {
		return false
	}
	return findMatchingConfmapCloseBrace(raw, 2) == len(raw)-1
}

// resolveCollectorConfmapString resolves OTel Collector confmap string expressions
// (`$$` escaping, bare `${VAR}`, and `${env:VAR}` / `${env:VAR:-default}` including
// nested fallbacks) against lookupEnv using the same rules as preflight validation,
// failing closed (ok=false) on unsupported schemes (e.g. file:, http:, yaml:),
// empty/malformed references, unclosed `${`, or cycle/depth overflow.
func resolveCollectorConfmapString(raw string, lookupEnv func(string) (string, bool)) (string, bool) {
	resolved, err := resolveCollectorEnvStringWithOptions(raw, lookupEnv, true)
	if err != nil {
		return "", false
	}
	return resolved, true
}

func resolveCollectorConfmapActionValue(raw any, lookupEnv func(string) (string, bool)) (any, bool) {
	v, isStr := raw.(string)
	if !isStr {
		return raw, true
	}
	resolved, ok := resolveCollectorConfmapString(v, lookupEnv)
	if !ok {
		return nil, false
	}
	if !isSingleStandaloneConfmapExpr(v) {
		return resolved, true
	}
	if resolved == "" {
		// Standalone unset or empty ${env:...} unmarshals as nil YAML; fail closed.
		return nil, false
	}
	var parsed any
	if err := yaml.Unmarshal([]byte(resolved), &parsed); err != nil {
		return nil, false
	}
	if parsed == nil || !isScalarAttrLiteral(parsed) {
		return nil, false
	}
	if strParsed, okStr := parsed.(string); okStr && strParsed != resolved {
		// Fail closed if YAML unmarshaling alters string content (e.g. quoted YAML scalars),
		// since confmap preserves raw yamlBytes verbatim when rawConf is string.
		return nil, false
	}
	return parsed, true
}

// collectorPipelineIdentityEffect classifies active pipeline processors for
// identity-key mutation, non-identity attribute modification, and deterministic
// pre-exporter attribute simulation using process environment lookups.
func collectorPipelineIdentityEffect(
	signal string,
	procIDs []string,
	procMap map[string]any,
	logNameAttr, insertIDAttr string,
) collectorPipelineIdentityImpact {
	return collectorPipelineIdentityEffectWithLookup(signal, procIDs, procMap, logNameAttr, insertIDAttr, os.LookupEnv)
}

func collectorPipelineIdentityEffectWithLookup(
	signal string,
	procIDs []string,
	procMap map[string]any,
	logNameAttr, insertIDAttr string,
	lookupEnv func(string) (string, bool),
) collectorPipelineIdentityImpact {
	if len(procIDs) == 0 {
		return collectorPipelineIdentityImpact{canSimulate: true}
	}
	recordIdentityAttrs := make([]string, 0, 1+len(benchLogNameAttrs)+len(benchInsertIDAttrs)+2)
	recordIdentityAttrs = append(recordIdentityAttrs, "service.name")
	recordIdentityAttrs = append(recordIdentityAttrs, benchLogNameAttrs...)
	recordIdentityAttrs = append(recordIdentityAttrs, benchInsertIDAttrs...)
	if logNameAttr != "" {
		recordIdentityAttrs = append(recordIdentityAttrs, logNameAttr)
	}
	if insertIDAttr != "" {
		recordIdentityAttrs = append(recordIdentityAttrs, insertIDAttr)
	}

	inspectAndCompileAction := func(scope string, action map[string]any, identityAttrs []string) (ops []collectorAttrOp, simOK bool, altersID bool) {
		rawActStr, ok := action["action"].(string)
		if !ok {
			return nil, false, true
		}
		actStr, ok := resolveCollectorConfmapString(rawActStr, lookupEnv)
		if !ok {
			return nil, false, true
		}
		act := strings.ToLower(strings.TrimSpace(actStr))
		switch act {
		case "delete", "insert", "update", "upsert", "hash", "convert":
		default:
			return nil, false, true
		}
		for k := range action {
			switch k {
			case "action", "key", "pattern", "value", "from_attribute", "from_context", "converted_type":
			default:
				return nil, false, true
			}
		}
		var (
			keyStr   string
			patStr   string
			compiled *regexp.Regexp
		)
		hasTarget := false
		if rawKey, hasKey := action["key"]; hasKey && rawKey != nil {
			k, ok := rawKey.(string)
			if !ok {
				return nil, false, true
			}
			resolvedKey, ok := resolveCollectorConfmapString(k, lookupEnv)
			if !ok {
				return nil, false, true
			}
			keyStr = resolvedKey
			if keyStr != "" {
				hasTarget = true
			}
			if slices.Contains(identityAttrs, keyStr) {
				return nil, false, true
			}
		}
		if rawPat, hasPat := action["pattern"]; hasPat && rawPat != nil {
			p, ok := rawPat.(string)
			if !ok {
				return nil, false, true
			}
			resolvedPat, ok := resolveCollectorConfmapString(p, lookupEnv)
			if !ok {
				return nil, false, true
			}
			re, err := regexp.Compile(resolvedPat)
			if err != nil {
				return nil, false, true
			}
			patStr = resolvedPat
			compiled = re
			if patStr != "" {
				hasTarget = true
			}
			for _, idKey := range identityAttrs {
				if re.MatchString(idKey) {
					return nil, false, true
				}
			}
		}
		if !hasTarget {
			return nil, false, true
		}

		hasFromAttr := action["from_attribute"] != nil
		hasFromCtx := action["from_context"] != nil
		hasConvType := action["converted_type"] != nil
		val, hasVal := action["value"]

		switch act {
		case "delete":
			if hasFromAttr || hasFromCtx || hasConvType || (hasVal && val != nil) {
				return nil, false, false
			}
			if keyStr != "" {
				ops = append(ops, collectorAttrOp{scope: scope, kind: "delete_key", key: keyStr})
			}
			if compiled != nil {
				ops = append(ops, collectorAttrOp{scope: scope, kind: "delete_pattern", pattern: compiled})
			}
			return ops, true, false
		case "insert", "update", "upsert":
			if keyStr == "" || compiled != nil || hasFromAttr || hasFromCtx || hasConvType || !hasVal {
				return nil, false, false
			}
			resolvedVal, valOK := resolveCollectorConfmapActionValue(val, lookupEnv)
			if !valOK || !isScalarAttrLiteral(resolvedVal) {
				return nil, false, false
			}
			return []collectorAttrOp{{
				scope: scope,
				kind:  act + "_literal",
				key:   keyStr,
				value: resolvedVal,
			}}, true, false
		default: // hash, convert
			return nil, false, false
		}
	}

	impact := collectorPipelineIdentityImpact{canSimulate: true}
	failClosed := collectorPipelineIdentityImpact{
		altersIdentityKeys:       true,
		modifiesNonIdentityAttrs: true,
		canSimulate:              false,
	}

	for _, id := range procIDs {
		switch {
		case id == "memory_limiter" || strings.HasPrefix(id, "memory_limiter/"):
			continue
		case id == "batch" || strings.HasPrefix(id, "batch/"):
			continue
		case id == "resource" || strings.HasPrefix(id, "resource/"):
			rawProcCfg, hasProcCfg := procMap[id]
			if !hasProcCfg || rawProcCfg == nil {
				continue
			}
			cfgMap, ok := rawProcCfg.(map[string]any)
			if !ok {
				return failClosed
			}
			hasFilter := false
			for k, v := range cfgMap {
				switch k {
				case "attributes":
				case "include", "exclude":
					if v != nil {
						hasFilter = true
					}
				default:
					return failClosed
				}
			}
			if hasFilter {
				impact.canSimulate = false
			}
			rawActions, hasActions := cfgMap["attributes"]
			if hasActions && rawActions != nil {
				actions, ok := rawActions.([]any)
				if !ok {
					return failClosed
				}
				if len(actions) > 0 {
					impact.modifiesNonIdentityAttrs = true
				}
				for _, item := range actions {
					actMap, ok := item.(map[string]any)
					if !ok {
						return failClosed
					}
					actOps, simOK, altersID := inspectAndCompileAction("resource", actMap, []string{"service.name"})
					if altersID {
						return failClosed
					}
					if !simOK {
						impact.canSimulate = false
					} else if impact.canSimulate {
						impact.ops = append(impact.ops, actOps...)
					}
				}
			}
		case id == "attributes" || strings.HasPrefix(id, "attributes/"):
			rawProcCfg, hasProcCfg := procMap[id]
			if !hasProcCfg || rawProcCfg == nil {
				continue
			}
			cfgMap, ok := rawProcCfg.(map[string]any)
			if !ok {
				return failClosed
			}
			hasFilter := false
			for k, v := range cfgMap {
				switch k {
				case "actions":
				case "include", "exclude":
					if v != nil {
						hasFilter = true
					}
				default:
					return failClosed
				}
			}
			if hasFilter {
				impact.canSimulate = false
			}
			rawActions, hasActions := cfgMap["actions"]
			if hasActions && rawActions != nil {
				actions, ok := rawActions.([]any)
				if !ok {
					return failClosed
				}
				if len(actions) > 0 {
					impact.modifiesNonIdentityAttrs = true
				}
				for _, item := range actions {
					actMap, ok := item.(map[string]any)
					if !ok {
						return failClosed
					}
					actOps, simOK, altersID := inspectAndCompileAction("record", actMap, recordIdentityAttrs)
					if altersID {
						return failClosed
					}
					if !simOK {
						impact.canSimulate = false
					} else if impact.canSimulate {
						impact.ops = append(impact.ops, actOps...)
					}
				}
			}
		case id == "transform" || strings.HasPrefix(id, "transform/"):
			if signal != "logs" {
				return failClosed
			}
			rawProcCfg, hasProcCfg := procMap[id]
			if !hasProcCfg || rawProcCfg == nil {
				continue
			}
			cfgMap, ok := rawProcCfg.(map[string]any)
			if !ok {
				return failClosed
			}
			for k := range cfgMap {
				if k != "error_mode" && k != "log_statements" {
					return failClosed
				}
			}
			rawGroups, hasGroups := cfgMap["log_statements"]
			if hasGroups && rawGroups != nil {
				groups, ok := rawGroups.([]any)
				if !ok {
					return failClosed
				}
				for _, g := range groups {
					gMap, ok := g.(map[string]any)
					if !ok {
						return failClosed
					}
					rawCtxStr, ok := gMap["context"].(string)
					if !ok {
						return failClosed
					}
					ctxStr, ok := resolveCollectorConfmapString(rawCtxStr, lookupEnv)
					if !ok {
						return failClosed
					}
					var (
						opScope       string
						scopeIdentity []string
					)
					switch strings.TrimSpace(ctxStr) {
					case "resource":
						opScope = "resource"
						scopeIdentity = []string{"service.name"}
					case "log":
						opScope = "record"
						scopeIdentity = recordIdentityAttrs
					default:
						return failClosed
					}
					for gk := range gMap {
						if gk != "context" && gk != "statements" && gk != "conditions" && gk != "error_mode" {
							return failClosed
						}
					}
					if rawConds, hasConds := gMap["conditions"]; hasConds && rawConds != nil {
						if condSlice, ok := rawConds.([]any); !ok || len(condSlice) > 0 {
							return failClosed
						}
					}
					var rawStmts []any
					if rawStmtsVal, hasStmts := gMap["statements"]; hasStmts && rawStmtsVal != nil {
						var stmtsOK bool
						rawStmts, stmtsOK = rawStmtsVal.([]any)
						if !stmtsOK {
							return failClosed
						}
					}
					if len(rawStmts) > 0 {
						impact.modifiesNonIdentityAttrs = true
					}
					for _, s := range rawStmts {
						rawStmtStr, ok := s.(string)
						if !ok {
							return failClosed
						}
						stmtStr, ok := resolveCollectorConfmapString(rawStmtStr, lookupEnv)
						if !ok {
							return failClosed
						}
						switch {
						case ottlDeleteMatchingKeysStmtPattern.MatchString(stmtStr):
							m := ottlDeleteMatchingKeysStmtPattern.FindStringSubmatch(stmtStr)
							pat, err := strconv.Unquote(m[1])
							if err != nil {
								return failClosed
							}
							re, err := regexp.Compile(pat)
							if err != nil {
								return failClosed
							}
							for _, idKey := range scopeIdentity {
								if re.MatchString(idKey) {
									return failClosed
								}
							}
							if impact.canSimulate {
								impact.ops = append(impact.ops, collectorAttrOp{
									scope:   opScope,
									kind:    "delete_pattern",
									pattern: re,
								})
							}
						case ottlDeleteKeyStmtPattern.MatchString(stmtStr):
							m := ottlDeleteKeyStmtPattern.FindStringSubmatch(stmtStr)
							key, err := strconv.Unquote(m[1])
							if err != nil || slices.Contains(scopeIdentity, key) {
								return failClosed
							}
							if impact.canSimulate {
								impact.ops = append(impact.ops, collectorAttrOp{
									scope: opScope,
									kind:  "delete_key",
									key:   key,
								})
							}
						case ottlSetAttrStmtPattern.MatchString(stmtStr):
							m := ottlSetAttrStmtPattern.FindStringSubmatch(stmtStr)
							key, err := strconv.Unquote(m[1])
							if err != nil || slices.Contains(scopeIdentity, key) {
								return failClosed
							}
							rhs := m[2]
							if strings.Contains(rhs, "set(") || strings.Contains(rhs, "delete_") || strings.Contains(rhs, "keep_") || strings.Contains(rhs, "replace_") || strings.Contains(rhs, ";") {
								return failClosed
							}
							scalar, litOK := parseOTTLAttrLiteral(rhs)
							if !litOK {
								impact.canSimulate = false
							} else if impact.canSimulate {
								impact.ops = append(impact.ops, collectorAttrOp{
									scope: opScope,
									kind:  "upsert_literal",
									key:   key,
									value: scalar,
								})
							}
						default:
							return failClosed
						}
					}
				}
			}
		default:
			return failClosed
		}
	}
	if !impact.canSimulate {
		impact.ops = nil
	}
	return impact
}

func validateCollectorPreflightConfig(cfg RunnerConfig, signal string) error {
	_, err := validateCollectorPreflightConfigWithMeta(cfg, signal)
	return err
}

func validateCollectorPreflightConfigWithMeta(cfg RunnerConfig, signal string) (collectorRewriteMeta, error) {
	var emptyMeta collectorRewriteMeta
	if strings.TrimSpace(cfg.CollectorBin) != "" {
		if _, err := resolveCollectorBinaryPath(cfg.CollectorBin); err != nil {
			return emptyMeta, err
		}
	}
	resolvedCfgPath := resolveCollectorConfigPath(cfg.CollectorConfig)
	rawYAML, err := os.ReadFile(resolvedCfgPath)
	if err != nil {
		return emptyMeta, fmt.Errorf("reading collector config %q: %w", cfg.CollectorConfig, err)
	}
	rewrittenYAML, meta, err := rewriteCollectorLoopbackConfig(rawYAML, cfg, signal, collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:4317",
		healthAddr:  "127.0.0.1:13133",
		storageRoot: "preflight",
		useBQFake:   !cfg.CollectorAllowLive,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080",
		dryRun:      true,
	})
	if err != nil {
		return emptyMeta, err
	}

	var rawDoc any
	if err := yaml.Unmarshal(rewrittenYAML, &rawDoc); err != nil {
		return emptyMeta, fmt.Errorf("parsing rewritten collector YAML config: %w", err)
	}
	if err := rejectCollidingYAMLMapKeys(rawDoc, "rewritten collector YAML config", false); err != nil {
		return emptyMeta, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(rewrittenYAML, &doc); err != nil {
		return emptyMeta, fmt.Errorf("parsing rewritten collector YAML config: %w", err)
	}
	exportersMap, ok := doc["exporters"].(map[string]any)
	if !ok {
		return emptyMeta, errors.New("rewritten collector config missing exporters map")
	}
	diagExporterID := meta.exporterDiagnosticID()
	bqMap, ok := exportersMap[meta.activeExporterID].(map[string]any)
	if !ok {
		return emptyMeta, fmt.Errorf("rewritten collector exporter %q is not a map", diagExporterID)
	}

	bqForDecode := make(map[string]any, len(bqMap))
	for k, v := range bqMap {
		// Credentials are validated and stored into meta.effectiveCredentials by
		// rewriteBigQueryExporterMapWithLookup; excluding them (and live endpoints,
		// which are already unmarshaled into meta.effectiveEndpoint) guarantees
		// secret paths, inline JSON, and admin_url userinfo/queries never appear
		// in confmap decode errors.
		if k == "credentials" || (cfg.CollectorAllowLive && k == "endpoint") {
			continue
		}
		bqForDecode[k] = v
	}

	lookupEnv := collectorEnvLookup(cfg.MaxProcs)
	bqNilPaths := make(map[string]struct{})
	resolvedBQAny, resErr := resolveCollectorEnvYAMLValueTracked(bqForDecode, "exporters."+diagExporterID, lookupEnv, true, bqNilPaths)
	if resErr != nil {
		return emptyMeta, resErr
	}
	sqNullSizers := meta.sqConfmapNullSizers.merge(extractSQNullSizers(bqNilPaths, "exporters."+diagExporterID+"."))
	resolvedBQRaw, normErr := normalizeNestedMapsToStringKeys(resolvedBQAny)
	if normErr != nil {
		return emptyMeta, normErr
	}
	resolvedBQMap, ok := resolvedBQRaw.(map[string]any)
	if !ok || resolvedBQMap == nil {
		return emptyMeta, fmt.Errorf("resolved collector exporter %q is not a map", diagExporterID)
	}
	if _, stErr := normalizeSendingQueueStorageWithConfmap(bqForDecode["sending_queue"], resolvedBQMap["sending_queue"], diagExporterID, meta.activeExporterBodyEnvSourced, lookupEnv); stErr != nil {
		return emptyMeta, stErr
	}

	expCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config)
	if !ok {
		return emptyMeta, errors.New("unexpected exporter config type")
	}
	if err := confmap.NewFromStringMap(resolvedBQMap).Unmarshal(expCfg); err != nil {
		return emptyMeta, fmt.Errorf("decoding collector exporter %q config: %w", diagExporterID, scrubInterpolatedErrorWithScopeAndForceLookup(nil, bqForDecode, resolvedBQMap, err, meta.activeExporterBodyEnvSourced, lookupEnv))
	}
	applyConfmapNullSizersToQueue(&expCfg.QueueSettings, resolvedBQMap["sending_queue"], sqNullSizers)
	rawWriteMap, _ := bqForDecode["write"].(map[string]any)
	if err := validateCollectorWriteLimits(expCfg.Write, inspectCollectorWriteInterpMaskWithForce(rawWriteMap, meta.activeExporterBodyEnvSourced)); err != nil {
		return emptyMeta, fmt.Errorf("validating collector exporter %q write config: %w", diagExporterID, err)
	}

	// Preserve all rewritten YAML fields (QueueSettings, merged Redaction.BlockedValuePatterns,
	// Offload, AutoCreate, Quarantine, Write, TimeoutSettings, BackOffConfig) so preflight
	// validates the exact effective config loaded by the Collector child process.
	if cfg.OffloadDir != "" && (signal == "traces" || signal == "logs") {
		expCfg.Redaction.Enabled = false
	}
	if !cfg.CollectorAllowLive {
		expCfg.Credentials = bigqueryexporter.CredentialsConfig{}
		if expCfg.TimeoutSettings.Timeout > 0 {
			expCfg.TimeoutSettings.Timeout = 10 * time.Second
		}
	} else {
		expCfg.Endpoint = meta.effectiveEndpoint
		expCfg.Credentials = meta.effectiveCredentials
		if expCfg.TimeoutSettings.Timeout > 0 {
			expCfg.TimeoutSettings.Timeout = 30 * time.Second
		}
	}
	if cfg.CallTimeout > 0 && expCfg.TimeoutSettings.Timeout > 0 {
		expCfg.TimeoutSettings.Timeout = cfg.CallTimeout
	}
	if err := confmap.Validate(expCfg); err != nil {
		return emptyMeta, fmt.Errorf("validating exporter config: %w", scrubInterpolatedErrorWithScopeAndForceLookup(nil, bqForDecode, resolvedBQMap, err, meta.activeExporterBodyEnvSourced, lookupEnv))
	}
	meta.effectiveKMSKeyName = strings.TrimSpace(expCfg.KMSKeyName)
	meta.effectiveLabels = maps.Clone(expCfg.Labels)
	provisionsDedupView := (cfg.CollectorAllowLive && cfg.EphemeralDataset) || expCfg.AutoCreate.Tables || expCfg.AutoCreate.CompanionViews
	meta.destinationTables = buildCollectorEphemeralTableSpecs(signal, diagExporterID, provisionsDedupView, expCfg)
	if cfg.EphemeralDataset && cfg.CollectorAllowLive && meta.effectiveEndpoint.WithoutAuthentication {
		meta.ephemeralTables = meta.destinationTables
	}
	return meta, nil
}

func parseCollectorDurationOrZero(raw string) time.Duration {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0
	}
	d, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0
	}
	return d
}

func mergeCollectorLabels(base, override map[string]string) map[string]string {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(override))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

func collectorEffectiveKMSKey(expCfg *bigqueryexporter.Config, override string) string {
	if override != "" {
		return override
	}
	return expCfg.KMSKeyName
}

func buildCollectorEphemeralTableSpecs(signal, exporterID string, provisionsDedupView bool, expCfg *bigqueryexporter.Config) []ephemeralTableSpec {
	if expCfg == nil {
		return nil
	}
	var specs []ephemeralTableSpec
	switch signal {
	case "traces":
		specs = append(specs, ephemeralTableSpec{
			signal:              "traces",
			exporterID:          exporterID,
			table:               expCfg.Traces.Table,
			provisionsDedupView: provisionsDedupView,
			destOpts: schema.DestinationOptions{
				PartitionExpirationDays: expCfg.Traces.PartitionExpirationDays,
				PartitionGranularity:    bigquery.TimePartitioningType(expCfg.Traces.PartitionGranularity),
				Clustering:              slices.Clone(expCfg.Traces.Clustering),
				RequirePartitionFilter:  expCfg.Traces.RequirePartitionFilter,
				KMSKeyName:              collectorEffectiveKMSKey(expCfg, expCfg.Traces.KMSKeyName),
				Labels:                  mergeCollectorLabels(expCfg.Labels, expCfg.Traces.Labels),
				MaxStaleness:            parseCollectorDurationOrZero(expCfg.Traces.MaxStaleness),
			},
		})
	case "metrics":
		specs = append(specs, ephemeralTableSpec{
			signal:              "metrics",
			exporterID:          exporterID,
			table:               expCfg.Metrics.Table,
			provisionsDedupView: provisionsDedupView,
			destOpts: schema.DestinationOptions{
				PartitionExpirationDays: expCfg.Metrics.PartitionExpirationDays,
				PartitionGranularity:    bigquery.TimePartitioningType(expCfg.Metrics.PartitionGranularity),
				Clustering:              slices.Clone(expCfg.Metrics.Clustering),
				RequirePartitionFilter:  expCfg.Metrics.RequirePartitionFilter,
				KMSKeyName:              collectorEffectiveKMSKey(expCfg, expCfg.Metrics.KMSKeyName),
				Labels:                  mergeCollectorLabels(expCfg.Labels, expCfg.Metrics.Labels),
				MaxStaleness:            parseCollectorDurationOrZero(expCfg.Metrics.MaxStaleness),
			},
		})
	default:
		specs = append(specs, ephemeralTableSpec{
			signal:              "logs",
			exporterID:          exporterID,
			table:               expCfg.Logs.Table,
			provisionsDedupView: provisionsDedupView,
			destOpts: schema.DestinationOptions{
				PartitionExpirationDays: expCfg.Logs.PartitionExpirationDays,
				PartitionGranularity:    bigquery.TimePartitioningType(expCfg.Logs.PartitionGranularity),
				Clustering:              slices.Clone(expCfg.Logs.Clustering),
				RequirePartitionFilter:  expCfg.Logs.RequirePartitionFilter,
				KMSKeyName:              collectorEffectiveKMSKey(expCfg, expCfg.Logs.KMSKeyName),
				Labels:                  mergeCollectorLabels(expCfg.Labels, expCfg.Logs.Labels),
				MaxStaleness:            parseCollectorDurationOrZero(expCfg.Logs.MaxStaleness),
			},
		})
	}
	if expCfg.Quarantine.Enabled && strings.TrimSpace(expCfg.Quarantine.Table) != "" {
		specs = append(specs, ephemeralTableSpec{
			signal:     "quarantine",
			exporterID: exporterID,
			table:      expCfg.Quarantine.Table,
			destOpts: schema.DestinationOptions{
				PartitionExpirationDays: expCfg.Quarantine.PartitionExpirationDays,
				RequirePartitionFilter:  expCfg.Quarantine.RequirePartitionFilter,
				KMSKeyName:              collectorEffectiveKMSKey(expCfg, expCfg.Quarantine.KMSKeyName),
				Labels:                  mergeCollectorLabels(expCfg.Labels, expCfg.Quarantine.Labels),
				MaxStaleness:            parseCollectorDurationOrZero(expCfg.Quarantine.MaxStaleness),
			},
		})
	}
	return specs
}

func resolveCollectorBinaryPath(rawBin string) (string, error) {
	bin := strings.TrimSpace(rawBin)
	if bin == "" {
		return "", errors.New("collector binary path is empty")
	}
	hasSep := strings.ContainsRune(bin, os.PathSeparator) ||
		(os.PathSeparator != '/' && strings.ContainsRune(bin, '/')) ||
		filepath.VolumeName(bin) != ""
	var candidate string
	if hasSep {
		candidate = bin
	} else {
		lookedUp, err := exec.LookPath(bin)
		if err != nil {
			if errors.Is(err, exec.ErrDot) {
				return "", fmt.Errorf("collector binary %q resolved to current working directory; specify an explicit relative path (e.g. %q): %w", rawBin, "./"+bin, err)
			}
			return "", fmt.Errorf("looking up collector binary %q in PATH: %w", rawBin, err)
		}
		candidate = lookedUp
	}
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolving absolute path for collector binary %q: %w", rawBin, err)
	}
	binInfo, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("stat collector binary %q: %w", rawBin, err)
	}
	if binInfo.IsDir() {
		return "", fmt.Errorf("collector binary %q is a directory", rawBin)
	}
	if !binInfo.Mode().IsRegular() {
		return "", fmt.Errorf("collector binary %q is not a regular file", rawBin)
	}
	if runtime.GOOS != "windows" && binInfo.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("collector binary %q is not executable", rawBin)
	}
	return abs, nil
}

func resolveCollectorConfigPath(cfgPath string) string {
	if filepath.IsAbs(cfgPath) {
		return cfgPath
	}
	if _, err := os.Stat(cfgPath); err == nil {
		return cfgPath
	}
	wd, err := os.Getwd()
	if err != nil {
		return cfgPath
	}
	dir := wd
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			candidate := filepath.Join(dir, cfgPath)
			if _, cErr := os.Stat(candidate); cErr == nil {
				return candidate
			}
			return cfgPath
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return cfgPath
		}
		dir = parent
	}
}

func readPIDCPUSeconds(pid int) (float64, bool) {
	if pid <= 0 {
		return 0, false
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	s := string(raw)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+1 >= len(s) {
		return 0, false
	}
	fields := strings.Fields(s[closeParen+1:])
	if len(fields) <= 12 {
		return 0, false
	}
	utimeTicks, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, false
	}
	stimeTicks, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, false
	}
	return float64(utimeTicks+stimeTicks) / linuxUserHZ, true
}

func readPIDMemoryMB(pid int) (vmRSSMB, vmHWMMB float64, ok bool) {
	if pid <= 0 {
		return 0, 0, false
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		if pid == os.Getpid() {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			sysMB := float64(ms.Sys) / (1024.0 * 1024.0)
			return sysMB, sysMB, sysMB > 0
		}
		return 0, 0, false
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "VmRSS:"):
			vmRSSMB = parseProcStatusKBToMB(strings.TrimPrefix(line, "VmRSS:"))
		case strings.HasPrefix(line, "VmHWM:"):
			vmHWMMB = parseProcStatusKBToMB(strings.TrimPrefix(line, "VmHWM:"))
		}
	}
	if vmHWMMB < vmRSSMB {
		vmHWMMB = vmRSSMB
	}
	if vmRSSMB <= 0 && vmHWMMB <= 0 {
		if pid == os.Getpid() {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			sysMB := float64(ms.Sys) / (1024.0 * 1024.0)
			return sysMB, sysMB, sysMB > 0
		}
		return 0, 0, false
	}
	return vmRSSMB, vmHWMMB, true
}

func parseProcStatusKBToMB(rawVal string) float64 {
	fields := strings.Fields(rawVal)
	if len(fields) == 0 {
		return 0
	}
	kb, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return float64(kb) / 1024.0
}

func cloneCollectorPreparedBatch(src collectorPreparedBatch) collectorPreparedBatch {
	out := collectorPreparedBatch{
		sourceBytes: src.sourceBytes,
		otlpBytes:   src.otlpBytes,
		recordCount: src.recordCount,
	}
	if src.logsReq != (plogotlp.ExportRequest{}) {
		dst := plog.NewLogs()
		src.logsReq.Logs().CopyTo(dst)
		out.logsReq = plogotlp.NewExportRequestFromLogs(dst)
	}
	if src.tracesReq != (ptraceotlp.ExportRequest{}) {
		dst := ptrace.NewTraces()
		src.tracesReq.Traces().CopyTo(dst)
		out.tracesReq = ptraceotlp.NewExportRequestFromTraces(dst)
	}
	if src.metricsReq != (pmetricotlp.ExportRequest{}) {
		dst := pmetric.NewMetrics()
		src.metricsReq.Metrics().CopyTo(dst)
		out.metricsReq = pmetricotlp.NewExportRequestFromMetrics(dst)
	}
	return out
}

func selectEarliestSliceKeepMask(tsNanos []int64, targetRows int) []bool {
	type slicePointRef struct {
		tsNano int64
		ord    int
	}
	refs := make([]slicePointRef, len(tsNanos))
	for i, ts := range tsNanos {
		refs[i] = slicePointRef{tsNano: ts, ord: i}
	}
	slices.SortFunc(refs, func(a, b slicePointRef) int {
		if c := cmp.Compare(a.tsNano, b.tsNano); c != 0 {
			return c
		}
		return cmp.Compare(a.ord, b.ord)
	})
	keep := make([]bool, len(tsNanos))
	for idx := 0; idx < len(refs) && idx < targetRows; idx++ {
		keep[refs[idx].ord] = true
	}
	return keep
}

func sliceCollectorPreparedBatch(src collectorPreparedBatch, signal string, targetRows int) (collectorPreparedBatch, error) {
	if targetRows <= 0 {
		return collectorPreparedBatch{}, fmt.Errorf("cannot slice collector %s batch to %d rows", signal, targetRows)
	}
	if int64(targetRows) >= src.recordCount {
		return cloneCollectorPreparedBatch(src), nil
	}
	out := cloneCollectorPreparedBatch(src)
	switch signal {
	case "traces":
		td := out.tracesReq.Traces()
		rss := td.ResourceSpans()
		var tsNanos []int64
		for i := 0; i < rss.Len(); i++ {
			sss := rss.At(i).ScopeSpans()
			for j := 0; j < sss.Len(); j++ {
				spans := sss.At(j).Spans()
				for k := 0; k < spans.Len(); k++ {
					tsNanos = append(tsNanos, spans.At(k).StartTimestamp().AsTime().UnixNano())
				}
			}
		}
		keep := selectEarliestSliceKeepMask(tsNanos, targetRows)
		curOrd := 0
		for i := 0; i < rss.Len(); i++ {
			sss := rss.At(i).ScopeSpans()
			for j := 0; j < sss.Len(); j++ {
				spans := sss.At(j).Spans()
				spans.RemoveIf(func(ptrace.Span) bool {
					keepThis := curOrd < len(keep) && keep[curOrd]
					curOrd++
					return !keepThis
				})
			}
			sss.RemoveIf(func(ss ptrace.ScopeSpans) bool {
				return ss.Spans().Len() == 0
			})
		}
		rss.RemoveIf(func(rs ptrace.ResourceSpans) bool {
			return rs.ScopeSpans().Len() == 0
		})
		out.sourceBytes = tracesSourceContentBytes(td)
		raw, err := out.tracesReq.MarshalProto()
		if err != nil {
			return collectorPreparedBatch{}, err
		}
		out.otlpBytes = int64(len(raw))
		out.recordCount = int64(td.SpanCount())
	case "logs":
		ld := out.logsReq.Logs()
		rls := ld.ResourceLogs()
		var tsNanos []int64
		for i := 0; i < rls.Len(); i++ {
			sls := rls.At(i).ScopeLogs()
			for j := 0; j < sls.Len(); j++ {
				lrs := sls.At(j).LogRecords()
				for k := 0; k < lrs.Len(); k++ {
					tsNanos = append(tsNanos, lrs.At(k).Timestamp().AsTime().UnixNano())
				}
			}
		}
		keep := selectEarliestSliceKeepMask(tsNanos, targetRows)
		curOrd := 0
		for i := 0; i < rls.Len(); i++ {
			sls := rls.At(i).ScopeLogs()
			for j := 0; j < sls.Len(); j++ {
				lrs := sls.At(j).LogRecords()
				lrs.RemoveIf(func(plog.LogRecord) bool {
					keepThis := curOrd < len(keep) && keep[curOrd]
					curOrd++
					return !keepThis
				})
			}
			sls.RemoveIf(func(sl plog.ScopeLogs) bool {
				return sl.LogRecords().Len() == 0
			})
		}
		rls.RemoveIf(func(rl plog.ResourceLogs) bool {
			return rl.ScopeLogs().Len() == 0
		})
		out.sourceBytes = logsSourceContentBytes(ld)
		raw, err := out.logsReq.MarshalProto()
		if err != nil {
			return collectorPreparedBatch{}, err
		}
		out.otlpBytes = int64(len(raw))
		out.recordCount = int64(ld.LogRecordCount())
	case "metrics":
		md := out.metricsReq.Metrics()
		rms := md.ResourceMetrics()
		var tsNanos []int64
		collectPoint := func(ts pcommon.Timestamp) {
			tsNanos = append(tsNanos, ts.AsTime().UnixNano())
		}
		for i := 0; i < rms.Len(); i++ {
			sms := rms.At(i).ScopeMetrics()
			for j := 0; j < sms.Len(); j++ {
				ms := sms.At(j).Metrics()
				for k := 0; k < ms.Len(); k++ {
					m := ms.At(k)
					switch m.Type() {
					case pmetric.MetricTypeHistogram:
						dps := m.Histogram().DataPoints()
						for l := 0; l < dps.Len(); l++ {
							collectPoint(dps.At(l).Timestamp())
						}
					case pmetric.MetricTypeGauge:
						dps := m.Gauge().DataPoints()
						for l := 0; l < dps.Len(); l++ {
							collectPoint(dps.At(l).Timestamp())
						}
					case pmetric.MetricTypeSum:
						dps := m.Sum().DataPoints()
						for l := 0; l < dps.Len(); l++ {
							collectPoint(dps.At(l).Timestamp())
						}
					case pmetric.MetricTypeSummary:
						dps := m.Summary().DataPoints()
						for l := 0; l < dps.Len(); l++ {
							collectPoint(dps.At(l).Timestamp())
						}
					case pmetric.MetricTypeExponentialHistogram:
						dps := m.ExponentialHistogram().DataPoints()
						for l := 0; l < dps.Len(); l++ {
							collectPoint(dps.At(l).Timestamp())
						}
					}
				}
			}
		}
		keep := selectEarliestSliceKeepMask(tsNanos, targetRows)
		curOrd := 0
		nextKept := func() bool {
			keepThis := curOrd < len(keep) && keep[curOrd]
			curOrd++
			return keepThis
		}
		for i := 0; i < rms.Len(); i++ {
			sms := rms.At(i).ScopeMetrics()
			for j := 0; j < sms.Len(); j++ {
				ms := sms.At(j).Metrics()
				ms.RemoveIf(func(m pmetric.Metric) bool {
					var remaining int
					switch m.Type() {
					case pmetric.MetricTypeHistogram:
						dps := m.Histogram().DataPoints()
						dps.RemoveIf(func(pmetric.HistogramDataPoint) bool {
							return !nextKept()
						})
						remaining = dps.Len()
					case pmetric.MetricTypeGauge:
						dps := m.Gauge().DataPoints()
						dps.RemoveIf(func(pmetric.NumberDataPoint) bool {
							return !nextKept()
						})
						remaining = dps.Len()
					case pmetric.MetricTypeSum:
						dps := m.Sum().DataPoints()
						dps.RemoveIf(func(pmetric.NumberDataPoint) bool {
							return !nextKept()
						})
						remaining = dps.Len()
					case pmetric.MetricTypeSummary:
						dps := m.Summary().DataPoints()
						dps.RemoveIf(func(pmetric.SummaryDataPoint) bool {
							return !nextKept()
						})
						remaining = dps.Len()
					case pmetric.MetricTypeExponentialHistogram:
						dps := m.ExponentialHistogram().DataPoints()
						dps.RemoveIf(func(pmetric.ExponentialHistogramDataPoint) bool {
							return !nextKept()
						})
						remaining = dps.Len()
					}
					return remaining == 0
				})
			}
			sms.RemoveIf(func(sm pmetric.ScopeMetrics) bool {
				return sm.Metrics().Len() == 0
			})
		}
		rms.RemoveIf(func(rm pmetric.ResourceMetrics) bool {
			return rm.ScopeMetrics().Len() == 0
		})
		out.sourceBytes = metricsSourceContentBytes(md)
		raw, err := out.metricsReq.MarshalProto()
		if err != nil {
			return collectorPreparedBatch{}, err
		}
		out.otlpBytes = int64(len(raw))
		out.recordCount = int64(md.DataPointCount())
	default:
		return collectorPreparedBatch{}, fmt.Errorf("unsupported signal %q", signal)
	}
	return out, nil
}

func stampCollectorPreparedBatchIdentity(signal string, b collectorPreparedBatch, baseTime time.Time, startSeq uint64, upstreamInsertID bool) {
	switch signal {
	case "logs":
		if b.logsReq != (plogotlp.ExportRequest{}) {
			stampFreshLogsIdentity(b.logsReq.Logs(), baseTime, startSeq, upstreamInsertID)
		}
	case "traces":
		if b.tracesReq != (ptraceotlp.ExportRequest{}) {
			stampFreshTracesIdentity(b.tracesReq.Traces(), baseTime, startSeq)
		}
	case "metrics":
		if b.metricsReq != (pmetricotlp.ExportRequest{}) {
			stampFreshMetricsIdentity(b.metricsReq.Metrics(), baseTime, startSeq)
		}
	}
}

func stampCollectorPreparedBatchTreeEpoch(
	signal string,
	b collectorPreparedBatch,
	baseTime time.Time,
	treeStride, treeDelta uint64,
	fallbackSeq *atomic.Uint64,
	upstreamInsertID bool,
) {
	switch signal {
	case "logs":
		if b.logsReq != (plogotlp.ExportRequest{}) {
			stampLogsTreeEpoch(b.logsReq.Logs(), baseTime, treeStride, treeDelta, fallbackSeq, upstreamInsertID)
		}
	case "traces":
		if b.tracesReq != (ptraceotlp.ExportRequest{}) {
			stampTracesTreeEpoch(b.tracesReq.Traces(), baseTime, treeStride, treeDelta, fallbackSeq)
		}
	case "metrics":
		if b.metricsReq != (pmetricotlp.ExportRequest{}) {
			stampMetricsTreeEpoch(b.metricsReq.Metrics(), baseTime, treeStride, treeDelta, fallbackSeq)
		}
	}
}

func dialCollectorOTLPClient(otlpAddr string) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		otlpAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(math.MaxInt32)),
	)
}

func newCollectorBatchBuilder(cfg RunnerConfig, signal string) (func(int) (collectorPreparedBatch, error), error) {
	return newCollectorBatchBuilderWithSeed(cfg, signal, 0)
}

func newCollectorBatchBuilderWithSeed(cfg RunnerConfig, signal string, seed uint64) (func(int) (collectorPreparedBatch, error), error) {
	gen := NewGenerator(GeneratorConfig{
		Seed:             seed,
		BaseTime:         benchmarkGeneratorBaseTime(cfg),
		WorkloadProfile:  cfg.WorkloadProfile,
		PayloadBytes:     cfg.PayloadBytes,
		UniquePayloads:   cfg.UniquePayloads,
		PlantSecrets:     cfg.Redaction || cfg.PlantSecrets,
		ResourceAttrs:    cfg.ResourceAttrs,
		UpstreamInsertID: cfg.UpstreamInsertID,
	})
	switch signal {
	case "logs":
		return func(n int) (collectorPreparedBatch, error) {
			ld := gen.LogsBatch(n)
			if cfg.UpstreamInsertID && cfg.WorkloadProfile != WorkloadProfileAccessLogs {
				populateLogsUpstreamInsertIDPlaceholder(ld)
			}
			srcBytes := logsSourceContentBytes(ld)
			req := plogotlp.NewExportRequestFromLogs(ld)
			raw, err := req.MarshalProto()
			if err != nil {
				return collectorPreparedBatch{}, err
			}
			return collectorPreparedBatch{
				logsReq:     req,
				sourceBytes: srcBytes,
				otlpBytes:   int64(len(raw)),
				recordCount: int64(ld.LogRecordCount()),
			}, nil
		}, nil
	case "traces":
		return func(n int) (collectorPreparedBatch, error) {
			td := gen.TracesBatch(n)
			srcBytes := tracesSourceContentBytes(td)
			req := ptraceotlp.NewExportRequestFromTraces(td)
			raw, err := req.MarshalProto()
			if err != nil {
				return collectorPreparedBatch{}, err
			}
			return collectorPreparedBatch{
				tracesReq:   req,
				sourceBytes: srcBytes,
				otlpBytes:   int64(len(raw)),
				recordCount: int64(td.SpanCount()),
			}, nil
		}, nil
	case "metrics":
		return func(n int) (collectorPreparedBatch, error) {
			md := gen.MetricsBatch(n)
			srcBytes := metricsSourceContentBytes(md)
			req := pmetricotlp.NewExportRequestFromMetrics(md)
			raw, err := req.MarshalProto()
			if err != nil {
				return collectorPreparedBatch{}, err
			}
			return collectorPreparedBatch{
				metricsReq:  req,
				sourceBytes: srcBytes,
				otlpBytes:   int64(len(raw)),
				recordCount: int64(md.DataPointCount()),
			}, nil
		}, nil
	default:
		return nil, fmt.Errorf("unsupported signal %q", signal)
	}
}

func buildCollectorEnv(maxProcs int) []string {
	base := os.Environ()
	if maxProcs <= 0 {
		return base
	}
	out := make([]string, 0, len(base)+1)
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if runtime.GOOS == "windows" {
			if strings.EqualFold(k, "GOMAXPROCS") {
				continue
			}
		} else if k == "GOMAXPROCS" {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, fmt.Sprintf("GOMAXPROCS=%d", maxProcs))
	return out
}

func probeHTTPOK(ctx context.Context, httpClient *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func normalizeHealthCheckPath(healthPath string) string {
	p := strings.TrimSpace(healthPath)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func stopCollectorProcess(p *os.Process) (killed bool) {
	if p == nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return p.Kill() == nil
	}
	err := p.Signal(syscall.SIGTERM)
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
		return false
	}
	return p.Kill() == nil
}

func finalizeCollectorShutdown(
	proc *os.Process,
	doneCh <-chan struct{},
	cmdWaitErr *error,
	ctxErr error,
	diag *boundedDiagBuffer,
) (childDone bool, err error) {
	var killedByShutdown bool
	select {
	case <-doneCh:
		childDone = true
	default:
	}
	if !childDone {
		killedByShutdown = stopCollectorProcess(proc)
		shutdownTimer := time.NewTimer(collectorShutdownTimeout)
		defer shutdownTimer.Stop()
		select {
		case <-doneCh:
			childDone = true
		case <-shutdownTimer.C:
			if proc != nil {
				_ = proc.Kill()
			}
			<-doneCh
			var diagText string
			if diag != nil {
				diagText = diag.String()
			}
			return true, fmt.Errorf("collector did not exit within %s after SIGTERM: %s", collectorShutdownTimeout, diagText)
		}
	}

	var waitErr error
	if cmdWaitErr != nil {
		waitErr = *cmdWaitErr
	}
	if waitErr != nil && ctxErr == nil && !killedByShutdown {
		var diagText string
		if diag != nil {
			diagText = diag.String()
		}
		return true, fmt.Errorf("collector exited with error (%w): %s", waitErr, diagText)
	}
	return true, nil
}

func probeCollectorReady(ctx context.Context, httpClient *http.Client, healthAddr, healthPath, metricsAddr, otlpAddr string, hasHealthCheck bool) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	if hasHealthCheck {
		hcPath := normalizeHealthCheckPath(healthPath)
		if !probeHTTPOK(probeCtx, httpClient, "http://"+healthAddr+hcPath) {
			return false
		}
	}
	if metricsAddr != "" {
		if !probeHTTPOK(probeCtx, httpClient, "http://"+metricsAddr+"/metrics") {
			return false
		}
	}

	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(probeCtx, "tcp", otlpAddr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func waitCollectorReady(ctx context.Context, doneCh <-chan struct{}, waitErr *error, diag *boundedDiagBuffer, healthAddr, healthPath, metricsAddr, otlpAddr string, hasHealthCheck bool) error {
	httpClient := &http.Client{Timeout: 500 * time.Millisecond}
	defer httpClient.CloseIdleConnections()

	deadline := time.Now().Add(collectorStartupTimeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		if probeCollectorReady(ctx, httpClient, healthAddr, healthPath, metricsAddr, otlpAddr, hasHealthCheck) {
			return nil
		}
		select {
		case <-doneCh:
			var wErr error
			if waitErr != nil {
				wErr = *waitErr
			}
			return formatCollectorExitErr("collector exited before becoming ready", wErr, diag)
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				var diagText string
				if diag != nil {
					diagText = diag.String()
				}
				return fmt.Errorf("timed out after %s waiting for collector readiness on %s: %s", collectorStartupTimeout, otlpAddr, diagText)
			}
		}
	}
}

func parsePromLabels(raw string) map[string]string {
	labels := make(map[string]string)
	i := 0
	n := len(raw)
	for i < n {
		for i < n && (raw[i] == ',' || raw[i] == ' ' || raw[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		eq := strings.IndexByte(raw[i:], '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(raw[i : i+eq])
		i += eq + 1
		if i >= n || raw[i] != '"' {
			break
		}
		i++
		var val strings.Builder
		for i < n {
			ch := raw[i]
			i++
			if ch == '\\' && i < n {
				esc := raw[i]
				i++
				switch esc {
				case 'n':
					val.WriteByte('\n')
				case 't':
					val.WriteByte('\t')
				default:
					val.WriteByte(esc)
				}
				continue
			}
			if ch == '"' {
				break
			}
			val.WriteByte(ch)
		}
		if key != "" {
			labels[key] = val.String()
		}
	}
	return labels
}

func parsePromExpositionLine(line string) (string, map[string]string, float64, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil, 0, false
	}
	var name string
	var labels map[string]string
	var rest string
	if openIdx := strings.IndexByte(line, '{'); openIdx >= 0 {
		name = strings.TrimSpace(line[:openIdx])
		closeIdx := -1
		inQuotes := false
		for i := openIdx + 1; i < len(line); i++ {
			ch := line[i]
			if ch == '\\' && inQuotes {
				i++
				continue
			}
			if ch == '"' {
				inQuotes = !inQuotes
				continue
			}
			if ch == '}' && !inQuotes {
				closeIdx = i
				break
			}
		}
		if closeIdx < 0 {
			return "", nil, 0, false
		}
		labels = parsePromLabels(line[openIdx+1 : closeIdx])
		rest = strings.TrimSpace(line[closeIdx+1:])
	} else {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return "", nil, 0, false
		}
		name = fields[0]
		rest = fields[1]
	}
	valFields := strings.Fields(rest)
	if len(valFields) == 0 || name == "" {
		return "", nil, 0, false
	}
	val, err := strconv.ParseFloat(valFields[0], 64)
	if err != nil || math.IsNaN(val) || math.IsInf(val, 0) {
		return "", nil, 0, false
	}
	return name, labels, val, true
}

func exporterMetricSignalLabel(signal string) string {
	if signal == "traces" {
		return schema.SignalSpans
	}
	return signal
}

func exporterHelperSignalSuffix(signal string) string {
	switch signal {
	case "traces":
		return "spans"
	case "logs":
		return "log_records"
	case "metrics":
		return "metric_points"
	default:
		return ""
	}
}

func matchesSignalLabel(labels map[string]string, signal string) bool {
	if len(labels) == 0 {
		return true
	}
	sig := labels["signal"]
	return sig == "" || sig == exporterMetricSignalLabel(signal)
}

func matchesExporterLabel(labels map[string]string, activeExporterID string) bool {
	exp := labels["exporter"]
	return exp == "" ||
		(activeExporterID != "" && sameComponentID(exp, activeExporterID)) ||
		(activeExporterID == "" && isBigQueryComponentID(exp))
}

func parseCollectorPrometheusMetrics(body, signal, exporterID string) collectorMetricsSample {
	var s collectorMetricsSample
	helperSuffix := exporterHelperSignalSuffix(signal)
	var sentMetricName, sendFailedMetricName, enqueueFailedMetricName string
	if helperSuffix != "" {
		sentMetricName = "otelcol_exporter_sent_" + helperSuffix
		sendFailedMetricName = "otelcol_exporter_send_failed_" + helperSuffix
		enqueueFailedMetricName = "otelcol_exporter_enqueue_failed_" + helperSuffix
	}
	for line := range strings.SplitSeq(body, "\n") {
		rawName, labels, val, ok := parsePromExpositionLine(line)
		if !ok {
			continue
		}
		name := strings.TrimSuffix(rawName, "_total")
		switch name {
		case "otelcol_exporter_bigquery_acknowledged_rows":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.AcknowledgedRows += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_rejected_rows":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				n := int64(math.Round(val))
				s.Telemetry.RejectedRows += n
				switch labels["reason"] {
				case "request_permanent":
					s.RejectedRequestPermanent += n
				case "row_error":
					s.RejectedRowError += n
				case "offload_permanent":
					s.RejectedOffloadPermanent += n
				}
			}
		case "otelcol_exporter_bigquery_quarantined_rows":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.QuarantinedRows += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_retries":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.Retries += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_append_bytes":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.AppendBytesTotal += int64(math.Round(val))
				s.HasAppendBytesMetric = true
			}
		case "otelcol_exporter_bigquery_append_result_wait_count":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				if val > 0 {
					s.Telemetry.AppendWaitCount += uint64(math.Round(val))
				}
			}
		case "otelcol_exporter_bigquery_append_result_wait_sum":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.AppendWaitSumSeconds += val
			}
		case "otelcol_exporter_bigquery_redacted_values":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				n := int64(math.Round(val))
				s.Telemetry.RedactedValuesTotal += n
				mt := labels["match_type"]
				if mt != "" {
					if s.Telemetry.RedactedByMatchType == nil {
						s.Telemetry.RedactedByMatchType = make(map[string]int64)
					}
					s.Telemetry.RedactedByMatchType[mt] += n
				}
			}
		case "otelcol_exporter_bigquery_offloaded_payloads":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.OffloadedPayloads += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_offloaded_bytes":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.OffloadedBytes += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_offload_dedup_hits":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.OffloadDedupHits += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_backpressure_level":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				lvl := round2(val)
				if lvl > s.Telemetry.BackpressureLevel {
					s.Telemetry.BackpressureLevel = lvl
				}
			}
		case "otelcol_exporter_bigquery_effective_request_bytes":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				eff := int64(math.Round(val))
				if eff > 0 {
					s.Telemetry.EffectiveRequestBytes = eff
				}
			}
		case "otelcol_exporter_bigquery_backpressure_events":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				trig := labels["trigger"]
				if trig == "" {
					trig = "unknown"
				}
				if s.Telemetry.BackpressureEvents == nil {
					s.Telemetry.BackpressureEvents = make(map[string]int64)
				}
				s.Telemetry.BackpressureEvents[trig] += int64(math.Round(val))
			}
		case "otelcol_exporter_queue_size":
			if matchesExporterLabel(labels, exporterID) {
				s.QueueSize += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_inflight_requests":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.InflightRequests += int64(math.Round(val))
			}
		case sentMetricName:
			if sentMetricName != "" && matchesExporterLabel(labels, exporterID) {
				s.Sent += int64(math.Round(val))
				s.HasSentMetric = true
			}
		case sendFailedMetricName:
			if sendFailedMetricName != "" && matchesExporterLabel(labels, exporterID) {
				s.SendFailed += int64(math.Round(val))
			}
		case enqueueFailedMetricName:
			if enqueueFailedMetricName != "" && matchesExporterLabel(labels, exporterID) {
				s.EnqueueFailed += int64(math.Round(val))
			}
		case "otelcol_process_runtime_heap_alloc_bytes":
			if val >= 0 {
				s.HeapAllocBytes = uint64(math.Round(val))
			}
		}
	}
	rawWaitSum := s.Telemetry.AppendWaitSumSeconds
	s.Telemetry.appendWaitSumSecondsRaw = rawWaitSum
	s.Telemetry.hasRawAppendWaitSum = true
	if s.Telemetry.AppendWaitCount > 0 {
		s.Telemetry.AppendWaitMeanMs = round2((rawWaitSum * 1000.0) / float64(s.Telemetry.AppendWaitCount))
	}
	s.Telemetry.AppendWaitSumSeconds = round2(rawWaitSum)
	return s
}

func diffCollectorTelemetry(before, after collectorMetricsSample) (TelemetrySnapshot, int64) {
	var waitCount uint64
	if after.Telemetry.AppendWaitCount > before.Telemetry.AppendWaitCount {
		waitCount = after.Telemetry.AppendWaitCount - before.Telemetry.AppendWaitCount
	}
	waitSumSec := max(0.0, after.Telemetry.rawAppendWaitSumSeconds()-before.Telemetry.rawAppendWaitSumSeconds())
	var waitMeanMs float64
	if waitCount > 0 {
		waitMeanMs = round2((waitSumSec * 1000.0) / float64(waitCount))
	}

	var redactedByType map[string]int64
	for k, v := range after.Telemetry.RedactedByMatchType {
		d := v - before.Telemetry.RedactedByMatchType[k]
		if d > 0 {
			if redactedByType == nil {
				redactedByType = make(map[string]int64)
			}
			redactedByType[k] = d
		}
	}

	var bpEvents map[string]int64
	for k, v := range after.Telemetry.BackpressureEvents {
		d := v - before.Telemetry.BackpressureEvents[k]
		if d > 0 {
			if bpEvents == nil {
				bpEvents = make(map[string]int64)
			}
			bpEvents[k] = d
		}
	}

	deltaSendFailed := max(int64(0), after.SendFailed-before.SendFailed)
	return TelemetrySnapshot{
		AcknowledgedRows:        max(int64(0), after.Telemetry.AcknowledgedRows-before.Telemetry.AcknowledgedRows),
		RejectedRows:            max(int64(0), after.Telemetry.RejectedRows-before.Telemetry.RejectedRows),
		QuarantinedRows:         max(int64(0), after.Telemetry.QuarantinedRows-before.Telemetry.QuarantinedRows),
		Retries:                 max(int64(0), after.Telemetry.Retries-before.Telemetry.Retries),
		AppendBytesTotal:        max(int64(0), after.Telemetry.AppendBytesTotal-before.Telemetry.AppendBytesTotal),
		AppendWaitCount:         waitCount,
		AppendWaitSumSeconds:    round2(waitSumSec),
		AppendWaitMeanMs:        waitMeanMs,
		RedactedValuesTotal:     max(int64(0), after.Telemetry.RedactedValuesTotal-before.Telemetry.RedactedValuesTotal),
		RedactedByMatchType:     redactedByType,
		OffloadedPayloads:       max(int64(0), after.Telemetry.OffloadedPayloads-before.Telemetry.OffloadedPayloads),
		OffloadedBytes:          max(int64(0), after.Telemetry.OffloadedBytes-before.Telemetry.OffloadedBytes),
		OffloadDedupHits:        max(int64(0), after.Telemetry.OffloadDedupHits-before.Telemetry.OffloadDedupHits),
		BackpressureLevel:       after.Telemetry.BackpressureLevel,
		EffectiveRequestBytes:   after.Telemetry.EffectiveRequestBytes,
		BackpressureEvents:      bpEvents,
		appendWaitSumSecondsRaw: waitSumSec,
		hasRawAppendWaitSum:     true,
	}, deltaSendFailed
}

func scrapeCollectorMetrics(ctx context.Context, httpClient *http.Client, metricsAddr, signal, exporterID string) (collectorMetricsSample, error) {
	scrapeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(scrapeCtx, http.MethodGet, "http://"+metricsAddr+"/metrics", http.NoBody)
	if err != nil {
		return collectorMetricsSample{}, fmt.Errorf("building collector metrics request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return collectorMetricsSample{}, fmt.Errorf("scraping collector metrics from %s: %w", metricsAddr, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return collectorMetricsSample{}, fmt.Errorf("scraping collector metrics from %s: unexpected status %d", metricsAddr, resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return collectorMetricsSample{}, fmt.Errorf("reading collector metrics body: %w", err)
	}
	return parseCollectorPrometheusMetrics(string(bodyBytes), signal, exporterID), nil
}

func drainCollectorPipeline(
	ctx context.Context,
	httpClient *http.Client,
	metricsAddr, signal, exporterID string,
	baseline collectorMetricsSample,
	expectedSubmitted int64,
	timeout time.Duration,
	doneCh <-chan struct{},
	waitErr *error,
	diag *boundedDiagBuffer,
) (collectorMetricsSample, error) {
	sample, _, err := drainCollectorPipelineWithUnique(
		ctx, httpClient, metricsAddr, signal, exporterID,
		baseline, expectedSubmitted, timeout, doneCh, waitErr, diag,
		0, nil, 0, 0,
	)
	return sample, err
}

func computeCollectorDrainAccounted(
	baseline, cur collectorMetricsSample,
	deltaTelem TelemetrySnapshot,
	deltaSendFailed int64,
	uniqueAckedBefore int64,
	uniqueAckedFn func() int64,
) int64 {
	deltaReqPerm := max(int64(0), cur.RejectedRequestPermanent-baseline.RejectedRequestPermanent)
	deltaSent := max(int64(0), cur.Sent-baseline.Sent)
	deltaEnqueueFailed := max(int64(0), cur.EnqueueFailed-baseline.EnqueueFailed)

	nonPermRejected := max(int64(0), deltaTelem.RejectedRows-deltaReqPerm)
	exporterAccounted := deltaTelem.AcknowledgedRows + nonPermRejected + deltaSendFailed + deltaEnqueueFailed
	if cur.HasSentMetric {
		helperAccounted := deltaSent + deltaSendFailed + deltaEnqueueFailed
		exporterAccounted = min(exporterAccounted, helperAccounted)
	}
	if uniqueAckedFn != nil {
		rawUnique := uniqueAckedFn()
		if rawUnique == math.MaxInt64 {
			return exporterAccounted
		}
		uniqueAccounted := max(int64(0), rawUnique-uniqueAckedBefore) + nonPermRejected + deltaSendFailed + deltaEnqueueFailed
		return min(exporterAccounted, uniqueAccounted)
	}
	return exporterAccounted
}

func drainCollectorPipelineWithUnique(
	ctx context.Context,
	httpClient *http.Client,
	metricsAddr, signal, exporterID string,
	baseline collectorMetricsSample,
	expectedSubmitted int64,
	timeout time.Duration,
	doneCh <-chan struct{},
	waitErr *error,
	diag *boundedDiagBuffer,
	uniqueAckedBefore int64,
	uniqueAckedFn func() int64,
	batchTimeout time.Duration,
	batchSendSize int,
) (collectorMetricsSample, time.Duration, error) {
	return drainCollectorPipelineWithBatchWait(
		ctx, httpClient, metricsAddr, signal, exporterID,
		baseline, expectedSubmitted, timeout, doneCh, waitErr, diag,
		uniqueAckedBefore, uniqueAckedFn,
		collectorBatchWaitConfig{
			batchProcTimeout:  batchTimeout,
			batchProcSendSize: batchSendSize,
		},
	)
}

func drainCollectorPipelineWithBatchWait(
	ctx context.Context,
	httpClient *http.Client,
	metricsAddr, signal, exporterID string,
	baseline collectorMetricsSample,
	expectedSubmitted int64,
	timeout time.Duration,
	doneCh <-chan struct{},
	waitErr *error,
	diag *boundedDiagBuffer,
	uniqueAckedBefore int64,
	uniqueAckedFn func() int64,
	waitCfg collectorBatchWaitConfig,
) (collectorMetricsSample, time.Duration, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var (
		lastSample     collectorMetricsSample
		stableTicks    int
		lastScrape     error
		hasPrevSample  bool
		prevAccounted  int64
		lastTickTime   = time.Now()
		batchProcWait  time.Duration
		queueBatchWait time.Duration
		idleBatchWait  time.Duration
	)

	computeAccounted := func(cur collectorMetricsSample, deltaTelem TelemetrySnapshot, deltaSendFailed int64) int64 {
		return computeCollectorDrainAccounted(baseline, cur, deltaTelem, deltaSendFailed, uniqueAckedBefore, uniqueAckedFn)
	}

	for {
		cur, scrapeErr := scrapeCollectorMetrics(ctx, httpClient, metricsAddr, signal, exporterID)
		now := time.Now()
		tickDelta := now.Sub(lastTickTime)
		lastTickTime = now
		if scrapeErr == nil {
			lastSample = cur
			lastScrape = nil
			deltaTelem, deltaSendFailed := diffCollectorTelemetry(baseline, cur)
			accounted := computeAccounted(cur, deltaTelem, deltaSendFailed)
			if !hasPrevSample {
				hasPrevSample = true
				prevAccounted = accounted
			} else {
				if tickDelta > 0 && cur.InflightRequests <= 0 && accounted == prevAccounted {
					pending := expectedSubmitted - accounted
					if pending > 0 {
						if waitCfg.batchProcTimeout > 0 && cur.QueueSize <= 0 &&
							(waitCfg.batchProcSendSize <= 0 || pending < int64(waitCfg.batchProcSendSize)) &&
							batchProcWait < waitCfg.batchProcTimeout {
							batchProcWait = min(waitCfg.batchProcTimeout, batchProcWait+tickDelta)
						} else if waitCfg.queueBatchFlushTimeout > 0 &&
							(waitCfg.queueBatchMinItems <= 0 || pending < int64(waitCfg.queueBatchMinItems)) &&
							queueBatchWait < waitCfg.queueBatchFlushTimeout {
							queueBatchWait = min(waitCfg.queueBatchFlushTimeout, queueBatchWait+tickDelta)
						}
					}
					idleBatchWait = min(waitCfg.batchProcTimeout+waitCfg.queueBatchFlushTimeout, batchProcWait+queueBatchWait)
				}
				prevAccounted = accounted
			}
			if accounted >= expectedSubmitted && cur.QueueSize <= 0 && cur.InflightRequests <= 0 {
				stableTicks++
				if stableTicks >= 2 || (expectedSubmitted == 0 && stableTicks >= 1) {
					return cur, idleBatchWait, nil
				}
			} else {
				stableTicks = 0
			}
		} else {
			lastScrape = scrapeErr
			stableTicks = 0
		}

		if time.Now().After(deadline) {
			deltaTelem, deltaSendFailed := diffCollectorTelemetry(baseline, lastSample)
			accounted := computeAccounted(lastSample, deltaTelem, deltaSendFailed)
			if lastScrape != nil {
				return lastSample, idleBatchWait, fmt.Errorf(
					"timed out after %s waiting for collector pipeline to drain (submitted=%d, accounted=%d, acked=%d, rejected=%d, quarantined=%d, send_failed=%d, queue_size=%d, inflight=%d, last_scrape_err=%w)",
					timeout, expectedSubmitted, accounted,
					deltaTelem.AcknowledgedRows, deltaTelem.RejectedRows, deltaTelem.QuarantinedRows,
					deltaSendFailed, lastSample.QueueSize, lastSample.InflightRequests, lastScrape,
				)
			}
			return lastSample, idleBatchWait, fmt.Errorf(
				"timed out after %s waiting for collector pipeline to drain (submitted=%d, accounted=%d, acked=%d, rejected=%d, quarantined=%d, send_failed=%d, queue_size=%d, inflight=%d)",
				timeout, expectedSubmitted, accounted,
				deltaTelem.AcknowledgedRows, deltaTelem.RejectedRows, deltaTelem.QuarantinedRows,
				deltaSendFailed, lastSample.QueueSize, lastSample.InflightRequests,
			)
		}

		select {
		case <-ctx.Done():
			return lastSample, idleBatchWait, ctx.Err()
		case <-doneCh:
			var wErr error
			if waitErr != nil {
				wErr = *waitErr
			}
			return lastSample, idleBatchWait, formatCollectorExitErr("collector exited during pipeline drain", wErr, diag)
		case <-ticker.C:
		}
	}
}

func exportCollectorBatch(
	ctx context.Context,
	signal string,
	batch collectorPreparedBatch,
	tracesClient ptraceotlp.GRPCClient,
	logsClient plogotlp.GRPCClient,
	metricsClient pmetricotlp.GRPCClient,
) (rejected int64, err error) {
	switch signal {
	case "traces":
		resp, rpcErr := tracesClient.Export(ctx, batch.tracesReq)
		if rpcErr != nil {
			return 0, rpcErr
		}
		return resp.PartialSuccess().RejectedSpans(), nil
	case "logs":
		resp, rpcErr := logsClient.Export(ctx, batch.logsReq)
		if rpcErr != nil {
			return 0, rpcErr
		}
		return resp.PartialSuccess().RejectedLogRecords(), nil
	case "metrics":
		resp, rpcErr := metricsClient.Export(ctx, batch.metricsReq)
		if rpcErr != nil {
			return 0, rpcErr
		}
		return resp.PartialSuccess().RejectedDataPoints(), nil
	default:
		return 0, fmt.Errorf("unsupported signal %q", signal)
	}
}

type collectorPhaseStats struct {
	batchesAttempted      int64
	batchesSucceeded      int64
	batchesFailed         int64
	recordsAttempted      int64
	recordsSubmitted      int64
	rejectedRecords       int64
	dispatchedSourceBytes int64
	dispatchedOTLPBytes   int64
	dispatchedRecords     int64
	hasPartialReject      bool
	latencyHist           latencyHistogram
	firstErr              error
}

type collectorWorkerBatch struct {
	batch collectorPreparedBatch
}

func buildCollectorWorkerBatchesFromPrebuilt(workers int, prebuilt []collectorPreparedBatch, ownWorkerZero bool) [][]collectorWorkerBatch {
	if workers <= 0 || len(prebuilt) == 0 {
		return nil
	}
	workerBatches := make([][]collectorWorkerBatch, workers)
	// Build higher-indexed worker clones before moving ownership of prebuilt into worker 0
	// so worker 0 avoids a duplicate copy and peaks at `workers` copies total.
	for w := workers - 1; w >= 0; w-- {
		workerBatches[w] = make([]collectorWorkerBatch, len(prebuilt))
		for i := range prebuilt {
			if ownWorkerZero && w == 0 {
				workerBatches[w][i] = collectorWorkerBatch{
					batch: prebuilt[i],
				}
				prebuilt[i] = collectorPreparedBatch{}
			} else {
				workerBatches[w][i] = collectorWorkerBatch{
					batch: cloneCollectorPreparedBatch(prebuilt[i]),
				}
			}
		}
	}
	return workerBatches
}

func runCollectorWorkerPhase(
	ctx context.Context,
	cfg RunnerConfig,
	signal string,
	duration time.Duration,
	maxBatches int,
	prebuilt []collectorPreparedBatch,
	makeBatch func(int) (collectorPreparedBatch, error),
	tracesClient ptraceotlp.GRPCClient,
	logsClient plogotlp.GRPCClient,
	metricsClient pmetricotlp.GRPCClient,
	childDoneCh <-chan struct{},
) collectorPhaseStats {
	return runCollectorWorkerPhaseWithSeq(
		ctx, cfg, signal, duration, maxBatches, prebuilt, makeBatch,
		tracesClient, logsClient, metricsClient, childDoneCh, new(atomic.Uint64),
	)
}

func runCollectorWorkerPhaseWithSeq(
	ctx context.Context,
	cfg RunnerConfig,
	signal string,
	duration time.Duration,
	maxBatches int,
	prebuilt []collectorPreparedBatch,
	makeBatch func(int) (collectorPreparedBatch, error),
	tracesClient ptraceotlp.GRPCClient,
	logsClient plogotlp.GRPCClient,
	metricsClient pmetricotlp.GRPCClient,
	childDoneCh <-chan struct{},
	dispatchSeq *atomic.Uint64,
) collectorPhaseStats {
	seedCount := max(1, len(prebuilt))
	workerBatches := buildCollectorWorkerBatchesFromPrebuilt(cfg.Workers, prebuilt, false)
	treeStride := computePrebuiltTreeStride(seedCount, cfg.BatchSize)
	if signal == "logs" && cfg.WorkloadProfile == WorkloadProfileAccessLogs {
		treeStride = computePrebuiltAccessLogSeqStride(seedCount, cfg.BatchSize)
	}
	return runCollectorWorkerPhasePrepared(
		ctx, cfg, signal, duration, maxBatches,
		workerBatches, treeStride, 0,
		makeBatch, tracesClient, logsClient, metricsClient, childDoneCh, dispatchSeq,
		nil, traceKeyRecordOptions{}, logKeyRecordOptions{synthesizeInsertID: true}, metricKeyRecordOptions{},
	)
}

func runCollectorWorkerPhasePrepared(
	ctx context.Context,
	cfg RunnerConfig,
	signal string,
	duration time.Duration,
	maxBatches int,
	workerBatches [][]collectorWorkerBatch,
	treeStride uint64,
	epochOffset uint64,
	makeBatch func(int) (collectorPreparedBatch, error),
	tracesClient ptraceotlp.GRPCClient,
	logsClient plogotlp.GRPCClient,
	metricsClient pmetricotlp.GRPCClient,
	childDoneCh <-chan struct{},
	dispatchSeq *atomic.Uint64,
	phaseSubmitted *bqfake.SubmittedKeySet,
	traceKeyOpts traceKeyRecordOptions,
	logKeyOpts logKeyRecordOptions,
	metricKeyOpts metricKeyRecordOptions,
) collectorPhaseStats {
	if dispatchSeq == nil {
		dispatchSeq = new(atomic.Uint64)
	}
	if treeStride == 0 {
		if signal == "logs" && cfg.WorkloadProfile == WorkloadProfileAccessLogs {
			treeStride = computePrebuiltAccessLogSeqStride(1, cfg.BatchSize)
		} else {
			treeStride = computePrebuiltTreeStride(1, cfg.BatchSize)
		}
	}
	var (
		batchesAttempted      atomic.Int64
		batchesSucceeded      atomic.Int64
		batchesFailed         atomic.Int64
		recordsAttempted      atomic.Int64
		recordsSubmitted      atomic.Int64
		rejectedRecords       atomic.Int64
		dispatchedSourceBytes atomic.Int64
		dispatchedOTLPBytes   atomic.Int64
		dispatchedRecords     atomic.Int64
		hasPartialReject      atomic.Bool
		globalSeq             atomic.Int64
		prebuiltDispatchSeq   atomic.Uint64
		errOnce               sync.Once
		firstErr              error
	)

	callTimeout := cfg.CallTimeout
	if callTimeout <= 0 {
		callTimeout = 30 * time.Second
	}

	startPhase := time.Now()
	deadline := startPhase.Add(duration)
	phaseCtx, phaseCancel := context.WithDeadline(ctx, deadline)
	defer phaseCancel()

	var (
		pacerMu         sync.Mutex
		nextScheduled   = startPhase
		remainingBudget int64
		pacedBatchCap   = cfg.BatchSize
	)
	budgetLimited := cfg.TargetRate > 0 && maxBatches == 0
	if budgetLimited {
		totalBudget := max(int64(1), int64(math.Round(float64(cfg.TargetRate)*duration.Seconds())))
		remainingBudget = totalBudget
		pacedBatchCap = min(cfg.BatchSize, max(1, cfg.TargetRate/max(4, cfg.Workers)))
	}

	rpcParentCtx, rpcParentCancel := context.WithCancel(ctx)
	defer rpcParentCancel()

	if childDoneCh != nil {
		go func() {
			select {
			case <-childDoneCh:
				phaseCancel()
				rpcParentCancel()
			case <-phaseCtx.Done():
			}
		}()
	}

	baseTime := benchmarkGeneratorBaseTime(cfg)
	perWorkerLatencies := make([]latencyHistogram, cfg.Workers)

	var wg sync.WaitGroup
	for workerID := range cfg.Workers {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			var workerSubmitted *bqfake.SubmittedKeySet
			if phaseSubmitted != nil {
				workerSubmitted = bqfake.NewSubmittedKeySet()
				defer func() {
					phaseSubmitted.Merge(workerSubmitted)
				}()
			}
			var (
				hasWorkerPrebuilt bool
				myBatches         []collectorWorkerBatch
			)
			if wID < len(workerBatches) && len(workerBatches[wID]) > 0 {
				hasWorkerPrebuilt = true
				myBatches = workerBatches[wID]
			}
			localSeq := 0
			for phaseCtx.Err() == nil && time.Now().Before(deadline) {
				gSeq := int(globalSeq.Add(1))
				if maxBatches > 0 && gSeq > maxBatches {
					return
				}

				var (
					batchRows       int64
					prebuiltOrdinal uint64
				)
				if cfg.TargetRate > 0 {
					pacerMu.Lock()
					if !nextScheduled.Before(deadline) || (budgetLimited && remainingBudget <= 0) {
						pacerMu.Unlock()
						if maxBatches == 0 {
							<-phaseCtx.Done()
						}
						return
					}
					if budgetLimited {
						batchRows = min(remainingBudget, int64(pacedBatchCap))
						remainingBudget -= batchRows
					} else {
						batchRows = int64(cfg.BatchSize)
					}
					if hasWorkerPrebuilt {
						prebuiltOrdinal = prebuiltDispatchSeq.Add(1) - 1
					}
					scheduledAt := nextScheduled
					nextScheduled = nextScheduled.Add(time.Duration(float64(time.Second) * float64(batchRows) / float64(cfg.TargetRate)))
					pacerMu.Unlock()

					if waitDur := time.Until(scheduledAt); waitDur > 0 {
						timer := time.NewTimer(waitDur)
						select {
						case <-phaseCtx.Done():
							timer.Stop()
							return
						case <-timer.C:
						}
					}
					if phaseCtx.Err() != nil {
						return
					}
				} else {
					batchRows = int64(cfg.BatchSize)
					if hasWorkerPrebuilt {
						prebuiltOrdinal = prebuiltDispatchSeq.Add(1) - 1
					}
				}

				if cfg.workerHook != nil {
					cfg.workerHook(wID, localSeq)
				}

				var (
					batch collectorPreparedBatch
					err   error
				)
				if hasWorkerPrebuilt {
					d := prebuiltOrdinal
					slotIdx := int(d % uint64(len(myBatches)))
					epoch := d / uint64(len(myBatches))
					batch = myBatches[slotIdx].batch
					if int(batchRows) < cfg.BatchSize {
						batch, err = sliceCollectorPreparedBatch(batch, signal, int(batchRows))
						if err != nil {
							batchesAttempted.Add(1)
							batchesFailed.Add(1)
							errOnce.Do(func() { firstErr = err })
							localSeq++
							continue
						}
					}
					if batch.recordCount > 0 {
						treeDelta := (epochOffset + epoch) * treeStride
						stampCollectorPreparedBatchTreeEpoch(signal, batch, baseTime, treeStride, treeDelta, dispatchSeq, cfg.UpstreamInsertID)
					}
				} else {
					batch, err = makeBatch(int(batchRows))
					if err != nil {
						batchesAttempted.Add(1)
						batchesFailed.Add(1)
						errOnce.Do(func() { firstErr = err })
						localSeq++
						continue
					}
				}
				localSeq++

				batchesAttempted.Add(1)
				recordsAttempted.Add(batch.recordCount)
				dispatchedSourceBytes.Add(batch.sourceBytes)
				dispatchedOTLPBytes.Add(batch.otlpBytes)
				dispatchedRecords.Add(batch.recordCount)

				rpcCtx, cancel := context.WithTimeout(rpcParentCtx, callTimeout)
				rpcStart := time.Now()
				rejected, rpcErr := exportCollectorBatch(rpcCtx, signal, batch, tracesClient, logsClient, metricsClient)
				rpcMs := float64(time.Since(rpcStart).Microseconds()) / 1000.0
				cancel()

				if rpcErr != nil {
					if ctx.Err() != nil {
						return
					}
					batchesFailed.Add(1)
					errOnce.Do(func() { firstErr = rpcErr })
					if childDoneCh != nil {
						select {
						case <-childDoneCh:
							return
						default:
						}
					}
					continue
				}

				perWorkerLatencies[wID].Record(rpcMs)
				if rejected > 0 {
					rejectedRecords.Add(rejected)
				}
				accepted := max(int64(0), batch.recordCount-rejected)
				if accepted == 0 && batch.recordCount > 0 {
					batchesFailed.Add(1)
					errOnce.Do(func() {
						firstErr = fmt.Errorf("collector rejected all %d records in batch", batch.recordCount)
					})
					continue
				}
				if rejected > 0 && accepted > 0 {
					hasPartialReject.Store(true)
				}
				if workerSubmitted != nil && rejected == 0 && accepted > 0 {
					switch signal {
					case "traces":
						recordDispatchedTracesKeys(workerSubmitted, batch.tracesReq.Traces(), traceKeyOpts)
					case "logs":
						recordDispatchedLogsKeys(workerSubmitted, batch.logsReq.Logs(), logKeyOpts)
					case "metrics":
						recordDispatchedMetricsKeys(workerSubmitted, batch.metricsReq.Metrics(), metricKeyOpts)
					}
				}
				batchesSucceeded.Add(1)
				recordsSubmitted.Add(accepted)
			}
		}(workerID)
	}
	wg.Wait()

	var mergedLatencies latencyHistogram
	for i := range perWorkerLatencies {
		mergedLatencies.Merge(&perWorkerLatencies[i])
	}

	return collectorPhaseStats{
		batchesAttempted:      batchesAttempted.Load(),
		batchesSucceeded:      batchesSucceeded.Load(),
		batchesFailed:         batchesFailed.Load(),
		recordsAttempted:      recordsAttempted.Load(),
		recordsSubmitted:      recordsSubmitted.Load(),
		rejectedRecords:       rejectedRecords.Load(),
		dispatchedSourceBytes: dispatchedSourceBytes.Load(),
		dispatchedOTLPBytes:   dispatchedOTLPBytes.Load(),
		dispatchedRecords:     dispatchedRecords.Load(),
		hasPartialReject:      hasPartialReject.Load(),
		latencyHist:           mergedLatencies,
		firstErr:              firstErr,
	}
}

func collectorTargetTable(signal string) string {
	switch signal {
	case "traces":
		return "otel_spans"
	case "logs":
		return "otel_logs"
	case "metrics":
		return "otel_metrics"
	default:
		return "otel_logs"
	}
}

func runCollectorSingleSignal(ctx context.Context, cfg RunnerConfig, signal string) (SignalResult, error, error) {
	return runCollectorSingleSignalWithFake(ctx, cfg, signal, nil)
}

func runCollectorSingleSignalWithFake(ctx context.Context, cfg RunnerConfig, signal string, injectedFake *bqfake.Server) (SignalResult, error, error) {
	if isLiveSinkConfig(cfg) && cfg.liveRunBaseTime.IsZero() {
		cfg.liveRunBaseTime = time.Now().UTC().Truncate(time.Second)
	}
	resolvedBin, err := resolveCollectorBinaryPath(cfg.CollectorBin)
	if err != nil {
		return SignalResult{}, nil, err
	}

	resolvedCfgPath := resolveCollectorConfigPath(cfg.CollectorConfig)
	rawYAML, err := os.ReadFile(resolvedCfgPath)
	if err != nil {
		return SignalResult{}, nil, fmt.Errorf("reading collector config %q: %w", cfg.CollectorConfig, err)
	}

	useBQFake := !cfg.CollectorAllowLive
	var fakeSrv *bqfake.Server
	if useBQFake {
		if injectedFake != nil {
			fakeSrv = injectedFake
		} else {
			fakeSrv, err = bqfake.New()
			if err != nil {
				return SignalResult{}, nil, fmt.Errorf("starting bqfake for collector mode: %w", err)
			}
			defer func() { _ = fakeSrv.Close() }()
			fakeSrv.SetDiscardRows(true)
		}
		fakeSrv.SeedDataset(cfg.ProjectID, cfg.DatasetID, cfg.Location)
	}

	storageRoot, err := os.MkdirTemp("", "bq-otel-collector-storage-*")
	if err != nil {
		return SignalResult{}, nil, fmt.Errorf("creating temporary collector storage directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(storageRoot) }()

	otlpLis, otlpAddr, err := reserveLoopbackAddr(ctx)
	if err != nil {
		return SignalResult{}, nil, err
	}
	healthLis, healthAddr, err := reserveLoopbackAddr(ctx)
	if err != nil {
		_ = otlpLis.Close()
		return SignalResult{}, nil, err
	}
	metricsLis, metricsAddr, err := reserveLoopbackAddr(ctx)
	if err != nil {
		_ = otlpLis.Close()
		_ = healthLis.Close()
		return SignalResult{}, nil, err
	}

	extraCount := max(0, countActiveSignalOTLPReceivers(rawYAML, signal)-1)
	extraListeners := make([]net.Listener, 0, extraCount)
	extraOTLPAddrs := make([]string, 0, extraCount)
	closeReservedListeners := func() {
		_ = otlpLis.Close()
		_ = healthLis.Close()
		_ = metricsLis.Close()
		for _, l := range extraListeners {
			_ = l.Close()
		}
	}
	for range extraCount {
		exLis, exAddr, exErr := reserveLoopbackAddr(ctx)
		if exErr != nil {
			closeReservedListeners()
			return SignalResult{}, nil, exErr
		}
		extraListeners = append(extraListeners, exLis)
		extraOTLPAddrs = append(extraOTLPAddrs, exAddr)
	}

	metricsHost, metricsPortStr, splitErr := net.SplitHostPort(metricsAddr)
	if splitErr != nil {
		closeReservedListeners()
		return SignalResult{}, nil, fmt.Errorf("splitting metrics address %q: %w", metricsAddr, splitErr)
	}
	metricsPort, portErr := strconv.Atoi(metricsPortStr)
	if portErr != nil {
		closeReservedListeners()
		return SignalResult{}, nil, fmt.Errorf("parsing metrics port %q: %w", metricsPortStr, portErr)
	}

	override := collectorEndpointOverride{
		otlpAddr:       otlpAddr,
		extraOTLPAddrs: extraOTLPAddrs,
		healthAddr:     healthAddr,
		metricsHost:    metricsHost,
		metricsPort:    metricsPort,
		storageRoot:    storageRoot,
		useBQFake:      useBQFake,
	}
	if fakeSrv != nil {
		override.fakeGRPCURL = fakeSrv.Addr()
		override.fakeRESTURL = strings.TrimRight(fakeSrv.RESTURL(), "/") + "/bigquery/v2/"
	}

	rewrittenYAML, meta, err := rewriteCollectorLoopbackConfig(rawYAML, cfg, signal, override)
	if err != nil {
		closeReservedListeners()
		return SignalResult{}, nil, err
	}
	if fakeSrv != nil && meta.effectiveTable != collectorTargetTable(signal) {
		if seedErr := fakeSrv.SeedTable(cfg.ProjectID, cfg.DatasetID, meta.effectiveTable, signalTableSchema(signal)); seedErr != nil {
			closeReservedListeners()
			return SignalResult{}, nil, fmt.Errorf("seeding custom table %q in bqfake: %w", meta.effectiveTable, seedErr)
		}
	}

	tempCfgFile, err := os.CreateTemp("", "bq-otel-collector-*.yaml")
	if err != nil {
		closeReservedListeners()
		return SignalResult{}, nil, fmt.Errorf("creating temporary collector config: %w", err)
	}
	tempCfgPath := tempCfgFile.Name()
	defer func() { _ = os.Remove(tempCfgPath) }()
	if _, writeErr := tempCfgFile.Write(rewrittenYAML); writeErr != nil {
		_ = tempCfgFile.Close()
		closeReservedListeners()
		return SignalResult{}, nil, fmt.Errorf("writing temporary collector config: %w", writeErr)
	}
	if closeErr := tempCfgFile.Close(); closeErr != nil {
		closeReservedListeners()
		return SignalResult{}, nil, fmt.Errorf("closing temporary collector config: %w", closeErr)
	}

	usesNullIDTracker := signal == "logs" && !meta.effectiveLogsSynthesizeInsertID && !cfg.UpstreamInsertID
	usesTaggedTracker := signal == "metrics" || (signal == "logs" && meta.effectiveLogsSynthesizeInsertID && !cfg.UpstreamInsertID)
	faultSimEnabled := fakeSrv != nil && (cfg.SimulateThrottleEvery > 0 || cfg.SimulateAckDelay > 0)
	if faultSimEnabled && cfg.TargetRate > 0 {
		var limit int64
		if usesNullIDTracker {
			limit = int64(fakeSrv.MaxTrackedNullIDLogRows())
		} else {
			limit = int64(fakeSrv.MaxTrackedGeneratedRowsForSignal(signal, usesTaggedTracker))
		}
		estimatedRows := max(int64(1), int64(math.Round(float64(cfg.TargetRate)*cfg.Duration.Seconds())))
		if estimatedRows > limit {
			closeReservedListeners()
			return SignalResult{}, nil, fmt.Errorf(
				"estimated steady-state volume (%d rows at rate=%d for duration=%s) exceeds bqfake unique-acked row tracking limit (%d) on destination table %q; lower -rate or -duration so fault-simulated runs stay within %d unique rows, or omit -simulate-throttle-every / -simulate-ack-delay",
				estimatedRows, cfg.TargetRate, cfg.Duration, limit, meta.effectiveTable, limit,
			)
		}
	}
	effectiveUniquePayloads := cfg.UniquePayloads
	usePrebuilt := !effectiveUniquePayloads && !collectorUsesDynamicPacing(cfg)
	if usePrebuilt {
		if bErr := validatePrebuiltBatchBudget(cfg); bErr != nil {
			closeReservedListeners()
			return SignalResult{}, nil, bErr
		}
	}
	batchCfg := cfg
	batchCfg.UniquePayloads = effectiveUniquePayloads

	var (
		workerBatches          [][]collectorWorkerBatch
		treeStride             uint64 = 7
		makeBatch              func(int) (collectorPreparedBatch, error)
		warmupPartialMakeBatch func(int) (collectorPreparedBatch, error)
		steadyPartialMakeBatch func(int) (collectorPreparedBatch, error)
	)
	if usePrebuilt && cfg.Workers > 0 {
		geom := computeWorkerSlotGeometry(cfg, signal)
		if geom.seedBatchCount > 0 {
			seedMakeBatch, sErr := newCollectorBatchBuilder(batchCfg, signal)
			if sErr != nil {
				closeReservedListeners()
				return SignalResult{}, nil, sErr
			}
			seedBatches := make([]collectorPreparedBatch, geom.seedBatchCount)
			for i := range geom.seedBatchCount {
				sb, bErr := seedMakeBatch(cfg.BatchSize)
				if bErr != nil {
					closeReservedListeners()
					return SignalResult{}, nil, bErr
				}
				seedBatches[i] = sb
			}
			workerBatches = buildCollectorWorkerBatchesFromPrebuilt(cfg.Workers, seedBatches, true)
			seedBatches = nil
			if signal == "logs" && cfg.WorkloadProfile == WorkloadProfileAccessLogs {
				treeStride = computePrebuiltAccessLogSeqStride(geom.seedBatchCount, cfg.BatchSize)
			} else {
				treeStride = computePrebuiltTreeStride(geom.seedBatchCount, cfg.BatchSize)
			}
		}
	}
	if len(workerBatches) == 0 {
		var makeBatchSeed uint64
		if cfg.WarmupDuration > 0 && !usePrebuilt {
			makeBatchSeed = uint64(warmupTreeBaseOffset)
		}
		makeBatch, err = newCollectorBatchBuilderWithSeed(batchCfg, signal, makeBatchSeed)
		if err != nil {
			closeReservedListeners()
			return SignalResult{}, nil, err
		}
		warmupPartialMakeBatch = makeBatch
		steadyPartialMakeBatch = makeBatch
		if signal == "logs" && cfg.WorkloadProfile == WorkloadProfileAccessLogs {
			treeStride = computePrebuiltAccessLogSeqStride(1, cfg.BatchSize)
		} else {
			treeStride = computePrebuiltTreeStride(1, cfg.BatchSize)
		}
	}
	var warmupEpochOffset uint64
	if signal == "logs" && cfg.WorkloadProfile == WorkloadProfileAccessLogs {
		warmupEpochOffset = max(uint64(1), (uint64(warmupAccessLogSeqOffset)+treeStride-1)/treeStride)
	} else {
		warmupEpochOffset = max(uint64(1), (uint64(warmupTreeBaseOffset)+treeStride-1)/treeStride)
	}

	closeReservedListeners()

	diag := &boundedDiagBuffer{}
	if meta.activeExporterDiagnosticID == interpolatedExporterPlaceholder && meta.activeExporterID != "" {
		diag.SetExporterIDRedaction(meta.activeExporterID)
	}
	diagSecrets := slices.Clone(meta.rawCredentialSecrets)
	if cfg.CollectorAllowLive {
		diagSecrets = append(diagSecrets, collectEndpointURLSecrets(meta.effectiveEndpoint)...)
	}
	diag.SetCredentialRedactions(meta.effectiveCredentials, diagSecrets...)
	cmd := exec.CommandContext(ctx, resolvedBin, "--config="+tempCfgPath)
	cmd.Env = buildCollectorEnv(cfg.MaxProcs)
	cmd.Stdout = diag
	cmd.Stderr = diag
	cmd.Cancel = func() error {
		stopCollectorProcess(cmd.Process)
		return nil
	}
	cmd.WaitDelay = 10 * time.Second

	if startErr := cmd.Start(); startErr != nil {
		return SignalResult{}, nil, fmt.Errorf("starting collector %q: %w", cfg.CollectorBin, startErr)
	}

	doneCh := make(chan struct{})
	var cmdWaitErr error
	go func() {
		cmdWaitErr = cmd.Wait()
		close(doneCh)
	}()

	childDone := false
	terminateCollector := func() {
		if !childDone && cmd.Process != nil {
			stopCollectorProcess(cmd.Process)
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-doneCh:
			case <-timer.C:
				_ = cmd.Process.Kill()
				<-doneCh
			}
			childDone = true
		}
	}
	defer terminateCollector()

	if readyErr := waitCollectorReady(ctx, doneCh, &cmdWaitErr, diag, healthAddr, meta.healthCheckPath, metricsAddr, otlpAddr, meta.hasHealthCheck); readyErr != nil {
		return SignalResult{}, nil, readyErr
	}

	metricsClientHTTP := &http.Client{Timeout: 2 * time.Second}
	defer metricsClientHTTP.CloseIdleConnections()

	conn, err := dialCollectorOTLPClient(otlpAddr)
	if err != nil {
		return SignalResult{}, nil, fmt.Errorf("dialing collector OTLP gRPC %s: %w", otlpAddr, err)
	}
	defer func() { _ = conn.Close() }()

	tracesClient := ptraceotlp.NewGRPCClient(conn)
	logsClient := plogotlp.NewGRPCClient(conn)
	metricsClient := pmetricotlp.NewGRPCClient(conn)

	drainTimeout := max(collectorMinDrainTimeout, cfg.CallTimeout)
	totalBatchTimeout := meta.batchProcessorTimeout + meta.queueBatchFlushTimeout
	if totalBatchTimeout > 0 {
		drainTimeout = max(drainTimeout, 2*totalBatchTimeout+5*time.Second)
	}
	batchWaitCfg := collectorBatchWaitConfig{
		batchProcTimeout:       meta.batchProcessorTimeout,
		batchProcSendSize:      meta.batchProcessorSendSize,
		queueBatchFlushTimeout: meta.queueBatchFlushTimeout,
		queueBatchMinItems:     meta.queueBatchMinItems,
	}
	baseMetrics, err := scrapeCollectorMetrics(ctx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID)
	if err != nil {
		return SignalResult{}, nil, err
	}

	var dispatchSeq atomic.Uint64
	targetTableKey := bqfake.CanonicalTableKey(cfg.ProjectID, cfg.DatasetID, meta.effectiveTable)
	activeTrackingLimit := func(snap bqfake.TableStatsSnapshot, rec bqfake.ReconciliationResult) (int, string) {
		if usesNullIDTracker && !snap.UniqueSaturated && !rec.Saturated {
			if _, tier2Hashes := fakeSrv.UniqueAckedTierCountsForTable(targetTableKey); tier2Hashes == 0 {
				return fakeSrv.MaxTrackedNullIDLogRows(), bqfake.SaturationUnitRows
			}
		}
		return effectiveUniqueSaturatedLimit(fakeSrv, targetTableKey, signal, usesTaggedTracker, snap, rec)
	}
	formatWarmupUniqueAckedSaturatedErr := func(snap bqfake.TableStatsSnapshot, rec bqfake.ReconciliationResult) error {
		limit, unit := activeTrackingLimit(snap, rec)
		return fmt.Errorf(
			"bqfake warmup unique-acked row tracking saturated at %d %s on destination table %q; warmup distinct-row delivery cannot be verified (lower -rate, shorten warmup_duration, or omit -soak so warmup stays within %d %s)",
			limit, unit, meta.effectiveTable, limit, unit,
		)
	}
	formatUniqueAckedSaturatedErr := func(snap bqfake.TableStatsSnapshot, rec bqfake.ReconciliationResult) error {
		limit, unit := activeTrackingLimit(snap, rec)
		if faultSimEnabled {
			return fmt.Errorf(
				"bqfake unique-acked row tracking saturated at %d %s on destination table %q; unique_delivery_verified cannot be asserted (lower -rate or -duration so fault-simulated runs stay within %d %s, or disable -simulate-throttle-every / -simulate-ack-delay)",
				limit, unit, meta.effectiveTable, limit, unit,
			)
		}
		return fmt.Errorf(
			"bqfake unique-acked row tracking saturated at %d %s on destination table %q; unique_delivery_verified cannot be asserted (lower -rate or -duration so runs stay within %d %s)",
			limit, unit, meta.effectiveTable, limit, unit,
		)
	}

	pid := cmd.Process.Pid
	var keyRedactor *redact.Redactor
	redactorOK := true
	if meta.effectiveRedaction {
		if !meta.effectiveRedactionConfig.Enabled {
			redactorOK = false
		} else {
			keyRedactor, redactorOK = buildBenchRedactor(meta.effectiveRedactionConfig)
		}
	}
	needsDerivedTag := (signal == "logs" && meta.effectiveLogsSynthesizeInsertID && !cfg.UpstreamInsertID) || signal == "metrics"
	canPredictDerivedTag := redactorOK && (!meta.pipelineModifiesNonIdentityAttrs || meta.canSimulateNonIdentityAttrs)
	canReconcile := !meta.pipelineAltersIdentityKeys && redactorOK && (!needsDerivedTag || canPredictDerivedTag)
	var attrOps []collectorAttrOp
	if canReconcile {
		attrOps = meta.nonIdentityAttrOps
	}
	traceKeyOpts := traceKeyRecordOptions{
		redactor: keyRedactor,
		attrOps:  attrOps,
	}
	logKeyOpts := logKeyRecordOptions{
		logNameAttr:        meta.effectiveLogsLogNameAttr,
		insertIDAttr:       meta.effectiveLogsInsertIDAttr,
		synthesizeInsertID: meta.effectiveLogsSynthesizeInsertID,
		predictDerivedTag:  canPredictDerivedTag,
		redactor:           keyRedactor,
		attrOps:            attrOps,
	}
	metricKeyOpts := metricKeyRecordOptions{
		predictDerivedTag: canPredictDerivedTag,
		redactor:          keyRedactor,
		attrOps:           attrOps,
	}
	// Enable unique tracking once per signal before any warmup phase so steady-state
	// replays of warmup rows remain recognized and counted against delta tracking.
	if fakeSrv != nil {
		fakeSrv.SetTrackUniqueAcked(true)
	}
	if cfg.WarmupDuration > 0 {
		warmupRunCtx := ctx
		var (
			cancelWarmupRun       context.CancelFunc
			warmupBeforeSnap      bqfake.TableStatsSnapshot
			warmupSubmitted       *bqfake.SubmittedKeySet
			warmupSinkAckedBefore int64
			warmupSinkAckedFn     func() int64
			warmupFaultSimEnabled bool
		)
		if fakeSrv != nil {
			// Periodic faults are only activated after warmup, so only relax warmup
			// replay/commit checks when retry/delay faults were already queued for warmup.
			warmupFaultSimEnabled = faultSimEnabled && fakeSrv.PendingFaultsForTable(targetTableKey) > 0
			warmupRunCtx, cancelWarmupRun = context.WithCancel(ctx)
			fakeSrv.SetOnUniqueAckedSaturated(func(tbl string) {
				if tbl == "" || tbl == targetTableKey {
					cancelWarmupRun()
				}
			})
			fakeSrv.BeginUniqueAckedPhase(targetTableKey)
			warmupBeforeSnap = fakeSrv.TableStatsSnapshotForTable(targetTableKey)
			if canReconcile {
				warmupSubmitted = bqfake.NewSubmittedKeySet()
			}
			warmupSinkAckedBefore = warmupBeforeSnap.UniqueAckedRows
			warmupSinkAckedFn = func() int64 {
				snap := fakeSrv.TableStatsSnapshotForTable(targetTableKey)
				if snap.UniqueSaturated {
					return math.MaxInt64
				}
				return snap.UniqueAckedRows
			}
		}
		dispatchSeq.Store(warmupAccessLogSeqOffset)
		warmupStats := runCollectorWorkerPhasePrepared(
			warmupRunCtx, cfg, signal, cfg.WarmupDuration, 0,
			workerBatches, treeStride, warmupEpochOffset,
			warmupPartialMakeBatch, tracesClient, logsClient, metricsClient, doneCh, &dispatchSeq,
			warmupSubmitted, traceKeyOpts, logKeyOpts, metricKeyOpts,
		)
		if cancelWarmupRun != nil {
			cancelWarmupRun()
		}
		if fakeSrv != nil {
			fakeSrv.SetOnUniqueAckedSaturated(nil)
		}
		if fakeSrv != nil {
			if snap := fakeSrv.TableStatsSnapshotForTable(targetTableKey); snap.UniqueSaturated {
				_ = conn.Close()
				terminateCollector()
				satErr := formatWarmupUniqueAckedSaturatedErr(snap, bqfake.ReconciliationResult{})
				return SignalResult{}, errors.Join(warmupStats.firstErr, satErr), satErr
			}
		}
		if ctx.Err() != nil {
			return SignalResult{}, warmupStats.firstErr, ctx.Err()
		}
		if warmupStats.firstErr != nil && !cfg.AllowPartialFailures {
			return SignalResult{}, warmupStats.firstErr, warmupStats.firstErr
		}
		warmupAfter, _, drainErr := drainCollectorPipelineWithBatchWait(
			ctx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID,
			baseMetrics, warmupStats.recordsSubmitted, drainTimeout, doneCh, &cmdWaitErr, diag,
			warmupSinkAckedBefore, warmupSinkAckedFn, batchWaitCfg,
		)
		if drainErr != nil {
			if fakeSrv != nil {
				if snap := fakeSrv.TableStatsSnapshotForTable(targetTableKey); snap.UniqueSaturated {
					_ = conn.Close()
					terminateCollector()
					satErr := formatWarmupUniqueAckedSaturatedErr(snap, bqfake.ReconciliationResult{})
					return SignalResult{}, errors.Join(warmupStats.firstErr, satErr), satErr
				}
			}
			return SignalResult{}, warmupStats.firstErr, drainErr
		}
		var (
			warmupCommitted       int64
			warmupUnique          int64
			warmupReplayed        int64
			warmupUnexpected      int64
			warmupUncertainFaults int64
			warmupUncertainRows   int64
			warmupDelayedAcks     int64
			warmupReplayAllowed   bool
			warmupAfterSnap       bqfake.TableStatsSnapshot
			warmupRec             bqfake.ReconciliationResult
			warmupHasRec          bool
		)
		warmupTelem, warmupSendFailed := diffCollectorTelemetry(baseMetrics, warmupAfter)
		warmupEnqueueFailed := max(int64(0), warmupAfter.EnqueueFailed-baseMetrics.EnqueueFailed)
		if fakeSrv != nil {
			if warmupSubmitted != nil && !warmupStats.hasPartialReject {
				warmupAfterSnap, warmupRec = fakeSrv.ReconcileAndSnapshotForTable(targetTableKey, warmupSubmitted)
				warmupHasRec = true
			} else {
				warmupAfterSnap = fakeSrv.TableStatsSnapshotForTable(targetTableKey)
			}
			if warmupAfterSnap.UniqueSaturated || warmupRec.Saturated {
				_ = conn.Close()
				terminateCollector()
				satErr := formatWarmupUniqueAckedSaturatedErr(warmupAfterSnap, warmupRec)
				return SignalResult{}, errors.Join(warmupStats.firstErr, satErr), satErr
			}
			warmupUncertainFaults = max(int64(0), warmupAfterSnap.TriggeredUncertainCommitFaults-warmupBeforeSnap.TriggeredUncertainCommitFaults)
			warmupUncertainRows = max(int64(0), warmupAfterSnap.TriggeredUncertainCommitRows-warmupBeforeSnap.TriggeredUncertainCommitRows)
			warmupDelayedAcks = max(int64(0), warmupAfterSnap.TriggeredDelayedAckFaults-warmupBeforeSnap.TriggeredDelayedAckFaults)
			warmupReplayAllowed = warmupFaultSimEnabled && (warmupTelem.Retries > 0 || warmupUncertainFaults > 0)
			warmupCommitted = max(int64(0), warmupAfterSnap.AckedRows-warmupBeforeSnap.AckedRows)
			warmupRawUnique := max(int64(0), warmupAfterSnap.UniqueAckedRows-warmupBeforeSnap.UniqueAckedRows)
			warmupRawBytes := max(int64(0), warmupAfterSnap.UniqueAckedBytes-warmupBeforeSnap.UniqueAckedBytes)
			warmupNullRepeatRows := max(int64(0), warmupAfterSnap.NullIDRepeatRows-warmupBeforeSnap.NullIDRepeatRows)
			warmupNullRepeatBytes := max(int64(0), warmupAfterSnap.NullIDRepeatBytes-warmupBeforeSnap.NullIDRepeatBytes)
			warmupUnique, _, warmupReplayed, warmupUnexpected = computeFakePhaseDeliveryStats(
				warmupCommitted, warmupRawUnique, warmupRawBytes,
				warmupNullRepeatRows, warmupNullRepeatBytes,
				warmupRec, warmupHasRec, warmupReplayAllowed,
			)
		}
		warmupAckBad := warmupTelem.AcknowledgedRows != warmupStats.recordsSubmitted
		if warmupReplayAllowed && fakeSrv != nil {
			warmupAckBad = warmupTelem.AcknowledgedRows < warmupStats.recordsSubmitted || warmupTelem.AcknowledgedRows > warmupCommitted
		}
		maxWarmupReplays := warmupUncertainRows
		if warmupDelayedAcks > 0 && warmupTelem.Retries > 0 && cfg.BatchSize > 0 {
			maxWarmupReplays += warmupTelem.Retries * int64(cfg.BatchSize)
		}
		warmupReplayExceedsObserved := warmupRec.UnexplainedReplayRows > 0 || warmupReplayed > maxWarmupReplays
		warmupFakeBad := fakeSrv != nil && (warmupUnique != warmupStats.recordsSubmitted ||
			(warmupHasRec && (warmupRec.MissingRows > 0 || warmupUnexpected > 0)) ||
			(!warmupReplayAllowed && (warmupCommitted != warmupStats.recordsSubmitted || warmupReplayed != 0 || warmupRec.UnexplainedReplayRows > 0)) ||
			(warmupReplayAllowed && warmupReplayExceedsObserved))
		if !cfg.AllowPartialFailures && (warmupStats.batchesFailed > 0 || warmupStats.rejectedRecords > 0 || warmupSendFailed > 0 || warmupEnqueueFailed > 0 || warmupTelem.RejectedRows > 0 || warmupTelem.QuarantinedRows > 0 || warmupAckBad || warmupFakeBad) {
			sendErr := fmt.Errorf(
				"collector warmup failed gate for %s (submitted=%d, otlp_rejected=%d, acked=%d, committed=%d, unique_committed=%d, replayed=%d, unexplained_replays=%d, retries=%d, uncertain_faults=%d, missing=%d, unexpected=%d, rejected=%d, quarantined=%d, send_failed=%d, enqueue_failed=%d)",
				signal, warmupStats.recordsSubmitted, warmupStats.rejectedRecords, warmupTelem.AcknowledgedRows, warmupCommitted, warmupUnique, warmupReplayed,
				warmupRec.UnexplainedReplayRows, warmupTelem.Retries, warmupUncertainFaults,
				warmupRec.MissingRows, warmupUnexpected,
				warmupTelem.RejectedRows, warmupTelem.QuarantinedRows, warmupSendFailed, warmupEnqueueFailed,
			)
			return SignalResult{}, errors.Join(warmupStats.firstErr, sendErr), sendErr
		}
		dispatchSeq.Store(0)
		if len(workerBatches) == 0 {
			makeBatch, err = newCollectorBatchBuilder(batchCfg, signal)
			if err != nil {
				return SignalResult{}, nil, err
			}
			steadyPartialMakeBatch = makeBatch
		}
		baseMetrics = warmupAfter
	}

	var (
		steadyBeforeSnap bqfake.TableStatsSnapshot
		steadySubmitted  *bqfake.SubmittedKeySet
		sinkAckedBefore  int64
		sinkAckedFn      func() int64
	)
	if fakeSrv != nil {
		fakeSrv.BeginUniqueAckedPhase(targetTableKey)
		steadyBeforeSnap = fakeSrv.TableStatsSnapshotForTable(targetTableKey)
		if canReconcile {
			steadySubmitted = bqfake.NewSubmittedKeySet()
		}
		sinkAckedBefore = steadyBeforeSnap.UniqueAckedRows
		sinkAckedFn = func() int64 {
			snap := fakeSrv.TableStatsSnapshotForTable(targetTableKey)
			if snap.UniqueSaturated {
				return math.MaxInt64
			}
			return snap.UniqueAckedRows
		}
	}
	cpuBeforeSec, cpuBeforeOK := readPIDCPUSeconds(pid)

	var (
		memMu        sync.Mutex
		lastRSSMB    float64
		peakRSSMB    float64
		memSampledOK bool
		stopMemCh    = make(chan struct{})
		memDoneWg    sync.WaitGroup
	)
	sampleMem := func() {
		rss, hwm, ok := readPIDMemoryMB(pid)
		memMu.Lock()
		if ok {
			memSampledOK = true
		}
		if rss > 0 {
			lastRSSMB = rss
		}
		if hwm > peakRSSMB {
			peakRSSMB = hwm
		}
		if rss > peakRSSMB {
			peakRSSMB = rss
		}
		memMu.Unlock()
	}
	sampleMem()
	memDoneWg.Add(1)
	go func() {
		defer memDoneWg.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopMemCh:
				return
			case <-ticker.C:
				sampleMem()
			}
		}
	}()
	stopMemSampler := sync.OnceFunc(func() {
		close(stopMemCh)
		memDoneWg.Wait()
	})
	defer stopMemSampler()

	phaseRunCtx := ctx
	if fakeSrv != nil {
		var cancelPhaseRun context.CancelFunc
		phaseRunCtx, cancelPhaseRun = context.WithCancel(ctx)
		defer cancelPhaseRun()
		fakeSrv.SetOnUniqueAckedSaturated(func(tbl string) {
			if tbl == "" || tbl == targetTableKey {
				cancelPhaseRun()
			}
		})
		defer fakeSrv.SetOnUniqueAckedSaturated(nil)
		if faultSimEnabled {
			fakeSrv.SetPeriodicFaults(ctx, targetTableKey, cfg.SimulateThrottleEvery, cfg.SimulateAckDelay)
		}
	}

	startWall := time.Now()
	steadyStats := runCollectorWorkerPhasePrepared(
		phaseRunCtx, cfg, signal, cfg.Duration, cfg.maxBatches,
		workerBatches, treeStride, 0,
		steadyPartialMakeBatch, tracesClient, logsClient, metricsClient, doneCh, &dispatchSeq,
		steadySubmitted, traceKeyOpts, logKeyOpts, metricKeyOpts,
	)
	phaseEnd := time.Now()
	preSaturated := fakeSrv != nil && fakeSrv.TableStatsSnapshotForTable(targetTableKey).UniqueSaturated
	var (
		afterMetrics  collectorMetricsSample
		idleBatchWait time.Duration
		drainErr      error
	)
	if preSaturated {
		mCtx, mCancel := context.WithTimeout(context.Background(), 2*time.Second)
		if mSample, mErr := scrapeCollectorMetrics(mCtx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID); mErr == nil {
			afterMetrics = mSample
		} else {
			afterMetrics = baseMetrics
		}
		mCancel()
	} else {
		afterMetrics, idleBatchWait, drainErr = drainCollectorPipelineWithBatchWait(
			ctx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID,
			baseMetrics, steadyStats.recordsSubmitted, drainTimeout, doneCh, &cmdWaitErr, diag,
			sinkAckedBefore, sinkAckedFn, batchWaitCfg,
		)
	}
	phaseElapsed := phaseEnd.Sub(startWall)
	totalElapsed := time.Since(startWall)
	elapsed := max(phaseElapsed, totalElapsed-idleBatchWait)
	if elapsed <= 0 {
		elapsed = time.Microsecond
	}

	var (
		cutoffSnap               bqfake.TableStatsSnapshot
		reconcileRes             bqfake.ReconciliationResult
		fakeUniqueAckedSaturated bool
	)
	if fakeSrv != nil {
		if steadySubmitted != nil && !steadyStats.hasPartialReject {
			cutoffSnap, reconcileRes = fakeSrv.ReconcileAndSnapshotForTable(targetTableKey, steadySubmitted)
		} else {
			cutoffSnap = fakeSrv.TableStatsSnapshotForTable(targetTableKey)
		}
		fakeUniqueAckedSaturated = cutoffSnap.UniqueSaturated || reconcileRes.Saturated
	}
	cpuAfterDrainSec, cpuAfterOK := readPIDCPUSeconds(pid)

	stopMemSampler()
	sampleMem()

	var satErr error
	if fakeUniqueAckedSaturated {
		satErr = formatUniqueAckedSaturatedErr(cutoffSnap, reconcileRes)
	}

	var throttleErr error
	if faultSimEnabled && cfg.SimulateThrottleEvery > 0 && steadyStats.recordsSubmitted > 0 {
		if (cutoffSnap.ThrottlesInjected - steadyBeforeSnap.ThrottlesInjected) == 0 {
			throttleErr = fmt.Errorf(
				"-simulate-throttle-every=%d never fired on destination table %q",
				cfg.SimulateThrottleEvery, meta.effectiveTable,
			)
		}
	}

	preDrainFirstErr := steadyStats.firstErr
	var (
		incompleteDrain bool
		drainWarning    string
	)
	if drainErr != nil {
		incompleteDrain = true
		drainWarning = drainErr.Error()
		steadyStats.batchesFailed = max(int64(1), steadyStats.batchesFailed)
		if steadyStats.firstErr == nil {
			steadyStats.firstErr = drainErr
		}
	}

	_ = conn.Close()

	var shutdownErr error
	childDone, shutdownErr = finalizeCollectorShutdown(cmd.Process, doneCh, &cmdWaitErr, ctx.Err(), diag)

	cpuUnavailable := !cpuBeforeOK || !cpuAfterOK
	var cpuDeltaSec float64
	if !cpuUnavailable {
		cpuDeltaSec = max(0.0, cpuAfterDrainSec-cpuBeforeSec)
	}

	telem, deltaSendFailed := diffCollectorTelemetry(baseMetrics, afterMetrics)
	deltaEnqueueFailed := max(int64(0), afterMetrics.EnqueueFailed-baseMetrics.EnqueueFailed)
	if steadyStats.rejectedRecords > telem.RejectedRows {
		telem.RejectedRows = steadyStats.rejectedRecords
	}
	if deltaSendFailed > 0 || deltaEnqueueFailed > 0 {
		if steadyStats.batchesFailed == 0 {
			steadyStats.batchesFailed = 1
		}
		if steadyStats.firstErr == nil {
			if deltaEnqueueFailed == 0 {
				steadyStats.firstErr = fmt.Errorf("collector exporter failed to send %d %s records", deltaSendFailed, signal)
			} else {
				steadyStats.firstErr = fmt.Errorf("collector exporter failed to send or enqueue %s records (send_failed=%d, enqueue_failed=%d)", signal, deltaSendFailed, deltaEnqueueFailed)
			}
		}
	}

	ackedRows := telem.AcknowledgedRows
	attemptedProtoBytes := telem.AppendBytesTotal
	var committedRows int64
	if fakeSrv != nil {
		committedRows = max(int64(0), cutoffSnap.AckedRows-steadyBeforeSnap.AckedRows)
		fakeAckedBytes := max(int64(0), cutoffSnap.AckedBytes-steadyBeforeSnap.AckedBytes)
		if attemptedProtoBytes == 0 {
			attemptedProtoBytes = fakeAckedBytes
			telem.AppendBytesTotal = fakeAckedBytes
		}
	}

	var (
		deliveredRows                 int64
		matchedRows                   int64
		replayedRows                  int64
		missingRows                   int64
		unexpectedRows                int64
		reconciled                    bool
		uniqueDeliveryVerified        bool
		observedUncertainCommitFaults int64
		observedUncertainCommitRows   int64
		observedDelayedAckFaults      int64
		unexplainedReplayRows         int64
		bytesPerRowUnavailable        bool
		bytesPerRow                   float64
		attemptedBytesPerAckedRow     float64
	)
	if ackedRows > 0 {
		attemptedBytesPerAckedRow = float64(attemptedProtoBytes) / float64(ackedRows)
	}

	if fakeSrv != nil {
		reconciled = steadySubmitted != nil && !steadyStats.hasPartialReject
		observedUncertainCommitFaults = max(int64(0), cutoffSnap.TriggeredUncertainCommitFaults-steadyBeforeSnap.TriggeredUncertainCommitFaults)
		observedUncertainCommitRows = max(int64(0), cutoffSnap.TriggeredUncertainCommitRows-steadyBeforeSnap.TriggeredUncertainCommitRows)
		observedDelayedAckFaults = max(int64(0), cutoffSnap.TriggeredDelayedAckFaults-steadyBeforeSnap.TriggeredDelayedAckFaults)
		replayTolerance := faultSimEnabled && (telem.Retries > 0 || observedUncertainCommitFaults > 0)
		rawUniqueRows := max(int64(0), cutoffSnap.UniqueAckedRows-steadyBeforeSnap.UniqueAckedRows)
		rawUniqueBytes := max(int64(0), cutoffSnap.UniqueAckedBytes-steadyBeforeSnap.UniqueAckedBytes)
		nullIDRepeatRows := max(int64(0), cutoffSnap.NullIDRepeatRows-steadyBeforeSnap.NullIDRepeatRows)
		nullIDRepeatBytes := max(int64(0), cutoffSnap.NullIDRepeatBytes-steadyBeforeSnap.NullIDRepeatBytes)
		var deliveredBytes int64
		deliveredRows, deliveredBytes, replayedRows, unexpectedRows = computeFakePhaseDeliveryStats(
			committedRows, rawUniqueRows, rawUniqueBytes,
			nullIDRepeatRows, nullIDRepeatBytes,
			reconcileRes, reconciled, replayTolerance,
		)
		if reconciled {
			matchedRows = reconcileRes.MatchedRows
		}
		missingRows = reconcileRes.MissingRows
		unexplainedReplayRows = reconcileRes.UnexplainedReplayRows
		uniqueDeliveryVerified = !fakeUniqueAckedSaturated && reconciled
		if deliveredRows > 0 {
			bytesPerRow = float64(deliveredBytes) / float64(deliveredRows)
		}
	} else {
		deliveredRows = min(ackedRows, steadyStats.recordsSubmitted)
		replayedRows = max(int64(0), ackedRows-steadyStats.recordsSubmitted)
		if telem.Retries > 0 || deltaSendFailed > 0 || deltaEnqueueFailed > 0 || telem.RejectedRows > 0 || telem.QuarantinedRows > 0 ||
			incompleteDrain || replayedRows > 0 || (steadyStats.recordsSubmitted > 0 && ackedRows < steadyStats.recordsSubmitted) ||
			(ackedRows > 0 && (!afterMetrics.HasAppendBytesMetric || attemptedProtoBytes <= 0)) {
			bytesPerRowUnavailable = true
		} else if ackedRows > 0 {
			bytesPerRow = float64(attemptedProtoBytes) / float64(ackedRows)
		}
		if ackedRows > 0 && (!afterMetrics.HasAppendBytesMetric || attemptedProtoBytes <= 0) {
			attemptedBytesPerAckedRow = 0
		}
	}
	telem.ReplayedRows = replayedRows

	elapsedSec := elapsed.Seconds()
	rowsPerSec := float64(deliveredRows) / elapsedSec
	var wireMBPerSec float64
	if !bytesPerRowUnavailable {
		wireMBPerSec = (bytesPerRow * float64(deliveredRows)) / (1024.0 * 1024.0) / elapsedSec
	}

	var byteLayers *ByteLayersSummary
	if steadyStats.dispatchedRecords > 0 && bytesPerRow > 0 {
		dispatched := dispatchedByteTotals{
			sourceBytes: steadyStats.dispatchedSourceBytes,
			otlpBytes:   steadyStats.dispatchedOTLPBytes,
			records:     steadyStats.dispatchedRecords,
		}
		byteLayers = buildByteLayersSummaryFromMeasured(dispatched, bytesPerRow)
		if !useBQFake && byteLayers != nil {
			if hasUnroutedCustomCollectorEndpoint(meta.effectiveEndpoint) {
				byteLayers.BQStorageQueryNote = "INFORMATION_SCHEMA.TABLE_STORAGE lookup skipped: collector exporter uses custom endpoint.url or without_authentication without endpoint.admin_url"
			} else {
				populateLiveTableStorageWithCollectorOptions(ctx, cfg, meta.effectiveTable, &meta.effectiveEndpoint, &meta.effectiveCredentials, byteLayers)
			}
		}
	}

	var cpuCoresUsed, cpuCoresPer10k float64
	if !cpuUnavailable {
		cpuCoresUsed = cpuDeltaSec / elapsedSec
		if rowsPerSec > 0 {
			cpuCoresPer10k = cpuCoresUsed / (rowsPerSec / 10000.0)
		}
	}

	res := SignalResult{
		Signal:                        signal,
		Mode:                          cfg.Mode,
		WorkloadProfile:               cfg.WorkloadProfile,
		StreamPoolSize:                meta.effectiveStreamPoolSize,
		ConnectionPoolSize:            meta.effectiveConnectionPoolSize,
		Workers:                       cfg.Workers,
		BatchSize:                     cfg.BatchSize,
		PayloadBytes:                  cfg.PayloadBytes,
		Redaction:                     meta.effectiveRedaction,
		Backpressure:                  meta.effectiveBackpressure,
		ElapsedSeconds:                round2(elapsedSec),
		BatchesAttempted:              steadyStats.batchesAttempted,
		BatchesSucceeded:              steadyStats.batchesSucceeded,
		BatchesFailed:                 steadyStats.batchesFailed,
		RecordsAttempted:              steadyStats.recordsAttempted,
		RecordsSubmitted:              steadyStats.recordsSubmitted,
		DeliveredRows:                 deliveredRows,
		MatchedRows:                   matchedRows,
		MissingRows:                   missingRows,
		UnexpectedRows:                unexpectedRows,
		Reconciled:                    reconciled,
		UniqueDeliveryVerified:        uniqueDeliveryVerified,
		ObservedUncertainCommitFaults: observedUncertainCommitFaults,
		ObservedUncertainCommitRows:   observedUncertainCommitRows,
		ObservedDelayedAckFaults:      observedDelayedAckFaults,
		UnexplainedReplayRows:         unexplainedReplayRows,
		AchievedRowsPerSec:            round2(rowsPerSec),
		WireMBPerSec:                  round2(wireMBPerSec),
		BytesPerRow:                   round2(bytesPerRow),
		BytesPerRowUnavailable:        bytesPerRowUnavailable,
		AttemptedBytesPerAckedRow:     round2(attemptedBytesPerAckedRow),
		IncompleteDrain:               incompleteDrain,
		DrainWarning:                  drainWarning,
		Latency:                       steadyStats.latencyHist.Summary(),
		Memory: MemorySummary{
			HeapAllocBytes:      afterMetrics.HeapAllocBytes,
			HeapAllocMB:         round2(float64(afterMetrics.HeapAllocBytes) / (1024.0 * 1024.0)),
			SysMB:               round2(lastRSSMB),
			PeakRSSMB:           round2(peakRSSMB),
			PeakRSSUnavailable:  !memSampledOK,
			CPUUnavailable:      cpuUnavailable,
			CPUSeconds:          round2(cpuDeltaSec),
			CPUCoresUsed:        round2(cpuCoresUsed),
			CPUCoresPer10kRowsS: round2(cpuCoresPer10k),
		},
		Telemetry:  telem,
		ByteLayers: byteLayers,
	}
	var cutoffHardErrs []error
	if satErr != nil {
		cutoffHardErrs = append(cutoffHardErrs, satErr)
	}
	if drainErr != nil && !cfg.AllowPartialFailures {
		cutoffHardErrs = append(cutoffHardErrs, drainErr)
	}
	if throttleErr != nil {
		cutoffHardErrs = append(cutoffHardErrs, throttleErr)
	}
	if shutdownErr != nil {
		cutoffHardErrs = append(cutoffHardErrs, shutdownErr)
	}
	if len(cutoffHardErrs) > 0 {
		hardErr := errors.Join(cutoffHardErrs...)
		return res, errors.Join(preDrainFirstErr, hardErr), hardErr
	}
	return res, steadyStats.firstErr, nil
}
