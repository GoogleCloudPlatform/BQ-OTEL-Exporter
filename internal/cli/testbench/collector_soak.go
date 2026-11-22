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

	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	bigqueryexporter "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/redact"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testfakes/bqfake"
	"go.opentelemetry.io/collector/confmap"
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

const maxDroppedPEMTailBytes = 256

type boundedDiagBuffer struct {
	mu                sync.Mutex
	retained          bytes.Buffer
	pending           bytes.Buffer
	droppingLine      bool
	droppedLineSawPEM bool
	droppedPEMTail    string
	inPEMKeyBlock     bool
	truncated         bool
	droppedOverlong   bool
	preparedSecrets   []string
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
		return
	}
	b.retained.WriteString(cleanLine)
	b.retained.WriteByte('\n')
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

func sanitizePEMLine(
	line string,
	inBlock bool,
	secrets []string,
) (clean string, nextInBlock bool, suppress bool) {
	if !inBlock && !reDiagPEMBegin.MatchString(line) && !reDiagPEMEnd.MatchString(line) {
		return sanitizeCollectorDiagnostics(line, secrets), false, false
	}

	rem := line
	curInBlock := inBlock
	if !curInBlock {
		for _, secret := range secrets {
			rem = strings.ReplaceAll(rem, secret, "[REDACTED]")
		}
	}

	var out strings.Builder
	sawOutput := false
	for len(rem) > 0 {
		if curInBlock {
			endLoc := reDiagPEMEnd.FindStringIndex(rem)
			if endLoc == nil {
				rem = ""
				break
			}
			rem = rem[endLoc[1]:]
			curInBlock = false
			continue
		}
		beginLoc := reDiagPEMBegin.FindStringIndex(rem)
		if beginLoc == nil {
			out.WriteString(sanitizeCollectorDiagnostics(rem, secrets))
			sawOutput = true
			rem = ""
			break
		}
		if beginLoc[0] > 0 {
			out.WriteString(sanitizeCollectorDiagnostics(rem[:beginLoc[0]], secrets))
			sawOutput = true
		}
		out.WriteString("[REDACTED_PRIVATE_KEY]")
		sawOutput = true
		rem = rem[beginLoc[1]:]
		curInBlock = true
	}

	if !sawOutput {
		return "", curInBlock, true
	}
	return out.String(), curInBlock, false
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
				var saw bool
				b.inPEMKeyBlock, saw, b.droppedPEMTail = updatePEMStateForDroppedBytes(b.inPEMKeyBlock, b.droppedPEMTail, rem)
				b.droppedLineSawPEM = b.droppedLineSawPEM || saw
				break
			}
			var saw bool
			b.inPEMKeyBlock, saw, _ = updatePEMStateForDroppedBytes(b.inPEMKeyBlock, b.droppedPEMTail, rem[:nl])
			sawPEM := b.droppedLineSawPEM || saw
			b.droppingLine = false
			b.droppedLineSawPEM = false
			b.droppedPEMTail = ""
			switch {
			case sawPEM:
				b.appendRetainedLineLocked("[REDACTED_PRIVATE_KEY] [overlong diagnostic line omitted]")
			case !b.inPEMKeyBlock:
				b.appendRetainedLineLocked("[overlong diagnostic line omitted]")
			}
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
			var saw1, saw2 bool
			b.inPEMKeyBlock, saw1, b.droppedPEMTail = updatePEMStateForDroppedBytes(b.inPEMKeyBlock, "", b.pending.Bytes())
			b.inPEMKeyBlock, saw2, b.droppedPEMTail = updatePEMStateForDroppedBytes(b.inPEMKeyBlock, b.droppedPEMTail, chunk)
			b.pending.Reset()
			b.droppedOverlong = true
			sawPEM := saw1 || saw2
			if hasNewline {
				b.droppedPEMTail = ""
				b.droppedLineSawPEM = false
				switch {
				case sawPEM:
					b.appendRetainedLineLocked("[REDACTED_PRIVATE_KEY] [overlong diagnostic line omitted]")
				case !startedInBlock:
					b.appendRetainedLineLocked("[overlong diagnostic line omitted]")
				}
			} else {
				b.droppingLine = true
				b.droppedLineSawPEM = sawPEM
			}
			continue
		}
		if len(chunk) > 0 {
			_, _ = b.pending.Write(chunk)
		}
		if hasNewline {
			line := strings.TrimSuffix(b.pending.String(), "\r")
			b.pending.Reset()
			clean, nextInBlock, suppress := sanitizePEMLine(line, b.inPEMKeyBlock, b.preparedSecrets)
			b.inPEMKeyBlock = nextInBlock
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
	truncated := b.truncated
	preparedSecrets := b.preparedSecrets
	b.mu.Unlock()

	var out strings.Builder
	if retainedRaw != "" {
		out.WriteString(sanitizeCollectorDiagnostics(retainedRaw, preparedSecrets))
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
		cleanPending, _, suppress := sanitizePEMLine(strings.TrimSuffix(pendingRaw, "\r"), inPEMBlock, preparedSecrets)
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

var (
	reDiagPEMBegin                  = regexp.MustCompile(`(?i)-----BEGIN [^\r\n-]*PRIVATE KEY-----`)
	reDiagPEMEnd                    = regexp.MustCompile(`(?i)-----END [^\r\n-]*PRIVATE KEY-----`)
	reDiagPEMBlock                  = regexp.MustCompile(`-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----`)
	reDiagPEMPrefix                 = regexp.MustCompile(`-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*`)
	reDiagBearerToken               = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	reDiagJSONSecretEscaped         = regexp.MustCompile(`(\\"(?:private_key|private_key_id|client_secret|client_email|client_id|refresh_token|access_token|id_token|credentials_json|audience)\\"\s*:\s*\\")(?:[^\\]|\\[^"])*(\\")`)
	reDiagJSONSecretPlain           = regexp.MustCompile(`("(?:private_key|private_key_id|client_secret|client_email|client_id|refresh_token|access_token|id_token|credentials_json|audience)"\s*:\s*")(?:[^"\\]|\\.)*(")`)
	reDiagJSONSecretUnclosedEscaped = regexp.MustCompile(`(\\"(?:private_key|private_key_id|client_secret|client_email|client_id|refresh_token|access_token|id_token|credentials_json|audience)\\"\s*:\s*\\")[^\r\n"]*$`)
	reDiagJSONSecretUnclosedPlain   = regexp.MustCompile(`("(?:private_key|private_key_id|client_secret|client_email|client_id|refresh_token|access_token|id_token|credentials_json|audience)"\s*:\s*")[^\r\n"]*$`)
	reDiagUnsupportedTypeEscaped    = regexp.MustCompile(`((?:unsupported(?:\s+credentials)?\s+type|unknown\s+credentials\s+type|has\s+unsupported\s+type)\s+)\\"(?:[^\\]|\\[^"])*\\"`)
	reDiagUnsupportedTypePlain      = regexp.MustCompile(`((?:unsupported(?:\s+credentials)?\s+type|unknown\s+credentials\s+type|has\s+unsupported\s+type)\s+)"[^"]*"`)
	reDiagCredFileQuotedEscaped     = regexp.MustCompile(`((?:(?:reading|parsing|loading)\s+)?credentials(?:\s+file|\.file)\s+)\\"(?:[^\\]|\\[^"])*\\"`)
	reDiagCredFileQuotedPlain       = regexp.MustCompile(`((?:(?:reading|parsing|loading)\s+)?credentials(?:\s+file|\.file)\s+)"[^"]*"`)
	reDiagPathOpPrefix              = regexp.MustCompile(`(?:open|lstat|stat|CreateFile)\s+`)
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

func scrubCollectorPathErrorsInLine(line string) string {
	lower := strings.ToLower(line)
	hasCredContext := strings.Contains(lower, "credentials") ||
		strings.Contains(line, "open {") ||
		strings.Contains(line, `open {\"`) ||
		strings.Contains(line, "CreateFile {") ||
		strings.Contains(line, `CreateFile {\"`)
	if !hasCredContext {
		return line
	}

	var b strings.Builder
	cursor := 0
	for cursor < len(line) {
		loc := reDiagPathOpPrefix.FindStringIndex(line[cursor:])
		if loc == nil {
			b.WriteString(line[cursor:])
			break
		}
		pathStart := cursor + loc[1]
		// Scan to the first unescaped quote (for JSON-encoded log lines) or end of line.
		segEnd := pathStart
		escaped := false
		for segEnd < len(line) {
			ch := line[segEnd]
			if escaped {
				escaped = false
				segEnd++
				continue
			}
			if ch == '\\' {
				escaped = true
				segEnd++
				continue
			}
			if ch == '"' || ch == '\r' || ch == '\n' {
				break
			}
			segEnd++
		}
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
		b.WriteString(line[cursor:pathStart])
		b.WriteString("[REDACTED]")
		cursor = pathEnd
	}
	return b.String()
}

func sanitizeCollectorDiagnostics(raw string, secrets []string) string {
	out := raw
	for _, secret := range secrets {
		out = strings.ReplaceAll(out, secret, "[REDACTED]")
	}
	out = reDiagPEMBlock.ReplaceAllString(out, "[REDACTED]")
	out = reDiagPEMPrefix.ReplaceAllString(out, "[REDACTED]")
	out = reDiagBearerToken.ReplaceAllString(out, "Bearer [REDACTED]")
	out = reDiagJSONSecretEscaped.ReplaceAllString(out, "${1}[REDACTED]${2}")
	out = reDiagJSONSecretPlain.ReplaceAllString(out, "${1}[REDACTED]${2}")
	out = reDiagJSONSecretUnclosedEscaped.ReplaceAllString(out, "${1}[REDACTED]")
	out = reDiagJSONSecretUnclosedPlain.ReplaceAllString(out, "${1}[REDACTED]")
	out = reDiagUnsupportedTypeEscaped.ReplaceAllString(out, `${1}\"[REDACTED]\"`)
	out = reDiagUnsupportedTypePlain.ReplaceAllString(out, `${1}"[REDACTED]"`)
	out = reDiagCredFileQuotedEscaped.ReplaceAllString(out, `${1}\"[REDACTED]\"`)
	out = reDiagCredFileQuotedPlain.ReplaceAllString(out, `${1}"[REDACTED]"`)

	if strings.Contains(out, "\n") {
		lines := strings.Split(out, "\n")
		for i, line := range lines {
			lines[i] = scrubCollectorPathErrorsInLine(line)
		}
		out = strings.Join(lines, "\n")
	} else {
		out = scrubCollectorPathErrorsInLine(out)
	}
	return out
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

func resolveCollectorTableRefWithLookup(raw string, lookupEnv func(string) (string, bool)) (string, error) {
	return resolveCollectorEnvStringWithLookup(raw, lookupEnv)
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

func validateSingleDocEnvYAML(val string) error {
	dec := yaml.NewDecoder(strings.NewReader(val))
	var firstDoc any
	if err1 := dec.Decode(&firstDoc); err1 == nil {
		var extraDoc any
		if err2 := dec.Decode(&extraDoc); !errors.Is(err2, io.EOF) {
			return redactedConfmapError{msg: "multi-document YAML in environment variable is not allowed"}
		}
	}
	return nil
}

func (p *lookupEnvConfmapProvider) Retrieve(_ context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if !strings.HasPrefix(uri, collectorEnvConfmapScheme+":") {
		return nil, redactedConfmapError{msg: "unsupported collector config provider"}
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
	ret, err := confmap.NewRetrievedFromYAML([]byte(val))
	if err != nil {
		return nil, redactedConfmapError{msg: "invalid environment variable YAML value"}
	}
	return ret, nil
}

var (
	confmapUnsupportedSchemeErrorPattern = regexp.MustCompile(`scheme "([A-Za-z][A-Za-z0-9+.-]+)" is not supported`)
	confmapDecodePatternIndexPattern     = regexp.MustCompile(`blocked_value_patterns\[(\d+)\]`)
)

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
	if m := confmapUnsupportedSchemeErrorPattern.FindStringSubmatch(msg); len(m) == 2 {
		return fmt.Errorf("unsupported collector config provider %q (only env is supported)", m[1])
	}
	if strings.Contains(msg, "unsupported scheme on URI") || strings.Contains(msg, "is not supported for uri") {
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

	const rootURI = collectorInlineConfmapScheme + ":blocked_value_patterns"
	rootFactory := confmap.NewProviderFactory(func(confmap.ProviderSettings) confmap.Provider {
		return &inlineConfmapProvider{
			scheme: collectorInlineConfmapScheme,
			uri:    rootURI,
			data:   map[string]any{"blocked_value_patterns": inlineRoot},
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
		return nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: %w", exporterPath, sanitizeCollectorConfmapError(err))
	}
	ctx := context.Background()
	defer func() {
		_ = resolver.Shutdown(ctx)
	}()

	resolvedConf, err := resolver.Resolve(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: %w", exporterPath, sanitizeCollectorConfmapError(err))
	}

	container := resolvedConf.Get("blocked_value_patterns")
	if container == nil {
		return nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: expected YAML sequence of strings, got null", exporterPath)
	}
	rawSeq, isSeq := container.([]any)
	if !isSeq {
		return nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: expected YAML sequence of strings, got %s", exporterPath, describeYAMLValueKind(container))
	}
	if len(rawSeq) == 0 {
		return []string{}, nil
	}
	for i, elem := range rawSeq {
		switch elem.(type) {
		case nil:
			return nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: expected string, got null", exporterPath, i)
		case map[string]any, map[any]any:
			return nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: expected string, got map", exporterPath, i)
		}
	}

	var decoded struct {
		Patterns []string `mapstructure:"blocked_value_patterns"`
	}
	if err := resolvedConf.Unmarshal(&decoded); err != nil {
		for i, elem := range rawSeq {
			switch elem.(type) {
			case string, []any:
			default:
				return nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: expected string, got %s", exporterPath, i, describeYAMLValueKind(elem))
			}
		}
		if m := confmapDecodePatternIndexPattern.FindStringSubmatch(err.Error()); len(m) == 2 {
			if idx, pErr := strconv.Atoi(m[1]); pErr == nil && idx >= 0 && idx < len(rawSeq) {
				return nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: expected string, got %s", exporterPath, idx, describeYAMLValueKind(rawSeq[idx]))
			}
		}
		for i, elem := range rawSeq {
			if _, ok := elem.(string); !ok {
				return nil, fmt.Errorf("%s.redaction.blocked_value_patterns[%d]: expected string, got %s", exporterPath, i, describeYAMLValueKind(elem))
			}
		}
		return nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: expected YAML sequence of strings", exporterPath)
	}
	if len(decoded.Patterns) != len(rawSeq) {
		return nil, fmt.Errorf("reading %s.redaction.blocked_value_patterns: expected YAML sequence of strings", exporterPath)
	}

	patterns := make([]string, 0, len(decoded.Patterns))
	for i, resolvedElem := range decoded.Patterns {
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
		resolved, err := resolveCollectorEnvStringWithLookup(v, lookupEnv)
		if err != nil {
			return false, fmt.Errorf("resolving %s: %w", fieldPath, err)
		}
		trimmed := strings.TrimSpace(resolved)
		if trimmed == "" {
			return false, nil
		}
		parsed, err := strconv.ParseBool(trimmed)
		if err != nil {
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
		".sending_queue.storage",
		".sending_queue.sizer",
		".sending_queue.batch.sizer",
		".redaction.mask_replacement",
		".offload.bucket",
		".offload.prefix",
		".offload.authorizer",
		".path",
		".endpoint",
		".level",
		".encoding",
		".format",
	} {
		if pathDesc == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(pathDesc, suffix) {
			return true
		}
	}
	for _, elemSub := range []string{
		".credentials.impersonate_delegates[",
		".clustering[",
		".search_index.columns[",
		".redaction.blocked_keys[",
		".redaction.blocked_key_patterns[",
		".redaction.blocked_value_patterns[",
	} {
		if idx := strings.Index(pathDesc, elemSub); idx >= 0 && strings.HasSuffix(pathDesc, "]") {
			return true
		}
	}
	return strings.Contains(pathDesc, ".labels.")
}

func resolveCollectorEnvYAMLValueWithLookup(raw any, pathDesc string, lookupEnv func(string) (string, bool)) (any, error) {
	return resolveCollectorEnvYAMLValueWithOptions(raw, pathDesc, lookupEnv, false)
}

func resolveCollectorEnvYAMLValueWithOptions(raw any, pathDesc string, lookupEnv func(string) (string, bool), redactValues bool) (any, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	switch v := raw.(type) {
	case map[string]any:
		if v == nil {
			return nil, nil
		}
		cloned := make(map[string]any, len(v))
		for k, val := range v {
			childPath := k
			if pathDesc != "" {
				childPath = pathDesc + "." + k
			}
			resolvedVal, err := resolveCollectorEnvYAMLValueWithOptions(val, childPath, lookupEnv, redactValues)
			if err != nil {
				return nil, err
			}
			cloned[k] = resolvedVal
		}
		return cloned, nil
	case []any:
		if v == nil {
			return nil, nil
		}
		cloned := make([]any, len(v))
		for idx, val := range v {
			childPath := fmt.Sprintf("%s[%d]", pathDesc, idx)
			resolvedVal, err := resolveCollectorEnvYAMLValueWithOptions(val, childPath, lookupEnv, redactValues)
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
		trimmed := strings.TrimSpace(v)
		if isSingleStandaloneConfmapExpr(trimmed) {
			var parsed any
			if err := yaml.Unmarshal([]byte(resolved), &parsed); err == nil {
				return parsed, nil
			}
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

func isBigQueryComponentID(id string) bool {
	return id == "bigquery" || strings.HasPrefix(id, "bigquery/")
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
	if tlsStr, isStr := rawTLS.(string); isStr && strings.Contains(tlsStr, "$") {
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
	if rawTable, exists := sigMap["table"]; exists && rawTable != nil {
		rawStr, ok := rawTable.(string)
		if !ok {
			return fmt.Errorf("collector exporter %s.table must be a string, got %T", signal, rawTable)
		}
		if strings.TrimSpace(rawStr) != "" {
			hasExplicitTable = true
			resolvedTable, resErr := resolveCollectorTableRefWithLookup(rawStr, lookupEnv)
			if resErr != nil {
				return fmt.Errorf("resolving collector exporter %s.table: %w", signal, resErr)
			}
			effectiveTable = strings.TrimSpace(resolvedTable)
			if effectiveTable == "" {
				return fmt.Errorf("collector exporter %s.table %q resolved to an empty table name", signal, rawStr)
			}
			if !collectorTableIDPattern.MatchString(effectiveTable) {
				return fmt.Errorf("collector exporter %s.table %q (%q) must contain only letters, numbers and underscores", signal, effectiveTable, rawStr)
			}
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
		yamlBackpressure, err = resolveCollectorYAMLBoolWithLookup(bpMap["enabled"], exporterPath+".write.backpressure.enabled", lookupEnv)
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

	resolvedWriteAny, err := resolveCollectorEnvYAMLValueWithLookup(writeCfg, exporterPath+".write", lookupEnv)
	if err != nil {
		return err
	}
	resolvedWriteMap, _ := resolvedWriteAny.(map[string]any)
	defaultExpCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config)
	if !ok {
		return errors.New("unexpected exporter config type")
	}
	if resolvedWriteMap != nil {
		if err := confmap.NewFromStringMap(resolvedWriteMap).Unmarshal(&defaultExpCfg.Write); err != nil {
			return fmt.Errorf("decoding collector exporter %q write config: %w", exporterID, err)
		}
	}
	if err := validateCollectorWriteLimits(defaultExpCfg.Write); err != nil {
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
		yamlRedaction, err = resolveCollectorYAMLBoolWithLookup(redMap["enabled"], exporterPath+".redaction.enabled", lookupEnv)
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
		offEnabled, offBoolErr := resolveCollectorYAMLBoolWithLookup(offMap["enabled"], exporterPath+".offload.enabled", lookupEnv)
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
		if _, err := resolveCollectorYAMLBoolWithLookup(quarantineMap["enabled"], exporterPath+".quarantine.enabled", lookupEnv); err != nil {
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
				if err := decodeCollectorEndpointMap(exporterID, exporterPath, resolvedEPMap, &defaultExpCfg.Endpoint); err != nil {
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
				if err := decodeCollectorCredentialsMap(exporterID, exporterPath, resolvedCredMap, &defaultExpCfg.Credentials); err != nil {
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

func validateCollectorWriteLimits(w bigqueryexporter.WriteConfig) error {
	if w.StreamPoolSize < 1 || w.StreamPoolSize > 16 {
		return fmt.Errorf("effective write.stream_pool_size %d must be between 1 and 16", w.StreamPoolSize)
	}
	if w.ConnectionPoolSize < 1 || w.ConnectionPoolSize > 16 {
		return fmt.Errorf("effective write.connection_pool_size %d must be between 1 and 16", w.ConnectionPoolSize)
	}
	if w.MaxInflightRequests < 1 || w.MaxInflightRequests > MaxBenchmarkInflightRequests {
		return fmt.Errorf("effective write.max_inflight_requests %d must be between 1 and %d", w.MaxInflightRequests, MaxBenchmarkInflightRequests)
	}
	if w.MaxRequestBytes <= 0 {
		return fmt.Errorf("effective write.max_request_bytes %d must be > 0", w.MaxRequestBytes)
	}
	return nil
}

func isBlockedValuePatternsConfigPath(path string) bool {
	return strings.HasPrefix(path, "exporters.") && strings.HasSuffix(path, ".redaction.blocked_value_patterns")
}

func rejectConfmapDelimiterKeys(node any, path string) error {
	if isBlockedValuePatternsConfigPath(path) {
		switch m := node.(type) {
		case map[string]any, map[any]any:
			return fmt.Errorf("reading %s: expected YAML sequence of strings, got map", path)
		case []any:
			for i, elem := range m {
				if _, ok := elem.(string); !ok {
					return fmt.Errorf("%s[%d]: expected string, got %s", path, i, describeYAMLValueKind(elem))
				}
			}
			return nil
		default:
			return nil
		}
	}
	switch m := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			if strings.Contains(k, "::") {
				return fmt.Errorf("collector config key %q (at %s) contains unsupported confmap path delimiter \"::\"", k, childPath)
			}
			if err := rejectConfmapDelimiterKeys(m[k], childPath); err != nil {
				return err
			}
		}
	case map[any]any:
		type anyEntry struct {
			kStr string
			val  any
		}
		entries := make([]anyEntry, 0, len(m))
		for k, v := range m {
			entries = append(entries, anyEntry{kStr: fmt.Sprint(k), val: v})
		}
		slices.SortFunc(entries, func(a, b anyEntry) int {
			return strings.Compare(a.kStr, b.kStr)
		})
		for _, e := range entries {
			childPath := e.kStr
			if path != "" {
				childPath = path + "." + e.kStr
			}
			if strings.Contains(e.kStr, "::") {
				return fmt.Errorf("collector config key %q (at %s) contains unsupported confmap path delimiter \"::\"", e.kStr, childPath)
			}
			if err := rejectConfmapDelimiterKeys(e.val, childPath); err != nil {
				return err
			}
		}
	case []any:
		for i, elem := range m {
			elemPath := fmt.Sprintf("%s[%d]", path, i)
			if err := rejectConfmapDelimiterKeys(elem, elemPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func rewriteCollectorLoopbackConfig(rawYAML []byte, cfg RunnerConfig, signal string, ep collectorEndpointOverride) ([]byte, collectorRewriteMeta, error) {
	var meta collectorRewriteMeta
	lookupEnv := collectorEnvLookup(cfg.MaxProcs)
	var doc map[string]any
	if err := yaml.Unmarshal(rawYAML, &doc); err != nil {
		return nil, meta, fmt.Errorf("parsing collector YAML config: %w", err)
	}
	if len(doc) == 0 {
		return nil, meta, errors.New("collector YAML config is empty")
	}
	if err := rejectConfmapDelimiterKeys(doc, ""); err != nil {
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
				if strings.Contains(tStr, "$") {
					resolvedT, rErr := resolveCollectorEnvStringWithLookup(tStr, lookupEnv)
					if rErr != nil {
						return nil, meta, fmt.Errorf("resolving collector processor %q timeout: %w", id, rErr)
					}
					tStr = resolvedT
				}
				parsedT, pErr := time.ParseDuration(strings.TrimSpace(tStr))
				if pErr != nil {
					return nil, meta, fmt.Errorf("parsing collector processor %q timeout %q: %w", id, tStr, pErr)
				}
				if parsedT < 0 {
					return nil, meta, fmt.Errorf("collector processor %q timeout %q must be >= 0", id, tStr)
				}
				procTimeout = parsedT
			}
			if rawS, hasS := procCfg["send_batch_size"]; hasS && rawS != nil {
				if sStr, isStr := rawS.(string); isStr && strings.Contains(sStr, "$") {
					resolvedS, rErr := resolveCollectorEnvStringWithLookup(sStr, lookupEnv)
					if rErr != nil {
						return nil, meta, fmt.Errorf("resolving collector processor %q send_batch_size: %w", id, rErr)
					}
					n, sErr := strconv.Atoi(strings.TrimSpace(resolvedS))
					if sErr != nil || n < 0 {
						return nil, meta, fmt.Errorf("parsing collector processor %q send_batch_size %q: expected non-negative integer", id, resolvedS)
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

	exporterIDs, err := extractYAMLStringSlice(activePipe["exporters"])
	if err != nil {
		return nil, meta, fmt.Errorf("reading exporters for collector pipeline %q: %w", meta.activePipelineKey, err)
	}
	if len(exporterIDs) != 1 {
		return nil, meta, fmt.Errorf("collector pipeline %q must configure exactly 1 bigquery exporter for single-sink accounting, got %d (%v)", meta.activePipelineKey, len(exporterIDs), exporterIDs)
	}
	if !isBigQueryComponentID(exporterIDs[0]) {
		return nil, meta, fmt.Errorf("collector pipeline %q references unsupported non-bigquery exporter %q", meta.activePipelineKey, exporterIDs[0])
	}
	meta.activeExporterID = exporterIDs[0]

	exportersMap, err := optionalInlineYAMLSubmap(doc, "exporters", "exporters")
	if err != nil {
		return nil, meta, err
	}
	if exportersMap == nil {
		return nil, meta, fmt.Errorf("collector pipeline %q references undefined exporter %q (exporters section is missing)", meta.activePipelineKey, meta.activeExporterID)
	}
	if _, exists := exportersMap[meta.activeExporterID]; !exists {
		defined := make([]string, 0, len(exportersMap))
		for k := range exportersMap {
			defined = append(defined, k)
		}
		slices.Sort(defined)
		return nil, meta, fmt.Errorf("collector pipeline %q references undefined exporter %q (defined exporters: %v)", meta.activePipelineKey, meta.activeExporterID, defined)
	}
	bq, err := ensureInlineYAMLSubmap(exportersMap, meta.activeExporterID, "exporters."+meta.activeExporterID)
	if err != nil {
		return nil, meta, err
	}
	if err := rewriteBigQueryExporterMapWithLookup(bq, meta.activeExporterID, signal, cfg, ep, &meta, lookupEnv); err != nil {
		return nil, meta, err
	}
	meta.effectiveLogsSynthesizeInsertID = true
	if defaultCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config); ok {
		meta.effectiveLogsSynthesizeInsertID = defaultCfg.Logs.SynthesizeInsertID
		if rawLogs, hasLogs := bq["logs"]; hasLogs && rawLogs != nil {
			logsMap, isMap := rawLogs.(map[string]any)
			if !isMap {
				return nil, meta, fmt.Errorf("collector exporter %q logs must be an inline YAML map, got %T", meta.activeExporterID, rawLogs)
			}
			resolvedLogsAny, resLogsErr := resolveCollectorEnvYAMLValueWithLookup(logsMap, "exporters."+meta.activeExporterID+".logs", lookupEnv)
			if resLogsErr != nil {
				return nil, meta, resLogsErr
			}
			if resolvedLogsMap, ok := resolvedLogsAny.(map[string]any); ok && resolvedLogsMap != nil {
				if err := confmap.NewFromStringMap(resolvedLogsMap).Unmarshal(&defaultCfg.Logs); err != nil {
					return nil, meta, fmt.Errorf("decoding collector exporter %q logs config: %w", meta.activeExporterID, err)
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

	sqMap, err := optionalInlineYAMLSubmap(bq, "sending_queue", "exporters."+meta.activeExporterID+".sending_queue")
	if err != nil {
		return nil, meta, err
	}
	if sqMap != nil {
		if rawStorage, hasStorage := sqMap["storage"]; hasStorage && rawStorage != nil {
			origStID, isStr := rawStorage.(string)
			if !isStr {
				return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage must be a string extension ID, got %T", meta.activeExporterID, rawStorage)
			}
			stID := origStID
			if strings.Contains(stID, "$") {
				resolvedStID, rErr := resolveCollectorEnvStringWithLookup(stID, lookupEnv)
				if rErr != nil {
					return nil, meta, fmt.Errorf("resolving collector exporter %q sending_queue.storage: %w", meta.activeExporterID, rErr)
				}
				stID = strings.TrimSpace(resolvedStID)
				if strings.TrimSpace(origStID) != "" && stID == "" {
					return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage %q resolved to an empty extension ID", meta.activeExporterID, origStID)
				}
			} else {
				stID = strings.TrimSpace(stID)
			}
			if stID != "" {
				if !isFileStorageComponentID(stID) {
					return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage %q is unsupported; only file_storage* extensions are supported", meta.activeExporterID, stID)
				}
				if _, isActive := activeExtSet[stID]; !isActive {
					return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage %q is not enabled in service.extensions", meta.activeExporterID, stID)
				}
			}
		}
		if _, err := optionalInlineYAMLSubmap(sqMap, "batch", "exporters."+meta.activeExporterID+".sending_queue.batch"); err != nil {
			return nil, meta, err
		}
		resolvedSQAny, resSQErr := resolveCollectorEnvYAMLValueWithLookup(sqMap, "exporters."+meta.activeExporterID+".sending_queue", lookupEnv)
		if resSQErr != nil {
			return nil, meta, resSQErr
		}
		sqExpCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config)
		if !ok {
			return nil, meta, errors.New("unexpected exporter config type")
		}
		if err := confmap.NewFromStringMap(map[string]any{"sending_queue": resolvedSQAny}).Unmarshal(sqExpCfg); err != nil {
			return nil, meta, fmt.Errorf("decoding collector exporter %q sending_queue config: %w", meta.activeExporterID, err)
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
						resolvedPath, rErr := resolveCollectorEnvStringWithLookup(pStr, lookupEnv)
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

	var doc map[string]any
	if err := yaml.Unmarshal(rewrittenYAML, &doc); err != nil {
		return emptyMeta, fmt.Errorf("parsing rewritten collector YAML config: %w", err)
	}
	exportersMap, ok := doc["exporters"].(map[string]any)
	if !ok {
		return emptyMeta, errors.New("rewritten collector config missing exporters map")
	}
	bqMap, ok := exportersMap[meta.activeExporterID].(map[string]any)
	if !ok {
		return emptyMeta, fmt.Errorf("rewritten collector exporter %q is not a map", meta.activeExporterID)
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
	resolvedBQAny, resErr := resolveCollectorEnvYAMLValueWithOptions(bqForDecode, "exporters."+meta.activeExporterID, lookupEnv, true)
	if resErr != nil {
		return emptyMeta, resErr
	}
	resolvedBQMap, ok := resolvedBQAny.(map[string]any)
	if !ok || resolvedBQMap == nil {
		return emptyMeta, fmt.Errorf("resolved collector exporter %q is not a map", meta.activeExporterID)
	}

	expCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config)
	if !ok {
		return emptyMeta, errors.New("unexpected exporter config type")
	}
	if err := confmap.NewFromStringMap(resolvedBQMap).Unmarshal(expCfg); err != nil {
		return emptyMeta, fmt.Errorf("decoding collector exporter %q config: %w", meta.activeExporterID, err)
	}
	if err := validateCollectorWriteLimits(expCfg.Write); err != nil {
		return emptyMeta, fmt.Errorf("validating collector exporter %q write config: %w", meta.activeExporterID, err)
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
		return emptyMeta, fmt.Errorf("validating exporter config: %w", err)
	}
	meta.effectiveKMSKeyName = strings.TrimSpace(expCfg.KMSKeyName)
	meta.effectiveLabels = maps.Clone(expCfg.Labels)
	provisionsDedupView := (cfg.CollectorAllowLive && cfg.EphemeralDataset) || expCfg.AutoCreate.Tables || expCfg.AutoCreate.CompanionViews
	meta.destinationTables = buildCollectorEphemeralTableSpecs(signal, meta.activeExporterID, provisionsDedupView, expCfg)
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
	return exp == "" || (activeExporterID != "" && exp == activeExporterID) || (activeExporterID == "" && isBigQueryComponentID(exp))
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
