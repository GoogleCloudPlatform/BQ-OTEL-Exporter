// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testsupport // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/googleapi"
)

// isAllowedContinuousQueryDryRunReason reports whether a BigQuery ErrorProto or
// googleapi.ErrorItem Reason can represent an expected Continuous Query
// edition/reservation or Pub/Sub topic permission gate on an on-demand test
// project. Backend/service failures, rate/quota/resource limits, missing
// datasets/tables, and empty reasons are never eligible for test skip.
func isAllowedContinuousQueryDryRunReason(reason string) bool {
	switch reason {
	case "invalid", "invalidQuery", "billingTierLimitExceeded", "accessDenied":
		return true
	default:
		return false
	}
}

// rejectContinuousQueryMessage reports whether msg contains a substring that
// indicates a SQL/construct/option error, missing resource, backend failure, or
// quota/rate limit — none of which are eligible for an entitlement/topic skip.
func rejectContinuousQueryMessage(msg string) bool {
	m := strings.ToLower(msg)
	for _, reject := range []string{
		"syntax error",
		"unrecognized",
		"invalid value for option",
		"unsupported",
		"do not support",
		"does not support",
		"is not supported in this query",
		"not supported in continuous",
		"group by",
		"order by",
		"join",
		"window",
		"aggregate",
		"subquery",
		"not found",
		"dataset",
		"table",
		"column",
		"bigquery.jobs.create",
		"bigquery.tables",
		"bigquery.datasets",
		"bigquery.routines",
		"internal error",
		"backend error",
		"service unavailable",
		"rate limit",
		"quota exceeded",
		"resources exceeded",
	} {
		if strings.Contains(m, reject) {
			return true
		}
	}
	return false
}

// isAllowedContinuousQueryMessage reports whether msg contains a substring
// indicating an expected entitlement, assignment, or topic-permission gate.
func isAllowedContinuousQueryMessage(code int, msg string) bool {
	m := strings.ToLower(msg)
	hasReservationOrEditionGate := (strings.Contains(m, "continuous queries") || strings.Contains(m, "continuous query")) &&
		(strings.Contains(m, "require the project to have a continuous assignment") ||
			strings.Contains(m, "continuous assignment to a reservation") ||
			strings.Contains(m, "require an enterprise or enterprise plus reservation") ||
			strings.Contains(m, "continuous query reservation") ||
			strings.Contains(m, "are not enabled") ||
			strings.Contains(m, "is not enabled") ||
			strings.Contains(m, "not supported in standard edition") ||
			strings.Contains(m, "without an enterprise") ||
			strings.Contains(m, "billing tier"))
	hasPubSubPermGate := (code == http.StatusForbidden || strings.Contains(m, "access denied") || strings.Contains(m, "permission denied")) &&
		(strings.Contains(m, "permission") || strings.Contains(m, "access denied")) &&
		(strings.Contains(m, "pubsub.topics") ||
			strings.Contains(m, "cloud_pubsub") ||
			strings.Contains(m, "/topics/"))
	return hasReservationOrEditionGate || hasPubSubPermGate
}

// IsExpectedContinuousQueryDryRunError reports whether err from a dry-run
// Continuous Query EXPORT DATA ... CLOUD_PUBSUB job on an on-demand project
// without an Enterprise/Enterprise Plus CONTINUOUS reservation or Pub/Sub
// topic is an expected environment/reservation/topic-permission rejection
// rather than a SQL syntax/construct error, EXPORT DATA option error, missing
// table/dataset, project-level bigquery.jobs.create denial, or 5xx/backend error.
//
// Every non-nil ErrorProto/ErrorItem message is classified independently:
// the primary message and every secondary message must each be an allowed
// entitlement, assignment, or topic rejection, and none may contain a
// rejected substring. This prevents a valid primary reservation-rejection
// from masking a secondary SQL syntax error.
func IsExpectedContinuousQueryDryRunError(err error) bool {
	if err == nil {
		return false
	}
	code := extractHTTPStatusCode(err)
	// Only HTTP 400 (edition/reservation capability check) and HTTP 403
	// (accessDenied on Pub/Sub topic or CONTINUOUS assignment) can qualify as
	// expected environment capability rejections; 404, 5xx, and unknown errors
	// must always fail the test.
	if code != http.StatusBadRequest && code != http.StatusForbidden {
		return false
	}
	// Collect the primary message and every structured ErrorItem message (even
	// when empty or whitespace-only) so an empty/unclassified message fails the
	// allow check rather than being silently ignored.
	var messages []string
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		messages = append(messages, apiErr.Message)
		for _, item := range apiErr.Errors {
			if !isAllowedContinuousQueryDryRunReason(item.Reason) {
				return false
			}
			messages = append(messages, item.Message)
		}
	} else {
		messages = append(messages, primaryErrorMessage(err))
	}
	// Check the trailing reason on the primary message.
	rawMsg := primaryErrorMessage(err)
	if idx := strings.LastIndex(rawMsg, ","); idx >= 0 {
		if trailingReason := strings.TrimSpace(rawMsg[idx+1:]); trailingReason != "" && !strings.Contains(trailingReason, " ") {
			if !isAllowedContinuousQueryDryRunReason(trailingReason) {
				return false
			}
		}
	}
	// Every collected message must be non-empty and pass the reject and allow
	// checks independently.
	for _, msg := range messages {
		if strings.TrimSpace(msg) == "" {
			return false
		}
		if rejectContinuousQueryMessage(msg) {
			return false
		}
		if !isAllowedContinuousQueryMessage(code, msg) {
			return false
		}
	}
	return true
}

var googleapiStatusRe = regexp.MustCompile(`googleapi:\s*Error\s+(\d{3})\b`)

func primaryErrorMessage(err error) string {
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) && apiErr.Message != "" {
		return apiErr.Message
	}
	msg := err.Error()
	if before, _, ok := strings.Cut(msg, "\nDetails:"); ok {
		return before
	}
	return msg
}

func extractHTTPStatusCode(err error) int {
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) && apiErr.Code != 0 {
		return apiErr.Code
	}
	if m := googleapiStatusRe.FindStringSubmatch(err.Error()); len(m) == 2 {
		if n, convErr := strconv.Atoi(m[1]); convErr == nil {
			return n
		}
	}
	return 0
}

// ValidateContinuousExportDryRunJob inspects both the RPC error and the
// returned *bigqueryapi.Job payload from rawSvc.Jobs.Insert(...).Do().
// BigQuery can return HTTP 200 with job.Status.ErrorResult populated or
// Statistics == nil; those must never be treated as validated dry-runs.
func ValidateContinuousExportDryRunJob(job *bigqueryapi.Job, err error) (skipReason string, fatalErr error) {
	if err != nil {
		if IsExpectedContinuousQueryDryRunError(err) {
			return primaryErrorMessage(err), nil
		}
		return "", err
	}
	if job == nil {
		return "", errors.New("Jobs.Insert returned nil job without error")
	}
	if job.Status == nil {
		return "", errors.New("Jobs.Insert returned job with nil Status")
	}
	if job.Status.ErrorResult != nil {
		if !isAllowedContinuousQueryDryRunReason(job.Status.ErrorResult.Reason) {
			return "", fmt.Errorf("job.Status.ErrorResult = %s: %s", job.Status.ErrorResult.Reason, job.Status.ErrorResult.Message)
		}
		for i, item := range job.Status.Errors {
			if item == nil {
				return "", fmt.Errorf("job.Status.Errors[%d] is nil", i)
			}
			if !isAllowedContinuousQueryDryRunReason(item.Reason) {
				return "", fmt.Errorf("job.Status.Errors[%d] = %s: %s", i, item.Reason, item.Message)
			}
		}
		code := http.StatusBadRequest
		if job.Status.ErrorResult.Reason == "accessDenied" {
			code = http.StatusForbidden
		}
		// Keep the original ErrorResult.Message separate from the composite
		// diagnostic so an empty ErrorResult.Message is classified as-is by
		// IsExpectedContinuousQueryDryRunError rather than being masked by a
		// non-empty secondary message.
		primaryMsg := job.Status.ErrorResult.Message
		compositeDiag := primaryMsg
		errItems := []googleapi.ErrorItem{{
			Reason:  job.Status.ErrorResult.Reason,
			Message: primaryMsg,
		}}
		for _, item := range job.Status.Errors {
			if item != nil {
				errItems = append(errItems, googleapi.ErrorItem{
					Reason:  item.Reason,
					Message: item.Message,
				})
				if item.Message != "" && !strings.Contains(compositeDiag, item.Message) {
					if compositeDiag == "" {
						compositeDiag = item.Message
					} else {
						compositeDiag += " | " + item.Message
					}
				}
			}
		}
		statusErr := &googleapi.Error{
			Code:    code,
			Message: primaryMsg,
			Errors:  errItems,
		}
		if IsExpectedContinuousQueryDryRunError(statusErr) {
			return fmt.Sprintf("googleapi: Error %d: %s", code, compositeDiag), nil
		}
		return "", fmt.Errorf("job.Status.ErrorResult = %s: %s", job.Status.ErrorResult.Reason, compositeDiag)
	}
	if len(job.Status.Errors) > 0 {
		for i, item := range job.Status.Errors {
			if item == nil {
				return "", fmt.Errorf("job.Status.Errors[%d] is nil", i)
			}
		}
		first := job.Status.Errors[0]
		return "", fmt.Errorf("job.Status.Errors[0] = %s: %s", first.Reason, first.Message)
	}
	if job.Statistics == nil {
		return "", errors.New("Jobs.Insert dry-run returned nil job.Statistics")
	}
	return "", nil
}
