// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testsupport // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/option"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/googlehttp"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

// MustBigQuerySchema converts a storagepb.TableSchema to bq.Schema and fails t
// if conversion returns an error.
func MustBigQuerySchema(t testing.TB, in *storagepb.TableSchema) bq.Schema {
	t.Helper()
	out, err := schema.ToBigQuery(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// ShouldDeleteDatasetOnCreate reports whether an integration test owns the
// dataset and may register DeleteWithContents cleanup (true only when
// Dataset.Create succeeded without error, never when Dataset.Create returned
// 409 AlreadyExists or any other error).
func ShouldDeleteDatasetOnCreate(createErr error) bool {
	return createErr == nil
}

// UniqueEphemeralDatasetID returns a unique BigQuery dataset ID prefixed with
// prefix, a millisecond timestamp, and 4 random bytes encoded in hex.
func UniqueEphemeralDatasetID(prefix string) string {
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	return fmt.Sprintf("%s_%d_%s", prefix, time.Now().UnixMilli(), hex.EncodeToString(rnd[:]))
}

// CreateOwnedEphemeralDataset creates dataset via
// Dataset.Create(ctx, &bq.DatasetMetadata{Location: location}) and registers
// DeleteWithContents on cleanup ONLY if Dataset.Create returns nil. Deletion
// errors are reported through reportCleanupError so they are never silently
// discarded.
func CreateOwnedEphemeralDataset(
	ctx context.Context,
	admin *bq.Client,
	dataset, location string,
	registerCleanup func(func()),
	reportCleanupError func(error),
) error {
	createErr := admin.Dataset(dataset).Create(ctx, &bq.DatasetMetadata{Location: location})
	if !ShouldDeleteDatasetOnCreate(createErr) {
		return createErr
	}
	registerCleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := admin.Dataset(dataset).DeleteWithContents(cleanCtx); err != nil {
			reportCleanupError(fmt.Errorf("delete ephemeral dataset %s: %w", dataset, err))
		}
	})
	return nil
}

// NewLiveBigQueryClientE creates an authenticated BigQuery client and its
// retained HTTP client for live integration tests, returning any construction
// error to the caller instead of failing t directly. When scopes is empty, it
// defaults to bigqueryapi.BigqueryScope. Callers must run the returned cleanup
// function (via defer or t.Cleanup) after all uses complete; cleanup closes the
// BigQuery client before closing the owned HTTP transport.
func NewLiveBigQueryClientE(ctx context.Context, project string, scopes ...string) (*bq.Client, *http.Client, func(), error) {
	return newLiveBigQueryClient(ctx, project, nil, scopes...)
}

func newLiveBigQueryClient(ctx context.Context, project string, onCloseErr func(error), scopes ...string) (*bq.Client, *http.Client, func(), error) {
	if len(scopes) == 0 {
		scopes = []string{bigqueryapi.BigqueryScope}
	}
	httpClient, _, closeHTTP, err := googlehttp.NewClient(ctx, scopes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create cleanup/query HTTP client: %w", err)
	}
	client, err := bq.NewClient(ctx, project, option.WithHTTPClient(httpClient))
	if err != nil {
		closeHTTP()
		return nil, nil, nil, fmt.Errorf("create cleanup/query client: %w", err)
	}
	cleanup := func() {
		if closeErr := client.Close(); closeErr != nil && onCloseErr != nil {
			onCloseErr(closeErr)
		}
		closeHTTP()
	}
	return client, httpClient, cleanup, nil
}

// NewLiveBigQueryClient creates an authenticated BigQuery client and its
// retained HTTP client for live integration tests. When scopes is empty, it
// defaults to bigqueryapi.BigqueryScope. Callers must run the returned cleanup
// function (via defer or t.Cleanup) after all uses complete.
func NewLiveBigQueryClient(ctx context.Context, t testing.TB, project string, scopes ...string) (*bq.Client, *http.Client, func()) {
	t.Helper()
	client, httpClient, cleanup, err := newLiveBigQueryClient(ctx, project, func(closeErr error) {
		t.Errorf("close cleanup/query client: %v", closeErr)
	}, scopes...)
	if err != nil {
		t.Fatal(err)
	}
	return client, httpClient, cleanup
}

// NewLiveBigQueryAdmin creates an authenticated BigQuery admin client,
// registers its close cleanup, and provisions an owned ephemeral dataset whose
// contents are deleted on test cleanup.
func NewLiveBigQueryAdmin(ctx context.Context, t testing.TB, project, dataset, location string) *bq.Client {
	t.Helper()
	admin, _, cleanup := NewLiveBigQueryClient(ctx, t, project)
	t.Cleanup(cleanup)
	if err := CreateOwnedEphemeralDataset(ctx, admin, dataset, location, t.Cleanup, func(err error) {
		t.Errorf("%v", err)
	}); err != nil {
		t.Fatalf("create dataset %s.%s: %v", project, dataset, err)
	}
	return admin
}
