// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package bigqueryexporter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdhttp "net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/auth/credentials"
	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"cloud.google.com/go/bigquery/storage/managedwriter"
	"cloud.google.com/go/bigquery/storage/managedwriter/adapt"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/googlehttp"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/protoenc"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
)

func requireSpikeLiveBQConfig(t *testing.T) (project, location string) {
	t.Helper()
	project = os.Getenv("BQ_PROJECT")
	if project == "" {
		if os.Getenv("REQUIRE_LIVE_BQ") == "1" {
			t.Fatal("REQUIRE_LIVE_BQ=1 is set but BQ_PROJECT is empty")
		}
		t.Skip("BQ_PROJECT is unset; skipping live BigQuery v1 spike test")
	}
	location = os.Getenv("BQ_LOCATION")
	if location == "" {
		location = "US"
	}
	return project, location
}

func newSpikeClients(
	ctx context.Context, t *testing.T, project string, scopes []string,
) (*bq.Client, *bigqueryapi.Service, *stdhttp.Client) {
	t.Helper()
	httpClient, _, closeHTTP, err := googlehttp.NewClient(ctx, scopes)
	if err != nil {
		t.Fatalf("create HTTP client: %v", err)
	}
	admin, err := bq.NewClient(ctx, project, option.WithHTTPClient(httpClient))
	if err != nil {
		closeHTTP()
		t.Fatalf("create BigQuery client: %v", err)
	}
	rawSvc, err := bigqueryapi.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		_ = admin.Close()
		closeHTTP()
		t.Fatalf("create BigQuery v2 service: %v", err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Errorf("close BigQuery client: %v", err)
		}
		closeHTTP()
	})
	return admin, rawSvc, httpClient
}

func newSpikeManagedWriterClient(ctx context.Context, t *testing.T, project string) *managedwriter.Client {
	t.Helper()
	creds, closeAuth, err := googlehttp.Credentials(credentials.DetectOptions{
		Scopes:           []string{bigqueryapi.BigqueryInsertdataScope},
		UseSelfSignedJWT: true,
	}, nil)
	if err != nil {
		t.Fatalf("googlehttp.Credentials: %v", err)
	}
	t.Cleanup(closeAuth)
	mwClient, err := managedwriter.NewClient(
		ctx, project,
		option.WithAuthCredentials(creds),
		option.WithScopes(bigqueryapi.BigqueryInsertdataScope),
	)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = mwClient.Close() })
	return mwClient
}

func randomHexSuffix(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func createEphemeralGCSBucket(
	ctx context.Context, t *testing.T, httpClient *stdhttp.Client, project, location string,
) (string, error) {
	t.Helper()
	bucket := fmt.Sprintf("bq-otel-v1-spike-%d-%s", time.Now().UnixMilli(), randomHexSuffix(4))
	body, err := json.Marshal(map[string]any{
		"name":     bucket,
		"location": location,
		"iamConfiguration": map[string]any{
			"uniformBucketLevelAccess": map[string]any{"enabled": true},
		},
	})
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s", url.QueryEscape(project))
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != stdhttp.StatusOK && resp.StatusCode != stdhttp.StatusCreated {
		return "", fmt.Errorf("create GCS bucket %q returned HTTP %d: %s", bucket, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		deleteEndpoint := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s", url.PathEscape(bucket))
		dreq, derr := stdhttp.NewRequestWithContext(cleanCtx, stdhttp.MethodDelete, deleteEndpoint, nil)
		if derr != nil {
			t.Errorf("build delete bucket request for %q: %v", bucket, derr)
			return
		}
		dresp, derr := httpClient.Do(dreq)
		if derr != nil {
			t.Errorf("delete ephemeral GCS bucket %q: %v", bucket, derr)
			return
		}
		defer func() { _ = dresp.Body.Close() }()
		if dresp.StatusCode != stdhttp.StatusNoContent && dresp.StatusCode != stdhttp.StatusOK && dresp.StatusCode != stdhttp.StatusNotFound {
			msg, _ := io.ReadAll(dresp.Body)
			t.Errorf("delete ephemeral GCS bucket %q returned HTTP %d: %s", bucket, dresp.StatusCode, strings.TrimSpace(string(msg)))
		}
	})
	return bucket, nil
}

type gcsUploadedObject struct {
	URI         string
	Generation  string
	MD5Hash     string
	Size        string
	ContentType string
	Updated     string
}

func uploadSpikeGCSObject(
	ctx context.Context, t *testing.T, httpClient *stdhttp.Client, bucket, object, contentType string, data []byte,
) (gcsUploadedObject, error) {
	t.Helper()
	endpoint := fmt.Sprintf(
		"https://storage.googleapis.com/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
		url.PathEscape(bucket), url.QueryEscape(object),
	)
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return gcsUploadedObject{}, err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := httpClient.Do(req)
	if err != nil {
		return gcsUploadedObject{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != stdhttp.StatusOK && resp.StatusCode != stdhttp.StatusCreated {
		return gcsUploadedObject{}, fmt.Errorf("upload gs://%s/%s returned HTTP %d: %s", bucket, object, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var obj struct {
		Generation  string `json:"generation"`
		MD5Hash     string `json:"md5Hash"`
		Size        string `json:"size"`
		ContentType string `json:"contentType"`
		Updated     string `json:"updated"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return gcsUploadedObject{}, fmt.Errorf("decode GCS upload response: %w", err)
	}
	uri := "gs://" + bucket + "/" + object
	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		deleteGCSObject(cleanCtx, t, httpClient, uri)
	})
	return gcsUploadedObject{
		URI:         uri,
		Generation:  obj.Generation,
		MD5Hash:     obj.MD5Hash,
		Size:        obj.Size,
		ContentType: obj.ContentType,
		Updated:     obj.Updated,
	}, nil
}

type bqCloudResourceConn struct {
	Name             string
	ServiceAccountID string
}

func discoverOrCreateCloudResourceConnection(
	ctx context.Context, t *testing.T, httpClient *stdhttp.Client, project, location string,
) (bqCloudResourceConn, error) {
	t.Helper()
	locLower := strings.ToLower(location)
	listURL := fmt.Sprintf(
		"https://bigqueryconnection.googleapis.com/v1/projects/%s/locations/%s/connections",
		url.PathEscape(project), url.PathEscape(locLower),
	)
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, listURL, nil)
	if err != nil {
		return bqCloudResourceConn{}, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return bqCloudResourceConn{}, err
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == stdhttp.StatusOK {
		var listResp struct {
			Connections []struct {
				Name          string `json:"name"`
				CloudResource *struct {
					ServiceAccountID string `json:"serviceAccountId"`
				} `json:"cloudResource"`
			} `json:"connections"`
		}
		if err := json.Unmarshal(raw, &listResp); err == nil {
			for _, c := range listResp.Connections {
				if c.CloudResource != nil && c.CloudResource.ServiceAccountID != "" {
					return bqCloudResourceConn{
						Name:             c.Name,
						ServiceAccountID: c.CloudResource.ServiceAccountID,
					}, nil
				}
			}
		}
	}

	connID := fmt.Sprintf("v1_spike_conn_%d_%s", time.Now().UnixMilli(), randomHexSuffix(3))
	createURL := fmt.Sprintf("%s?connectionId=%s", listURL, url.QueryEscape(connID))
	payload := []byte(`{"cloudResource":{}}`)
	creq, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPost, createURL, bytes.NewReader(payload))
	if err != nil {
		return bqCloudResourceConn{}, err
	}
	creq.Header.Set("Content-Type", "application/json")
	cresp, err := httpClient.Do(creq)
	if err != nil {
		return bqCloudResourceConn{}, err
	}
	craw, _ := io.ReadAll(cresp.Body)
	_ = cresp.Body.Close()
	if cresp.StatusCode != stdhttp.StatusOK && cresp.StatusCode != stdhttp.StatusCreated {
		return bqCloudResourceConn{}, fmt.Errorf("create connection HTTP %d: %s", cresp.StatusCode, strings.TrimSpace(string(craw)))
	}
	var created struct {
		Name          string `json:"name"`
		CloudResource *struct {
			ServiceAccountID string `json:"serviceAccountId"`
		} `json:"cloudResource"`
	}
	if err := json.Unmarshal(craw, &created); err != nil {
		return bqCloudResourceConn{}, err
	}
	if created.CloudResource == nil || created.CloudResource.ServiceAccountID == "" {
		return bqCloudResourceConn{}, fmt.Errorf("created connection %q missing cloudResource.serviceAccountId", created.Name)
	}
	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		delURL := fmt.Sprintf("https://bigqueryconnection.googleapis.com/v1/%s", created.Name)
		dreq, derr := stdhttp.NewRequestWithContext(cleanCtx, stdhttp.MethodDelete, delURL, nil)
		if derr != nil {
			t.Errorf("build delete connection request: %v", derr)
			return
		}
		dresp, derr := httpClient.Do(dreq)
		if derr != nil {
			t.Errorf("delete ephemeral connection %q: %v", created.Name, derr)
			return
		}
		_ = dresp.Body.Close()
	})
	return bqCloudResourceConn{
		Name:             created.Name,
		ServiceAccountID: created.CloudResource.ServiceAccountID,
	}, nil
}

func grantBucketObjectViewer(
	ctx context.Context, httpClient *stdhttp.Client, bucket, serviceAccountEmail string,
) error {
	iamURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/iam", url.PathEscape(bucket))
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, iamURL, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != stdhttp.StatusOK {
		return fmt.Errorf("get bucket IAM HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var policy map[string]any
	if err := json.Unmarshal(raw, &policy); err != nil {
		return err
	}
	member := "serviceAccount:" + serviceAccountEmail
	bindings, _ := policy["bindings"].([]any)
	bindings = append(bindings, map[string]any{
		"role":    "roles/storage.objectViewer",
		"members": []string{member},
	})
	policy["bindings"] = bindings
	updated, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	putReq, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPut, iamURL, bytes.NewReader(updated))
	if err != nil {
		return err
	}
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := httpClient.Do(putReq)
	if err != nil {
		return err
	}
	putRaw, _ := io.ReadAll(putResp.Body)
	_ = putResp.Body.Close()
	if putResp.StatusCode != stdhttp.StatusOK {
		return fmt.Errorf("set bucket IAM HTTP %d: %s", putResp.StatusCode, strings.TrimSpace(string(putRaw)))
	}
	return nil
}

// TestLiveObjectRefDetailsCompatibility probes NV-01 and NV-09 against live BigQuery
// and GCS: OBJ.MAKE_REF, OBJ.FETCH_METADATA, OBJ.GET_ACCESS_URL, md5_hash encoding,
// and whether pre-populated details / sibling details.otel survive OBJ.FETCH_METADATA.
func TestLiveObjectRefDetailsCompatibility(t *testing.T) {
	project, location := requireSpikeLiveBQConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)

	admin, _, httpClient := newSpikeClients(ctx, t, project, []string{bigqueryapi.CloudPlatformScope})
	dataset := uniqueEphemeralDatasetID("otel_v1_spike_objref")
	if err := createOwnedEphemeralDataset(ctx, admin, dataset, location, t.Cleanup, func(err error) {
		t.Errorf("%v", err)
	}); err != nil {
		t.Fatalf("create dataset %s.%s: %v", project, dataset, err)
	}

	callerBucket := os.Getenv("BQ_OFFLOAD_TEST_BUCKET")
	if callerBucket == "" {
		callerBucket = os.Getenv("BQ_OFFLOAD_BUCKET")
	}
	bucket := callerBucket
	ownedBucket := false
	if bucket == "" {
		createdBucket, err := createEphemeralGCSBucket(ctx, t, httpClient, project, location)
		if err != nil {
			if os.Getenv("REQUIRE_LIVE_GCS") == "1" {
				t.Fatalf("create ephemeral GCS bucket (BQ_OFFLOAD_TEST_BUCKET unset): %v", err)
			}
			t.Skipf("create ephemeral GCS bucket failed and BQ_OFFLOAD_TEST_BUCKET is unset: %v", err)
		}
		bucket = createdBucket
		ownedBucket = true
	}

	objectKey := fmt.Sprintf("v1-spike-%d-%s/sample.txt", time.Now().UnixMilli(), randomHexSuffix(3))
	uploaded, err := uploadSpikeGCSObject(ctx, t, httpClient, bucket, objectKey, "text/plain", []byte("hello objectref v1 spike\n"))
	if err != nil {
		t.Fatalf("upload GCS object: %v", err)
	}
	t.Logf("uploaded GCS object: uri=%s generation=%s md5Hash=%s size=%s updated=%s",
		uploaded.URI, uploaded.Generation, uploaded.MD5Hash, uploaded.Size, uploaded.Updated)

	conn, err := discoverOrCreateCloudResourceConnection(ctx, t, httpClient, project, location)
	if err != nil {
		t.Skipf("skipping OBJ.FETCH_METADATA probe; BigQuery Cloud Resource connection unavailable/blocked: %v", err)
	}
	t.Logf("using Cloud Resource connection: name=%s serviceAccountId=%s", conn.Name, conn.ServiceAccountID)

	if ownedBucket {
		if err := grantBucketObjectViewer(ctx, httpClient, bucket, conn.ServiceAccountID); err != nil {
			t.Skipf("skipping OBJ.FETCH_METADATA probe; cannot grant storage.objectViewer on ephemeral bucket: %v", err)
		}
	}

	// Ensure BigQuery object table/functions recognize the connection format.
	// Connection resource format: projects/<project>/locations/<loc>/connections/<id>
	tblDDL := fmt.Sprintf(
		"CREATE TABLE `%s.%s.objref_probe` (row_id STRING NOT NULL, ref STRUCT<uri STRING, version STRING, authorizer STRING, details JSON>)",
		project, dataset,
	)
	if _, _, err := runSpikeQuery(ctx, admin, tblDDL); err != nil {
		t.Fatalf("create objref_probe table: %v", err)
	}

	insertSQL := fmt.Sprintf(`
INSERT INTO `+"`%s.%s.objref_probe`"+` (row_id, ref) VALUES
  ('case_a_make_ref', OBJ.MAKE_REF(@uri, @auth)),
  ('case_b_empty_details_pinned', STRUCT(@uri AS uri, @gen AS version, @auth AS authorizer, JSON '{}' AS details)),
  ('case_c_gcs_metadata_null_gen', STRUCT(@uri AS uri, CAST(NULL AS STRING) AS version, @auth AS authorizer, JSON '{"gcs_metadata":{"content_type":"text/plain"}}' AS details)),
  ('case_d_gcs_metadata_plus_otel_pinned', STRUCT(@uri AS uri, @gen AS version, @auth AS authorizer, JSON '{"gcs_metadata":{"content_type":"text/plain"},"otel":{"attribute_path":"body","part_index":0,"storage_mode":"gcs"}}' AS details)),
  ('case_e_otel_only_pinned', STRUCT(@uri AS uri, @gen AS version, @auth AS authorizer, JSON '{"otel":{"attribute_path":"body","part_index":0}}' AS details))
`, project, dataset)
	qIns := admin.Query(insertSQL)
	qIns.Parameters = []bq.QueryParameter{
		{Name: "uri", Value: uploaded.URI},
		{Name: "auth", Value: conn.Name},
		{Name: "gen", Value: uploaded.Generation},
	}
	insJob, err := qIns.Run(ctx)
	if err != nil {
		t.Fatalf("start insert objref_probe: %v", err)
	}
	insStatus, err := insJob.Wait(ctx)
	if err != nil {
		t.Fatalf("wait insert objref_probe: %v", err)
	}
	if err := insStatus.Err(); err != nil {
		t.Fatalf("insert objref_probe failed: %v", err)
	}

	cases := []string{
		"case_a_make_ref",
		"case_b_empty_details_pinned",
		"case_c_gcs_metadata_null_gen",
		"case_d_gcs_metadata_plus_otel_pinned",
		"case_e_otel_only_pinned",
	}

	// Retry OBJ.FETCH_METADATA briefly in case bucket IAM propagation takes a few seconds.
	var iamPropagated bool
	for attempt := range 6 {
		probeSQL := fmt.Sprintf(
			"SELECT TO_JSON_STRING(OBJ.FETCH_METADATA(ref)) FROM `%s.%s.objref_probe` WHERE row_id = 'case_a_make_ref'",
			project, dataset,
		)
		_, _, perr := runSpikeQuery(ctx, admin, probeSQL)
		if perr == nil {
			iamPropagated = true
			break
		}
		if !strings.Contains(strings.ToLower(perr.Error()), "access denied") &&
			!strings.Contains(strings.ToLower(perr.Error()), "permission") {
			t.Logf("case_a_make_ref OBJ.FETCH_METADATA failed with non-IAM error: %v", perr)
			break
		}
		if attempt < 5 {
			time.Sleep(5 * time.Second)
		}
	}
	if !iamPropagated && !ownedBucket {
		t.Skipf("skipping OBJ.FETCH_METADATA assertions; connection %s lacks read access on caller bucket %s", conn.Name, bucket)
	}

	for _, c := range cases {
		fetchSQL := fmt.Sprintf(`
SELECT
  row_id,
  TO_JSON_STRING(ref) AS raw_ref,
  TO_JSON_STRING(OBJ.FETCH_METADATA(ref)) AS fetched_ref,
  STRING(OBJ.GET_ACCESS_URL(ref, 'r').access_urls.read_url) AS read_url
FROM `+"`%s.%s.objref_probe`"+`
WHERE row_id = @row_id
`, project, dataset)
		q := admin.Query(fetchSQL)
		q.Parameters = []bq.QueryParameter{{Name: "row_id", Value: c}}
		job, err := q.Run(ctx)
		if err != nil {
			t.Fatalf("[%s] query start error: %v", c, err)
		}
		it, err := job.Read(ctx)
		if err != nil {
			t.Fatalf("[%s] OBJ.FETCH_METADATA / OBJ.GET_ACCESS_URL error: %v", c, err)
		}
		var row struct {
			RowID      string        `bigquery:"row_id"`
			RawRef     string        `bigquery:"raw_ref"`
			FetchedRef string        `bigquery:"fetched_ref"`
			ReadURL    bq.NullString `bigquery:"read_url"`
		}
		if err := it.Next(&row); err != nil {
			t.Fatalf("[%s] read row error: %v", c, err)
		}
		t.Logf("[%s] raw_ref=%s", c, row.RawRef)
		t.Logf("[%s] fetched_ref=%s", c, row.FetchedRef)
		t.Logf("[%s] read_url_present=%v", c, row.ReadURL.Valid && row.ReadURL.StringVal != "")

		var fetchedObj struct {
			Version string         `json:"version"`
			Details map[string]any `json:"details"`
		}
		if err := json.Unmarshal([]byte(row.FetchedRef), &fetchedObj); err != nil {
			t.Fatalf("[%s] unmarshal fetched_ref: %v", c, err)
		}
		switch c {
		case "case_d_gcs_metadata_plus_otel_pinned", "case_e_otel_only_pinned":
			_, hasOtel := fetchedObj.Details["otel"]
			_, hasErrs := fetchedObj.Details["errors"]
			t.Logf("[%s] details.otel preserved=%v details.errors_present=%v", c, hasOtel, hasErrs)
			if hasOtel || !hasErrs {
				t.Fatalf("[%s] expected BigQuery OBJ.FETCH_METADATA to reject details.otel with details.errors, got: %s", c, row.FetchedRef)
			}
		default:
			gcsMeta, ok := fetchedObj.Details["gcs_metadata"].(map[string]any)
			if !ok {
				t.Fatalf("[%s] expected gcs_metadata in OBJ.FETCH_METADATA output, got: %s", c, row.FetchedRef)
			}
			wantMD5Bytes, decErr := base64.StdEncoding.DecodeString(uploaded.MD5Hash)
			if decErr != nil {
				t.Fatalf("decode uploaded md5Hash %q: %v", uploaded.MD5Hash, decErr)
			}
			wantMD5Hex := hex.EncodeToString(wantMD5Bytes)
			if gotMD5, _ := gcsMeta["md5_hash"].(string); gotMD5 != wantMD5Hex {
				t.Fatalf("[%s] OBJ.FETCH_METADATA md5_hash = %q, want lowercase hex %q (base64 %q)", c, gotMD5, wantMD5Hex, uploaded.MD5Hash)
			}
			if !row.ReadURL.Valid || row.ReadURL.StringVal == "" {
				t.Fatalf("[%s] expected non-empty OBJ.GET_ACCESS_URL read_url", c)
			}
			uReq, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, row.ReadURL.StringVal, nil)
			if err != nil {
				t.Fatalf("[%s] build read_url GET: %v", c, err)
			}
			tr := &stdhttp.Transport{}
			defer tr.CloseIdleConnections()
			plainClient := &stdhttp.Client{Transport: tr}
			uResp, err := plainClient.Do(uReq)
			if err != nil {
				t.Fatalf("[%s] GET read_url: %v", c, err)
			}
			body, _ := io.ReadAll(uResp.Body)
			_ = uResp.Body.Close()
			t.Logf("[%s] GET read_url HTTP=%d body=%q", c, uResp.StatusCode, string(body))
			if uResp.StatusCode != stdhttp.StatusOK || string(body) != "hello objectref v1 spike\n" {
				t.Fatalf("[%s] unexpected read_url response: HTTP=%d body=%q", c, uResp.StatusCode, string(body))
			}
		}
	}
}

// TestLiveDedupViewPartitionPruningAndSlotCost probes NV-02 against live BigQuery:
// compares dry-run TotalBytesProcessed and executed TotalSlotMs between
// QUALIFY insert_id IS NULL OR ROW_NUMBER() ... = 1 and two-branch UNION ALL.
func TestLiveDedupViewPartitionPruningAndSlotCost(t *testing.T) {
	project, location := requireSpikeLiveBQConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)

	admin, rawSvc, _ := newSpikeClients(ctx, t, project, []string{bigqueryapi.BigqueryScope})
	dataset := uniqueEphemeralDatasetID("otel_v1_spike_dedup")
	if err := createOwnedEphemeralDataset(ctx, admin, dataset, location, t.Cleanup, func(err error) {
		t.Errorf("%v", err)
	}); err != nil {
		t.Fatalf("create dataset %s.%s: %v", project, dataset, err)
	}

	const tableName = "otel_logs_v1_spike"
	md := &bq.TableMetadata{
		TimePartitioning: &bq.TimePartitioning{
			Type:  bq.DayPartitioningType,
			Field: "timestamp",
		},
		RequirePartitionFilter: true,
		Clustering: &bq.Clustering{
			Fields: []string{"service_name", "trace_id", "severity_number"},
		},
		Schema: bq.Schema{
			{Name: "timestamp", Type: bq.TimestampFieldType, Required: true},
			{Name: "time_unix_nano", Type: bq.IntegerFieldType, Required: true},
			{Name: "receive_time", Type: bq.TimestampFieldType, Required: true},
			{Name: "receive_time_unix_nano", Type: bq.IntegerFieldType, Required: true},
			{Name: "service_name", Type: bq.StringFieldType, Required: true},
			{Name: "trace_id", Type: bq.StringFieldType},
			{Name: "span_id", Type: bq.StringFieldType},
			{Name: "severity_number", Type: bq.IntegerFieldType, Required: true},
			{Name: "log_name", Type: bq.StringFieldType, Required: true},
			{Name: "insert_id", Type: bq.StringFieldType}, // NULLABLE per v1 ADR-07
			{Name: "body", Type: bq.JSONFieldType},
		},
	}
	if err := admin.Dataset(dataset).Table(tableName).Create(ctx, md); err != nil {
		t.Fatalf("create %s: %v", tableName, err)
	}

	nowUTC := time.Now().UTC().Truncate(24 * time.Hour)
	day0 := nowUTC.Add(-48 * time.Hour)
	day1 := nowUTC.Add(-24 * time.Hour)
	day2 := nowUTC

	// Populate 3 daily partitions with duplicate non-null insert_id rows and distinct NULL insert_id rows.
	// Use substantial body strings (~10 KB per row via REPEAT) so BigQuery reports distinct partition sizes cleanly.
	insertSQL := fmt.Sprintf(`
INSERT INTO `+"`%s.%s.%s`"+` (
  timestamp, time_unix_nano, receive_time, receive_time_unix_nano,
  service_name, trace_id, span_id, severity_number, log_name, insert_id, body
)
SELECT
  TIMESTAMP_ADD(day_ts, INTERVAL MOD(seq, 10) MINUTE) AS timestamp,
  UNIX_MICROS(TIMESTAMP_ADD(day_ts, INTERVAL MOD(seq, 10) MINUTE)) * 1000 AS time_unix_nano,
  TIMESTAMP_ADD(day_ts, INTERVAL copy_num SECOND) AS receive_time,
  UNIX_MICROS(TIMESTAMP_ADD(day_ts, INTERVAL copy_num SECOND)) * 1000 AS receive_time_unix_nano,
  'edge-proxy' AS service_name,
  CAST(NULL AS STRING) AS trace_id,
  CAST(NULL AS STRING) AS span_id,
  9 AS severity_number,
  'access' AS log_name,
  IF(MOD(seq, 2) = 0, CONCAT('id1:', CAST(day_idx AS STRING), '-', CAST(seq AS STRING)), CAST(NULL AS STRING)) AS insert_id,
  PARSE_JSON(CONCAT('{"msg":"', REPEAT('x', 2048), '","seq":', CAST(seq AS STRING), ',"copy":', CAST(copy_num AS STRING), '}')) AS body
FROM UNNEST([
  STRUCT(0 AS day_idx, @day0 AS day_ts),
  STRUCT(1 AS day_idx, @day1 AS day_ts),
  STRUCT(2 AS day_idx, @day2 AS day_ts)
]),
UNNEST(GENERATE_ARRAY(1, 20)) AS seq,
UNNEST([1, 2]) AS copy_num
`, project, dataset, tableName)
	qIns := admin.Query(insertSQL)
	qIns.Parameters = []bq.QueryParameter{
		{Name: "day0", Value: day0},
		{Name: "day1", Value: day1},
		{Name: "day2", Value: day2},
	}
	job, err := qIns.Run(ctx)
	if err != nil {
		t.Fatalf("run insert across 3 partitions: %v", err)
	}
	st, err := job.Wait(ctx)
	if err != nil {
		t.Fatalf("wait insert: %v", err)
	}
	if err := st.Err(); err != nil {
		t.Fatalf("insert failed: %v", err)
	}

	qualifyOrView := fmt.Sprintf("`%s.%s.v_dedup_qualify_or`", project, dataset)
	unionAllView := fmt.Sprintf("`%s.%s.v_dedup_union_all`", project, dataset)
	baseTable := fmt.Sprintf("`%s.%s.%s`", project, dataset, tableName)

	qualifyOrDDL := fmt.Sprintf(`
CREATE OR REPLACE VIEW %s AS
SELECT *
FROM %s
QUALIFY insert_id IS NULL OR ROW_NUMBER() OVER (
  PARTITION BY
    timestamp,
    time_unix_nano,
    service_name,
    trace_id,
    span_id,
    severity_number,
    log_name,
    insert_id
  ORDER BY
    receive_time_unix_nano DESC
) = 1
`, qualifyOrView, baseTable)
	if _, _, err := runSpikeQuery(ctx, admin, qualifyOrDDL); err != nil {
		t.Fatalf("create %s: %v", qualifyOrView, err)
	}

	unionAllDDL := fmt.Sprintf(`
CREATE OR REPLACE VIEW %s AS
SELECT *
FROM %s
WHERE insert_id IS NULL
UNION ALL
SELECT *
FROM %s
WHERE insert_id IS NOT NULL
QUALIFY ROW_NUMBER() OVER (
  PARTITION BY
    timestamp,
    time_unix_nano,
    service_name,
    trace_id,
    span_id,
    severity_number,
    log_name,
    insert_id
  ORDER BY
    receive_time_unix_nano DESC
) = 1
`, unionAllView, baseTable, baseTable)
	if _, _, err := runSpikeQuery(ctx, admin, unionAllDDL); err != nil {
		t.Fatalf("create %s: %v", unionAllView, err)
	}

	type queryStats struct {
		dryRunBytes int64
		execBytes   int64
		slotMs      int64
		partitions  int64
		rowCount    int64
	}
	measure := func(label, target string, startTS, endTS time.Time) queryStats {
		sql := fmt.Sprintf(`
SELECT
  COUNT(*) AS cnt,
  COUNTIF(insert_id IS NULL) AS null_cnt,
  COUNTIF(insert_id IS NOT NULL) AS non_null_cnt
FROM %s
WHERE timestamp >= @start_ts AND timestamp < @end_ts
`, target)
		params := []bq.QueryParameter{
			{Name: "start_ts", Value: startTS},
			{Name: "end_ts", Value: endTS},
		}
		qd := admin.Query(sql)
		qd.DryRun = true
		qd.Parameters = params
		dJob, err := qd.Run(ctx)
		if err != nil {
			t.Fatalf("%s dry-run: %v", label, err)
		}
		dStats := dJob.LastStatus().Statistics

		qe := admin.Query(sql)
		qe.DisableQueryCache = true
		qe.Parameters = params
		eJob, err := qe.Run(ctx)
		if err != nil {
			t.Fatalf("%s exec: %v", label, err)
		}
		it, err := eJob.Read(ctx)
		if err != nil {
			t.Fatalf("%s read: %v", label, err)
		}
		var res struct {
			Cnt        int64 `bigquery:"cnt"`
			NullCnt    int64 `bigquery:"null_cnt"`
			NonNullCnt int64 `bigquery:"non_null_cnt"`
		}
		if err := it.Next(&res); err != nil {
			t.Fatalf("%s next: %v", label, err)
		}
		eStats := eJob.LastStatus().Statistics
		var slotMs, parts int64
		if qDetails, ok := eStats.Details.(*bq.QueryStatistics); ok {
			slotMs = qDetails.SlotMillis
		}
		if rawJob, gerr := rawSvc.Jobs.Get(project, eJob.ID()).Location(eJob.Location()).Context(ctx).Do(); gerr == nil && rawJob.Statistics != nil && rawJob.Statistics.Query != nil {
			parts = rawJob.Statistics.Query.TotalPartitionsProcessed
			if slotMs == 0 {
				slotMs = rawJob.Statistics.Query.TotalSlotMs
			}
		}
		t.Logf("[%s] dryRunBytes=%d execBytes=%d slotMs=%d partitionsProcessed=%d totalRows=%d (null=%d nonNull=%d)",
			label, dStats.TotalBytesProcessed, eStats.TotalBytesProcessed, slotMs, parts, res.Cnt, res.NullCnt, res.NonNullCnt)
		return queryStats{
			dryRunBytes: dStats.TotalBytesProcessed,
			execBytes:   eStats.TotalBytesProcessed,
			slotMs:      slotMs,
			partitions:  parts,
			rowCount:    res.Cnt,
		}
	}

	raw1d := measure("raw_1day", baseTable, day1, day2)
	raw3d := measure("raw_3day", baseTable, day0, day2.Add(24*time.Hour))
	q1d := measure("qualify_or_1day", qualifyOrView, day1, day2)
	q3d := measure("qualify_or_3day", qualifyOrView, day0, day2.Add(24*time.Hour))
	u1d := measure("union_all_1day", unionAllView, day1, day2)
	u3d := measure("union_all_3day", unionAllView, day0, day2.Add(24*time.Hour))

	if raw1d.dryRunBytes >= raw3d.dryRunBytes {
		t.Fatalf("expected raw 1-day bytes (%d) < 3-day bytes (%d)", raw1d.dryRunBytes, raw3d.dryRunBytes)
	}
	if q1d.dryRunBytes >= q3d.dryRunBytes {
		t.Fatalf("QUALIFY OR lost partition pruning: 1-day dryRunBytes=%d >= 3-day dryRunBytes=%d", q1d.dryRunBytes, q3d.dryRunBytes)
	}
	if u1d.dryRunBytes >= u3d.dryRunBytes {
		t.Fatalf("UNION ALL lost partition pruning: 1-day dryRunBytes=%d >= 3-day dryRunBytes=%d", u1d.dryRunBytes, u3d.dryRunBytes)
	}
	// Each day has 10 odd seq * 2 copies = 20 NULL insert_id rows + 10 even seq * 1 deduped copy = 10 non-null rows = 30 rows.
	if q1d.rowCount != 30 || u1d.rowCount != 30 {
		t.Fatalf("unexpected 1-day deduped row counts: qualify_or=%d union_all=%d (want 30)", q1d.rowCount, u1d.rowCount)
	}
}

// TestLiveJSONInt64AndToJSONString probes NV-04 and NV-05 against live BigQuery:
// Storage Write API ingestion of +-9223372036854775807 (string and JSON number),
// LAX_INT64 round-trip precision, and TO_JSON_STRING normalization behavior.
func TestLiveJSONInt64AndToJSONString(t *testing.T) {
	project, location := requireSpikeLiveBQConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	admin, _, _ := newSpikeClients(ctx, t, project, []string{bigqueryapi.BigqueryScope})
	dataset := uniqueEphemeralDatasetID("otel_v1_spike_json")
	if err := createOwnedEphemeralDataset(ctx, admin, dataset, location, t.Cleanup, func(err error) {
		t.Errorf("%v", err)
	}); err != nil {
		t.Fatalf("create dataset %s.%s: %v", project, dataset, err)
	}

	const tableName = "json_probe"
	if err := admin.Dataset(dataset).Table(tableName).Create(ctx, &bq.TableMetadata{
		Schema: bq.Schema{
			{Name: "row_id", Type: bq.StringFieldType, Required: true},
			{Name: "attrs", Type: bq.JSONFieldType},
		},
	}); err != nil {
		t.Fatalf("create %s: %v", tableName, err)
	}

	ts := &storagepb.TableSchema{
		Fields: []*storagepb.TableFieldSchema{
			{Name: "row_id", Type: storagepb.TableFieldSchema_STRING, Mode: storagepb.TableFieldSchema_REQUIRED},
			{Name: "attrs", Type: storagepb.TableFieldSchema_JSON, Mode: storagepb.TableFieldSchema_NULLABLE},
		},
	}
	md, err := adapt.StorageSchemaToProto2Descriptor(ts, "root")
	if err != nil {
		t.Fatalf("StorageSchemaToProto2Descriptor: %v", err)
	}
	msgDesc := md.(protoreflect.MessageDescriptor)
	normDesc, err := adapt.NormalizeDescriptor(msgDesc)
	if err != nil {
		t.Fatalf("NormalizeDescriptor: %v", err)
	}

	mwClient := newSpikeManagedWriterClient(ctx, t, project)

	ms, err := mwClient.NewManagedStream(
		ctx,
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithDestinationTable(managedwriter.TableParentFromParts(project, dataset, tableName)),
		managedwriter.WithSchemaDescriptor(normDesc),
	)
	if err != nil {
		t.Fatalf("NewManagedStream: %v", err)
	}
	t.Cleanup(func() { _ = ms.Close() })

	marshalRow := func(rowID, attrsJSON string) []byte {
		msg := dynamicpb.NewMessage(msgDesc)
		msg.Set(msgDesc.Fields().ByName("row_id"), protoreflect.ValueOfString(rowID))
		msg.Set(msgDesc.Fields().ByName("attrs"), protoreflect.ValueOfString(attrsJSON))
		b, merr := proto.Marshal(msg)
		if merr != nil {
			t.Fatalf("marshal row %s: %v", rowID, merr)
		}
		return b
	}

	rows := [][]byte{
		marshalRow("write_api_strings", `{"z":1,"a":"<tag>&val","i64_max":"9223372036854775807","i64_min":"-9223372036854775808","p53":"9007199254740993"}`),
		marshalRow("write_api_numbers", `{"i64_max":9223372036854775807,"i64_min":-9223372036854775808,"p53":9007199254740993,"u64_max":18446744073709551615}`),
	}
	res, err := ms.AppendRows(ctx, rows)
	if err != nil {
		t.Fatalf("AppendRows: %v", err)
	}
	if _, err := res.GetResult(ctx); err != nil {
		t.Fatalf("AppendRows GetResult: %v", err)
	}

	sql := fmt.Sprintf(`
SELECT
  row_id,
  LAX_INT64(attrs.i64_max) AS lax_max,
  LAX_INT64(attrs.i64_min) AS lax_min,
  LAX_INT64(attrs.p53) AS lax_p53,
  JSON_TYPE(attrs.i64_max) AS type_max,
  JSON_TYPE(attrs.u64_max) AS type_u64,
  TO_JSON_STRING(attrs) AS to_json_str
FROM `+"`%s.%s.%s`"+`
ORDER BY row_id
`, project, dataset, tableName)
	q := admin.Query(sql)
	it, err := q.Read(ctx)
	if err != nil {
		t.Fatalf("read json_probe: %v", err)
	}
	for {
		var r struct {
			RowID     string        `bigquery:"row_id"`
			LaxMax    bq.NullInt64  `bigquery:"lax_max"`
			LaxMin    bq.NullInt64  `bigquery:"lax_min"`
			LaxP53    bq.NullInt64  `bigquery:"lax_p53"`
			TypeMax   bq.NullString `bigquery:"type_max"`
			TypeU64   bq.NullString `bigquery:"type_u64"`
			ToJSONStr string        `bigquery:"to_json_str"`
		}
		err := it.Next(&r)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			t.Fatalf("iterate json_probe: %v", err)
		}
		t.Logf("[%s] lax_max=%v(%d) lax_min=%v(%d) lax_p53=%v(%d) type_max=%s type_u64=%v to_json_str=%s",
			r.RowID, r.LaxMax.Valid, r.LaxMax.Int64, r.LaxMin.Valid, r.LaxMin.Int64,
			r.LaxP53.Valid, r.LaxP53.Int64, r.TypeMax.StringVal, r.TypeU64.StringVal, r.ToJSONStr)
		if !r.LaxMax.Valid || r.LaxMax.Int64 != 9223372036854775807 {
			t.Fatalf("[%s] LAX_INT64(i64_max) = %v (%d), want 9223372036854775807", r.RowID, r.LaxMax.Valid, r.LaxMax.Int64)
		}
		if !r.LaxMin.Valid || r.LaxMin.Int64 != -9223372036854775808 {
			t.Fatalf("[%s] LAX_INT64(i64_min) = %v (%d), want -9223372036854775808", r.RowID, r.LaxMin.Valid, r.LaxMin.Int64)
		}
		if !r.LaxP53.Valid || r.LaxP53.Int64 != 9007199254740993 {
			t.Fatalf("[%s] LAX_INT64(p53) = %v (%d), want 9007199254740993", r.RowID, r.LaxP53.Valid, r.LaxP53.Int64)
		}
	}
}

// TestLiveWriteAPIBillingBasisAndRequestLimit probes NV-12 and NV-20 against live BigQuery:
// tests an AppendRows request > 10 MB (~11.5 MiB) vs < 10 MB (~4 MiB) on the _default stream,
// and compares encoded ProtoRows bytes against reported table storage / streaming buffer bytes.
func TestLiveWriteAPIBillingBasisAndRequestLimit(t *testing.T) {
	project, location := requireSpikeLiveBQConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	admin, _, _ := newSpikeClients(ctx, t, project, []string{bigqueryapi.BigqueryScope})
	dataset := uniqueEphemeralDatasetID("otel_v1_spike_writeapi")
	if err := createOwnedEphemeralDataset(ctx, admin, dataset, location, t.Cleanup, func(err error) {
		t.Errorf("%v", err)
	}); err != nil {
		t.Fatalf("create dataset %s.%s: %v", project, dataset, err)
	}

	const tableName = "otel_logs"
	md, _, err := schema.DestinationMetadata(schema.LogsTableSchema(), project, dataset, tableName)
	if err != nil {
		t.Fatalf("DestinationMetadata: %v", err)
	}
	if err := admin.Dataset(dataset).Table(tableName).Create(ctx, md); err != nil {
		t.Fatalf("create %s: %v", tableName, err)
	}

	enc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New: %v", err)
	}

	mwClient := newSpikeManagedWriterClient(ctx, t, project)

	ms, err := mwClient.NewManagedStream(
		ctx,
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithDestinationTable(managedwriter.TableParentFromParts(project, dataset, tableName)),
		managedwriter.WithSchemaDescriptor(enc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream: %v", err)
	}
	t.Cleanup(func() { _ = ms.Close() })

	now := time.Now().UTC()
	nowNano := now.UnixNano()
	payloadStr := strings.Repeat("a", 64*1024)
	buildBatch := func(nRows int, tag string) ([][]byte, int64) {
		rows := make([][]byte, 0, nRows)
		var totalBytes int64
		for i := range nRows {
			row := transform.Row{
				"timestamp":                now.UnixMicro(),
				"observed_timestamp":       now.UnixMicro(),
				"receive_time":             now.UnixMicro(),
				"time_unix_nano":           nowNano,
				"observed_time_unix_nano":  nowNano,
				"receive_time_unix_nano":   nowNano,
				"timestamp_source":         "event",
				"service_name":             "v1-spike",
				"trace_id":                 "",
				"span_id":                  "",
				"flags":                    int64(0),
				"severity_number":          int64(9),
				"severity_text":            "INFO",
				"log_name":                 "access",
				"insert_id":                fmt.Sprintf("%s-%d", tag, i),
				"record_fingerprint":       fmt.Sprintf("fp1:%s-%d", tag, i),
				"body":                     fmt.Sprintf(`{"msg":%q}`, payloadStr),
				"attributes":               `{"http.request.method":"GET"}`,
				"attributes_schema":        `{"http.request.method":"string"}`,
				"dropped_attributes_count": int64(0),
				"resource": map[string]any{
					"attributes":               `{"service.name":"v1-spike"}`,
					"attributes_schema":        `{"service.name":"string"}`,
					"dropped_attributes_count": int64(0),
				},
				"instrumentation_scope": map[string]any{
					"name":                     "spike",
					"version":                  "0.1.0",
					"attributes":               `{}`,
					"attributes_schema":        `{}`,
					"dropped_attributes_count": int64(0),
				},
				"scope_schema_url": "",
				"schema_version":   schema.Version,
			}
			b, eerr := enc.Encode(row)
			if eerr != nil {
				t.Fatalf("enc.Encode: %v", eerr)
			}
			rows = append(rows, b)
			totalBytes += int64(len(b))
		}
		return rows, totalBytes
	}

	// 1. Sub-10 MB request (~2 MiB) must succeed.
	smallRows, smallBytes := buildBatch(32, "small")
	resSmall, err := ms.AppendRows(ctx, smallRows)
	if err != nil {
		t.Fatalf("small AppendRows (%d bytes): %v", smallBytes, err)
	}
	if _, err := resSmall.GetResult(ctx); err != nil {
		t.Fatalf("small AppendRows GetResult (%d bytes): %v", smallBytes, err)
	}
	t.Logf("small AppendRows succeeded: rows=%d encodedProtoRowsBytes=%d", len(smallRows), smallBytes)

	// 2. >10 MB request (~11.3 MiB) and >20 MB request (~20.1 MiB) probe the per-request ceiling.
	largeRows, largeBytes := buildBatch(180, "large11")
	t.Logf("probing 11.3 MiB AppendRows: rows=%d encodedProtoRowsBytes=%d (%.2f MiB)",
		len(largeRows), largeBytes, float64(largeBytes)/(1024*1024))
	resLarge, err := ms.AppendRows(ctx, largeRows)
	if err != nil {
		t.Fatalf("11.3 MiB AppendRows immediate error: %v", err)
	}
	if _, rerr := resLarge.GetResult(ctx); rerr != nil {
		t.Logf("11.3 MiB AppendRows GetResult error (rejected): %v", rerr)
	} else {
		t.Logf("11.3 MiB AppendRows SUCCEEDED at %d bytes (%.2f MiB)", largeBytes, float64(largeBytes)/(1024*1024))
	}

	over20Rows, over20Bytes := buildBatch(320, "over20")
	t.Logf("probing >20 MB AppendRows: rows=%d encodedProtoRowsBytes=%d (%.2f MiB)",
		len(over20Rows), over20Bytes, float64(over20Bytes)/(1024*1024))
	resOver20, err := ms.AppendRows(ctx, over20Rows)
	if err != nil {
		t.Logf(">20 MB AppendRows immediate error (expected rejection): %v", err)
	} else if _, rerr := resOver20.GetResult(ctx); rerr != nil {
		t.Logf(">20 MB AppendRows GetResult error (expected rejection): %v", rerr)
	} else {
		t.Logf(">20 MB AppendRows unexpectedly SUCCEEDED at %d bytes", over20Bytes)
	}

	cntSQL := fmt.Sprintf("SELECT COUNT(*) AS cnt FROM `%s.%s.%s`", project, dataset, tableName)
	cntIt, err := admin.Query(cntSQL).Read(ctx)
	if err != nil {
		t.Fatalf("count appended rows: %v", err)
	}
	var cntRow struct {
		Cnt int64 `bigquery:"cnt"`
	}
	if err := cntIt.Next(&cntRow); err != nil {
		t.Fatalf("read count row: %v", err)
	}
	t.Logf("live SELECT COUNT(*) after AppendRows = %d", cntRow.Cnt)
	if cntRow.Cnt < int64(len(smallRows)) {
		t.Fatalf("unexpected row count %d < %d", cntRow.Cnt, len(smallRows))
	}

	// 3. Record table metadata and INFORMATION_SCHEMA.TABLE_STORAGE snapshot.
	tmd, err := admin.Dataset(dataset).Table(tableName).Metadata(ctx)
	if err != nil {
		t.Fatalf("get table metadata: %v", err)
	}
	var sbBytes, sbRows uint64
	if tmd.StreamingBuffer != nil {
		sbBytes = tmd.StreamingBuffer.EstimatedBytes
		sbRows = tmd.StreamingBuffer.EstimatedRows
	}
	t.Logf("table.Metadata: numBytes=%d numRows=%d streamingBufferBytes=%d streamingBufferRows=%d",
		tmd.NumBytes, tmd.NumRows, sbBytes, sbRows)

	storageSQL := fmt.Sprintf(`
SELECT
  total_rows,
  total_logical_bytes,
  active_logical_bytes,
  total_physical_bytes,
  active_physical_bytes
FROM `+"`%s.region-%s.INFORMATION_SCHEMA.TABLE_STORAGE`"+`
WHERE table_schema = @dataset AND table_name = @table
`, project, strings.ToLower(location))
	qs := admin.Query(storageSQL)
	qs.Parameters = []bq.QueryParameter{
		{Name: "dataset", Value: dataset},
		{Name: "table", Value: tableName},
	}
	it, err := qs.Read(ctx)
	if err != nil {
		t.Logf("INFORMATION_SCHEMA.TABLE_STORAGE query error: %v", err)
		return
	}
	var tsRow struct {
		TotalRows           int64 `bigquery:"total_rows"`
		TotalLogicalBytes   int64 `bigquery:"total_logical_bytes"`
		ActiveLogicalBytes  int64 `bigquery:"active_logical_bytes"`
		TotalPhysicalBytes  int64 `bigquery:"total_physical_bytes"`
		ActivePhysicalBytes int64 `bigquery:"active_physical_bytes"`
	}
	if err := it.Next(&tsRow); err == nil {
		t.Logf("INFORMATION_SCHEMA.TABLE_STORAGE: total_rows=%d total_logical=%d active_logical=%d total_physical=%d active_physical=%d",
			tsRow.TotalRows, tsRow.TotalLogicalBytes, tsRow.ActiveLogicalBytes, tsRow.TotalPhysicalBytes, tsRow.ActivePhysicalBytes)
	} else {
		t.Logf("INFORMATION_SCHEMA.TABLE_STORAGE row read: %v", err)
	}
}

// TestLiveSearchIndexPredicatesAndDuplicateError probes NV-14 and NV-19 against live BigQuery:
// captures the exact BigQuery error when creating a second differently-named search index,
// queries INFORMATION_SCHEMA.SEARCH_INDEXES, and checks SearchStatistics for SEARCH vs JSON_VALUE.
func TestLiveSearchIndexPredicatesAndDuplicateError(t *testing.T) {
	project, location := requireSpikeLiveBQConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)

	admin, rawSvc, _ := newSpikeClients(ctx, t, project, []string{bigqueryapi.BigqueryScope})
	dataset := uniqueEphemeralDatasetID("otel_v1_spike_idx")
	if err := createOwnedEphemeralDataset(ctx, admin, dataset, location, t.Cleanup, func(err error) {
		t.Errorf("%v", err)
	}); err != nil {
		t.Fatalf("create dataset %s.%s: %v", project, dataset, err)
	}

	const tableName = "otel_logs_idx_probe"
	md, _, err := schema.DestinationMetadata(schema.LogsTableSchema(), project, dataset, tableName)
	if err != nil {
		t.Fatalf("DestinationMetadata: %v", err)
	}
	if err := admin.Dataset(dataset).Table(tableName).Create(ctx, md); err != nil {
		t.Fatalf("create %s: %v", tableName, err)
	}

	// 1. Create custom index first, then attempt creating otel_logs_search_idx (NV-19).
	ddl1 := fmt.Sprintf(
		"CREATE SEARCH INDEX IF NOT EXISTS idx_custom_a ON `%s.%s.%s`(body) OPTIONS (analyzer = 'LOG_ANALYZER')",
		project, dataset, tableName,
	)
	if _, _, err := runSpikeQuery(ctx, admin, ddl1); err != nil {
		t.Fatalf("create idx_custom_a: %v", err)
	}

	ddl2 := fmt.Sprintf(
		"CREATE SEARCH INDEX IF NOT EXISTS otel_logs_search_idx ON `%s.%s.%s`(trace_id, span_id) OPTIONS (analyzer = 'NO_OP_ANALYZER')",
		project, dataset, tableName,
	)
	_, _, dupErr := runSpikeQuery(ctx, admin, ddl2)
	if dupErr == nil {
		t.Fatal("expected error creating second search index on same table, got nil")
	}
	var gErr *googleapi.Error
	if errors.As(dupErr, &gErr) {
		t.Logf("NV-19 exact duplicate search index error: httpCode=%d message=%q full=%v", gErr.Code, gErr.Message, dupErr)
	} else {
		t.Logf("NV-19 exact duplicate search index error: %T: %q", dupErr, dupErr.Error())
	}
	t.Logf("NV-19 destination.go isSearchIndexAlreadyExists(dupErr) = %v", isSearchIndexAlreadyExists(dupErr))

	// 2. Query INFORMATION_SCHEMA.SEARCH_INDEXES.
	idxMetaSQL := fmt.Sprintf(`
SELECT
  index_name,
  index_status,
  coverage_percentage,
  total_logical_bytes,
  total_storage_bytes,
  ddl
FROM `+"`%s.%s.INFORMATION_SCHEMA.SEARCH_INDEXES`"+`
WHERE table_name = @table
`, project, dataset)
	qi := admin.Query(idxMetaSQL)
	qi.Parameters = []bq.QueryParameter{
		{Name: "table", Value: tableName},
	}
	it, err := qi.Read(ctx)
	if err != nil {
		t.Fatalf("query INFORMATION_SCHEMA.SEARCH_INDEXES: %v", err)
	}
	for {
		var r struct {
			IndexName          string       `bigquery:"index_name"`
			IndexStatus        string       `bigquery:"index_status"`
			CoveragePercentage bq.NullInt64 `bigquery:"coverage_percentage"`
			TotalLogicalBytes  bq.NullInt64 `bigquery:"total_logical_bytes"`
			TotalStorageBytes  bq.NullInt64 `bigquery:"total_storage_bytes"`
			DDL                string       `bigquery:"ddl"`
		}
		err := it.Next(&r)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			t.Fatalf("read SEARCH_INDEXES: %v", err)
		}
		t.Logf("SEARCH_INDEXES: name=%s status=%s coverage=%v(%d%%) logicalBytes=%v(%d) storageBytes=%v(%d) ddl=%s",
			r.IndexName, r.IndexStatus, r.CoveragePercentage.Valid, r.CoveragePercentage.Int64,
			r.TotalLogicalBytes.Valid, r.TotalLogicalBytes.Int64, r.TotalStorageBytes.Valid, r.TotalStorageBytes.Int64, r.DDL)
	}

	// 3. NV-14: Probe SearchStatistics for SEARCH vs JSON_VALUE vs STRING() on an indexed JSON column.
	const jsonIdxTable = "otel_logs_json_idx_probe"
	if err := admin.Dataset(dataset).Table(jsonIdxTable).Create(ctx, &bq.TableMetadata{
		TimePartitioning: &bq.TimePartitioning{Type: bq.DayPartitioningType, Field: "timestamp"},
		Schema: bq.Schema{
			{Name: "timestamp", Type: bq.TimestampFieldType, Required: true},
			{Name: "body", Type: bq.JSONFieldType},
			{Name: "attributes", Type: bq.JSONFieldType},
		},
	}); err != nil {
		t.Fatalf("create %s: %v", jsonIdxTable, err)
	}
	if _, _, err := runSpikeQuery(ctx, admin, fmt.Sprintf(
		"CREATE SEARCH INDEX IF NOT EXISTS idx_attrs ON `%s.%s.%s`(body, attributes) OPTIONS (analyzer = 'LOG_ANALYZER')",
		project, dataset, jsonIdxTable,
	)); err != nil {
		t.Fatalf("create idx_attrs: %v", err)
	}
	if _, _, err := runSpikeQuery(ctx, admin, fmt.Sprintf(
		`INSERT INTO `+"`%s.%s.%s`"+` (timestamp, body, attributes) VALUES (CURRENT_TIMESTAMP(), JSON '{"msg":"ok"}', JSON '{"http.request.method":"GET","http.response.status_code":"200"}')`,
		project, dataset, jsonIdxTable,
	)); err != nil {
		t.Fatalf("insert sample json idx row: %v", err)
	}

	predicates := []struct {
		name string
		sql  string
	}{
		{"SEARCH_attributes", fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.%s` WHERE SEARCH(attributes, 'GET')", project, dataset, jsonIdxTable)},
		{"JSON_VALUE_attributes", fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.%s` WHERE JSON_VALUE(attributes, '$.\"http.request.method\"') = 'GET'", project, dataset, jsonIdxTable)},
		{"STRING_subscript_attributes", fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.%s` WHERE STRING(attributes['http.request.method']) = 'GET'", project, dataset, jsonIdxTable)},
	}
	for _, p := range predicates {
		q := admin.Query(p.sql)
		q.DisableQueryCache = true
		job, err := q.Run(ctx)
		if err != nil {
			t.Fatalf("%s run: %v", p.name, err)
		}
		st, err := job.Wait(ctx)
		if err != nil {
			t.Fatalf("%s wait: %v", p.name, err)
		}
		if err := st.Err(); err != nil {
			t.Fatalf("%s failed: %v", p.name, err)
		}
		var mode string
		var reasons []string
		rawJob, gerr := rawSvc.Jobs.Get(project, job.ID()).Location(job.Location()).Context(ctx).Do()
		if gerr != nil {
			t.Fatalf("%s Jobs.Get: %v", p.name, gerr)
		}
		if rawJob.Statistics != nil && rawJob.Statistics.Query != nil && rawJob.Statistics.Query.SearchStatistics != nil {
			ss := rawJob.Statistics.Query.SearchStatistics
			mode = ss.IndexUsageMode
			for _, ur := range ss.IndexUnusedReasons {
				baseTbl := ""
				if ur.BaseTable != nil {
					baseTbl = ur.BaseTable.TableId
				}
				reasons = append(reasons, fmt.Sprintf("%s(%s): %s", ur.Code, baseTbl, ur.Message))
			}
		}
		t.Logf("[%s] IndexUsageMode=%q IndexUnusedReasons=%v", p.name, mode, reasons)
	}
}

// TestLivePartitionAndClusterConstraints probes NV-18 against live BigQuery:
// captures exact errors for in-place partition granularity change (DAY -> HOUR)
// and creating a table with CLUSTER BY on a JSON column.
func TestLivePartitionAndClusterConstraints(t *testing.T) {
	project, location := requireSpikeLiveBQConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	admin, _, _ := newSpikeClients(ctx, t, project, []string{bigqueryapi.BigqueryScope})
	dataset := uniqueEphemeralDatasetID("otel_v1_spike_ddl")
	if err := createOwnedEphemeralDataset(ctx, admin, dataset, location, t.Cleanup, func(err error) {
		t.Errorf("%v", err)
	}); err != nil {
		t.Fatalf("create dataset %s.%s: %v", project, dataset, err)
	}

	const dayTable = "day_partitioned_tbl"
	if err := admin.Dataset(dataset).Table(dayTable).Create(ctx, &bq.TableMetadata{
		TimePartitioning: &bq.TimePartitioning{
			Type:  bq.DayPartitioningType,
			Field: "timestamp",
		},
		Clustering: &bq.Clustering{
			Fields: []string{"service_name"},
		},
		Schema: bq.Schema{
			{Name: "timestamp", Type: bq.TimestampFieldType, Required: true},
			{Name: "service_name", Type: bq.StringFieldType, Required: true},
			{Name: "attributes", Type: bq.JSONFieldType},
		},
	}); err != nil {
		t.Fatalf("create %s: %v", dayTable, err)
	}

	// 1. Attempt in-place DAY -> HOUR partition granularity change via Tables.Patch/Update.
	md, err := admin.Dataset(dataset).Table(dayTable).Metadata(ctx)
	if err != nil {
		t.Fatalf("get metadata: %v", err)
	}
	_, updateErr := admin.Dataset(dataset).Table(dayTable).Update(ctx, bq.TableMetadataToUpdate{
		TimePartitioning: &bq.TimePartitioning{
			Type:  bq.HourPartitioningType,
			Field: "timestamp",
		},
	}, md.ETag)
	if updateErr == nil {
		t.Fatal("expected error altering partition granularity DAY -> HOUR in place, got nil")
	}
	t.Logf("NV-18a in-place DAY->HOUR Update error: %v", updateErr)

	// 2. Attempt CREATE TABLE ... CLUSTER BY attributes (JSON column).
	clusterJSONSQL := fmt.Sprintf(`
CREATE TABLE `+"`%s.%s.json_cluster_tbl`"+` (
  timestamp TIMESTAMP NOT NULL,
  attributes JSON
)
PARTITION BY DATE(timestamp)
CLUSTER BY attributes
`, project, dataset)
	_, _, clusterErr := runSpikeQuery(ctx, admin, clusterJSONSQL)
	if clusterErr == nil {
		t.Fatal("expected error clustering on JSON column, got nil")
	}
	t.Logf("NV-18b CLUSTER BY JSON column error: %v", clusterErr)
}

func runSpikeQuery(ctx context.Context, admin *bq.Client, sql string) (*bq.Job, *bq.JobStatus, error) {
	q := admin.Query(sql)
	job, err := q.Run(ctx)
	if err != nil {
		return nil, nil, err
	}
	st, err := job.Wait(ctx)
	if err != nil {
		return job, st, err
	}
	if err := st.Err(); err != nil {
		return job, st, err
	}
	return job, st, nil
}
