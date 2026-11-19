// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bqfake

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"cloud.google.com/go/bigquery/storage/managedwriter"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/protoenc"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
)

func TestServerDecodeSpanLogAndQuarantineRows(t *testing.T) {
	srv := NewServer(t)
	ctx := context.Background()

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	spanEnc, err := protoenc.New(schema.SpansTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(SpansTableSchema): %v", err)
	}
	stream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_spans"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(spanEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	start := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	end := start.Add(25 * time.Millisecond)
	row := transform.Row{
		"start_time":             start.UnixMicro(),
		"start_time_unix_nano":   start.UnixNano(),
		"end_time":               end.UnixMicro(),
		"end_time_unix_nano":     end.UnixNano(),
		"receive_time":           end.UnixMicro(),
		"receive_time_unix_nano": end.UnixNano(),
		"duration_nano":          int64(25 * time.Millisecond),
		"trace_id":               "0102030405060708090a0b0c0d0e0f10",
		"span_id":                "0102030405060708",
		"name":                   "invoke_agent",
		"kind":                   int64(2),
		"kind_name":              "SPAN_KIND_SERVER",
		"service_name":           "adk-service",
		"attributes":             `{"gen_ai.system":"gcp.vertex.agent"}`,
	}
	encoded, err := spanEnc.Encode(row)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	res, err := stream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows: %v", err)
	}
	if _, err := res.GetResult(ctx); err != nil {
		t.Fatalf("GetResult: %v", err)
	}

	gotRows := srv.Rows("otel_spans")
	if len(gotRows) != 1 {
		t.Fatalf("got %d rows, want 1", len(gotRows))
	}
	got := gotRows[0]
	if got["trace_id"] != "0102030405060708090a0b0c0d0e0f10" {
		t.Errorf("trace_id = %v, want 0102030405060708090a0b0c0d0e0f10", got["trace_id"])
	}
	if got["name"] != "invoke_agent" {
		t.Errorf("name = %v, want invoke_agent", got["name"])
	}
	hour, ok := StartTimeHour(got)
	if !ok || !hour.Equal(time.Date(2026, 8, 12, 14, 0, 0, 0, time.UTC)) {
		t.Errorf("StartTimeHour = (%v, %v), want 2026-08-12T14:00:00Z", hour, ok)
	}
}

func TestServerFaultInjectionModes(t *testing.T) {
	srv := NewServer(t)
	ctx := context.Background()

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	qEnc, err := protoenc.New(schema.QuarantineTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New: %v", err)
	}
	stream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_quarantine"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(qEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	encoded, err := qEnc.Encode(transform.Row{
		"ingest_time":   time.Now().UnixMicro(),
		"signal":        schema.SignalSpans,
		"error_code":    "INVALID_SPAN_ID",
		"error_message": "invalid_id: span_id",
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	srv.EnqueueFault(
		Fault{
			Mode:  FaultRowErrors,
			Table: "otel_quarantine",
			RowErrors: []*storagepb.RowError{
				{Index: 0, Code: storagepb.RowError_FIELDS_ERROR, Message: "bad field"},
			},
		},
		Fault{Mode: FaultUnavailable, Table: "otel_quarantine"},
		Fault{Mode: FaultResourceExhausted, Table: "otel_quarantine"},
		Fault{Mode: FaultDelayedAck, Table: "otel_quarantine", Delay: 10 * time.Millisecond},
	)

	// 1. RowErrors fault: GetResult returns error, FullResponse carries RowErrors, 0 rows stored.
	res1, err := stream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows #1: %v", err)
	}
	if _, err := res1.GetResult(ctx); err == nil {
		t.Fatal("expected RowErrors fault to return an error")
	}
	full1, err := res1.FullResponse(ctx)
	if status.Code(err) != codes.InvalidArgument || len(full1.GetRowErrors()) != 1 {
		t.Fatalf("FullResponse RowErrors = %v (err=%v), want 1 row error with InvalidArgument", full1.GetRowErrors(), err)
	}
	if srv.RowCount("otel_quarantine") != 0 {
		t.Fatalf("RowCount after RowErrors = %d, want 0", srv.RowCount("otel_quarantine"))
	}

	// 2. Unavailable fault.
	res2, err := stream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows #2: %v", err)
	}
	if _, err := res2.GetResult(ctx); status.Code(err) != codes.Unavailable {
		t.Fatalf("GetResult #2 status = %v, want Unavailable", status.Code(err))
	}

	// 3. ResourceExhausted fault.
	res3, err := stream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows #3: %v", err)
	}
	if _, err := res3.GetResult(ctx); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("GetResult #3 status = %v, want ResourceExhausted", status.Code(err))
	}

	// 4. DelayedAck fault succeeds after delay and stores the row.
	res4, err := stream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows #4: %v", err)
	}
	if _, err := res4.GetResult(ctx); err != nil {
		t.Fatalf("GetResult #4: %v", err)
	}
	if srv.RowCount("otel_quarantine") != 1 {
		t.Fatalf("RowCount after DelayedAck = %d, want 1", srv.RowCount("otel_quarantine"))
	}
}

func TestServerFaultContextExpiry(t *testing.T) {
	srv := NewServer(t)
	ctx := context.Background()

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	qEnc, err := protoenc.New(schema.QuarantineTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(QuarantineTableSchema): %v", err)
	}
	stream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_quarantine"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(qEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	encoded, err := qEnc.Encode(transform.Row{
		"ingest_time":   time.Now().UnixMicro(),
		"signal":        schema.SignalSpans,
		"error_code":    "INVALID_SPAN_ID",
		"error_message": "invalid_id: span_id",
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	otherStream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_other"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(qEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream(otel_other): %v", err)
	}
	t.Cleanup(func() { _ = otherStream.Close() })

	expiredCtx, cancelExpired := context.WithCancel(ctx)
	cancelExpired()
	srv.EnqueueFault(
		Fault{Mode: FaultUnavailable, Table: "otel_quarantine", Ctx: expiredCtx},
		Fault{Mode: FaultUnavailable, Table: "otel_other", Ctx: ctx},
		Fault{Mode: FaultInvalidArgument, Table: "otel_quarantine", Ctx: expiredCtx},
		Fault{Mode: FaultResourceExhausted, Table: "otel_quarantine", Ctx: ctx},
	)

	// Expired t1 faults are discarded while active(otherTable) survives slice
	// compaction and active(t1) still triggers on the first append.
	res1, err := stream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows #1: %v", err)
	}
	if _, err := res1.GetResult(ctx); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("GetResult #1 status = %v, want ResourceExhausted (expired faults should be skipped)", status.Code(err))
	}

	// Subsequent append on t1 sees no leftover faults and succeeds cleanly.
	res2, err := stream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows #2: %v", err)
	}
	if _, err := res2.GetResult(ctx); err != nil {
		t.Fatalf("GetResult #2 error = %v, want nil", err)
	}
	if srv.RowCount("otel_quarantine") != 1 {
		t.Fatalf("RowCount(otel_quarantine) = %d, want 1", srv.RowCount("otel_quarantine"))
	}

	// Active fault queued for otel_other survived compaction across expired(t1) entries.
	resOther1, err := otherStream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows(otel_other #1): %v", err)
	}
	if _, err := resOther1.GetResult(ctx); status.Code(err) != codes.Unavailable {
		t.Fatalf("GetResult(otel_other #1) status = %v, want Unavailable", status.Code(err))
	}
	resOther2, err := otherStream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows(otel_other #2): %v", err)
	}
	if _, err := resOther2.GetResult(ctx); err != nil {
		t.Fatalf("GetResult(otel_other #2) error = %v, want nil", err)
	}
	if srv.RowCount("otel_other") != 1 {
		t.Fatalf("RowCount(otel_other) = %d, want 1", srv.RowCount("otel_other"))
	}

	// Reused stream with FaultDelayedAck aborts early when fault.Ctx cancels
	// mid-delay instead of blocking for the full 5s delay, and recovers cleanly.
	delayedCtx, cancelDelayed := context.WithTimeout(ctx, 25*time.Millisecond)
	defer cancelDelayed()
	srv.EnqueueFault(Fault{
		Mode:  FaultDelayedAck,
		Table: "otel_quarantine",
		Delay: 5 * time.Second,
		Ctx:   delayedCtx,
	})

	delayStart := time.Now()
	resDelayed, err := stream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows(delayed): %v", err)
	}
	_, delayedErr := resDelayed.GetResult(ctx)
	delayElapsed := time.Since(delayStart)
	if delayElapsed >= 2*time.Second {
		t.Fatalf("FaultDelayedAck with canceled fault.Ctx took %s, want early abort < 2s", delayElapsed)
	}
	if status.Code(delayedErr) != codes.DeadlineExceeded {
		t.Fatalf("GetResult(delayed) error = %v (code=%v), want DeadlineExceeded", delayedErr, status.Code(delayedErr))
	}
	if srv.RowCount("otel_quarantine") != 1 {
		t.Fatalf("RowCount(otel_quarantine) after aborted delay = %d, want 1", srv.RowCount("otel_quarantine"))
	}

	// managedwriter detects the closed bidi stream on the next Send (io.EOF -> reconnect=true),
	// so the subsequent append on the same ManagedStream reconnects and succeeds cleanly.
	resAfterDelay, err := stream.AppendRows(ctx, [][]byte{encoded})
	if errors.Is(err, io.EOF) {
		resAfterDelay, err = stream.AppendRows(ctx, [][]byte{encoded})
	}
	if err != nil {
		t.Fatalf("AppendRows(after delay abort): %v", err)
	}
	if _, err := resAfterDelay.GetResult(ctx); err != nil {
		t.Fatalf("GetResult(after delay abort) error = %v, want nil", err)
	}
	if srv.RowCount("otel_quarantine") != 2 {
		t.Fatalf("RowCount(otel_quarantine) after recovery = %d, want 2", srv.RowCount("otel_quarantine"))
	}
}

func TestRESTMetadataEndpoints(t *testing.T) {
	srv := NewServer(t)
	ctx := context.Background()

	httpClient, httpBase := srv.NewHTTPClient()
	t.Cleanup(func() { httpBase.CloseIdleConnections() })

	client, err := bq.NewClient(ctx, "test-project", option.WithHTTPClient(httpClient))
	if err != nil {
		t.Fatalf("bq.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ds := client.Dataset("otel_ds")
	if _, err := ds.Metadata(ctx); err == nil {
		t.Fatal("expected 404 before dataset creation")
	}
	if err := ds.Create(ctx, &bq.DatasetMetadata{Location: "US"}); err != nil {
		t.Fatalf("Dataset.Create: %v", err)
	}
	md, err := ds.Metadata(ctx)
	if err != nil || md.Location != "US" {
		t.Fatalf("Dataset.Metadata = (%#v, %v), want Location US", md, err)
	}

	tblMD, viewQuery, err := schema.DestinationMetadata(schema.SpansTableSchema(), "test-project", "otel_ds", "otel_spans")
	if err != nil {
		t.Fatalf("DestinationMetadata: %v", err)
	}
	if err := ds.Table("otel_spans").Create(ctx, tblMD); err != nil {
		t.Fatalf("Table.Create: %v", err)
	}
	gotTbl, err := ds.Table("otel_spans").Metadata(ctx)
	if err != nil || len(gotTbl.Schema) != len(schema.SpansTableSchema().GetFields()) {
		t.Fatalf("Table.Metadata fields = %d (err=%v), want %d", len(gotTbl.Schema), err, len(schema.SpansTableSchema().GetFields()))
	}

	if err := ds.Table("otel_spans_dedup").Create(ctx, &bq.TableMetadata{ViewQuery: viewQuery, UseLegacySQL: false}); err != nil {
		t.Fatalf("View.Create: %v", err)
	}
	gotView, err := ds.Table("otel_spans_dedup").Metadata(ctx)
	if err != nil || gotView.ViewQuery != viewQuery {
		t.Fatalf("View.Metadata query = %q (err=%v), want %q", gotView.ViewQuery, err, viewQuery)
	}
}

func TestAppendRowsDecodesWithWriterDescriptorAndValidatesAgainstTableSchema(t *testing.T) {
	srv := NewServer(t)
	ctx := context.Background()

	if err := srv.RegisterTableSchema("pair_table", &storagepb.TableSchema{
		Fields: []*storagepb.TableFieldSchema{
			{Name: "first", Type: storagepb.TableFieldSchema_STRING, Mode: storagepb.TableFieldSchema_REQUIRED},
			{Name: "second", Type: storagepb.TableFieldSchema_STRING, Mode: storagepb.TableFieldSchema_NULLABLE},
		},
	}); err != nil {
		t.Fatalf("RegisterTableSchema: %v", err)
	}

	conn, err := grpc.NewClient(srv.Addr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	writeClient := storagepb.NewBigQueryWriteClient(conn)

	const streamName = "projects/test-project/datasets/otel/tables/pair_table/streams/_default"

	// 1. Reordered field numbers in the writer descriptor must decode by the
	// writer's field numbers rather than swapping values by table column order.
	reorderedDP := &descriptorpb.DescriptorProto{
		Name: proto.String("ReorderedRow"),
		Field: []*descriptorpb.FieldDescriptorProto{
			{
				Name:   proto.String("second"),
				Number: proto.Int32(1),
				Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			},
			{
				Name:   proto.String("first"),
				Number: proto.Int32(2),
				Label:  descriptorpb.FieldDescriptorProto_LABEL_REQUIRED.Enum(),
				Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			},
		},
	}
	fileDesc, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:        proto.String("reordered.proto"),
		Syntax:      proto.String("proto2"),
		MessageType: []*descriptorpb.DescriptorProto{reorderedDP},
	}, nil)
	if err != nil {
		t.Fatalf("protodesc.NewFile: %v", err)
	}
	msg := dynamicpb.NewMessage(fileDesc.Messages().ByName("ReorderedRow"))
	msg.Set(msg.Descriptor().Fields().ByName("first"), protoreflect.ValueOfString("alpha"))
	msg.Set(msg.Descriptor().Fields().ByName("second"), protoreflect.ValueOfString("beta"))
	raw, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	stream, err := writeClient.AppendRows(ctx)
	if err != nil {
		t.Fatalf("AppendRows: %v", err)
	}
	if err := stream.Send(&storagepb.AppendRowsRequest{
		WriteStream: streamName,
		Rows: &storagepb.AppendRowsRequest_ProtoRows{
			ProtoRows: &storagepb.AppendRowsRequest_ProtoData{
				WriterSchema: &storagepb.ProtoSchema{ProtoDescriptor: reorderedDP},
				Rows:         &storagepb.ProtoRows{SerializedRows: [][]byte{raw}},
			},
		},
	}); err != nil {
		t.Fatalf("Send reordered row: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv reordered row: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("unexpected error for reordered writer descriptor: %v", resp.GetError())
	}
	rows := srv.Rows("pair_table")
	if len(rows) != 1 || rows[0]["first"] != "alpha" || rows[0]["second"] != "beta" {
		t.Fatalf("decoded rows = %#v, want first=alpha and second=beta", rows)
	}

	// 2. Unknown column, incompatible type, missing required column, and
	// missing/invalid writer descriptor must be rejected with InvalidArgument.
	for _, tc := range []struct {
		name string
		dp   *descriptorpb.DescriptorProto
	}{
		{
			name: "unknown column",
			dp: &descriptorpb.DescriptorProto{
				Name: proto.String("UnknownColRow"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("first"),
						Number: proto.Int32(1),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_REQUIRED.Enum(),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
					},
					{
						Name:   proto.String("unknown_column"),
						Number: proto.Int32(2),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
					},
				},
			},
		},
		{
			name: "mismatched field type",
			dp: &descriptorpb.DescriptorProto{
				Name: proto.String("BadTypeRow"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("first"),
						Number: proto.Int32(1),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_REQUIRED.Enum(),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum(),
					},
				},
			},
		},
		{
			name: "missing required column",
			dp: &descriptorpb.DescriptorProto{
				Name: proto.String("MissingReqRow"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("second"),
						Number: proto.Int32(1),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
					},
				},
			},
		},
		{
			name: "missing writer descriptor",
			dp:   nil,
		},
		{
			name: "empty writer descriptor",
			dp:   &descriptorpb.DescriptorProto{Name: proto.String("")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := writeClient.AppendRows(ctx)
			if err != nil {
				t.Fatalf("AppendRows: %v", err)
			}
			var ws *storagepb.ProtoSchema
			if tc.dp != nil {
				ws = &storagepb.ProtoSchema{ProtoDescriptor: tc.dp}
			}
			if err := st.Send(&storagepb.AppendRowsRequest{
				WriteStream: streamName,
				Rows: &storagepb.AppendRowsRequest_ProtoRows{
					ProtoRows: &storagepb.AppendRowsRequest_ProtoData{
						WriterSchema: ws,
						Rows:         &storagepb.ProtoRows{SerializedRows: [][]byte{raw}},
					},
				},
			}); err != nil {
				t.Fatalf("Send: %v", err)
			}
			r, err := st.Recv()
			if err != nil {
				t.Fatalf("Recv: %v", err)
			}
			if r.GetError() == nil || codes.Code(r.GetError().GetCode()) != codes.InvalidArgument {
				t.Fatalf("response error = %v, want InvalidArgument", r.GetError())
			}
		})
	}
}

// relaxRequired returns a copy of ts with every REQUIRED field, at any depth,
// declared NULLABLE: the descriptor a writer built from a looser schema sends.
func relaxRequired(ts *storagepb.TableSchema) *storagepb.TableSchema {
	out := proto.Clone(ts).(*storagepb.TableSchema)
	var relax func([]*storagepb.TableFieldSchema)
	relax = func(fields []*storagepb.TableFieldSchema) {
		for _, f := range fields {
			if f.GetMode() == storagepb.TableFieldSchema_REQUIRED {
				f.Mode = storagepb.TableFieldSchema_NULLABLE
			}
			relax(f.GetFields())
		}
	}
	relax(out.GetFields())
	return out
}

// openAppendStream opens a raw AppendRows stream, bypassing managedwriter so a
// test controls the writer descriptor exactly.
func openAppendStream(t *testing.T, srv *Server) storagepb.BigQueryWrite_AppendRowsClient {
	t.Helper()
	conn, err := grpc.NewClient(srv.Addr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	st, err := storagepb.NewBigQueryWriteClient(conn).AppendRows(context.Background())
	if err != nil {
		t.Fatalf("AppendRows: %v", err)
	}
	return st
}

// appendProtoRows sends one request and returns its response. A nil writer
// descriptor reuses the one the stream already carries.
func appendProtoRows(t *testing.T, st storagepb.BigQueryWrite_AppendRowsClient, streamName string, writer *descriptorpb.DescriptorProto, rows ...[]byte) *storagepb.AppendRowsResponse {
	t.Helper()
	data := &storagepb.AppendRowsRequest_ProtoData{Rows: &storagepb.ProtoRows{SerializedRows: rows}}
	if writer != nil {
		data.WriterSchema = &storagepb.ProtoSchema{ProtoDescriptor: writer}
	}
	if err := st.Send(&storagepb.AppendRowsRequest{
		WriteStream: streamName,
		Rows:        &storagepb.AppendRowsRequest_ProtoRows{ProtoRows: data},
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	resp, err := st.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	return resp
}

func TestAppendRowsEnforcesRequiredValuesTheWriterDeclaresOptional(t *testing.T) {
	const (
		required = storagepb.TableFieldSchema_REQUIRED
		nullable = storagepb.TableFieldSchema_NULLABLE
		repeated = storagepb.TableFieldSchema_REPEATED
	)
	nested := &storagepb.TableSchema{Fields: []*storagepb.TableFieldSchema{
		{Name: "record_id", Type: storagepb.TableFieldSchema_STRING, Mode: required},
		{Name: "parent", Type: storagepb.TableFieldSchema_STRUCT, Mode: nullable, Fields: []*storagepb.TableFieldSchema{
			{Name: "child", Type: storagepb.TableFieldSchema_STRING, Mode: required},
		}},
		{Name: "items", Type: storagepb.TableFieldSchema_STRUCT, Mode: repeated, Fields: []*storagepb.TableFieldSchema{
			{Name: "child", Type: storagepb.TableFieldSchema_STRING, Mode: required},
		}},
	}}

	start := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	end := start.Add(25 * time.Millisecond)
	span := transform.Row{
		"start_time":             start.UnixMicro(),
		"start_time_unix_nano":   start.UnixNano(),
		"end_time":               end.UnixMicro(),
		"end_time_unix_nano":     end.UnixNano(),
		"receive_time":           end.UnixMicro(),
		"receive_time_unix_nano": end.UnixNano(),
		"duration_nano":          int64(25 * time.Millisecond),
		"trace_id":               "0102030405060708090a0b0c0d0e0f10",
		"span_id":                "0102030405060708",
		"name":                   "invoke_agent",
		"kind":                   int64(2),
	}
	spanWithoutStart := maps.Clone(span)
	delete(spanWithoutStart, "start_time")

	for _, tc := range []struct {
		name   string
		table  string
		schema *storagepb.TableSchema // nil: the otel_spans table New registers
		row    transform.Row
		// wantMissing names the column the row error must report; empty means
		// the row is valid and must be stored.
		wantMissing string
	}{
		{name: "span without start_time", table: "otel_spans", row: spanWithoutStart, wantMissing: "start_time"},
		{name: "span with every required value", table: "otel_spans", row: span},
		{
			name: "top-level value absent", table: "nested", schema: nested,
			row:         transform.Row{"parent": transform.Row{"child": "c"}},
			wantMissing: "record_id",
		},
		{
			name: "present parent without its required child", table: "nested", schema: nested,
			row:         transform.Row{"record_id": "r", "parent": transform.Row{}},
			wantMissing: "parent.child",
		},
		{
			name: "repeated element without its required child", table: "nested", schema: nested,
			row:         transform.Row{"record_id": "r", "items": []transform.Row{{"child": "c"}, {}}},
			wantMissing: "items[1].child",
		},
		{
			name: "absent nullable parent", table: "nested", schema: nested,
			row: transform.Row{"record_id": "r"},
		},
		{
			name: "every required value present", table: "nested", schema: nested,
			row: transform.Row{"record_id": "r", "parent": transform.Row{"child": "c"}, "items": []transform.Row{{"child": "c"}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewServer(t)
			destination := schema.SpansTableSchema()
			if tc.schema != nil {
				destination = tc.schema
				if err := srv.RegisterTableSchema(tc.table, destination); err != nil {
					t.Fatalf("RegisterTableSchema: %v", err)
				}
			}
			enc, err := protoenc.New(relaxRequired(destination))
			if err != nil {
				t.Fatalf("protoenc.New: %v", err)
			}
			raw, err := enc.Encode(tc.row)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}

			resp := appendProtoRows(t, openAppendStream(t, srv),
				"projects/test-project/datasets/otel/tables/"+tc.table+"/streams/_default", enc.Descriptor(), raw)
			_, _, acked := srv.Counts()

			if tc.wantMissing == "" {
				if resp.GetError() != nil || srv.RowCount(tc.table) != 1 || acked != 1 {
					t.Fatalf("valid row: response error = %v, stored %d, acked %d; want no error, 1 stored, 1 acked",
						resp.GetError(), srv.RowCount(tc.table), acked)
				}
				return
			}
			if resp.GetError() == nil || codes.Code(resp.GetError().GetCode()) != codes.InvalidArgument {
				t.Fatalf("response error = %v, want InvalidArgument", resp.GetError())
			}
			rowErrs := resp.GetRowErrors()
			if len(rowErrs) != 1 || rowErrs[0].GetIndex() != 0 || rowErrs[0].GetCode() != storagepb.RowError_FIELDS_ERROR {
				t.Fatalf("row errors = %v, want one FIELDS_ERROR at index 0", rowErrs)
			}
			if msg := rowErrs[0].GetMessage(); !strings.Contains(msg, tc.wantMissing) {
				t.Errorf("row error message %q does not name %s", msg, tc.wantMissing)
			}
			if srv.RowCount(tc.table) != 0 || acked != 0 {
				t.Errorf("stored %d rows and acked %d, want neither", srv.RowCount(tc.table), acked)
			}
		})
	}
}

func TestAppendRowsRejectsTheWholeRequestWhenAnyRowLacksARequiredValue(t *testing.T) {
	srv := NewServer(t)
	table := &storagepb.TableSchema{Fields: []*storagepb.TableFieldSchema{
		{Name: "record_id", Type: storagepb.TableFieldSchema_STRING, Mode: storagepb.TableFieldSchema_REQUIRED},
		{Name: "note", Type: storagepb.TableFieldSchema_STRING, Mode: storagepb.TableFieldSchema_NULLABLE},
	}}
	if err := srv.RegisterTableSchema("batch_table", table); err != nil {
		t.Fatalf("RegisterTableSchema: %v", err)
	}
	enc, err := protoenc.New(relaxRequired(table))
	if err != nil {
		t.Fatalf("protoenc.New: %v", err)
	}
	valid, err := enc.Encode(transform.Row{"record_id": "r"})
	if err != nil {
		t.Fatalf("Encode valid: %v", err)
	}
	missing, err := enc.Encode(transform.Row{"note": "no record_id"})
	if err != nil {
		t.Fatalf("Encode missing: %v", err)
	}

	const streamName = "projects/test-project/datasets/otel/tables/batch_table/streams/_default"
	st := openAppendStream(t, srv)

	resp := appendProtoRows(t, st, streamName, enc.Descriptor(), valid, missing, valid, missing)
	if resp.GetError() == nil || codes.Code(resp.GetError().GetCode()) != codes.InvalidArgument {
		t.Fatalf("response error = %v, want InvalidArgument", resp.GetError())
	}
	var indexes []int64
	for _, re := range resp.GetRowErrors() {
		if re.GetCode() != storagepb.RowError_FIELDS_ERROR {
			t.Errorf("row %d error code = %v, want FIELDS_ERROR", re.GetIndex(), re.GetCode())
		}
		indexes = append(indexes, re.GetIndex())
	}
	if !slices.Equal(indexes, []int64{1, 3}) {
		t.Fatalf("row error indexes = %v, want [1 3]", indexes)
	}
	if _, _, acked := srv.Counts(); srv.RowCount("batch_table") != 0 || acked != 0 {
		t.Fatalf("stored %d rows and acked %d after a rejected request, want neither", srv.RowCount("batch_table"), acked)
	}

	// The stream stays usable: the next request reuses its writer descriptor.
	resp = appendProtoRows(t, st, "", nil, valid)
	if _, _, acked := srv.Counts(); resp.GetError() != nil || srv.RowCount("batch_table") != 1 || acked != 1 {
		t.Fatalf("follow-up request: response error = %v, stored %d, acked %d; want no error, 1 stored, 1 acked",
			resp.GetError(), srv.RowCount("batch_table"), acked)
	}
}

func TestConcurrentTableGetAndPatch(t *testing.T) {
	srv := NewServer(t)
	ctx := context.Background()

	httpClient, httpBase := srv.NewHTTPClient()
	t.Cleanup(func() { httpBase.CloseIdleConnections() })

	client, err := bq.NewClient(ctx, "test-project", option.WithHTTPClient(httpClient))
	if err != nil {
		t.Fatalf("bq.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ds := client.Dataset("race_ds")
	if err := ds.Create(ctx, &bq.DatasetMetadata{Location: "US"}); err != nil {
		t.Fatalf("Dataset.Create: %v", err)
	}
	tblMD, _, err := schema.DestinationMetadata(schema.SpansTableSchema(), "test-project", "race_ds", "otel_spans")
	if err != nil {
		t.Fatalf("DestinationMetadata: %v", err)
	}
	tbl := ds.Table("otel_spans")
	if err := tbl.Create(ctx, tblMD); err != nil {
		t.Fatalf("Table.Create: %v", err)
	}

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 25 {
				if _, err := tbl.Metadata(ctx); err != nil {
					t.Errorf("Table.Metadata: %v", err)
					return
				}
				if got, ok := srv.Table("test-project", "race_ds", "otel_spans"); !ok || got == nil {
					t.Errorf("srv.Table returned (%v, %v)", got, ok)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 25 {
				if _, err := tbl.Update(ctx, bq.TableMetadataToUpdate{
					Schema: tblMD.Schema,
				}, ""); err != nil {
					t.Errorf("Table.Update: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestRESTTableUpdateEnforcesIfMatchETagAndAdditiveSchema(t *testing.T) {
	srv := NewServer(t)
	ctx := context.Background()

	httpClient, httpBase := srv.NewHTTPClient()
	t.Cleanup(func() { httpBase.CloseIdleConnections() })

	client, err := bq.NewClient(ctx, "test-project", option.WithHTTPClient(httpClient))
	if err != nil {
		t.Fatalf("bq.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ds := client.Dataset("etag_ds")
	if err := ds.Create(ctx, &bq.DatasetMetadata{Location: "US"}); err != nil {
		t.Fatalf("Dataset.Create: %v", err)
	}
	tbl := ds.Table("otel_spans")
	initialSchema := bq.Schema{
		{Name: "trace_id", Type: bq.StringFieldType, Required: true},
	}
	if err := tbl.Create(ctx, &bq.TableMetadata{Schema: initialSchema}); err != nil {
		t.Fatalf("Table.Create: %v", err)
	}
	md1, err := tbl.Metadata(ctx)
	if err != nil || md1.ETag == "" {
		t.Fatalf("Table.Metadata = (%#v, %v), want non-empty ETag", md1, err)
	}

	// 1. Stale ETag must fail with HTTP 412 Precondition Failed.
	additiveSchema := bq.Schema{
		{Name: "trace_id", Type: bq.StringFieldType, Required: true},
		{Name: "custom_note", Type: bq.StringFieldType, Required: false},
	}
	_, err = tbl.Update(ctx, bq.TableMetadataToUpdate{Schema: additiveSchema}, "stale-etag")
	var gerr *googleapi.Error
	if !errors.As(err, &gerr) || gerr.Code != 412 {
		t.Fatalf("Table.Update with stale ETag err = %v, want googleapi.Error with HTTP 412", err)
	}

	// 2. Matching ETag succeeds and advances ETag without inflating AppendRows request count.
	md2, err := tbl.Update(ctx, bq.TableMetadataToUpdate{Schema: additiveSchema}, md1.ETag)
	if err != nil {
		t.Fatalf("Table.Update with matching ETag failed: %v", err)
	}
	if md2.ETag == "" || md2.ETag == md1.ETag {
		t.Errorf("updated ETag = %q, want distinct non-empty ETag from %q", md2.ETag, md1.ETag)
	}
	if _, reqs, _ := srv.Counts(); reqs != 0 {
		t.Errorf("srv.Counts() requests = %d after REST PATCH, want 0", reqs)
	}

	// 3. Removing an existing column fails with HTTP 400 Bad Request.
	_, err = tbl.Update(ctx, bq.TableMetadataToUpdate{Schema: initialSchema}, md2.ETag)
	gerr = nil
	if !errors.As(err, &gerr) || gerr.Code != 400 {
		t.Fatalf("Table.Update removing custom_note err = %v, want googleapi.Error with HTTP 400", err)
	}

	// 4. Adding a new REQUIRED column fails with HTTP 400 Bad Request.
	withNewRequired := bq.Schema{
		{Name: "trace_id", Type: bq.StringFieldType, Required: true},
		{Name: "custom_note", Type: bq.StringFieldType, Required: false},
		{Name: "must_fail", Type: bq.StringFieldType, Required: true},
	}
	_, err = tbl.Update(ctx, bq.TableMetadataToUpdate{Schema: withNewRequired}, md2.ETag)
	gerr = nil
	if !errors.As(err, &gerr) || gerr.Code != 400 {
		t.Fatalf("Table.Update adding new REQUIRED column err = %v, want googleapi.Error with HTTP 400", err)
	}
}

func TestRESTTableKeepsPolicyTagsAsSent(t *testing.T) {
	srv := NewServer(t)
	ctx := context.Background()

	httpClient, httpBase := srv.NewHTTPClient()
	t.Cleanup(func() { httpBase.CloseIdleConnections() })

	client, err := bq.NewClient(ctx, "test-project", option.WithHTTPClient(httpClient))
	if err != nil {
		t.Fatalf("bq.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ds := client.Dataset("tags_ds")
	if err := ds.Create(ctx, &bq.DatasetMetadata{Location: "US"}); err != nil {
		t.Fatalf("Dataset.Create: %v", err)
	}
	const tag = "projects/test-project/locations/us/taxonomies/1/policyTags/2"
	tbl := ds.Table("tagged")
	if err := tbl.Create(ctx, &bq.TableMetadata{Schema: bq.Schema{
		{Name: "ingest_time", Type: bq.TimestampFieldType, Required: true},
		{Name: "raw_payload", Type: bq.StringFieldType, PolicyTags: &bq.PolicyTagList{Names: []string{tag}}},
		{Name: "status", Type: bq.RecordFieldType, Schema: bq.Schema{
			{Name: "code", Type: bq.IntegerFieldType},
			{Name: "message", Type: bq.StringFieldType, PolicyTags: &bq.PolicyTagList{Names: []string{tag}}},
		}},
	}}); err != nil {
		t.Fatalf("Table.Create: %v", err)
	}
	wantTags := map[string][]string{"raw_payload": {tag}, "status.message": {tag}}

	// 1. GET returns the tags the table was created with, nested ones
	// included, and so does the server-side snapshot.
	created, err := tbl.Metadata(ctx)
	if err != nil {
		t.Fatalf("Table.Metadata after create: %v", err)
	}
	if got := policyTagsByPath(created.Schema); !maps.EqualFunc(got, wantTags, slices.Equal) {
		t.Errorf("policy tags after create = %v, want %v", got, wantTags)
	}
	snapshot, ok := srv.Table("test-project", "tags_ds", "tagged")
	if !ok {
		t.Fatal("srv.Table did not find the created table")
	}
	if got := snapshot.Schema.Fields[1].PolicyTags; got == nil || !slices.Equal(got.Names, []string{tag}) {
		t.Errorf("snapshot raw_payload policy tags = %#v, want [%s]", got, tag)
	}
	if got := snapshot.Schema.Fields[2].Fields[1].PolicyTags; got == nil || !slices.Equal(got.Names, []string{tag}) {
		t.Errorf("snapshot status.message policy tags = %#v, want [%s]", got, tag)
	}

	// 2. A PATCH that sends the tags back alongside a new column keeps them.
	withAdded := append(slices.Clone(created.Schema), &bq.FieldSchema{Name: "error_message", Type: bq.StringFieldType})
	if _, err := tbl.Update(ctx, bq.TableMetadataToUpdate{Schema: withAdded}, created.ETag); err != nil {
		t.Fatalf("Table.Update with the tags sent back: %v", err)
	}
	patched, err := tbl.Metadata(ctx)
	if err != nil {
		t.Fatalf("Table.Metadata after the first update: %v", err)
	}
	if len(patched.Schema) != 4 || patched.Schema[3].Name != "error_message" {
		t.Errorf("schema after the first update = %v, want error_message appended", schemaNames(patched.Schema))
	}
	if got := policyTagsByPath(patched.Schema); !maps.EqualFunc(got, wantTags, slices.Equal) {
		t.Errorf("policy tags after an update that sent them = %v, want %v", got, wantTags)
	}

	// 3. A PATCH that leaves the tags out stores none, so a test can tell
	// whether an update carried them.
	clearPolicyTags(patched.Schema)
	if _, err := tbl.Update(ctx, bq.TableMetadataToUpdate{Schema: patched.Schema}, patched.ETag); err != nil {
		t.Fatalf("Table.Update without the tags: %v", err)
	}
	untagged, err := tbl.Metadata(ctx)
	if err != nil {
		t.Fatalf("Table.Metadata after the second update: %v", err)
	}
	if got := policyTagsByPath(untagged.Schema); len(got) != 0 {
		t.Errorf("policy tags after an update that left them out = %v, want none", got)
	}
}

// policyTagsByPath maps the dotted path of every field of s that carries
// policy tags, nested fields included, to the tag names.
func policyTagsByPath(s bq.Schema) map[string][]string {
	out := make(map[string][]string)
	var walk func(prefix string, s bq.Schema)
	walk = func(prefix string, s bq.Schema) {
		for _, f := range s {
			if f.PolicyTags != nil {
				out[prefix+f.Name] = f.PolicyTags.Names
			}
			walk(prefix+f.Name+".", f.Schema)
		}
	}
	walk("", s)
	return out
}

// clearPolicyTags removes the policy tags from every field of s, nested
// fields included.
func clearPolicyTags(s bq.Schema) {
	for _, f := range s {
		f.PolicyTags = nil
		clearPolicyTags(f.Schema)
	}
}

func schemaNames(s bq.Schema) []string {
	names := make([]string, 0, len(s))
	for _, f := range s {
		names = append(names, f.Name)
	}
	return names
}

func TestServerSetDiscardRows(t *testing.T) {
	srv := NewServer(t)
	srv.SetDiscardRows(true)
	ctx := context.Background()

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Use an optional-field writer descriptor so missing REQUIRED trace_id passes
	// client encoding and must be caught by bqfake's server-side validation.
	optSchema := &storagepb.TableSchema{
		Fields: func() []*storagepb.TableFieldSchema {
			orig := schema.SpansTableSchema().GetFields()
			out := make([]*storagepb.TableFieldSchema, len(orig))
			for i, f := range orig {
				cp := proto.Clone(f).(*storagepb.TableFieldSchema)
				if cp.GetMode() == storagepb.TableFieldSchema_REQUIRED {
					cp.Mode = storagepb.TableFieldSchema_NULLABLE
				}
				out[i] = cp
			}
			return out
		}(),
	}
	spanEnc, err := protoenc.New(optSchema)
	if err != nil {
		t.Fatalf("protoenc.New(optSchema): %v", err)
	}
	stream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_spans"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(spanEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	start := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	end := start.Add(25 * time.Millisecond)
	validEncoded, err := spanEnc.Encode(transform.Row{
		"start_time":             start.UnixMicro(),
		"start_time_unix_nano":   start.UnixNano(),
		"end_time":               end.UnixMicro(),
		"end_time_unix_nano":     end.UnixNano(),
		"receive_time":           end.UnixMicro(),
		"receive_time_unix_nano": end.UnixNano(),
		"duration_nano":          int64(25 * time.Millisecond),
		"trace_id":               "0102030405060708090a0b0c0d0e0f10",
		"span_id":                "0102030405060708",
		"name":                   "invoke_agent",
		"kind":                   int64(2),
		"kind_name":              "SPAN_KIND_SERVER",
		"service_name":           "adk-service",
		"attributes":             `{"gen_ai.system":"gcp.vertex.agent"}`,
	})
	if err != nil {
		t.Fatalf("Encode(valid): %v", err)
	}

	// 1. Valid append updates ackedRows/ackedBytes while leaving Rows() empty.
	res1, err := stream.AppendRows(ctx, [][]byte{validEncoded})
	if err != nil {
		t.Fatalf("AppendRows #1: %v", err)
	}
	if _, err := res1.GetResult(ctx); err != nil {
		t.Fatalf("GetResult #1: %v", err)
	}
	_, reqs, acked := srv.Counts()
	if reqs != 1 || acked != 1 {
		t.Fatalf("Counts() after valid append = (reqs=%d, acked=%d), want (1, 1)", reqs, acked)
	}
	if gotBytes, wantBytes := srv.AckedBytes(), int64(len(validEncoded)); gotBytes != wantBytes {
		t.Fatalf("AckedBytes() = %d, want %d", gotBytes, wantBytes)
	}
	if srv.RowCount("otel_spans") != 0 || len(srv.Rows("otel_spans")) != 0 {
		t.Fatalf("expected 0 retained rows in discard mode, got RowCount=%d len(Rows)=%d",
			srv.RowCount("otel_spans"), len(srv.Rows("otel_spans")))
	}

	// 2. Invalid row (missing REQUIRED trace_id) is still rejected in discard mode.
	missingRequiredEncoded, err := spanEnc.Encode(transform.Row{
		"start_time":   start.UnixMicro(),
		"end_time":     end.UnixMicro(),
		"receive_time": end.UnixMicro(),
		"span_id":      "0102030405060708",
		"name":         "invoke_agent",
		"kind":         int64(2),
	})
	if err != nil {
		t.Fatalf("Encode(missingRequired): %v", err)
	}
	res2, err := stream.AppendRows(ctx, [][]byte{missingRequiredEncoded})
	if err != nil {
		t.Fatalf("AppendRows #2: %v", err)
	}
	if _, err := res2.GetResult(ctx); err == nil {
		t.Fatal("expected missing REQUIRED column to fail in discard mode")
	}
	full2, err := res2.FullResponse(ctx)
	if status.Code(err) != codes.InvalidArgument || len(full2.GetRowErrors()) != 1 {
		t.Fatalf("FullResponse RowErrors = %v (err=%v), want 1 InvalidArgument row error", full2.GetRowErrors(), err)
	}
	_, reqs, acked = srv.Counts()
	if reqs != 2 || acked != 1 {
		t.Fatalf("Counts() after rejected append = (reqs=%d, acked=%d), want (2, 1)", reqs, acked)
	}
	if srv.AckedBytes() != int64(len(validEncoded)) {
		t.Fatalf("AckedBytes() changed on rejected append: got %d, want %d", srv.AckedBytes(), len(validEncoded))
	}

	// 3. Disabling discard mode resumes retaining subsequent rows.
	srv.SetDiscardRows(false)
	res3, err := stream.AppendRows(ctx, [][]byte{validEncoded})
	if err != nil {
		t.Fatalf("AppendRows #3: %v", err)
	}
	if _, err := res3.GetResult(ctx); err != nil {
		t.Fatalf("GetResult #3: %v", err)
	}
	if srv.RowCount("otel_spans") != 1 {
		t.Fatalf("RowCount after SetDiscardRows(false) = %d, want 1", srv.RowCount("otel_spans"))
	}
	_, reqs, acked = srv.Counts()
	if reqs != 3 || acked != 2 {
		t.Fatalf("Counts() after retained append = (reqs=%d, acked=%d), want (3, 2)", reqs, acked)
	}
}

func TestServerSetPeriodicFaultsThrottleAndDelayedRetry(t *testing.T) {
	srv := NewServer(t)
	ctx := context.Background()

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	stream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	ts := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	encoded, err := logEnc.Encode(transform.Row{
		"timestamp":               ts.UnixMicro(),
		"timestamp_source":        "observed",
		"time_unix_nano":          ts.UnixNano(),
		"observed_time_unix_nano": ts.UnixNano(),
		"receive_time":            ts.UnixMicro(),
		"receive_time_unix_nano":  ts.UnixNano(),
		"log_name":                "projects/test-project/logs/app",
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	srv.SetPeriodicFaults(ctx, "otel_logs", 1, 50*time.Millisecond)

	// Logical batch 1, attempt 1: throttled with ResourceExhausted.
	res1, err := stream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows #1: %v", err)
	}
	if _, err := res1.GetResult(ctx); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("GetResult #1 status = %v, want ResourceExhausted", status.Code(err))
	}

	// Logical batch 1, retry attempt 2: delayed ack (>= 40ms) because logicalSeq == 1.
	delayedBefore2 := srv.DelayedAcksInjectedForTable("otel_logs")
	start2 := time.Now()
	res2, err := stream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows #2: %v", err)
	}
	if _, err := res2.GetResult(ctx); err != nil {
		t.Fatalf("GetResult #2: %v", err)
	}
	if got := srv.DelayedAcksInjectedForTable("otel_logs"); got != delayedBefore2+1 {
		t.Fatalf("attempt 2 DelayedAcksInjectedForTable(otel_logs) = %d, want %d", got, delayedBefore2+1)
	}
	if dur2 := time.Since(start2); dur2 < 40*time.Millisecond {
		t.Fatalf("attempt 2 duration = %s, want >= 40ms delayed ack", dur2)
	}

	// Logical batch 2, attempt 3: throttled with ResourceExhausted.
	res3, err := stream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows #3: %v", err)
	}
	if _, err := res3.GetResult(ctx); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("GetResult #3 status = %v, want ResourceExhausted", status.Code(err))
	}

	// Logical batch 2, retry attempt 4: immediate ack without ackDelay (logicalSeq == 2).
	delayedBefore4 := srv.DelayedAcksInjectedForTable("otel_logs")
	res4, err := stream.AppendRows(ctx, [][]byte{encoded})
	if err != nil {
		t.Fatalf("AppendRows #4: %v", err)
	}
	if _, err := res4.GetResult(ctx); err != nil {
		t.Fatalf("GetResult #4: %v", err)
	}
	if got := srv.DelayedAcksInjectedForTable("otel_logs"); got != delayedBefore4 {
		t.Fatalf("attempt 4 DelayedAcksInjectedForTable(otel_logs) = %d, want %d (no ackDelay on logicalSeq 2)", got, delayedBefore4)
	}

	if got := srv.RowCount("otel_logs"); got != 2 {
		t.Fatalf("RowCount(otel_logs) = %d, want 2", got)
	}
}

func TestServerSetPeriodicFaultsMultiStreamIsolation(t *testing.T) {
	srv := NewServer(t)
	ctx := context.Background()

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	stream1, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream(stream1): %v", err)
	}
	t.Cleanup(func() { _ = stream1.Close() })

	stream2, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream(stream2): %v", err)
	}
	t.Cleanup(func() { _ = stream2.Close() })

	ts := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	encodeLog := func(logName string) []byte {
		t.Helper()
		raw, encErr := logEnc.Encode(transform.Row{
			"timestamp":               ts.UnixMicro(),
			"timestamp_source":        "observed",
			"time_unix_nano":          ts.UnixNano(),
			"observed_time_unix_nano": ts.UnixNano(),
			"receive_time":            ts.UnixMicro(),
			"receive_time_unix_nano":  ts.UnixNano(),
			"log_name":                logName,
		})
		if encErr != nil {
			t.Fatalf("Encode(%q): %v", logName, encErr)
		}
		return raw
	}

	warmup1 := [][]byte{encodeLog("projects/test-project/logs/warmup-1")}
	warmup2 := [][]byte{encodeLog("projects/test-project/logs/warmup-2")}
	batchA := [][]byte{encodeLog("projects/test-project/logs/batch-a")}
	batchB := [][]byte{encodeLog("projects/test-project/logs/batch-b")}

	srv.SetPeriodicFaults(ctx, "otel_logs", 3, 50*time.Millisecond)

	// Send 2 non-throttled warmup batches (logicalSeq=1, logicalSeq=2) so logicalSeq=3 is ready.
	for i, wb := range [][][]byte{warmup1, warmup2} {
		res, appendErr := stream1.AppendRows(ctx, wb)
		if appendErr != nil {
			t.Fatalf("warmup #%d AppendRows: %v", i+1, appendErr)
		}
		if _, getErr := res.GetResult(ctx); getErr != nil {
			t.Fatalf("warmup #%d GetResult: %v", i+1, getErr)
		}
	}

	// Send batchA on stream1 (logicalSeq=3, 3%3 == 0) -> ResourceExhausted, queuing 50ms retry delay keyed to hash(batchA).
	resA1, err := stream1.AppendRows(ctx, batchA)
	if err != nil {
		t.Fatalf("batchA attempt 1 AppendRows: %v", err)
	}
	if _, err := resA1.GetResult(ctx); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("batchA attempt 1 GetResult status = %v, want ResourceExhausted", status.Code(err))
	}

	// Send fresh batchB on stream2 (logicalSeq=4) -> succeeds cleanly without stealing batchA's retry delay.
	delayedBeforeB := srv.DelayedAcksInjectedForTable("otel_logs")
	resB, err := stream2.AppendRows(ctx, batchB)
	if err != nil {
		t.Fatalf("batchB AppendRows: %v", err)
	}
	if _, err := resB.GetResult(ctx); err != nil {
		t.Fatalf("batchB GetResult: %v", err)
	}
	if got := srv.DelayedAcksInjectedForTable("otel_logs"); got != delayedBeforeB {
		t.Fatalf("batchB DelayedAcksInjectedForTable(otel_logs) = %d, want %d (must not steal batchA's retry delay)", got, delayedBeforeB)
	}

	// Retry batchA on stream1 -> matches queued 50ms retry delay (>= 40ms) and succeeds.
	delayedBeforeA2 := srv.DelayedAcksInjectedForTable("otel_logs")
	startA2 := time.Now()
	resA2, err := stream1.AppendRows(ctx, batchA)
	if err != nil {
		t.Fatalf("batchA retry AppendRows: %v", err)
	}
	if _, err := resA2.GetResult(ctx); err != nil {
		t.Fatalf("batchA retry GetResult: %v", err)
	}
	if got := srv.DelayedAcksInjectedForTable("otel_logs"); got != delayedBeforeA2+1 {
		t.Fatalf("batchA retry DelayedAcksInjectedForTable(otel_logs) = %d, want %d", got, delayedBeforeA2+1)
	}
	if durA2 := time.Since(startA2); durA2 < 40*time.Millisecond {
		t.Fatalf("batchA retry duration = %s, want >= 40ms delayed ack", durA2)
	}

	if got := srv.RowCount("otel_logs"); got != 4 {
		t.Fatalf("RowCount(otel_logs) = %d, want 4", got)
	}
}

func TestServerUniqueAckedTracking(t *testing.T) {
	srv := NewServer(t)
	srv.SetTrackUniqueAcked(true)
	ctx := context.Background()

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Use an optional-field writer descriptor so a row missing REQUIRED columns
	// passes client encoding and is rejected by bqfake's server-side validation.
	optSchema := &storagepb.TableSchema{
		Fields: func() []*storagepb.TableFieldSchema {
			orig := schema.LogsTableSchema().GetFields()
			out := make([]*storagepb.TableFieldSchema, len(orig))
			for i, f := range orig {
				cp := proto.Clone(f).(*storagepb.TableFieldSchema)
				if cp.GetMode() == storagepb.TableFieldSchema_REQUIRED {
					cp.Mode = storagepb.TableFieldSchema_NULLABLE
				}
				out[i] = cp
			}
			return out
		}(),
	}
	logEnc, err := protoenc.New(optSchema)
	if err != nil {
		t.Fatalf("protoenc.New(optSchema): %v", err)
	}
	stream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	ts := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	row1, err := logEnc.Encode(transform.Row{
		"timestamp":               ts.UnixMicro(),
		"timestamp_source":        "observed",
		"time_unix_nano":          ts.UnixNano(),
		"observed_time_unix_nano": ts.UnixNano(),
		"receive_time":            ts.UnixMicro(),
		"receive_time_unix_nano":  ts.UnixNano(),
		"log_name":                "projects/test-project/logs/row-1",
	})
	if err != nil {
		t.Fatalf("Encode(row1): %v", err)
	}
	row2, err := logEnc.Encode(transform.Row{
		"timestamp":               ts.UnixMicro(),
		"timestamp_source":        "observed",
		"time_unix_nano":          ts.UnixNano(),
		"observed_time_unix_nano": ts.UnixNano(),
		"receive_time":            ts.UnixMicro(),
		"receive_time_unix_nano":  ts.UnixNano(),
		"log_name":                "projects/test-project/logs/row-2-distinct-length",
	})
	if err != nil {
		t.Fatalf("Encode(row2): %v", err)
	}

	// 1. Append row1 twice: total acked is 2x, unique acked stays 1x.
	for i := range 2 {
		res, appendErr := stream.AppendRows(ctx, [][]byte{row1})
		if appendErr != nil {
			t.Fatalf("row1 AppendRows #%d: %v", i+1, appendErr)
		}
		if _, getErr := res.GetResult(ctx); getErr != nil {
			t.Fatalf("row1 GetResult #%d: %v", i+1, getErr)
		}
	}
	_, _, acked := srv.Counts()
	if acked != 2 {
		t.Fatalf("Counts() acked = %d, want 2", acked)
	}
	if got, want := srv.AckedBytes(), 2*int64(len(row1)); got != want {
		t.Fatalf("AckedBytes() = %d, want %d", got, want)
	}
	if got := srv.UniqueAckedRows(); got != 1 {
		t.Fatalf("UniqueAckedRows() = %d, want 1", got)
	}
	if got, want := srv.UniqueAckedBytes(), int64(len(row1)); got != want {
		t.Fatalf("UniqueAckedBytes() = %d, want %d", got, want)
	}

	// 2. Append distinct row2: unique counters advance to include row2.
	res2, err := stream.AppendRows(ctx, [][]byte{row2})
	if err != nil {
		t.Fatalf("row2 AppendRows: %v", err)
	}
	if _, err := res2.GetResult(ctx); err != nil {
		t.Fatalf("row2 GetResult: %v", err)
	}
	if got := srv.UniqueAckedRows(); got != 2 {
		t.Fatalf("UniqueAckedRows() after row2 = %d, want 2", got)
	}
	wantUniqueBytes := int64(len(row1) + len(row2))
	if got := srv.UniqueAckedBytes(); got != wantUniqueBytes {
		t.Fatalf("UniqueAckedBytes() after row2 = %d, want %d", got, wantUniqueBytes)
	}

	// 3. Invalid/rejected row (missing REQUIRED timestamp columns) leaves unique counters unchanged.
	invalidRow, err := logEnc.Encode(transform.Row{
		"log_name": "projects/test-project/logs/missing-required",
	})
	if err != nil {
		t.Fatalf("Encode(invalidRow): %v", err)
	}
	resBad, err := stream.AppendRows(ctx, [][]byte{invalidRow})
	if err != nil {
		t.Fatalf("invalidRow AppendRows: %v", err)
	}
	if _, err := resBad.GetResult(ctx); err == nil {
		t.Fatal("expected invalidRow missing REQUIRED columns to fail")
	}
	if got := srv.UniqueAckedRows(); got != 2 {
		t.Fatalf("UniqueAckedRows() after rejected row = %d, want 2", got)
	}
	if got := srv.UniqueAckedBytes(); got != wantUniqueBytes {
		t.Fatalf("UniqueAckedBytes() after rejected row = %d, want %d", got, wantUniqueBytes)
	}

	// 4. ResetRows() resets unique counters to 0 while keeping tracking enabled.
	srv.ResetRows()
	if got := srv.UniqueAckedRows(); got != 0 {
		t.Fatalf("UniqueAckedRows() after ResetRows = %d, want 0", got)
	}
	if got := srv.UniqueAckedBytes(); got != 0 {
		t.Fatalf("UniqueAckedBytes() after ResetRows = %d, want 0", got)
	}
	resAfterReset, err := stream.AppendRows(ctx, [][]byte{row1})
	if err != nil {
		t.Fatalf("AppendRows after ResetRows: %v", err)
	}
	if _, err := resAfterReset.GetResult(ctx); err != nil {
		t.Fatalf("GetResult after ResetRows: %v", err)
	}
	if got := srv.UniqueAckedRows(); got != 1 {
		t.Fatalf("UniqueAckedRows() on subsequent append after ResetRows = %d, want 1", got)
	}
	if got, want := srv.UniqueAckedBytes(), int64(len(row1)); got != want {
		t.Fatalf("UniqueAckedBytes() on subsequent append after ResetRows = %d, want %d", got, want)
	}

	// 5. SetTrackUniqueAcked(false) resets counters to 0 and keeps them 0 on subsequent appends.
	srv.SetTrackUniqueAcked(false)
	if got := srv.UniqueAckedRows(); got != 0 {
		t.Fatalf("UniqueAckedRows() after SetTrackUniqueAcked(false) = %d, want 0", got)
	}
	if got := srv.UniqueAckedBytes(); got != 0 {
		t.Fatalf("UniqueAckedBytes() after SetTrackUniqueAcked(false) = %d, want 0", got)
	}
	resDisabled, err := stream.AppendRows(ctx, [][]byte{row2})
	if err != nil {
		t.Fatalf("AppendRows with tracking disabled: %v", err)
	}
	if _, err := resDisabled.GetResult(ctx); err != nil {
		t.Fatalf("GetResult with tracking disabled: %v", err)
	}
	if got := srv.UniqueAckedRows(); got != 0 {
		t.Fatalf("UniqueAckedRows() while disabled = %d, want 0", got)
	}
	if got := srv.UniqueAckedBytes(); got != 0 {
		t.Fatalf("UniqueAckedBytes() while disabled = %d, want 0", got)
	}

	t.Run("UpdatedReceiveTimeReplayDeduplicated", func(t *testing.T) {
		srv.ResetRows()
		srv.SetTrackUniqueAcked(true)

		ts2 := ts.Add(5 * time.Second)
		row1Updated, encErr := logEnc.Encode(transform.Row{
			"timestamp":               ts.UnixMicro(),
			"timestamp_source":        "observed",
			"time_unix_nano":          ts.UnixNano(),
			"observed_time_unix_nano": ts.UnixNano(),
			"receive_time":            ts2.UnixMicro(),
			"receive_time_unix_nano":  ts2.UnixNano(),
			"log_name":                "projects/test-project/logs/row-1",
		})
		if encErr != nil {
			t.Fatalf("Encode(row1Updated): %v", encErr)
		}
		if bytes.Equal(row1, row1Updated) {
			t.Fatal("expected updated receive_time wire bytes to differ from initial encoding")
		}

		for i, candidate := range [][]byte{row1, row1Updated} {
			res, appendErr := stream.AppendRows(ctx, [][]byte{candidate})
			if appendErr != nil {
				t.Fatalf("AppendRows #%d: %v", i+1, appendErr)
			}
			if _, getErr := res.GetResult(ctx); getErr != nil {
				t.Fatalf("GetResult #%d: %v", i+1, getErr)
			}
		}

		_, _, ackedRows := srv.Counts()
		if ackedRows != 2 {
			t.Fatalf("Counts() acked = %d, want 2", ackedRows)
		}
		if got, want := srv.AckedBytes(), int64(len(row1)+len(row1Updated)); got != want {
			t.Fatalf("AckedBytes() = %d, want %d", got, want)
		}
		if got := srv.UniqueAckedRows(); got != 1 {
			t.Fatalf("UniqueAckedRows() = %d, want 1", got)
		}
		if got, want := srv.UniqueAckedBytes(), int64(len(row1)); got != want {
			t.Fatalf("UniqueAckedBytes() = %d, want %d", got, want)
		}
	})
}

func TestServerSetPeriodicFaultsRetryWithUpdatedReceiveTime(t *testing.T) {
	eventTS := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	ts1 := eventTS
	ts2 := ts1.Add(5 * time.Second)

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	encodeLogAt := func(t *testing.T, logName string, recvTS time.Time) []byte {
		t.Helper()
		raw, encErr := logEnc.Encode(transform.Row{
			"timestamp":               eventTS.UnixMicro(),
			"timestamp_source":        "observed",
			"time_unix_nano":          eventTS.UnixNano(),
			"observed_time_unix_nano": eventTS.UnixNano(),
			"receive_time":            recvTS.UnixMicro(),
			"receive_time_unix_nano":  recvTS.UnixNano(),
			"log_name":                logName,
		})
		if encErr != nil {
			t.Fatalf("Encode(%q): %v", logName, encErr)
		}
		return raw
	}

	t.Run("throttleEvery1", func(t *testing.T) {
		srv := NewServer(t)
		ctx := context.Background()

		client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
		if err != nil {
			t.Fatalf("managedwriter.NewClient: %v", err)
		}
		t.Cleanup(func() { _ = client.Close() })

		stream, err := client.NewManagedStream(ctx,
			managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
			managedwriter.WithType(managedwriter.DefaultStream),
			managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
		)
		if err != nil {
			t.Fatalf("NewManagedStream: %v", err)
		}
		t.Cleanup(func() { _ = stream.Close() })

		srv.SetPeriodicFaults(ctx, "otel_logs", 1, 50*time.Millisecond)

		batchA1 := [][]byte{encodeLogAt(t, "projects/test-project/logs/batch-a", ts1)}
		batchA2 := [][]byte{encodeLogAt(t, "projects/test-project/logs/batch-a", ts2)}
		if bytes.Equal(batchA1[0], batchA2[0]) {
			t.Fatal("expected batchA wire bytes at ts1 and ts2 to differ")
		}

		// Batch A attempt 1 (logicalSeq=1): throttled and queues 50ms retry delay.
		resA1, err := stream.AppendRows(ctx, batchA1)
		if err != nil {
			t.Fatalf("batchA attempt 1 AppendRows: %v", err)
		}
		if _, err := resA1.GetResult(ctx); status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("batchA attempt 1 status = %v, want ResourceExhausted", status.Code(err))
		}

		// Batch A retry with updated receive_time matches pendingRetries and takes >= 40ms.
		startA2 := time.Now()
		resA2, err := stream.AppendRows(ctx, batchA2)
		if err != nil {
			t.Fatalf("batchA retry AppendRows: %v", err)
		}
		if _, err := resA2.GetResult(ctx); err != nil {
			t.Fatalf("batchA retry GetResult: %v", err)
		}
		if durA2 := time.Since(startA2); durA2 < 40*time.Millisecond {
			t.Fatalf("batchA retry duration = %s, want >= 40ms delayed ack", durA2)
		}
		if got := srv.RowCount("otel_logs"); got != 1 {
			t.Fatalf("RowCount(otel_logs) after batchA = %d, want 1", got)
		}

		// Distinct batch B still gets throttled on attempt 1, then succeeds on retry with updated receive_time.
		batchB1 := [][]byte{encodeLogAt(t, "projects/test-project/logs/batch-b", ts1)}
		batchB2 := [][]byte{encodeLogAt(t, "projects/test-project/logs/batch-b", ts2)}
		if bytes.Equal(batchB1[0], batchB2[0]) {
			t.Fatal("expected batchB wire bytes at ts1 and ts2 to differ")
		}

		resB1, err := stream.AppendRows(ctx, batchB1)
		if err != nil {
			t.Fatalf("batchB attempt 1 AppendRows: %v", err)
		}
		if _, err := resB1.GetResult(ctx); status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("batchB attempt 1 status = %v, want ResourceExhausted", status.Code(err))
		}

		resB2, err := stream.AppendRows(ctx, batchB2)
		if err != nil {
			t.Fatalf("batchB retry AppendRows: %v", err)
		}
		if _, err := resB2.GetResult(ctx); err != nil {
			t.Fatalf("batchB retry GetResult: %v", err)
		}
		if got := srv.RowCount("otel_logs"); got != 2 {
			t.Fatalf("RowCount(otel_logs) after batchB = %d, want 2", got)
		}
	})

	t.Run("throttleEvery2WithAckDelay", func(t *testing.T) {
		srv := NewServer(t)
		ctx := context.Background()

		client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
		if err != nil {
			t.Fatalf("managedwriter.NewClient: %v", err)
		}
		t.Cleanup(func() { _ = client.Close() })

		stream1, err := client.NewManagedStream(ctx,
			managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
			managedwriter.WithType(managedwriter.DefaultStream),
			managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
		)
		if err != nil {
			t.Fatalf("NewManagedStream(stream1): %v", err)
		}
		t.Cleanup(func() { _ = stream1.Close() })

		stream2, err := client.NewManagedStream(ctx,
			managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
			managedwriter.WithType(managedwriter.DefaultStream),
			managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
		)
		if err != nil {
			t.Fatalf("NewManagedStream(stream2): %v", err)
		}
		t.Cleanup(func() { _ = stream2.Close() })

		srv.SetPeriodicFaults(ctx, "otel_logs", 2, 50*time.Millisecond)

		// Advance warmups to logicalSeq=5; logicalSeq 2 and 4 throttle and are retried cleanly.
		for seq := 1; seq <= 5; seq++ {
			warmupName := "projects/test-project/logs/warmup-" + strconv.Itoa(seq)
			wb := [][]byte{encodeLogAt(t, warmupName, ts1)}
			res, appendErr := stream1.AppendRows(ctx, wb)
			if appendErr != nil {
				t.Fatalf("warmup #%d AppendRows: %v", seq, appendErr)
			}
			_, getErr := res.GetResult(ctx)
			if seq%2 == 0 {
				if status.Code(getErr) != codes.ResourceExhausted {
					t.Fatalf("warmup #%d attempt 1 status = %v, want ResourceExhausted", seq, status.Code(getErr))
				}
				retryWB := [][]byte{encodeLogAt(t, warmupName, ts2)}
				retryRes, retryAppendErr := stream1.AppendRows(ctx, retryWB)
				if retryAppendErr != nil {
					t.Fatalf("warmup #%d retry AppendRows: %v", seq, retryAppendErr)
				}
				if _, retryGetErr := retryRes.GetResult(ctx); retryGetErr != nil {
					t.Fatalf("warmup #%d retry GetResult: %v", seq, retryGetErr)
				}
				continue
			}
			if getErr != nil {
				t.Fatalf("warmup #%d GetResult: %v", seq, getErr)
			}
		}

		// logicalSeq=6 (6%2==0 && 6%3==0): throttles batchA and queues 50ms delayed ack on retry.
		batchA1 := [][]byte{encodeLogAt(t, "projects/test-project/logs/batch-a", ts1)}
		batchA2 := [][]byte{encodeLogAt(t, "projects/test-project/logs/batch-a", ts2)}
		if bytes.Equal(batchA1[0], batchA2[0]) {
			t.Fatal("expected batchA wire bytes at ts1 and ts2 to differ")
		}
		resA1, err := stream1.AppendRows(ctx, batchA1)
		if err != nil {
			t.Fatalf("batchA attempt 1 AppendRows: %v", err)
		}
		if _, err := resA1.GetResult(ctx); status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("batchA attempt 1 status = %v, want ResourceExhausted", status.Code(err))
		}

		// logicalSeq=7 on stream2 (7%2 != 0 && 7%3 != 0): succeeds cleanly without stealing batchA's retry entry.
		batchB := [][]byte{encodeLogAt(t, "projects/test-project/logs/batch-b", ts1)}
		delayedBeforeB := srv.DelayedAcksInjectedForTable("otel_logs")
		resB, err := stream2.AppendRows(ctx, batchB)
		if err != nil {
			t.Fatalf("batchB AppendRows: %v", err)
		}
		if _, err := resB.GetResult(ctx); err != nil {
			t.Fatalf("batchB GetResult: %v", err)
		}
		if got := srv.DelayedAcksInjectedForTable("otel_logs"); got != delayedBeforeB {
			t.Fatalf("batchB DelayedAcksInjectedForTable(otel_logs) = %d, want %d (must not steal batchA's retry delay)", got, delayedBeforeB)
		}

		// Retry batchA on stream1 with updated receive_time: matches pendingRetries, takes >= 40ms, and succeeds.
		delayedBeforeA2 := srv.DelayedAcksInjectedForTable("otel_logs")
		startA2 := time.Now()
		resA2, err := stream1.AppendRows(ctx, batchA2)
		if err != nil {
			t.Fatalf("batchA retry AppendRows: %v", err)
		}
		if _, err := resA2.GetResult(ctx); err != nil {
			t.Fatalf("batchA retry GetResult: %v", err)
		}
		if got := srv.DelayedAcksInjectedForTable("otel_logs"); got != delayedBeforeA2+1 {
			t.Fatalf("batchA retry DelayedAcksInjectedForTable(otel_logs) = %d, want %d", got, delayedBeforeA2+1)
		}
		if durA2 := time.Since(startA2); durA2 < 40*time.Millisecond {
			t.Fatalf("batchA retry duration = %s, want >= 40ms delayed ack", durA2)
		}

		if got := srv.RowCount("otel_logs"); got != 7 {
			t.Fatalf("RowCount(otel_logs) = %d, want 7", got)
		}
	})
}

func TestHashCanonicalRowIgnoresIngestionTimestampsAndMalformedWire(t *testing.T) {
	if got := ingestionTimestampFieldNumbers(nil); got != ([3]protowire.Number{}) {
		t.Fatalf("ingestionTimestampFieldNumbers(nil) = %v, want zero array", got)
	}

	// 1. Quarantine descriptor: changing ingest_time across varint byte boundaries keeps hashes identical.
	qEnc, err := protoenc.New(schema.QuarantineTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(QuarantineTableSchema): %v", err)
	}
	qMD, err := descriptorFromProto(qEnc.Descriptor())
	if err != nil {
		t.Fatalf("descriptorFromProto(quarantine): %v", err)
	}
	qIgnore := ingestionTimestampFieldNumbers(qMD)
	if qIgnore[2] == 0 {
		t.Fatalf("quarantine ignore fields = %v, want non-zero ingest_time field number", qIgnore)
	}
	qSmall, err := qEnc.Encode(transform.Row{
		"ingest_time":   int64(1),
		"signal":        schema.SignalSpans,
		"error_code":    "INVALID_SPAN_ID",
		"error_message": "bad span",
	})
	if err != nil {
		t.Fatalf("Encode(qSmall): %v", err)
	}
	qLarge, err := qEnc.Encode(transform.Row{
		"ingest_time":   int64(1_786_545_310_000_000),
		"signal":        schema.SignalSpans,
		"error_code":    "INVALID_SPAN_ID",
		"error_message": "bad span",
	})
	if err != nil {
		t.Fatalf("Encode(qLarge): %v", err)
	}
	if len(qSmall) == len(qLarge) {
		t.Fatalf("expected varint length difference between qSmall (%d) and qLarge (%d)", len(qSmall), len(qLarge))
	}
	if got1, got2 := hashCanonicalRow(qSmall, qIgnore), hashCanonicalRow(qLarge, qIgnore); got1 != got2 {
		t.Fatalf("hashCanonicalRow quarantine mismatch across ingest_time varint boundary: %x != %x", got1, got2)
	}
	if got1, got2 := hashSerializedRows([][]byte{qSmall}, qIgnore), hashSerializedRows([][]byte{qLarge}, qIgnore); got1 != got2 {
		t.Fatalf("hashSerializedRows quarantine mismatch across ingest_time varint boundary: %x != %x", got1, got2)
	}

	// 2. Logs descriptor: changing receive_time & receive_time_unix_nano keeps hashes identical; changing log_name changes hash.
	lEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	lMD, err := descriptorFromProto(lEnc.Descriptor())
	if err != nil {
		t.Fatalf("descriptorFromProto(logs): %v", err)
	}
	lIgnore := ingestionTimestampFieldNumbers(lMD)
	if lIgnore[0] == 0 || lIgnore[1] == 0 {
		t.Fatalf("logs ignore fields = %v, want non-zero receive_time and receive_time_unix_nano", lIgnore)
	}
	baseTS := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	lRow1, err := lEnc.Encode(transform.Row{
		"timestamp":               baseTS.UnixMicro(),
		"timestamp_source":        "observed",
		"time_unix_nano":          baseTS.UnixNano(),
		"observed_time_unix_nano": baseTS.UnixNano(),
		"receive_time":            int64(1),
		"receive_time_unix_nano":  int64(1000),
		"log_name":                "projects/test-project/logs/a",
	})
	if err != nil {
		t.Fatalf("Encode(lRow1): %v", err)
	}
	lRow2, err := lEnc.Encode(transform.Row{
		"timestamp":               baseTS.UnixMicro(),
		"timestamp_source":        "observed",
		"time_unix_nano":          baseTS.UnixNano(),
		"observed_time_unix_nano": baseTS.UnixNano(),
		"receive_time":            int64(1_786_545_310_000_000),
		"receive_time_unix_nano":  int64(1_786_545_310_000_000_000),
		"log_name":                "projects/test-project/logs/a",
	})
	if err != nil {
		t.Fatalf("Encode(lRow2): %v", err)
	}
	lRowDiff, err := lEnc.Encode(transform.Row{
		"timestamp":               baseTS.UnixMicro(),
		"timestamp_source":        "observed",
		"time_unix_nano":          baseTS.UnixNano(),
		"observed_time_unix_nano": baseTS.UnixNano(),
		"receive_time":            int64(1_786_545_310_000_000),
		"receive_time_unix_nano":  int64(1_786_545_310_000_000_000),
		"log_name":                "projects/test-project/logs/b",
	})
	if err != nil {
		t.Fatalf("Encode(lRowDiff): %v", err)
	}
	if got1, got2 := hashCanonicalRow(lRow1, lIgnore), hashCanonicalRow(lRow2, lIgnore); got1 != got2 {
		t.Fatalf("hashCanonicalRow logs mismatch across receive_time update: %x != %x", got1, got2)
	}
	if got1, got2 := hashSerializedRows([][]byte{lRow1}, lIgnore), hashSerializedRows([][]byte{lRow2}, lIgnore); got1 != got2 {
		t.Fatalf("hashSerializedRows logs mismatch across receive_time update: %x != %x", got1, got2)
	}
	if hashCanonicalRow(lRow1, lIgnore) == hashCanonicalRow(lRowDiff, lIgnore) {
		t.Fatal("expected distinct log_name to produce distinct canonical row hash")
	}

	// 3. Malformed truncated wire bytes with non-zero ignore return deterministically without panicking.
	malformedTag := []byte{0x80}
	malformedVal := append(protowire.AppendTag(nil, 99, protowire.BytesType), 0x10, 'x')
	truncLen := len(lRow1) - 1
	for _, sample := range [][]byte{malformedTag, malformedVal, lRow1[:truncLen]} {
		if got1, got2 := hashCanonicalRow(sample, lIgnore), hashCanonicalRow(sample, lIgnore); got1 != got2 {
			t.Fatalf("non-deterministic hash for malformed wire %x: %x != %x", sample, got1, got2)
		}
	}
	if hashCanonicalRow(malformedTag, lIgnore) == hashCanonicalRow(malformedVal, lIgnore) {
		t.Fatal("expected distinct malformed wire payloads to hash distinctly")
	}
}

func TestPerTableAckedAndUniqueCountersIsolation(t *testing.T) {
	srv := NewServer(t)
	srv.SetTrackUniqueAcked(true)
	if err := srv.RegisterTableSchema("otel_logs_shadow", schema.LogsTableSchema()); err != nil {
		t.Fatalf("RegisterTableSchema(otel_logs_shadow): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	qEnc, err := protoenc.New(schema.QuarantineTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(QuarantineTableSchema): %v", err)
	}

	openStream := func(table string, desc *descriptorpb.DescriptorProto) *managedwriter.ManagedStream {
		t.Helper()
		st, sErr := client.NewManagedStream(ctx,
			managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/"+table),
			managedwriter.WithType(managedwriter.DefaultStream),
			managedwriter.WithSchemaDescriptor(desc),
		)
		if sErr != nil {
			t.Fatalf("NewManagedStream(%s): %v", table, sErr)
		}
		t.Cleanup(func() { _ = st.Close() })
		return st
	}

	logStream := openStream("otel_logs", logEnc.Descriptor())
	shadowStream := openStream("otel_logs_shadow", logEnc.Descriptor())
	qStream := openStream("otel_quarantine", qEnc.Descriptor())

	appendBatch := func(st *managedwriter.ManagedStream, rows ...[]byte) {
		t.Helper()
		res, aErr := st.AppendRows(ctx, rows)
		if aErr != nil {
			t.Fatalf("AppendRows: %v", aErr)
		}
		if _, gErr := res.GetResult(ctx); gErr != nil {
			t.Fatalf("GetResult: %v", gErr)
		}
	}

	baseTS := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	logRow1, err := logEnc.Encode(transform.Row{
		"timestamp":               baseTS.UnixMicro(),
		"timestamp_source":        "observed",
		"time_unix_nano":          baseTS.UnixNano(),
		"observed_time_unix_nano": baseTS.UnixNano(),
		"receive_time":            int64(1),
		"receive_time_unix_nano":  int64(1000),
		"log_name":                "projects/test-project/logs/primary-a",
	})
	if err != nil {
		t.Fatalf("Encode(logRow1): %v", err)
	}
	logRow1Replay, err := logEnc.Encode(transform.Row{
		"timestamp":               baseTS.UnixMicro(),
		"timestamp_source":        "observed",
		"time_unix_nano":          baseTS.UnixNano(),
		"observed_time_unix_nano": baseTS.UnixNano(),
		"receive_time":            int64(1_786_545_310_000_000),
		"receive_time_unix_nano":  int64(1_786_545_310_000_000_000),
		"log_name":                "projects/test-project/logs/primary-a",
	})
	if err != nil {
		t.Fatalf("Encode(logRow1Replay): %v", err)
	}
	logRow2, err := logEnc.Encode(transform.Row{
		"timestamp":               baseTS.UnixMicro(),
		"timestamp_source":        "observed",
		"time_unix_nano":          baseTS.UnixNano(),
		"observed_time_unix_nano": baseTS.UnixNano(),
		"receive_time":            int64(1),
		"receive_time_unix_nano":  int64(1000),
		"log_name":                "projects/test-project/logs/primary-b",
	})
	if err != nil {
		t.Fatalf("Encode(logRow2): %v", err)
	}

	qRow1, err := qEnc.Encode(transform.Row{
		"ingest_time":   int64(1),
		"signal":        schema.SignalLogs,
		"error_code":    "INVALID_UTF8",
		"error_message": "bad utf8 in log body",
	})
	if err != nil {
		t.Fatalf("Encode(qRow1): %v", err)
	}
	qRow1Replay, err := qEnc.Encode(transform.Row{
		"ingest_time":   int64(1_786_545_310_000_000),
		"signal":        schema.SignalLogs,
		"error_code":    "INVALID_UTF8",
		"error_message": "bad utf8 in log body",
	})
	if err != nil {
		t.Fatalf("Encode(qRow1Replay): %v", err)
	}
	qRow2, err := qEnc.Encode(transform.Row{
		"ingest_time":   int64(1),
		"signal":        schema.SignalLogs,
		"error_code":    "OVERSIZE_ROW",
		"error_message": "row exceeds limit",
	})
	if err != nil {
		t.Fatalf("Encode(qRow2): %v", err)
	}

	appendBatch(logStream, logRow1, logRow2)
	appendBatch(logStream, logRow1Replay)
	appendBatch(qStream, qRow1, qRow2)
	appendBatch(qStream, qRow1Replay)
	// Append exact identical row bytes to otel_logs_shadow to confirm per-table
	// seenAckedRowsByTable does not suppress unique counts on a second table.
	appendBatch(shadowStream, logRow1)

	wantLogsAckedBytes := int64(len(logRow1) + len(logRow2) + len(logRow1Replay))
	wantLogsUniqueBytes := int64(len(logRow1) + len(logRow2))
	wantQuarAckedBytes := int64(len(qRow1) + len(qRow2) + len(qRow1Replay))
	wantQuarUniqueBytes := int64(len(qRow1) + len(qRow2))

	if got := srv.AckedRowsForTable("otel_logs"); got != 3 {
		t.Fatalf("AckedRowsForTable(otel_logs) = %d, want 3", got)
	}
	if got := srv.AckedBytesForTable("otel_logs"); got != wantLogsAckedBytes {
		t.Fatalf("AckedBytesForTable(otel_logs) = %d, want %d", got, wantLogsAckedBytes)
	}
	if got := srv.UniqueAckedRowsForTable("otel_logs"); got != 2 {
		t.Fatalf("UniqueAckedRowsForTable(otel_logs) = %d, want 2", got)
	}
	if got := srv.UniqueAckedBytesForTable("otel_logs"); got != wantLogsUniqueBytes {
		t.Fatalf("UniqueAckedBytesForTable(otel_logs) = %d, want %d", got, wantLogsUniqueBytes)
	}

	if got := srv.AckedRowsForTable("otel_quarantine"); got != 3 {
		t.Fatalf("AckedRowsForTable(otel_quarantine) = %d, want 3", got)
	}
	if got := srv.AckedBytesForTable("otel_quarantine"); got != wantQuarAckedBytes {
		t.Fatalf("AckedBytesForTable(otel_quarantine) = %d, want %d", got, wantQuarAckedBytes)
	}
	if got := srv.UniqueAckedRowsForTable("otel_quarantine"); got != 2 {
		t.Fatalf("UniqueAckedRowsForTable(otel_quarantine) = %d, want 2", got)
	}
	if got := srv.UniqueAckedBytesForTable("otel_quarantine"); got != wantQuarUniqueBytes {
		t.Fatalf("UniqueAckedBytesForTable(otel_quarantine) = %d, want %d", got, wantQuarUniqueBytes)
	}

	if got := srv.AckedRowsForTable("otel_logs_shadow"); got != 1 {
		t.Fatalf("AckedRowsForTable(otel_logs_shadow) = %d, want 1", got)
	}
	if got := srv.UniqueAckedRowsForTable("otel_logs_shadow"); got != 1 {
		t.Fatalf("UniqueAckedRowsForTable(otel_logs_shadow) = %d, want 1", got)
	}
	if got := srv.UniqueAckedBytesForTable("otel_logs_shadow"); got != int64(len(logRow1)) {
		t.Fatalf("UniqueAckedBytesForTable(otel_logs_shadow) = %d, want %d", got, len(logRow1))
	}

	if srv.AckedRowsForTable("otel_spans") != 0 || srv.AckedBytesForTable("otel_spans") != 0 ||
		srv.UniqueAckedRowsForTable("otel_spans") != 0 || srv.UniqueAckedBytesForTable("otel_spans") != 0 {
		t.Fatal("expected untouched table otel_spans to have zero per-table counters")
	}

	// SetTrackUniqueAcked(false) clears unique maps while preserving total per-table acks.
	srv.SetTrackUniqueAcked(false)
	if srv.UniqueAckedRowsForTable("otel_logs") != 0 || srv.UniqueAckedBytesForTable("otel_logs") != 0 ||
		srv.UniqueAckedRowsForTable("otel_quarantine") != 0 || srv.UniqueAckedBytesForTable("otel_quarantine") != 0 {
		t.Fatal("expected SetTrackUniqueAcked(false) to zero per-table unique counters")
	}
	if got := srv.AckedRowsForTable("otel_logs"); got != 3 {
		t.Fatalf("AckedRowsForTable(otel_logs) after SetTrackUniqueAcked(false) = %d, want 3", got)
	}
	if got := srv.AckedBytesForTable("otel_quarantine"); got != wantQuarAckedBytes {
		t.Fatalf("AckedBytesForTable(otel_quarantine) after SetTrackUniqueAcked(false) = %d, want %d", got, wantQuarAckedBytes)
	}

	// Re-enabling unique tracking starts fresh per-table unique state, and ResetRows clears all per-table maps.
	srv.SetTrackUniqueAcked(true)
	appendBatch(logStream, logRow1)
	if got := srv.UniqueAckedRowsForTable("otel_logs"); got != 1 {
		t.Fatalf("UniqueAckedRowsForTable(otel_logs) after re-enabling = %d, want 1", got)
	}
	if got := srv.AckedRowsForTable("otel_logs"); got != 4 {
		t.Fatalf("AckedRowsForTable(otel_logs) = %d, want 4", got)
	}

	srv.ResetRows()
	for _, tbl := range []string{"otel_logs", "otel_quarantine", "otel_logs_shadow"} {
		if srv.AckedRowsForTable(tbl) != 0 || srv.AckedBytesForTable(tbl) != 0 ||
			srv.UniqueAckedRowsForTable(tbl) != 0 || srv.UniqueAckedBytesForTable(tbl) != 0 {
			t.Fatalf("expected ResetRows to clear all per-table counters for %s", tbl)
		}
	}
	appendBatch(logStream, logRow1)
	if srv.AckedRowsForTable("otel_logs") != 1 || srv.UniqueAckedRowsForTable("otel_logs") != 1 {
		t.Fatalf("expected post-ResetRows append to record 1 acked and 1 unique row, got acked=%d unique=%d",
			srv.AckedRowsForTable("otel_logs"), srv.UniqueAckedRowsForTable("otel_logs"))
	}

	srv.SetTrackUniqueAcked(false)
	srv.ResetRows()
	srv.mu.Lock()
	seenByTableNil := srv.seenAckedRowsByTable == nil
	srv.mu.Unlock()
	if !seenByTableNil {
		t.Fatal("expected ResetRows with trackUniqueAcked=false to leave seenAckedRowsByTable nil")
	}
}

func TestPeriodicThrottlesInjectedPerTableAndNoFaultFastPath(t *testing.T) {
	srv := NewServer(t)
	if srv.hasPeriodicFaults.Load() {
		t.Fatal("expected hasPeriodicFaults to default to false on new Server")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	qEnc, err := protoenc.New(schema.QuarantineTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(QuarantineTableSchema): %v", err)
	}

	logStream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream(otel_logs): %v", err)
	}
	t.Cleanup(func() { _ = logStream.Close() })

	qStream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_quarantine"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(qEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream(otel_quarantine): %v", err)
	}
	t.Cleanup(func() { _ = qStream.Close() })

	baseTS := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	makeLogRow := func(seq int) ([]byte, error) {
		return logEnc.Encode(transform.Row{
			"timestamp":               baseTS.UnixMicro(),
			"timestamp_source":        "observed",
			"time_unix_nano":          baseTS.UnixNano(),
			"observed_time_unix_nano": baseTS.UnixNano(),
			"receive_time":            int64(1),
			"receive_time_unix_nano":  int64(1000),
			"log_name":                "projects/test-project/logs/item-" + strconv.Itoa(seq),
		})
	}
	mustLogRow := func(seq int) []byte {
		t.Helper()
		b, encErr := makeLogRow(seq)
		if encErr != nil {
			t.Fatalf("Encode log row %d: %v", seq, encErr)
		}
		return b
	}
	mustQuarRow := func(seq int) []byte {
		t.Helper()
		b, encErr := qEnc.Encode(transform.Row{
			"ingest_time":   int64(1),
			"signal":        schema.SignalLogs,
			"error_code":    "INVALID_UTF8",
			"error_message": "err-" + strconv.Itoa(seq),
		})
		if encErr != nil {
			t.Fatalf("Encode quarantine row %d: %v", seq, encErr)
		}
		return b
	}
	appendRetryThrottle := func(st *managedwriter.ManagedStream, row []byte) (throttled bool, retErr error) {
		for attempt := range 4 {
			res, aErr := st.AppendRows(ctx, [][]byte{row})
			if aErr != nil {
				return throttled, aErr
			}
			_, gErr := res.GetResult(ctx)
			if gErr == nil {
				return throttled, nil
			}
			if status.Code(gErr) == codes.ResourceExhausted && attempt < 3 {
				throttled = true
				continue
			}
			return throttled, gErr
		}
		return throttled, nil
	}
	mustAppend := func(st *managedwriter.ManagedStream, row []byte) bool {
		t.Helper()
		throttled, aErr := appendRetryThrottle(st, row)
		if aErr != nil {
			t.Fatalf("appendRetryThrottle: %v", aErr)
		}
		return throttled
	}

	// 1. No-fault fast path (hasPeriodicFaults == false): zero throttles, clean acks.
	if mustAppend(logStream, mustLogRow(0)) {
		t.Fatal("unexpected throttle on otel_logs no-fault path")
	}
	if mustAppend(qStream, mustQuarRow(0)) {
		t.Fatal("unexpected throttle on otel_quarantine no-fault path")
	}
	if srv.hasPeriodicFaults.Load() {
		t.Fatal("expected hasPeriodicFaults to remain false on no-fault path")
	}
	if srv.PeriodicThrottlesInjected("") != 0 || srv.PeriodicThrottlesInjected("otel_logs") != 0 {
		t.Fatalf("expected 0 periodic throttles on no-fault path, got total=%d logs=%d",
			srv.PeriodicThrottlesInjected(""), srv.PeriodicThrottlesInjected("otel_logs"))
	}

	// 2. Throttle otel_logs only: otel_logs and "" increment; otel_quarantine stays 0.
	srv.SetPeriodicFaults(ctx, "otel_logs", 1, 0)
	if !srv.hasPeriodicFaults.Load() {
		t.Fatal("expected hasPeriodicFaults=true after SetPeriodicFaults")
	}
	if !mustAppend(logStream, mustLogRow(1)) {
		t.Fatal("expected throttle on otel_logs row 1")
	}
	if !mustAppend(logStream, mustLogRow(2)) {
		t.Fatal("expected throttle on otel_logs row 2")
	}
	if mustAppend(qStream, mustQuarRow(1)) {
		t.Fatal("unexpected throttle on unthrottled otel_quarantine")
	}

	if got := srv.PeriodicThrottlesInjected("otel_logs"); got != 2 {
		t.Fatalf("PeriodicThrottlesInjected(otel_logs) = %d, want 2", got)
	}
	if got := srv.PeriodicThrottlesInjected("otel_quarantine"); got != 0 {
		t.Fatalf("PeriodicThrottlesInjected(otel_quarantine) = %d, want 0", got)
	}
	if got := srv.PeriodicThrottlesInjected(""); got != 2 {
		t.Fatalf("PeriodicThrottlesInjected(\"\") = %d, want 2", got)
	}

	// 3. Add periodic fault on otel_quarantine; verify aggregate sum across tables and selective clear.
	srv.SetPeriodicFaults(ctx, "otel_quarantine", 1, 0)
	if !mustAppend(qStream, mustQuarRow(2)) {
		t.Fatal("expected throttle on otel_quarantine row 2")
	}
	if got := srv.PeriodicThrottlesInjected("otel_quarantine"); got != 1 {
		t.Fatalf("PeriodicThrottlesInjected(otel_quarantine) = %d, want 1", got)
	}
	if got := srv.PeriodicThrottlesInjected(""); got != 3 {
		t.Fatalf("PeriodicThrottlesInjected(\"\") = %d, want 3", got)
	}

	srv.SetPeriodicFaults(ctx, "otel_logs", 0, 0)
	if got := srv.PeriodicThrottlesInjected("otel_logs"); got != 0 {
		t.Fatalf("expected SetPeriodicFaults reset to clear otel_logs count, got %d", got)
	}
	if got := srv.PeriodicThrottlesInjected("otel_quarantine"); got != 1 {
		t.Fatalf("expected otel_quarantine count preserved at 1, got %d", got)
	}
	if !srv.hasPeriodicFaults.Load() {
		t.Fatal("expected hasPeriodicFaults=true while otel_quarantine periodic fault remains active")
	}

	srv.SetPeriodicFaults(ctx, "otel_quarantine", 0, 0)
	if srv.hasPeriodicFaults.Load() {
		t.Fatal("expected hasPeriodicFaults=false once all periodic faults are cleared")
	}
	if got := srv.PeriodicThrottlesInjected(""); got != 0 {
		t.Fatalf("PeriodicThrottlesInjected(\"\") after clearing both tables = %d, want 0", got)
	}

	// 4. Exercise lazy batchKey computation in popMatchingFaultLocked (when hasPeriodicFaults
	// flipped between Load() and s.mu.Lock()) and context expiry resetting hasPeriodicFaults.
	expCtx, expCancel := context.WithCancel(ctx)
	srv.SetPeriodicFaults(expCtx, "", 1, 0)
	lazyRows := [][]byte{mustLogRow(99)}
	srv.mu.Lock()
	f1 := srv.popMatchingFaultLocked("otel_logs", [32]byte{}, false, lazyRows, [3]protowire.Number{})
	f2 := srv.popMatchingFaultLocked("otel_logs", [32]byte{}, false, lazyRows, [3]protowire.Number{})
	srv.mu.Unlock()
	if f1.Mode != FaultResourceExhausted {
		t.Fatalf("lazy first attempt fault = %v, want FaultResourceExhausted", f1.Mode)
	}
	if f2.Mode != FaultNone {
		t.Fatalf("lazy retry fault = %v, want FaultNone", f2.Mode)
	}
	if got := srv.PeriodicThrottlesInjected("otel_logs"); got != 1 {
		t.Fatalf("PeriodicThrottlesInjected(otel_logs) after lazy throttle = %d, want 1", got)
	}

	srv.ResetRows()
	if got := srv.PeriodicThrottlesInjected(""); got != 0 {
		t.Fatalf("PeriodicThrottlesInjected(\"\") after ResetRows = %d, want 0", got)
	}

	expCancel()
	if mustAppend(logStream, mustLogRow(3)) {
		t.Fatal("unexpected throttle from canceled periodic fault context")
	}
	if srv.hasPeriodicFaults.Load() {
		t.Fatal("expected expired periodic fault context to reset hasPeriodicFaults=false")
	}

	// 5. Concurrent appends while SetPeriodicFaults toggles on and off.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 20 {
			row, encErr := makeLogRow(100 + i)
			if encErr != nil {
				t.Errorf("Encode concurrent log row %d: %v", i, encErr)
				return
			}
			if _, aErr := appendRetryThrottle(logStream, row); aErr != nil {
				t.Errorf("concurrent append %d: %v", i, aErr)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := range 10 {
			if i%2 == 0 {
				srv.SetPeriodicFaults(ctx, "otel_logs", 2, 0)
			} else {
				srv.SetPeriodicFaults(ctx, "otel_logs", 0, 0)
			}
		}
		srv.SetPeriodicFaults(ctx, "otel_logs", 0, 0)
	}()
	wg.Wait()
	if srv.hasPeriodicFaults.Load() {
		t.Fatal("expected hasPeriodicFaults=false after concurrent toggle loop")
	}
}

func TestServerFaultCommitThenStreamClosed(t *testing.T) {
	srv := NewServer(t)
	srv.SetTrackUniqueAcked(true)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Use an optional-field writer descriptor so both valid rows and rows missing
	// REQUIRED columns can be encoded client-side and validated by bqfake.
	optSchema := &storagepb.TableSchema{
		Fields: func() []*storagepb.TableFieldSchema {
			orig := schema.LogsTableSchema().GetFields()
			out := make([]*storagepb.TableFieldSchema, len(orig))
			for i, f := range orig {
				cp := proto.Clone(f).(*storagepb.TableFieldSchema)
				if cp.GetMode() == storagepb.TableFieldSchema_REQUIRED {
					cp.Mode = storagepb.TableFieldSchema_NULLABLE
				}
				out[i] = cp
			}
			return out
		}(),
	}
	logEnc, err := protoenc.New(optSchema)
	if err != nil {
		t.Fatalf("protoenc.New(optSchema): %v", err)
	}
	stream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream(otel_logs): %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	appendReconnect := func(st *managedwriter.ManagedStream, batch [][]byte) (*managedwriter.AppendResult, error) {
		res, appendErr := st.AppendRows(ctx, batch)
		if errors.Is(appendErr, io.EOF) {
			res, appendErr = st.AppendRows(ctx, batch)
		}
		return res, appendErr
	}

	ts := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	row, err := logEnc.Encode(transform.Row{
		"timestamp":               ts.UnixMicro(),
		"timestamp_source":        "observed",
		"time_unix_nano":          ts.UnixNano(),
		"observed_time_unix_nano": ts.UnixNano(),
		"receive_time":            ts.UnixMicro(),
		"receive_time_unix_nano":  ts.UnixNano(),
		"log_name":                "projects/test-project/logs/commit-then-abort-1",
	})
	if err != nil {
		t.Fatalf("Encode(row): %v", err)
	}

	// 1. FaultCommitThenStreamClosed commits the row and aborts the stream before sending an ack.
	srv.EnqueueFault(Fault{Mode: FaultCommitThenStreamClosed, Table: "otel_logs"})
	res1, err := stream.AppendRows(ctx, [][]byte{row})
	if err != nil {
		t.Fatalf("AppendRows #1: %v", err)
	}
	_, getErr1 := res1.GetResult(ctx)
	if status.Code(getErr1) != codes.Aborted {
		t.Fatalf("GetResult #1 status = %v (err=%v), want Aborted", status.Code(getErr1), getErr1)
	}

	// Verify row and counters are already committed BEFORE retry.
	wantRowBytes := int64(len(row))
	if got := srv.RowCount("otel_logs"); got != 1 {
		t.Fatalf("RowCount(otel_logs) before retry = %d, want 1", got)
	}
	if got := srv.AckedRowsForTable("otel_logs"); got != 1 {
		t.Fatalf("AckedRowsForTable(otel_logs) before retry = %d, want 1", got)
	}
	if got := srv.AckedBytesForTable("otel_logs"); got != wantRowBytes {
		t.Fatalf("AckedBytesForTable(otel_logs) before retry = %d, want %d", got, wantRowBytes)
	}
	if got := srv.UniqueAckedRowsForTable("otel_logs"); got != 1 {
		t.Fatalf("UniqueAckedRowsForTable(otel_logs) before retry = %d, want 1", got)
	}
	if got := srv.UniqueAckedBytesForTable("otel_logs"); got != wantRowBytes {
		t.Fatalf("UniqueAckedBytesForTable(otel_logs) before retry = %d, want %d", got, wantRowBytes)
	}

	// 2. Retry the same row on the managed stream -> reconnects cleanly, total acked doubles while unique stays 1.
	resRetry, err := appendReconnect(stream, [][]byte{row})
	if err != nil {
		t.Fatalf("AppendRows retry: %v", err)
	}
	if _, getErr := resRetry.GetResult(ctx); getErr != nil {
		t.Fatalf("GetResult retry: %v", getErr)
	}
	if got := srv.RowCount("otel_logs"); got != 2 {
		t.Fatalf("RowCount(otel_logs) after retry = %d, want 2", got)
	}
	if got := srv.AckedRowsForTable("otel_logs"); got != 2 {
		t.Fatalf("AckedRowsForTable(otel_logs) after retry = %d, want 2", got)
	}
	if got := srv.AckedBytesForTable("otel_logs"); got != 2*wantRowBytes {
		t.Fatalf("AckedBytesForTable(otel_logs) after retry = %d, want %d", got, 2*wantRowBytes)
	}
	if got := srv.UniqueAckedRowsForTable("otel_logs"); got != 1 {
		t.Fatalf("UniqueAckedRowsForTable(otel_logs) after retry = %d, want 1", got)
	}
	if got := srv.UniqueAckedBytesForTable("otel_logs"); got != wantRowBytes {
		t.Fatalf("UniqueAckedBytesForTable(otel_logs) after retry = %d, want %d", got, wantRowBytes)
	}

	// 3. Custom Message on FaultCommitThenStreamClosed is surfaced in the Aborted error.
	row2, err := logEnc.Encode(transform.Row{
		"timestamp":               ts.UnixMicro(),
		"timestamp_source":        "observed",
		"time_unix_nano":          ts.UnixNano(),
		"observed_time_unix_nano": ts.UnixNano(),
		"receive_time":            ts.UnixMicro(),
		"receive_time_unix_nano":  ts.UnixNano(),
		"log_name":                "projects/test-project/logs/commit-then-abort-custom-msg",
	})
	if err != nil {
		t.Fatalf("Encode(row2): %v", err)
	}
	const customMsg = "simulated post-commit transport teardown"
	srv.EnqueueFault(Fault{
		Mode:    FaultCommitThenStreamClosed,
		Table:   "otel_logs",
		Message: customMsg,
	})
	resCustom, err := appendReconnect(stream, [][]byte{row2})
	if err != nil {
		t.Fatalf("AppendRows custom msg: %v", err)
	}
	_, customErr := resCustom.GetResult(ctx)
	if status.Code(customErr) != codes.Aborted || !strings.Contains(customErr.Error(), customMsg) {
		t.Fatalf("GetResult custom msg = %v (code=%v), want Aborted containing %q",
			customErr, status.Code(customErr), customMsg)
	}
	if got := srv.RowCount("otel_logs"); got != 3 {
		t.Fatalf("RowCount(otel_logs) after custom-msg commit = %d, want 3", got)
	}
	if got := srv.UniqueAckedRowsForTable("otel_logs"); got != 2 {
		t.Fatalf("UniqueAckedRowsForTable(otel_logs) after custom-msg commit = %d, want 2", got)
	}

	// 4. Invalid row (missing REQUIRED fields) with FaultCommitThenStreamClosed queued returns
	// InvalidArgument with RowErrors and commits 0 extra rows.
	rowsBeforeInvalid := srv.RowCount("otel_logs")
	ackedRowsBeforeInvalid := srv.AckedRowsForTable("otel_logs")
	ackedBytesBeforeInvalid := srv.AckedBytesForTable("otel_logs")
	uniqueRowsBeforeInvalid := srv.UniqueAckedRowsForTable("otel_logs")

	invalidRow, err := logEnc.Encode(transform.Row{
		"log_name": "projects/test-project/logs/missing-required-fields",
	})
	if err != nil {
		t.Fatalf("Encode(invalidRow): %v", err)
	}
	srv.EnqueueFault(Fault{Mode: FaultCommitThenStreamClosed, Table: "otel_logs"})
	resInvalid, err := appendReconnect(stream, [][]byte{invalidRow})
	if err != nil {
		t.Fatalf("AppendRows invalidRow: %v", err)
	}
	fullInvalid, invalidErr := resInvalid.FullResponse(ctx)
	if status.Code(invalidErr) != codes.InvalidArgument || len(fullInvalid.GetRowErrors()) != 1 {
		t.Fatalf("FullResponse(invalidRow) = (rowErrs=%v, err=%v), want InvalidArgument with 1 RowError",
			fullInvalid.GetRowErrors(), invalidErr)
	}
	if srv.RowCount("otel_logs") != rowsBeforeInvalid ||
		srv.AckedRowsForTable("otel_logs") != ackedRowsBeforeInvalid ||
		srv.AckedBytesForTable("otel_logs") != ackedBytesBeforeInvalid ||
		srv.UniqueAckedRowsForTable("otel_logs") != uniqueRowsBeforeInvalid {
		t.Fatalf("expected 0 extra rows committed for invalid row, got rows=%d acked=%d bytes=%d unique=%d",
			srv.RowCount("otel_logs"), srv.AckedRowsForTable("otel_logs"),
			srv.AckedBytesForTable("otel_logs"), srv.UniqueAckedRowsForTable("otel_logs"))
	}

	// Also verify bad writer schema with FaultCommitThenStreamClosed queued returns InvalidArgument and commits 0 extra rows.
	badSchema := &storagepb.TableSchema{
		Fields: append(slices.Clone(optSchema.GetFields()), &storagepb.TableFieldSchema{
			Name: "unknown_extra_column",
			Type: storagepb.TableFieldSchema_STRING,
			Mode: storagepb.TableFieldSchema_NULLABLE,
		}),
	}
	badEnc, err := protoenc.New(badSchema)
	if err != nil {
		t.Fatalf("protoenc.New(badSchema): %v", err)
	}
	badStream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(badEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream(badSchema): %v", err)
	}
	t.Cleanup(func() { _ = badStream.Close() })

	srv.EnqueueFault(Fault{Mode: FaultCommitThenStreamClosed, Table: "otel_logs"})
	resBadSchema, err := badStream.AppendRows(ctx, [][]byte{row})
	if err != nil {
		t.Fatalf("AppendRows(badSchema): %v", err)
	}
	if _, badSchemaErr := resBadSchema.GetResult(ctx); status.Code(badSchemaErr) != codes.InvalidArgument {
		t.Fatalf("GetResult(badSchema) status = %v (err=%v), want InvalidArgument", status.Code(badSchemaErr), badSchemaErr)
	}
	if srv.RowCount("otel_logs") != rowsBeforeInvalid || srv.AckedRowsForTable("otel_logs") != ackedRowsBeforeInvalid {
		t.Fatalf("expected 0 extra rows committed for bad schema, got rows=%d acked=%d",
			srv.RowCount("otel_logs"), srv.AckedRowsForTable("otel_logs"))
	}
}

func TestServerThrottlesAndDelayedAcksInjectedForTable(t *testing.T) {
	srv := NewServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	qEnc, err := protoenc.New(schema.QuarantineTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(QuarantineTableSchema): %v", err)
	}

	logStream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream(otel_logs): %v", err)
	}
	t.Cleanup(func() { _ = logStream.Close() })

	qStream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_quarantine"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(qEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream(otel_quarantine): %v", err)
	}
	t.Cleanup(func() { _ = qStream.Close() })

	baseTS := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	mustLogRow := func(seq int) []byte {
		t.Helper()
		b, encErr := logEnc.Encode(transform.Row{
			"timestamp":               baseTS.UnixMicro(),
			"timestamp_source":        "observed",
			"time_unix_nano":          baseTS.UnixNano(),
			"observed_time_unix_nano": baseTS.UnixNano(),
			"receive_time":            int64(1),
			"receive_time_unix_nano":  int64(1000),
			"log_name":                "projects/test-project/logs/counter-" + strconv.Itoa(seq),
		})
		if encErr != nil {
			t.Fatalf("Encode log row %d: %v", seq, encErr)
		}
		return b
	}
	mustQuarRow := func(seq int) []byte {
		t.Helper()
		b, encErr := qEnc.Encode(transform.Row{
			"ingest_time":   int64(1),
			"signal":        schema.SignalLogs,
			"error_code":    "INVALID_UTF8",
			"error_message": "quar-" + strconv.Itoa(seq),
		})
		if encErr != nil {
			t.Fatalf("Encode quarantine row %d: %v", seq, encErr)
		}
		return b
	}
	appendRetryThrottle := func(st *managedwriter.ManagedStream, row []byte) int {
		t.Helper()
		throttles := 0
		for attempt := range 5 {
			res, aErr := st.AppendRows(ctx, [][]byte{row})
			if aErr != nil {
				t.Fatalf("AppendRows attempt %d: %v", attempt+1, aErr)
			}
			_, gErr := res.GetResult(ctx)
			if gErr == nil {
				return throttles
			}
			if status.Code(gErr) == codes.ResourceExhausted && attempt < 4 {
				throttles++
				continue
			}
			t.Fatalf("GetResult attempt %d: %v", attempt+1, gErr)
		}
		return throttles
	}

	// Initial counters are all 0.
	if srv.ThrottlesInjectedForTable("") != 0 || srv.DelayedAcksInjectedForTable("") != 0 ||
		srv.ThrottlesInjectedForTable("otel_spans") != 0 || srv.DelayedAcksInjectedForTable("otel_spans") != 0 {
		t.Fatal("expected initial throttle and delayed-ack counters to be 0")
	}

	// 1. One-shot EnqueueFault(FaultResourceExhausted) on otel_logs (2x) and otel_quarantine (1x).
	srv.EnqueueFault(
		Fault{Mode: FaultResourceExhausted, Table: "otel_logs"},
		Fault{Mode: FaultResourceExhausted, Table: "otel_logs"},
		Fault{Mode: FaultResourceExhausted, Table: "otel_quarantine"},
	)
	if got := appendRetryThrottle(logStream, mustLogRow(1)); got != 2 {
		t.Fatalf("otel_logs one-shot throttles observed = %d, want 2", got)
	}
	if got := appendRetryThrottle(qStream, mustQuarRow(1)); got != 1 {
		t.Fatalf("otel_quarantine one-shot throttles observed = %d, want 1", got)
	}
	if got := srv.ThrottlesInjectedForTable("otel_logs"); got != 2 {
		t.Fatalf("ThrottlesInjectedForTable(otel_logs) = %d, want 2", got)
	}
	if got := srv.ThrottlesInjectedForTable("otel_quarantine"); got != 1 {
		t.Fatalf("ThrottlesInjectedForTable(otel_quarantine) = %d, want 1", got)
	}
	if got := srv.ThrottlesInjectedForTable(""); got != 3 {
		t.Fatalf("ThrottlesInjectedForTable(\"\") = %d, want 3", got)
	}
	if got := srv.ThrottlesInjectedForTable("otel_spans"); got != 0 {
		t.Fatalf("ThrottlesInjectedForTable(otel_spans) = %d, want 0", got)
	}
	if got := srv.PeriodicThrottlesInjected(""); got != 0 {
		t.Fatalf("PeriodicThrottlesInjected(\"\") after one-shot faults = %d, want 0", got)
	}

	// 2. One-shot EnqueueFault(FaultDelayedAck): Delay == 0 and canceled fault.Ctx must NOT increment;
	// Delay > 0 increments per-table and "" aggregate.
	canceledCtx, cancelImmediate := context.WithCancel(ctx)
	cancelImmediate()
	srv.EnqueueFault(
		Fault{Mode: FaultDelayedAck, Table: "otel_logs", Delay: 0},
		Fault{Mode: FaultDelayedAck, Table: "otel_logs", Delay: 5 * time.Millisecond, Ctx: canceledCtx},
		Fault{Mode: FaultDelayedAck, Table: "otel_logs", Delay: 5 * time.Millisecond},
		Fault{Mode: FaultDelayedAck, Table: "otel_quarantine", Delay: 5 * time.Millisecond},
	)
	// First log append consumes Delay == 0 -> counter stays 0.
	appendRetryThrottle(logStream, mustLogRow(2))
	if got := srv.DelayedAcksInjectedForTable("otel_logs"); got != 0 {
		t.Fatalf("DelayedAcksInjectedForTable(otel_logs) after Delay==0 fault = %d, want 0", got)
	}
	// Second log append skips canceledCtx fault and consumes the 5ms Delay > 0 fault -> counter becomes 1.
	appendRetryThrottle(logStream, mustLogRow(3))
	if got := srv.DelayedAcksInjectedForTable("otel_logs"); got != 1 {
		t.Fatalf("DelayedAcksInjectedForTable(otel_logs) after active Delay>0 fault = %d, want 1", got)
	}
	// Quarantine append consumes its 5ms Delay > 0 fault -> counter becomes 1.
	appendRetryThrottle(qStream, mustQuarRow(2))
	if got := srv.DelayedAcksInjectedForTable("otel_quarantine"); got != 1 {
		t.Fatalf("DelayedAcksInjectedForTable(otel_quarantine) = %d, want 1", got)
	}
	if got := srv.DelayedAcksInjectedForTable(""); got != 2 {
		t.Fatalf("DelayedAcksInjectedForTable(\"\") = %d, want 2", got)
	}
	if got := srv.DelayedAcksInjectedForTable("otel_spans"); got != 0 {
		t.Fatalf("DelayedAcksInjectedForTable(otel_spans) = %d, want 0", got)
	}

	// 3. Periodic SetPeriodicFaults with both throttling and ackDelay > 0 on otel_logs and otel_quarantine.
	srv.SetPeriodicFaults(ctx, "otel_logs", 1, 5*time.Millisecond)
	srv.SetPeriodicFaults(ctx, "otel_quarantine", 2, 5*time.Millisecond)

	// otel_logs logicalSeq=1: throttles on attempt 1 (+1 periodic & cumulative throttle) and delays 5ms on retry (+1 delayed ack).
	if got := appendRetryThrottle(logStream, mustLogRow(4)); got != 1 {
		t.Fatalf("otel_logs periodic throttles observed = %d, want 1", got)
	}
	// otel_quarantine logicalSeq=1: not throttled (1%2 != 0), delays 5ms (+1 delayed ack).
	if got := appendRetryThrottle(qStream, mustQuarRow(3)); got != 0 {
		t.Fatalf("otel_quarantine logicalSeq=1 throttles observed = %d, want 0", got)
	}
	// otel_quarantine logicalSeq=2: throttled on attempt 1 (+1 periodic & cumulative throttle), retry has no delay.
	if got := appendRetryThrottle(qStream, mustQuarRow(4)); got != 1 {
		t.Fatalf("otel_quarantine logicalSeq=2 throttles observed = %d, want 1", got)
	}

	if got := srv.PeriodicThrottlesInjected("otel_logs"); got != 1 {
		t.Fatalf("PeriodicThrottlesInjected(otel_logs) = %d, want 1", got)
	}
	if got := srv.PeriodicThrottlesInjected("otel_quarantine"); got != 1 {
		t.Fatalf("PeriodicThrottlesInjected(otel_quarantine) = %d, want 1", got)
	}
	if got := srv.ThrottlesInjectedForTable("otel_logs"); got != 3 {
		t.Fatalf("ThrottlesInjectedForTable(otel_logs) = %d, want 3 (2 one-shot + 1 periodic)", got)
	}
	if got := srv.ThrottlesInjectedForTable("otel_quarantine"); got != 2 {
		t.Fatalf("ThrottlesInjectedForTable(otel_quarantine) = %d, want 2 (1 one-shot + 1 periodic)", got)
	}
	if got := srv.ThrottlesInjectedForTable(""); got != 5 {
		t.Fatalf("ThrottlesInjectedForTable(\"\") = %d, want 5", got)
	}
	if got := srv.ThrottlesInjectedForTable("otel_spans"); got != 0 {
		t.Fatalf("ThrottlesInjectedForTable(otel_spans) = %d, want 0", got)
	}
	if got := srv.DelayedAcksInjectedForTable("otel_logs"); got != 2 {
		t.Fatalf("DelayedAcksInjectedForTable(otel_logs) = %d, want 2 (1 one-shot + 1 periodic)", got)
	}
	if got := srv.DelayedAcksInjectedForTable("otel_quarantine"); got != 2 {
		t.Fatalf("DelayedAcksInjectedForTable(otel_quarantine) = %d, want 2 (1 one-shot + 1 periodic)", got)
	}
	if got := srv.DelayedAcksInjectedForTable(""); got != 4 {
		t.Fatalf("DelayedAcksInjectedForTable(\"\") = %d, want 4", got)
	}
	if got := srv.DelayedAcksInjectedForTable("otel_spans"); got != 0 {
		t.Fatalf("DelayedAcksInjectedForTable(otel_spans) = %d, want 0", got)
	}

	// 4. SetPeriodicFaults(..., 0, 0) clears PeriodicThrottlesInjected without clearing cumulative
	// ThrottlesInjectedForTable or DelayedAcksInjectedForTable.
	srv.SetPeriodicFaults(ctx, "otel_logs", 0, 0)
	if got := srv.PeriodicThrottlesInjected("otel_logs"); got != 0 {
		t.Fatalf("PeriodicThrottlesInjected(otel_logs) after SetPeriodicFaults(0,0) = %d, want 0", got)
	}
	if got := srv.ThrottlesInjectedForTable("otel_logs"); got != 3 {
		t.Fatalf("ThrottlesInjectedForTable(otel_logs) after SetPeriodicFaults(0,0) = %d, want 3", got)
	}
	if got := srv.DelayedAcksInjectedForTable("otel_logs"); got != 2 {
		t.Fatalf("DelayedAcksInjectedForTable(otel_logs) after SetPeriodicFaults(0,0) = %d, want 2", got)
	}
	if got := srv.ThrottlesInjectedForTable(""); got != 5 {
		t.Fatalf("ThrottlesInjectedForTable(\"\") after SetPeriodicFaults(0,0) = %d, want 5", got)
	}
	if got := srv.DelayedAcksInjectedForTable(""); got != 4 {
		t.Fatalf("DelayedAcksInjectedForTable(\"\") after SetPeriodicFaults(0,0) = %d, want 4", got)
	}
	srv.SetPeriodicFaults(ctx, "otel_quarantine", 0, 0)

	// 5. ResetRows() resets ThrottlesInjectedForTable and DelayedAcksInjectedForTable back to 0.
	srv.ResetRows()
	for _, tbl := range []string{"", "otel_logs", "otel_quarantine", "otel_spans"} {
		if got := srv.ThrottlesInjectedForTable(tbl); got != 0 {
			t.Fatalf("ThrottlesInjectedForTable(%q) after ResetRows = %d, want 0", tbl, got)
		}
		if got := srv.DelayedAcksInjectedForTable(tbl); got != 0 {
			t.Fatalf("DelayedAcksInjectedForTable(%q) after ResetRows = %d, want 0", tbl, got)
		}
	}
}

func TestServerSetPeriodicFaultsWildcardIsolatesPendingRetriesByTable(t *testing.T) {
	srv := NewServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	if err := srv.SeedTable("test-project", "otel", "custom_logs", schema.LogsTableSchema()); err != nil {
		t.Fatalf("SeedTable(custom_logs): %v", err)
	}

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}

	logsStream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream(otel_logs): %v", err)
	}
	t.Cleanup(func() { _ = logsStream.Close() })

	customStream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/custom_logs"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream(custom_logs): %v", err)
	}
	t.Cleanup(func() { _ = customStream.Close() })

	baseTS := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	encodeLog := func(logName string) []byte {
		t.Helper()
		b, encErr := logEnc.Encode(transform.Row{
			"timestamp":               baseTS.UnixMicro(),
			"timestamp_source":        "observed",
			"time_unix_nano":          baseTS.UnixNano(),
			"observed_time_unix_nano": baseTS.UnixNano(),
			"receive_time":            int64(1),
			"receive_time_unix_nano":  int64(1000),
			"log_name":                logName,
		})
		if encErr != nil {
			t.Fatalf("Encode(%q): %v", logName, encErr)
		}
		return b
	}
	appendOnce := func(st *managedwriter.ManagedStream, row []byte) error {
		t.Helper()
		res, aErr := st.AppendRows(ctx, [][]byte{row})
		if aErr != nil {
			t.Fatalf("AppendRows: %v", aErr)
		}
		_, gErr := res.GetResult(ctx)
		return gErr
	}

	srv.SetPeriodicFaults(ctx, "", 2, 50*time.Millisecond)

	// 1. Send 5 warmup distinct rows on otel_logs, retrying throttled seq 2 and seq 4 so logicalSeq reaches 5.
	for seq := 1; seq <= 5; seq++ {
		row := encodeLog("projects/test-project/logs/warmup-" + strconv.Itoa(seq))
		gErr := appendOnce(logsStream, row)
		if seq%2 == 0 {
			if status.Code(gErr) != codes.ResourceExhausted {
				t.Fatalf("warmup seq %d status = %v (err=%v), want ResourceExhausted", seq, status.Code(gErr), gErr)
			}
			if retryErr := appendOnce(logsStream, row); retryErr != nil {
				t.Fatalf("warmup seq %d retry: %v", seq, retryErr)
			}
		} else if gErr != nil {
			t.Fatalf("warmup seq %d: %v", seq, gErr)
		}
	}

	// 2. Send sharedRow to otel_logs -> hits logicalSeq=6 (6%2==0 && 6%3==0), fails with ResourceExhausted,
	// queuing pendingRetryKey{table: "otel_logs", batchHash: H} = 50ms.
	sharedRow := encodeLog("projects/test-project/logs/rowX")
	if gErr := appendOnce(logsStream, sharedRow); status.Code(gErr) != codes.ResourceExhausted {
		t.Fatalf("sharedRow initial append on otel_logs = %v (code=%v), want ResourceExhausted", gErr, status.Code(gErr))
	}

	// 3. Snapshot counters before sending sharedRow to custom_logs.
	delayedCustomBefore := srv.DelayedAcksInjectedForTable("custom_logs")
	throttlesCustomBefore := srv.ThrottlesInjectedForTable("custom_logs")
	delayedLogsBefore := srv.DelayedAcksInjectedForTable("otel_logs")

	// 4. Send the exact same serialized sharedRow bytes to custom_logs -> hits logicalSeq=7,
	// succeeds cleanly without stealing otel_logs's pending retry.
	if gErr := appendOnce(customStream, sharedRow); gErr != nil {
		t.Fatalf("sharedRow append on custom_logs: %v", gErr)
	}
	if got := srv.DelayedAcksInjectedForTable("custom_logs"); got != delayedCustomBefore {
		t.Fatalf("DelayedAcksInjectedForTable(custom_logs) = %d, want %d", got, delayedCustomBefore)
	}
	if got := srv.ThrottlesInjectedForTable("custom_logs"); got != throttlesCustomBefore {
		t.Fatalf("ThrottlesInjectedForTable(custom_logs) = %d, want %d", got, throttlesCustomBefore)
	}

	// 5. Retry sharedRow on otel_logs -> matches pendingRetryKey{table: "otel_logs", batchHash: H},
	// succeeds with delayed ack without advancing logicalSeq or re-throttling.
	retryStart := time.Now()
	if gErr := appendOnce(logsStream, sharedRow); gErr != nil {
		t.Fatalf("sharedRow retry on otel_logs: %v", gErr)
	}
	dur := time.Since(retryStart)
	if got := srv.DelayedAcksInjectedForTable("otel_logs"); got != delayedLogsBefore+1 {
		t.Fatalf("DelayedAcksInjectedForTable(otel_logs) = %d, want %d", got, delayedLogsBefore+1)
	}
	if dur < 40*time.Millisecond {
		t.Fatalf("sharedRow retry duration = %s, want >= 40ms", dur)
	}

	// 6. Send one more distinct row to otel_logs -> hits logicalSeq=8 (8%2==0), fails with ResourceExhausted,
	// proving the retry did not consume logicalSeq=8; retry succeeds.
	rowAfter := encodeLog("projects/test-project/logs/after-retry")
	if gErr := appendOnce(logsStream, rowAfter); status.Code(gErr) != codes.ResourceExhausted {
		t.Fatalf("rowAfter initial append on otel_logs = %v (code=%v), want ResourceExhausted", gErr, status.Code(gErr))
	}
	if gErr := appendOnce(logsStream, rowAfter); gErr != nil {
		t.Fatalf("rowAfter retry on otel_logs: %v", gErr)
	}

	if got := srv.RowCount("otel_logs"); got != 7 {
		t.Fatalf("RowCount(otel_logs) = %d, want 7", got)
	}
	if got := srv.RowCount("custom_logs"); got != 1 {
		t.Fatalf("RowCount(custom_logs) = %d, want 1", got)
	}
}

func TestServerUniqueAckedRowsCapPreventsUnboundedGrowth(t *testing.T) {
	srv := NewServer(t)
	srv.SetMaxUniqueAckedRows(3)
	srv.SetTrackUniqueAcked(true)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	client, err := managedwriter.NewClient(ctx, "test-project", srv.WriteClientOptions()...)
	if err != nil {
		t.Fatalf("managedwriter.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	stream, err := client.NewManagedStream(ctx,
		managedwriter.WithDestinationTable("projects/test-project/datasets/otel/tables/otel_logs"),
		managedwriter.WithType(managedwriter.DefaultStream),
		managedwriter.WithSchemaDescriptor(logEnc.Descriptor()),
	)
	if err != nil {
		t.Fatalf("NewManagedStream(otel_logs): %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })

	baseTS := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	encodeLog := func(seq int) []byte {
		t.Helper()
		b, encErr := logEnc.Encode(transform.Row{
			"timestamp":               baseTS.UnixMicro(),
			"timestamp_source":        "observed",
			"time_unix_nano":          baseTS.UnixNano(),
			"observed_time_unix_nano": baseTS.UnixNano(),
			"receive_time":            int64(1),
			"receive_time_unix_nano":  int64(1000),
			"log_name":                "projects/test-project/logs/cap-" + strconv.Itoa(seq),
		})
		if encErr != nil {
			t.Fatalf("Encode(%d): %v", seq, encErr)
		}
		return b
	}
	mustAppend := func(rows ...[]byte) {
		t.Helper()
		res, aErr := stream.AppendRows(ctx, rows)
		if aErr != nil {
			t.Fatalf("AppendRows: %v", aErr)
		}
		if _, gErr := res.GetResult(ctx); gErr != nil {
			t.Fatalf("GetResult: %v", gErr)
		}
	}

	row1 := encodeLog(1)
	row2 := encodeLog(2)
	row3 := encodeLog(3)
	row4 := encodeLog(4)

	// Send 3 distinct rows up to the cap -> not saturated.
	mustAppend(row1, row2, row3)
	if got := srv.UniqueAckedRows(); got != 3 {
		t.Fatalf("UniqueAckedRows() = %d, want 3", got)
	}
	if got := srv.UniqueAckedRowsForTable("otel_logs"); got != 3 {
		t.Fatalf("UniqueAckedRowsForTable(otel_logs) = %d, want 3", got)
	}
	if srv.UniqueAckedSaturated() || srv.UniqueAckedSaturatedForTable("otel_logs") {
		t.Fatalf("unexpected saturation at exact cap: global=%v table=%v",
			srv.UniqueAckedSaturated(), srv.UniqueAckedSaturatedForTable("otel_logs"))
	}

	// Resend row 1 (already seen) -> must not trigger saturation.
	mustAppend(row1)
	if got := srv.AckedRowsForTable("otel_logs"); got != 4 {
		t.Fatalf("AckedRowsForTable(otel_logs) = %d, want 4", got)
	}
	if got := srv.UniqueAckedRows(); got != 3 {
		t.Fatalf("UniqueAckedRows() after duplicate = %d, want 3", got)
	}
	if srv.UniqueAckedSaturated() || srv.UniqueAckedSaturatedForTable("otel_logs") {
		t.Fatalf("duplicate row must not trigger saturation: global=%v table=%v",
			srv.UniqueAckedSaturated(), srv.UniqueAckedSaturatedForTable("otel_logs"))
	}

	// Send a 4th distinct row -> saturates without growing unique counts past 3.
	mustAppend(row4)
	if got := srv.AckedRowsForTable("otel_logs"); got != 5 {
		t.Fatalf("AckedRowsForTable(otel_logs) = %d, want 5", got)
	}
	if got := srv.UniqueAckedRows(); got != 3 {
		t.Fatalf("UniqueAckedRows() after saturation = %d, want 3", got)
	}
	if got := srv.UniqueAckedRowsForTable("otel_logs"); got != 3 {
		t.Fatalf("UniqueAckedRowsForTable(otel_logs) after saturation = %d, want 3", got)
	}
	if !srv.UniqueAckedSaturated() {
		t.Fatal("UniqueAckedSaturated() = false, want true")
	}
	if !srv.UniqueAckedSaturatedForTable("otel_logs") {
		t.Fatal("UniqueAckedSaturatedForTable(otel_logs) = false, want true")
	}
	if !srv.UniqueAckedSaturatedForTable("") {
		t.Fatal("UniqueAckedSaturatedForTable(\"\") = false, want true")
	}
	if srv.UniqueAckedSaturatedForTable("otel_quarantine") {
		t.Fatal("UniqueAckedSaturatedForTable(otel_quarantine) = true, want false")
	}

	// ResetRows clears saturation and unique counts while keeping maxUniqueAckedRows=3.
	srv.ResetRows()
	if srv.UniqueAckedSaturated() || srv.UniqueAckedSaturatedForTable("otel_logs") {
		t.Fatalf("expected ResetRows to clear saturation, got global=%v table=%v",
			srv.UniqueAckedSaturated(), srv.UniqueAckedSaturatedForTable("otel_logs"))
	}
	if srv.UniqueAckedRows() != 0 || srv.UniqueAckedRowsForTable("otel_logs") != 0 {
		t.Fatalf("expected ResetRows to clear unique counts, got global=%d table=%d",
			srv.UniqueAckedRows(), srv.UniqueAckedRowsForTable("otel_logs"))
	}

	// Saturate again, then verify SetTrackUniqueAcked(true) clears saturation back to false.
	mustAppend(row1, row2, row3, row4)
	if !srv.UniqueAckedSaturated() || !srv.UniqueAckedSaturatedForTable("otel_logs") {
		t.Fatalf("expected saturation after re-sending 4 distinct rows under cap=3, got global=%v table=%v",
			srv.UniqueAckedSaturated(), srv.UniqueAckedSaturatedForTable("otel_logs"))
	}
	srv.SetTrackUniqueAcked(true)
	if srv.UniqueAckedSaturated() || srv.UniqueAckedSaturatedForTable("otel_logs") {
		t.Fatalf("expected SetTrackUniqueAcked(true) to clear saturation, got global=%v table=%v",
			srv.UniqueAckedSaturated(), srv.UniqueAckedSaturatedForTable("otel_logs"))
	}

	// SetMaxUniqueAckedRows(0) restores DefaultMaxUniqueAckedRows.
	srv.SetMaxUniqueAckedRows(0)
	mustAppend(row1, row2, row3, row4)
	if got := srv.UniqueAckedRows(); got != 4 {
		t.Fatalf("UniqueAckedRows() with default cap = %d, want 4", got)
	}
	if srv.UniqueAckedSaturated() || srv.UniqueAckedSaturatedForTable("otel_logs") {
		t.Fatalf("unexpected saturation with DefaultMaxUniqueAckedRows: global=%v table=%v",
			srv.UniqueAckedSaturated(), srv.UniqueAckedSaturatedForTable("otel_logs"))
	}
}
