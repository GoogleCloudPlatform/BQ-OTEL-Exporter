# Plans and applies the search index jobs with a mocked google provider, so it
# needs no credentials and makes no API calls. Mocked resources take generated
# values for computed attributes; every job here reports a finished job without
# an error. A mocked provider cannot report that an argument forces
# replacement, so each run that renames or recreates a table also asks for the
# replacement the real provider plans: table_id is a force-new argument of
# google_bigquery_table. The runs share one state and run in order.

mock_provider "google" {
  mock_resource "google_bigquery_job" {
    defaults = {
      status = [{ state = "DONE", error_result = [], errors = [] }]
    }
  }
}

variables {
  project_id            = "test-project"
  enable_search_indexes = true
}

run "disabled_creates_no_jobs" {
  command = plan

  variables {
    enable_search_indexes = false
  }

  assert {
    condition = (
      length(google_bigquery_job.otel_spans_search_index) == 0 &&
      length(google_bigquery_job.otel_logs_search_index) == 0 &&
      length(google_bigquery_job.otel_metrics_search_index) == 0 &&
      output.search_index_job_ids == null
    )
    error_message = "With enable_search_indexes off, no search index job may exist."
  }
}

run "create_jobs" {
  assert {
    condition = (
      startswith(output.search_index_job_ids.spans, "otel_search_idx_spans_") &&
      startswith(output.search_index_job_ids.logs, "otel_search_idx_logs_") &&
      startswith(output.search_index_job_ids.metrics, "otel_search_idx_metrics_") &&
      length(distinct(values(output.search_index_job_ids))) == 3
    )
    error_message = "Each table needs its own search index job with a signal-specific job ID prefix."
  }

  assert {
    condition = alltrue([
      for signal, job in {
        spans   = google_bigquery_job.otel_spans_search_index[0]
        logs    = google_bigquery_job.otel_logs_search_index[0]
        metrics = google_bigquery_job.otel_metrics_search_index[0]
      } :
      (
        job.query[0].use_legacy_sql == false &&
        job.query[0].create_disposition == "" &&
        job.query[0].write_disposition == "" &&
        strcontains(job.query[0].query, "IF NOT EXISTS (\n    SELECT 1 FROM `test-project.otel.INFORMATION_SCHEMA.SEARCH_INDEXES`\n    WHERE table_name = 'otel_${signal}'\n  ) THEN\n    CREATE SEARCH INDEX IF NOT EXISTS `otel_${signal}_trace_lookup_idx`\n    ON `test-project.otel.otel_${signal}`") &&
        strcontains(job.query[0].query, "EXCEPTION WHEN ERROR THEN\n  IF NOT EXISTS (\n    SELECT 1 FROM `test-project.otel.INFORMATION_SCHEMA.SEARCH_INDEXES`\n    WHERE table_name = 'otel_${signal}'\n  ) THEN\n    RAISE;\n  END IF;\nEND;")
      )
    ])
    error_message = "Each job must run its DDL as GoogleSQL, without dispositions, only when INFORMATION_SCHEMA.SEARCH_INDEXES lists no index on its table, and raise any error unless the table has an index afterwards."
  }
}

run "columns_and_analyzer_change_keeps_jobs" {
  command = plan

  variables {
    logs_search_index_columns  = ["trace_id", "span_id", "body"]
    logs_search_index_analyzer = "LOG_ANALYZER"
  }

  assert {
    condition     = google_bigquery_job.otel_logs_search_index[0].job_id == run.create_jobs.search_index_job_ids.logs
    error_message = "Changing only the logs search index columns or analyzer must not replace the logs search index job."
  }

  assert {
    condition     = strcontains(google_bigquery_job.otel_logs_search_index[0].query[0].query, "CREATE SEARCH INDEX IF NOT EXISTS `otel_logs_trace_lookup_idx`\n    ON `test-project.otel.otel_logs` (trace_id, span_id) OPTIONS (analyzer = 'NO_OP_ANALYZER');")
    error_message = "The existing logs search index job must keep the script it ran."
  }

  assert {
    condition     = strcontains(output.search_index_ddl.logs, "CREATE SEARCH INDEX IF NOT EXISTS `otel_logs_search_idx`\nON `test-project.otel.otel_logs` (trace_id, span_id, body) OPTIONS (analyzer = 'LOG_ANALYZER');")
    error_message = "search_index_ddl must show the configured columns and analyzer."
  }

  assert {
    condition = (
      google_bigquery_job.otel_spans_search_index[0].job_id == run.create_jobs.search_index_job_ids.spans &&
      google_bigquery_job.otel_metrics_search_index[0].job_id == run.create_jobs.search_index_job_ids.metrics
    )
    error_message = "Changing the logs search index options must not replace the spans or metrics jobs."
  }
}

run "rename_logs_table" {
  variables {
    logs_table = "otel_logs_v2"
  }

  plan_options {
    replace = [google_bigquery_table.otel_logs]
  }

  assert {
    condition     = output.search_index_job_ids.logs != run.create_jobs.search_index_job_ids.logs
    error_message = "Renaming the logs table must replace the logs search index job under a new job ID."
  }

  assert {
    condition = (
      strcontains(google_bigquery_job.otel_logs_search_index[0].query[0].query, "WHERE table_name = 'otel_logs_v2'") &&
      strcontains(google_bigquery_job.otel_logs_search_index[0].query[0].query, "CREATE SEARCH INDEX IF NOT EXISTS `otel_logs_v2_trace_lookup_idx`\n    ON `test-project.otel.otel_logs_v2`")
    )
    error_message = "The replacement logs search index job must index the renamed table."
  }

  assert {
    condition = (
      output.search_index_job_ids.spans == run.create_jobs.search_index_job_ids.spans &&
      output.search_index_job_ids.metrics == run.create_jobs.search_index_job_ids.metrics
    )
    error_message = "Renaming the logs table must not replace the spans or metrics jobs."
  }
}

run "rename_spans_table" {
  variables {
    logs_table  = "otel_logs_v2"
    spans_table = "otel_spans_v2"
  }

  plan_options {
    replace = [google_bigquery_table.otel_spans]
  }

  assert {
    condition     = output.search_index_job_ids.spans != run.create_jobs.search_index_job_ids.spans
    error_message = "Renaming the spans table must replace the spans search index job under a new job ID."
  }

  assert {
    condition = (
      strcontains(google_bigquery_job.otel_spans_search_index[0].query[0].query, "WHERE table_name = 'otel_spans_v2'") &&
      strcontains(google_bigquery_job.otel_spans_search_index[0].query[0].query, "CREATE SEARCH INDEX IF NOT EXISTS `otel_spans_v2_trace_lookup_idx`\n    ON `test-project.otel.otel_spans_v2`")
    )
    error_message = "The replacement spans search index job must index the renamed table."
  }

  assert {
    condition = (
      output.search_index_job_ids.logs == run.rename_logs_table.search_index_job_ids.logs &&
      output.search_index_job_ids.metrics == run.create_jobs.search_index_job_ids.metrics
    )
    error_message = "Renaming the spans table must not replace the logs or metrics jobs."
  }
}

run "rename_metrics_table" {
  variables {
    logs_table    = "otel_logs_v2"
    spans_table   = "otel_spans_v2"
    metrics_table = "otel_metrics_v2"
  }

  plan_options {
    replace = [google_bigquery_table.otel_metrics]
  }

  assert {
    condition     = output.search_index_job_ids.metrics != run.create_jobs.search_index_job_ids.metrics
    error_message = "Renaming the metrics table must replace the metrics search index job under a new job ID."
  }

  assert {
    condition = (
      strcontains(google_bigquery_job.otel_metrics_search_index[0].query[0].query, "WHERE table_name = 'otel_metrics_v2'") &&
      strcontains(google_bigquery_job.otel_metrics_search_index[0].query[0].query, "CREATE SEARCH INDEX IF NOT EXISTS `otel_metrics_v2_trace_lookup_idx`\n    ON `test-project.otel.otel_metrics_v2`")
    )
    error_message = "The replacement metrics search index job must index the renamed table."
  }

  assert {
    condition = (
      output.search_index_job_ids.logs == run.rename_logs_table.search_index_job_ids.logs &&
      output.search_index_job_ids.spans == run.rename_spans_table.search_index_job_ids.spans
    )
    error_message = "Renaming the metrics table must not replace the logs or spans jobs."
  }
}

run "recreate_logs_table_under_same_name" {
  variables {
    logs_table    = "otel_logs_v2"
    spans_table   = "otel_spans_v2"
    metrics_table = "otel_metrics_v2"
  }

  plan_options {
    replace = [google_bigquery_table.otel_logs]
  }

  assert {
    condition     = output.search_index_job_ids.logs != run.rename_logs_table.search_index_job_ids.logs
    error_message = "Recreating the logs table under the same name must rerun the logs search index job under a new job ID."
  }

  assert {
    condition = (
      output.search_index_job_ids.spans == run.rename_spans_table.search_index_job_ids.spans &&
      output.search_index_job_ids.metrics == run.rename_metrics_table.search_index_job_ids.metrics
    )
    error_message = "Recreating the logs table must not replace the spans or metrics jobs."
  }
}
