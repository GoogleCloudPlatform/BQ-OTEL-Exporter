# Checks how the search index jobs report their outcome, with a mocked google
# provider (no credentials, no API calls). override_resource sets the status
# BigQuery returns for a job; every other job reports a finished job without an
# error. The runs share one state and run in order.

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

run "create_jobs" {
  assert {
    condition     = output.search_index_job_ids != null
    error_message = "The search index jobs must be created."
  }
}

# A job that BigQuery has already finished with an error fails the apply.
run "failed_job_fails_apply" {
  plan_options {
    replace = [google_bigquery_job.otel_logs_search_index[0]]
  }

  override_resource {
    target = google_bigquery_job.otel_logs_search_index
    values = {
      status = [{
        state        = "DONE"
        error_result = [{ reason = "accessDenied", location = "", message = "Access Denied: Table test-project:otel.otel_logs: Permission bigquery.tables.update denied" }]
        errors       = [{ reason = "accessDenied", location = "", message = "Access Denied: Table test-project:otel.otel_logs: Permission bigquery.tables.update denied" }]
      }]
    }
  }

  expect_failures = [google_bigquery_job.otel_logs_search_index]
}

# The failed job stays in state, and every later plan fails on it rather than
# reporting no changes.
run "failed_job_fails_later_plans" {
  command = plan

  expect_failures = [google_bigquery_job.otel_logs_search_index]
}

# terraform apply -replace retries the job under a new job ID.
run "replace_retries_failed_job" {
  plan_options {
    replace = [google_bigquery_job.otel_logs_search_index[0]]
  }

  assert {
    condition = (
      startswith(output.search_index_job_ids.logs, "otel_search_idx_logs_") &&
      output.search_index_job_ids.logs != run.create_jobs.search_index_job_ids.logs
    )
    error_message = "The retried logs search index job must run under a new job ID."
  }

  assert {
    condition = (
      output.search_index_job_ids.spans == run.create_jobs.search_index_job_ids.spans &&
      output.search_index_job_ids.metrics == run.create_jobs.search_index_job_ids.metrics
    )
    error_message = "Retrying the logs search index job must not replace the spans or metrics jobs."
  }
}

# The provider records a job as soon as BigQuery accepts it, so a new job can
# still be running at the end of the apply. Its postcondition cannot judge it
# yet, and the check block warns instead of failing the apply.
run "running_job_warns_without_failing" {
  plan_options {
    replace = [google_bigquery_job.otel_metrics_search_index[0]]
  }

  override_resource {
    target = google_bigquery_job.otel_metrics_search_index
    values = {
      status = [{ state = "RUNNING", error_result = [], errors = [] }]
    }
  }

  expect_failures = [check.search_index_jobs_finished]
}
