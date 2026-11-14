#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Waits for a BigQuery job to finish and reports how it ended.

The google provider records a google_bigquery_job as soon as BigQuery accepts
the job, so the job can still be running, and can still fail, after Terraform
has moved on. main.tf runs this script from a local-exec provisioner once for
each search index job, so that terraform apply fails when the job fails or
does not finish in time.

All input comes from the environment, which keeps the access token out of the
argument list:

  BQ_JOB_PROJECT, BQ_JOB_LOCATION, BQ_JOB_ID
      The job to wait for.
  BQ_JOB_STATUS
      The job's status as Terraform last read it, as JSON in the shape of the
      REST API's JobStatus: {"state": "...", "errorResult": {...} or null}.
      A job that was already DONE is judged from this, without a request.
  BQ_JOB_WAIT_TIMEOUT_SECONDS
      How long to wait for the job to be DONE before giving up.
  BQ_JOB_TERRAFORM_ADDRESS
      The job's resource address, which the retry instructions name.
  BQ_ACCESS_TOKEN
      OAuth 2.0 access token that authorizes the jobs.get requests.
  GOOGLE_BIG_QUERY_CUSTOM_ENDPOINT
      Optional BigQuery API base URL: the override the google provider itself
      reads. Defaults to https://bigquery.googleapis.com/bigquery/v2/.
  BQ_JOB_POLL_INTERVAL_SECONDS
      Optional pause between requests. Defaults to 2.

Exit status:

  0  The job is DONE without an error.
  1  The job is DONE with an error.
  2  The outcome is unknown: the input is invalid, BigQuery rejected the
     access token, or the job was not DONE in time.
"""

import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_ENDPOINT = "https://bigquery.googleapis.com/bigquery/v2/"
DEFAULT_POLL_INTERVAL_SECONDS = 2.0
# One request may take this long at most, so a stalled connection cannot use
# up the whole wait.
REQUEST_TIMEOUT_SECONDS = 30.0
# A job's status is a few hundred bytes; anything larger is not one.
MAX_RESPONSE_BYTES = 1 << 20

EXIT_JOB_FAILED = 1
EXIT_OUTCOME_UNKNOWN = 2


class OutcomeUnknown(Exception):
    """The job's outcome cannot be determined, and asking again will not help."""


class RequestFailed(Exception):
    """A jobs.get request failed; a later one may succeed."""


def required(env, name):
    value = env.get(name, "")
    if not value:
        raise OutcomeUnknown(f"{name} is not set.")
    return value


def seconds(env, name, default=None):
    raw = env.get(name, "")
    if not raw and default is not None:
        return default
    try:
        value = float(raw)
    except ValueError:
        value = 0.0
    # The comparison is false for NaN as well.
    if not 0 < value < float("inf"):
        raise OutcomeUnknown(f"{name} must be a positive number of seconds, got {raw!r}.")
    return value


def job_url(endpoint, project, location, job_id):
    parts = urllib.parse.urlsplit(endpoint)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise OutcomeUnknown(
            f"GOOGLE_BIG_QUERY_CUSTOM_ENDPOINT must be an http or https URL, got {endpoint!r}."
        )
    quote = urllib.parse.quote
    path = f"projects/{quote(project, safe='')}/jobs/{quote(job_id, safe='')}"
    # fields=status asks for the job's status alone, not its whole description.
    query = urllib.parse.urlencode({"location": location, "fields": "status"})
    return f"{endpoint.rstrip('/')}/{path}?{query}"


def outcome(status):
    """Returns the state and the error text of a job from its JobStatus.

    The error text is None unless BigQuery reports an errorResult, which it
    sets only on a job that failed.
    """
    state = status.get("state")
    error = status.get("errorResult")
    if not error:
        return state, None
    if not isinstance(error, dict):
        return state, f"(unknown): {error}"
    return state, f"({error.get('reason') or 'unknown'}): {error.get('message') or 'no message'}"


def api_error(body):
    """Returns the message of a Google API error response, or its raw text."""
    text = body.decode("utf-8", "replace").strip()
    try:
        message = json.loads(text)["error"]["message"]
    except (ValueError, KeyError, TypeError):
        message = None
    return str(message or text or "no response body")[:500]


def get_status(url, token, timeout):
    """Returns the JobStatus of the job at url."""
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    # Unredirected, so that a redirect to another host never carries the token.
    request.add_unredirected_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as err:
        detail = api_error(err.read(MAX_RESPONSE_BYTES))
        if err.code == 401:
            raise OutcomeUnknown(
                f"BigQuery rejected the access token (HTTP 401): {detail}. The token Terraform "
                "passed may have expired: run terraform apply again."
            ) from err
        raise RequestFailed(f"HTTP {err.code}: {detail}") from err
    except (OSError, http.client.HTTPException) as err:
        # Connection errors, timeouts, and responses cut short.
        raise RequestFailed(str(err) or type(err).__name__) from err
    try:
        status = json.loads(body.decode("utf-8"))["status"]
    except (ValueError, KeyError, TypeError) as err:
        raise RequestFailed("the response is not a job with a status") from err
    if not isinstance(status, dict):
        raise RequestFailed("the response is not a job with a status")
    return status


def wait(env):
    project = required(env, "BQ_JOB_PROJECT")
    location = required(env, "BQ_JOB_LOCATION")
    job_id = required(env, "BQ_JOB_ID")
    address = required(env, "BQ_JOB_TERRAFORM_ADDRESS")
    token = required(env, "BQ_ACCESS_TOKEN")
    timeout = seconds(env, "BQ_JOB_WAIT_TIMEOUT_SECONDS")
    interval = seconds(env, "BQ_JOB_POLL_INTERVAL_SECONDS", DEFAULT_POLL_INTERVAL_SECONDS)
    url = job_url(
        env.get("GOOGLE_BIG_QUERY_CUSTOM_ENDPOINT") or DEFAULT_ENDPOINT, project, location, job_id
    )
    try:
        status = json.loads(required(env, "BQ_JOB_STATUS"))
    except ValueError as err:
        raise OutcomeUnknown(f"BQ_JOB_STATUS is not JSON: {err}.") from err
    if not isinstance(status, dict):
        raise OutcomeUnknown("BQ_JOB_STATUS is not a JSON object.")

    state, error = outcome(status)
    problem = None
    deadline = time.monotonic() + timeout
    if state != "DONE":
        print(f"Waiting up to {timeout:g}s for BigQuery job {job_id} to finish.", flush=True)
    while state != "DONE":
        remaining = deadline - time.monotonic()
        try:
            status = get_status(url, token, min(REQUEST_TIMEOUT_SECONDS, max(remaining, 1.0)))
            state, error = outcome(status)
            problem = None
        except RequestFailed as err:
            problem = str(err)
        if state == "DONE":
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            last_request = f" The last request failed: {problem}." if problem else ""
            raise OutcomeUnknown(
                f"BigQuery job {job_id} was not DONE after {timeout:g}s "
                f"(last state: {state or 'unknown'}).{last_request} The job may still finish: "
                "run terraform apply again to keep waiting for it, or raise "
                "search_index_job_wait_timeout_seconds."
            )
        time.sleep(min(interval, remaining))

    if error:
        print(
            f"BigQuery job {job_id} failed {error}. Fix the cause, then run "
            f"terraform apply -replace='{address}' to retry it under a new job ID.",
            file=sys.stderr,
        )
        return EXIT_JOB_FAILED
    print(f"BigQuery job {job_id} finished without an error.")
    return 0


def main():
    try:
        return wait(os.environ)
    except OutcomeUnknown as err:
        print(err, file=sys.stderr)
        return EXIT_OUTCOME_UNKNOWN
    except Exception as err:  # pylint: disable=broad-except
        # Python exits with status 1 on an uncaught exception, which would
        # read as a failed job.
        print(f"Could not find out how the BigQuery job ended: {err!r}", file=sys.stderr)
        return EXIT_OUTCOME_UNKNOWN


if __name__ == "__main__":
    sys.exit(main())
