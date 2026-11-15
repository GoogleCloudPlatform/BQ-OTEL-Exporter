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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_ENDPOINT = "https://bigquery.googleapis.com/bigquery/v2/"
DEFAULT_POLL_INTERVAL_SECONDS = 2.0
# The last request starts this long before the wait deadline, or one poll
# interval before it when that is shorter, so a job that finishes during the
# final poll interval is still seen instead of slept through.
FINAL_POLL_BUDGET_SECONDS = 1.0
# Per-socket-operation timeout inside the overall wall-clock wait deadline so a
# stalled socket cannot block indefinitely on a single poll.
REQUEST_TIMEOUT_SECONDS = 30.0
# Read responses in bounded chunks so each socket read can enforce the remaining
# wall-clock deadline instead of resetting the timeout on every trickled byte.
READ_CHUNK_BYTES = 8192
# A job's status is a few hundred bytes; anything larger is not one.
MAX_RESPONSE_BYTES = 1 << 20

EXIT_JOB_FAILED = 1
EXIT_OUTCOME_UNKNOWN = 2


class OutcomeUnknown(Exception):
    """The job's outcome cannot be determined, and asking again will not help."""


class RequestFailed(Exception):
    """A jobs.get request failed; a later one may succeed."""


class RequestDeadlineExceeded(RequestFailed):
    """The current poll ran into the overall wall-clock wait deadline."""


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


def rejected_token(detail):
    """Returns the error for an access token BigQuery rejected with HTTP 401."""
    return OutcomeUnknown(
        f"BigQuery rejected the access token (HTTP 401): {detail}. The token Terraform "
        "passed may have expired: run terraform apply again."
    )


def error_body_cut_short(code):
    """Returns the error for an error response the wait deadline cut short.

    BigQuery answered with an error status, so the request failed even though
    the deadline passed while its body was still arriving.
    """
    detail = "error body timed out at wait deadline"
    if code == 401:
        return rejected_token(detail)
    return RequestFailed(f"HTTP {code} ({detail})")


def _underlying_socket(stream):
    cur = stream
    for _ in range(6):
        if hasattr(cur, "_sock"):
            return cur._sock
        if hasattr(cur, "raw"):
            cur = cur.raw
        elif hasattr(cur, "fp"):
            cur = cur.fp
        else:
            break
    return None


def read_bounded(stream, deadline):
    """Reads up to MAX_RESPONSE_BYTES without exceeding deadline."""
    chunks = []
    total = 0
    while total < MAX_RESPONSE_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out")
        sock = _underlying_socket(stream)
        if sock is not None and hasattr(sock, "settimeout"):
            sock.settimeout(min(REQUEST_TIMEOUT_SECONDS, remaining))
        limit = min(READ_CHUNK_BYTES, MAX_RESPONSE_BYTES - total)
        chunk = stream.read1(limit) if hasattr(stream, "read1") else stream.read(limit)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def get_status(url, token, deadline, seen):
    """Returns the JobStatus of the job at url, or None if deadline already passed.

    seen["request_sent"] is set right before urlopen sends the request, and
    seen["http_error_code"] records the status of an error response as soon as
    it arrives, before its body is read, so that poll_status can report the
    failure even when the deadline passes while the body is still arriving.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    # Unredirected, so that a redirect to another host never carries the token.
    request.add_unredirected_header("Authorization", f"Bearer {token}")
    seen["request_sent"] = True
    try:
        with urllib.request.urlopen(request, timeout=min(REQUEST_TIMEOUT_SECONDS, remaining)) as response:
            body = read_bounded(response, deadline)
    except urllib.error.HTTPError as err:
        seen["http_error_code"] = err.code
        with err:
            timed_out = False
            try:
                err_body = read_bounded(err, deadline)
            except TimeoutError:
                timed_out = True
                err_body = b""
            except (OSError, http.client.HTTPException):
                err_body = b""
            if timed_out and time.monotonic() >= deadline:
                raise error_body_cut_short(err.code) from err
            if err.code == 401:
                detail = "error body timed out" if timed_out else api_error(err_body)
                raise rejected_token(detail) from err
            if timed_out:
                raise RequestFailed(f"HTTP {err.code} (error body timed out)") from err
            raise RequestFailed(f"HTTP {err.code}: {api_error(err_body)}") from err
    except TimeoutError as err:
        msg = str(err) or "timed out"
        if time.monotonic() >= deadline:
            raise RequestDeadlineExceeded(msg) from err
        raise RequestFailed(msg) from err
    except urllib.error.URLError as err:
        if isinstance(err.reason, TimeoutError):
            msg = str(err.reason) or "timed out"
            if time.monotonic() >= deadline:
                raise RequestDeadlineExceeded(msg) from err
            raise RequestFailed(msg) from err
        raise RequestFailed(str(err) or type(err).__name__) from err
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


def poll_status(url, token, deadline):
    """Runs get_status in a daemon thread bounded strictly by deadline."""
    result = {}
    seen = {}

    def target():
        try:
            result["status"] = get_status(url, token, deadline, seen)
        except BaseException as exc:  # pylint: disable=broad-except
            result["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    remaining = max(0.0, deadline - time.monotonic())
    thread.join(timeout=remaining)
    if thread.is_alive():
        # get_status reads the body of an error response against the same
        # deadline and can still be unwinding from that read here. Its status
        # has already arrived and says the request failed: report that, not a
        # request still in flight.
        code = seen.get("http_error_code")
        if code is not None:
            raise error_body_cut_short(code)
        if not seen.get("request_sent"):
            return None
        raise RequestDeadlineExceeded("timed out")
    if "error" in result:
        raise result["error"]
    return result.get("status")


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
    # problem is how the last request that finished failed, kept until a later
    # request succeeds. cut_short records that the wait deadline passed while
    # a request was still in flight, which says nothing about the API: an
    # earlier failure stays the reported cause, and without one the message
    # says the request was cut short instead of calling it a failure.
    problem = None
    cut_short = False
    deadline = time.monotonic() + timeout
    final_budget = min(FINAL_POLL_BUDGET_SECONDS, interval)
    if state != "DONE":
        print(f"Waiting up to {timeout:g}s for BigQuery job {job_id} to finish.", flush=True)
    while state != "DONE":
        try:
            next_status = poll_status(url, token, deadline)
        except OutcomeUnknown:
            raise
        except RequestDeadlineExceeded:
            cut_short = True
            break
        except RequestFailed as err:
            problem = str(err)
        else:
            if next_status is None:
                break
            if time.monotonic() > deadline:
                cut_short = True
                break
            status = next_status
            state, error = outcome(status)
            problem = None
            if state == "DONE":
                break
        remaining = deadline - time.monotonic()
        if remaining <= final_budget:
            # That was the last request with time to finish before the
            # deadline. Give up at the deadline, not before it.
            if remaining > 0:
                time.sleep(remaining)
            break
        # Sleep at most until final_budget before the deadline, so the last
        # request still runs instead of the loop sleeping out the remainder.
        time.sleep(min(interval, remaining - final_budget))

    if state != "DONE":
        if problem:
            last_request = f" The last request failed: {problem}."
        elif cut_short:
            last_request = " The last request was still in flight when the wait deadline passed."
        else:
            last_request = ""
        raise OutcomeUnknown(
            f"BigQuery job {job_id} was not DONE after {timeout:g}s "
            f"(last state: {state or 'unknown'}).{last_request} The job may still finish: "
            "run terraform apply again to keep waiting for it, or raise "
            "search_index_job_wait_timeout_seconds."
        )

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
