# Live BigQuery & GCS Integration CI Setup

The `.github/workflows/live-integration.yml` workflow runs the full `-tags=integration` suite against a dedicated non-production Google Cloud test project on a nightly schedule (`42 4 * * *`) and via manual `workflow_dispatch`.

Authentication uses keyless OpenID Connect (OIDC) through Google Cloud Workload Identity Federation (`google-github-actions/auth@v3`) — no long-lived service account JSON keys are stored in GitHub.

---

## 1. Provision Workload Identity Federation via Terraform

`deploy/terraform/ci_wif.tf` defines an opt-in Workload Identity Pool, OIDC Provider, and dedicated least-privilege CI service account gated by `enable_github_wif = true`:

- **`google_iam_workload_identity_pool.github_ci`** — Dedicated pool (`bq-otel-exporter-ci` by default).
- **`google_iam_workload_identity_pool_provider.github_ci`** — OIDC provider for `https://token.actions.githubusercontent.com` with an attribute condition pinning the immutable numeric `repository_owner_id` and `repository_id`, repository name, `refs/heads/main`, the workflow path (`.github/workflows/live-integration.yml`), and allowed trigger events (`schedule`, `workflow_dispatch`):
  ```hcl
  attribute_condition = join(" && ", [
    "attribute.repository_owner_id == \"${var.github_repository_owner_id}\"",
    "attribute.repository_id == \"${var.github_repository_id}\"",
    "attribute.repository == \"${var.github_repository}\"",
    "attribute.ref == \"refs/heads/main\"",
    "attribute.workflow_ref == \"${var.github_repository}/${var.github_workflow_ref}@refs/heads/main\"",
    "attribute.event_name in [${join(", ", formatlist("%q", var.github_allowed_events))}]",
  ])
  ```
- **`google_service_account.github_ci`** — Dedicated CI runner identity (`bq-otel-exporter-ci@<project>.iam.gserviceaccount.com`) bound by `attribute.repository_id/${var.github_repository_id}` and granted:
  - `roles/bigquery.user` on the dedicated CI test project so integration tests can create and tear down their own ephemeral `otel_exporter_it_*`, `otel_exporter_recovery_it_*`, `otel_cq_it_*`, `otel_offload_it_*`, `otel_exporter_issues_it_*`, and `otel_bench_*` datasets, run query/DDL jobs, read query results through the BigQuery Storage Read API, and stream rows into those ephemeral datasets via the BigQuery Storage Write API without write access to pre-existing datasets.
  - `roles/storage.objectUser` on the dedicated CI test bucket (`ci_offload_bucket`) with an IAM condition restricting object operations to the `it-offload-` prefix (`resource.name.startsWith("projects/_/buckets/${var.ci_offload_bucket}/objects/it-offload-")`).
    - **Prerequisite (`ci_offload_bucket`)**: Enable **Uniform Bucket-Level Access (UBLA)** (`uniform_bucket_level_access = true`) on `ci_offload_bucket` (required by Cloud Storage for conditional IAM bindings) and configure a 1-day Object Lifecycle Management `Delete` rule on `matchesPrefix = ["it-offload-"]` as a safety net for abruptly terminated runs.

Look up your repository's immutable numeric `id` and `owner.id` with `gh`:

```bash
REPO_ID="$(gh api repos/GoogleCloudPlatform/BQ-OTEL-Exporter --jq '.id')"
OWNER_ID="$(gh api repos/GoogleCloudPlatform/BQ-OTEL-Exporter --jq '.owner.id')"
```

Apply the WIF resources against your designated non-production CI test project:

```bash
cd deploy/terraform

terraform init
terraform apply \
  -var="project_id=YOUR_CI_GCP_PROJECT" \
  -var="enable_github_wif=true" \
  -var="github_repository=GoogleCloudPlatform/BQ-OTEL-Exporter" \
  -var="github_repository_id=${REPO_ID}" \
  -var="github_repository_owner_id=${OWNER_ID}" \
  -var="ci_offload_bucket=YOUR_CI_OFFLOAD_TEST_BUCKET"
```

Read back the provisioned provider resource name and service account email:

```bash
WIF_PROVIDER="$(terraform output -raw ci_workload_identity_provider)"
CI_SA_EMAIL="$(terraform output -raw ci_service_account_email)"
```

---

## 2. Configure GitHub Repository Variables

Set the repository variables consumed by `.github/workflows/live-integration.yml` using the GitHub CLI (`gh`):

```bash
gh variable set BQ_PROJECT \
  --repo GoogleCloudPlatform/BQ-OTEL-Exporter \
  --body "YOUR_CI_GCP_PROJECT"

gh variable set BQ_LOCATION \
  --repo GoogleCloudPlatform/BQ-OTEL-Exporter \
  --body "US"

gh variable set GCP_WORKLOAD_IDENTITY_PROVIDER \
  --repo GoogleCloudPlatform/BQ-OTEL-Exporter \
  --body "${WIF_PROVIDER}"

gh variable set GCP_SERVICE_ACCOUNT \
  --repo GoogleCloudPlatform/BQ-OTEL-Exporter \
  --body "${CI_SA_EMAIL}"

# Optional: enables live GCS bucket round-trip in TestLiveGCSOffloadAndQuarantineReplay
gh variable set BQ_OFFLOAD_TEST_BUCKET \
  --repo GoogleCloudPlatform/BQ-OTEL-Exporter \
  --body "YOUR_CI_OFFLOAD_TEST_BUCKET"
```

| Repository Variable | Required | Description |
|---|---|---|
| `BQ_PROJECT` | Yes | Dedicated non-production Google Cloud project ID where ephemeral integration datasets (`otel_exporter_it_*`, `otel_exporter_recovery_it_*`, `otel_cq_it_*`, `otel_offload_it_*`, `otel_exporter_issues_it_*`, `otel_bench_*`) are created and deleted. |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Yes | Full Workload Identity Provider resource path (`projects/<num>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`). |
| `GCP_SERVICE_ACCOUNT` | Yes | Email of the CI service account impersonated by `google-github-actions/auth@v3`. |
| `BQ_LOCATION` | No (defaults to `US`) | BigQuery dataset location used by the integration suite. |
| `BQ_OFFLOAD_TEST_BUCKET` | No | Dedicated GCS test bucket name (or `BQ_OFFLOAD_BUCKET` when running locally) with Uniform Bucket-Level Access enabled, used by `TestLiveGCSOffloadAndQuarantineReplay` to verify live GCS upload, Step-0 redaction before upload, BigQuery `ObjectRef` columns, and `quarantinereplay.Replay`, and by `TestLiveIssuesEndToEndBigQuery` for payload and quarantine offload, the Cloud Storage redaction scan, `quarantinereplay.ReplayBigQuery` through offloaded payloads, and the `bq-otel-backfill` archive source. When `BQ_OFFLOAD_TEST_BUCKET` is set in CI, the workflow automatically sets `REQUIRE_LIVE_GCS=1`. |

### Bootstrap Behavior Before Variables Are Configured

The `check-config` step runs first on every execution and evaluates the three required repository variables (`BQ_PROJECT`, `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT`) together with the trigger event and the `fail_if_unconfigured` boolean input. That input exists only for manual runs: set it on the **Actions → Live BigQuery Integration → Run workflow** form (or `gh workflow run live-integration.yml -f fail_if_unconfigured=false`); it defaults to `true`, and scheduled runs have no inputs at all. The complete behavior matrix is:

| Trigger | Required variables | `fail_if_unconfigured` | Result |
|---|---|---|---|
| `schedule` or `workflow_dispatch` | all set | any | `configured=true`; checkout, Workload Identity Federation authentication, and the live suite run with `REQUIRE_LIVE_BQ=1` (and `REQUIRE_LIVE_GCS=1` when `BQ_OFFLOAD_TEST_BUCKET` is set). |
| `schedule` | any missing | not applicable (no inputs on scheduled runs) | Fails closed: `::error::` annotation and `exit 1` before checkout or authentication, so scheduled evidence is never falsely green. |
| `workflow_dispatch` | any missing | `true` (the default) | Fails closed: `::error::` annotation and `exit 1` before checkout or authentication. |
| `workflow_dispatch` | any missing | `false` (explicit opt-out) | `::warning::` annotation, `configured=false`, and the checkout, authentication, and test steps skip cleanly; the job succeeds without running the live suite. |

The explicit `fail_if_unconfigured=false` opt-out is the only path that ends an unconfigured run successfully. Use it while bootstrapping a fork or a new CI project; once all three variables are set, every run executes the live suite fail-closed. `TestLiveIntegrationCheckConfigBehavior` executes this matrix against the workflow's actual shell script, and `TestLiveIntegrationDocsDescribeFailClosedMatrix` checks that this table stays aligned with it.

### Running the Live Suite Locally

The workflow's environment can be reproduced from a workstation with Application Default Credentials (`gcloud auth application-default login`) for an identity that holds the roles above on a non-production project:

```bash
export BQ_PROJECT=<GCP_PROJECT>
export REQUIRE_LIVE_BQ=1
# Optional: enables the Cloud Storage parts; the bucket needs Uniform Bucket-Level Access.
export BQ_OFFLOAD_TEST_BUCKET=<TEST_BUCKET>
export REQUIRE_LIVE_GCS=1
go test -v -race -tags=integration -count=1 -timeout=20m ./...
```

Two settings of the local machine, rather than of the suite, commonly get in the way:

- **Quota project.** Google API clients bill requests to the `quota_project_id` stored in the Application Default Credentials file, not to `BQ_PROJECT`. When that is a project the identity cannot use, every call fails with `403 USER_PROJECT_DENIED` (`serviceusage.services.use`) before it reaches BigQuery. Set `GOOGLE_CLOUD_QUOTA_PROJECT=<GCP_PROJECT>`, or run `gcloud auth application-default set-quota-project <GCP_PROJECT>`.
- **Client certificates.** On a machine configured for context-aware access or mTLS, the clients may switch to the `mtls.googleapis.com` endpoints. Set `GOOGLE_API_USE_CLIENT_CERTIFICATE=false` to use the regular endpoints.

---

## 3. Security & Fork-PR Isolation

1. **No `pull_request` trigger on untrusted forks**: `.github/workflows/live-integration.yml` triggers only on `schedule` (`42 4 * * *`) and `workflow_dispatch`.
2. **Immutable ID, branch, workflow, and event OIDC condition**: Even if another workflow were triggered from a non-`main` branch or renamed repository, the GCP Workload Identity Pool Provider enforces `attribute.repository_owner_id`, `attribute.repository_id`, `attribute.repository`, `attribute.ref == "refs/heads/main"`, `attribute.workflow_ref`, and `attribute.event_name` at the IAM token-exchange boundary.
3. **Fail-closed enforcement once configured**: When `BQ_PROJECT`, `GCP_WORKLOAD_IDENTITY_PROVIDER`, and `GCP_SERVICE_ACCOUNT` are set, the workflow sets `REQUIRE_LIVE_BQ=1` (and `REQUIRE_LIVE_GCS=1` when `BQ_OFFLOAD_TEST_BUCKET` is set), causing the live test suite to call `t.Fatal` rather than `t.Skip` if any prerequisite is missing. When any of the three variables is missing, the `check-config` step itself fails closed unless the run is a manual dispatch with the explicit `fail_if_unconfigured=false` opt-out (see the behavior matrix in section 2).
4. **Ephemeral resource cleanup**: Every live test targets uniquely suffixed datasets (`_<unix_milli>_<rand_hex>`) and deletes only datasets it created. `TestAutoCreateLiveBigQuery` exercises cold-dataset provisioning (`AutoCreate.Dataset = true`) and registers `DeleteWithContents` only when `traces.createdDataset` is `true` (set only when `CreateDataset` returns `nil`, never when `DatasetMetadata` succeeds or `CreateDataset` returns `409 AlreadyExists`). `TestRecoveryAfterAttemptTimeoutsLiveBigQuery`, `TestLiveGCSOffloadAndQuarantineReplay`, `TestLiveContinuousQueriesDryRun`, and `TestLiveIssuesEndToEndBigQuery` pre-create their datasets via `createOwnedEphemeralDataset`: the first two configure `AutoCreate.Dataset = false` on their exporter configs, `TestLiveContinuousQueriesDryRun` builds no exporter config and uses the BigQuery client directly to dry-run Continuous Query statements, and `TestLiveIssuesEndToEndBigQuery` keeps `auto_create.dataset: true` in its configuration against the dataset it already owns, so the exporter never creates one. `TestLiveRunMultiWorkerBytesPerRowParity` (in `internal/testbench`) creates an `otel_bench_*` dataset carrying a random ownership label and deletes it on cleanup. `TestLiveGCSOffloadAndQuarantineReplay` writes under a unique `it-offload-<unix_nano>` object prefix and `TestLiveIssuesEndToEndBigQuery` under `it-offload-issues-<rand_hex>/` and `it-offload-issues-<rand_hex>-backfill/`; both record every uploaded GCS object URI at the `WriteObject` boundary so `t.Cleanup` deletes each object directly via `storage.objects.delete` (satisfying the object-prefix IAM condition without requiring bucket-wide `storage.objects.list`).
