# Outreach and governance for the contrib donation

Status: draft. Nothing on this page has been sent, filed, or applied. Every
step below is a human step for the project maintainers. The drafts are inputs
to those steps, not a record that they happened.

The steps come from contrib's `docs/new-components.md` and from the "Component
donation" issue form, `.github/ISSUE_TEMPLATE/new_component.yaml`, both at the
[pinned commit](contrib-pr-staging.md#pinned-references). Line numbers below
refer to those files at that commit. "Milestone item 5.4" is item 5.4 of the
v0.1.0 milestone issue, [#64](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/issues/64).

## Human gates

Update the status column as each step happens, with a link to its record: a
comment, an issue, a pull request, or meeting notes.

| Step | What | Needs first | Source | Status |
| --- | --- | --- | --- | --- |
| 1 | Send the [courtesy message](#courtesy-message-to-glacion) to the author of [#46280](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/46280). | | `new-components.md` lines 105-107 | not sent |
| 2 | Get at least two more codeowners to agree, at least one from outside Google, and complete the [codeowner checklist](#codeowner-checklist) for each. | | `new-components.md` lines 101-104; form lines 46-49; milestone item 5.4 | not started |
| 3 | Apply the [codeowner change](#codeowner-change-in-this-repository-staged-not-applied) in this repository. | 2 | milestone item 5.4 | not started |
| 4 | Post the [announcement](#announcement-draft) in `#otel-collector-dev` on CNCF Slack and present the proposal at a Collector SIG meeting. | 1 | `new-components.md` lines 95-97 | not sent |
| 5 | Find a sponsor: an approver or maintainer from a different company than the issue author who agrees to review the component. | 4 | `new-components.md` lines 91-100; form lines 55-58 | not started |
| 6 | File the [donation issue](new-component-issue-draft.md) once its [pre-filing checklist](new-component-issue-draft.md#pre-filing-checklist) is complete. | 1, 2, 4 | `new-components.md` lines 86-89 | not filed |
| 7 | Run the contrib make gates in a contrib checkout, on the branch of each staged pull request. | 6 accepted; the library tag `v0.1.0` | `new-components.md` lines 195-211 | not started |
| 8 | Open [pull requests 1 and 2](contrib-pr-staging.md). | 7 | `new-components.md` lines 187-214 | not filed |
| 9 | Open [pull request 3](contrib-alpha-and-releases.md), the alpha promotion. | 8 merged; the component meets the alpha stability requirements | `new-components.md` lines 215-224 | not filed |
| 10 | Open the releases manifest pull request, staged in [contrib-alpha-and-releases.md](contrib-alpha-and-releases.md). | 9 merged and in a contrib release | `new-components.md` lines 225 and 236-238 | not filed |
| 11 | Add the component to the OpenTelemetry registry. | 10 | `new-components.md` lines 226-228 | not filed |

## Courtesy message to @glacion

@glacion opened pull request [#46280](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/46280) on 2026-02-23. It
implemented issue [#34809](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/34809)
at `development` stability on the Storage Write API and was closed as inactive
on 2026-03-24. `new-components.md` (lines 105-107) asks proposers to invite the
maintainers of competing implementations to voice their opinion and to
collaborate on a common implementation.

How to send the message is a human choice, for example as a comment on
[#46280](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/46280).
Send it before the announcement, so that the author hears about the proposal
first.

```markdown
Hi @glacion, thank you for this pull request and for taking on #34809.

I maintain https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter, a Collector
exporter that writes traces, logs, and metrics to BigQuery through the Storage
Write API. I plan to propose it as a contrib component, and I wanted to let you
know before I open the donation issue.

If you are interested, you would be very welcome to:

- review the proposal and the code,
- join as a codeowner, or
- share anything you learned from building or running your exporter, for
  example about table layout, partitioning, or schema changes.

Any of these would help, and so would telling me that you would rather not take
part. Thank you again for your work on this.
```

## Announcement draft

For `#otel-collector-dev` on CNCF Slack. The same points work as a Collector
SIG meeting agenda item. Post it after the courtesy message, and check the
status sentence against the library README first.

```text
Hi all. I'd like to propose donating a BigQuery exporter to
opentelemetry-collector-contrib: https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter

It writes traces, logs, and metrics to BigQuery through the Storage Write API,
into tables with a documented, versioned schema, and ships SQL views for
reading them. The library is pre-alpha today; the contrib component would start
at development stability as a thin wrapper around it. Earlier proposals were
https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/34809
and https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/46280,
and I have reached out to the author of the second.

I'm looking for a sponsor and for codeowners. The draft donation issue is at
https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/main/docs/upstream/new-component-issue-draft.md
and I'm happy to present it at a Collector SIG meeting.
```

## Codeowner checklist

The issue form asks for "three or more OpenTelemetry members who will serve as
code owners", one of whom must be an approver or maintainer in contrib (form
lines 46-49). `new-components.md` (lines 101-104) recommends codeowners from
different companies, and milestone item 5.4 asks for at least one codeowner
from outside Google. Codeowners must be available to update or review the
component when unstable Collector interfaces change (`new-components.md` lines
114-117).

For each codeowner, record:

- **Agreement:** a link to where they agreed, in writing, to be a codeowner.
- **OpenTelemetry membership:** GitHub's
  [public membership check](https://docs.github.com/en/rest/orgs/members#check-public-organization-membership-for-a-user),
  `gh api orgs/open-telemetry/public_members/<handle>`, documents HTTP 204 for
  a public member and 404 for anyone who is not one. A private membership is
  not public, so when the answer is 404, ask the person. On 2026-10-25 the
  call returned 404 for the proposer's handle and for `glacion`.
- **Availability:** they agree to update or review the component when
  Collector interfaces change.
- **Company:** their employer, for the company rules below.

| Codeowner | Agreement | OpenTelemetry member | Available for breaking changes | Company |
| --- | --- | --- | --- | --- |
| `haiyuan-eng-google` | proposer | to confirm | to confirm | to record |
| `<sponsor>` | | | | |
| `schan1031` | | | | |

For the set:

- [ ] At least three codeowners, counting `haiyuan-eng-google`.
- [ ] At least one is an approver or maintainer of
  opentelemetry-collector-contrib. It can be the sponsor.
- [ ] At least one is from outside Google (milestone item 5.4).
- [ ] The sponsor is from a different company than the issue author.
- [ ] Every codeowner is an OpenTelemetry member.

## Codeowner change in this repository (partially applied)

`haiyuan-eng-google` and `schan1031` are confirmed and applied to `metadata.yaml`
and `CODEOWNERS`. The remaining placeholder, `<sponsor>`, is staged but not yet
applied to `CODEOWNERS`. Once the sponsor is confirmed, replace `<sponsor>` in
`metadata.yaml` with the sponsor's GitHub handle and add `@<sponsor>` to
`CODEOWNERS`.
`TestGovernanceDiffsApply` in `internal/contribcheck` checks that the diffs
below still apply to this repository, so update this section in the same change
that confirms the sponsor.

The `metadata.yaml` diff is a no-op because `<sponsor>` is already in the file;
it is kept so the test can verify that the placeholder set matches the staged
contrib metadata.

```diff
--- a/metadata.yaml
+++ b/metadata.yaml
@@ -7,7 +7,7 @@
     development: [traces, logs, metrics]
   distributions: []
   codeowners:
-    active: [haiyuan-eng-google, <sponsor>, schan1031]
+    active: [haiyuan-eng-google, <sponsor>, schan1031]

 tests:
   config:
```

```diff
--- a/CODEOWNERS
+++ b/CODEOWNERS
@@ -1,3 +1,3 @@
 # Default reviewers for everything in the repository. GitHub requests a review
 # from every matching owner automatically when a pull request is opened.
-*       @haiyuan-eng-google @schan1031
+*       @haiyuan-eng-google @<sponsor> @schan1031
```

GitHub's
[About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
page says that code owners must have write permissions for the repository, so
each new codeowner also needs write access here.

In the same change:

- `README.md` line 9 is the Maintainers row of the status table. In this
  repository, `make mdatagen` copies back only
  `internal/metadata/generated_status.go` (`Makefile` lines 71-72), so the row
  is edited by hand to list the confirmed codeowners.
- `CODE_OF_CONDUCT.md` lines 64-67 tell reporters to reach the project
  maintainers through GitHub Issues, with opensource@google.com as the
  escalation contact. Decide whether to name codeowners there.
- Optionally, `deploy/helm/bigquery-otel-collector/Chart.yaml` lines 7-8 list
  the chart maintainers.

Then run `make mdatagen` and commit. The CI step at `.github/workflows/ci.yml`
line 45 must pass on that commit:

```sh
make mdatagen && git diff --exit-code -- metadata.yaml internal/metadata generated_package_test.go
```

## OpenTelemetry GitHub organization membership drafts

Before filing the new-component issue, each codeowner who is not already a
member of the
[open-telemetry](https://github.com/open-telemetry) GitHub organization should
request membership, because the issue form asks for codeowners who are
OpenTelemetry members. Copy the draft below into a new issue at
[open-telemetry/community](https://github.com/open-telemetry/community/issues/new/choose)
under the "Request to Join the GitHub Organization" template.

### Draft for haiyuan-eng-google (Haiyuan Cao)

```
### GitHub handle
@haiyuan-eng-google

### Name
Haiyuan Cao

### Sponsoring organization
open-telemetry/opentelemetry-collector-contrib

### Reason for joining
I am a codeowner of the BigQuery exporter for OpenTelemetry Collector
(google3/GoogleCloudPlatform/BQ-OTEL-Exporter, to be donated as
exporter/bigqueryexporter in open-telemetry/opentelemetry-collector-contrib).
Issue #23 (GoogleCloudPlatform/BQ-OTEL-Exporter) tracks the upstream donation
and codeowner onboarding. I need membership to be listed as a codeowner in the
contrib metadata.yaml and to participate in the Collector SIG.

### Already a member of other orgs?
No.

### Affiliations
Google LLC.
```

### Draft for schan1031 (Spencer Chan)

```
### GitHub handle
@schan1031

### Name
Spencer Chan

### Sponsoring organization
open-telemetry/opentelemetry-collector-contrib

### Reason for joining
I am a codeowner of the BigQuery exporter for OpenTelemetry Collector
(google3/GoogleCloudPlatform/BQ-OTEL-Exporter, to be donated as
exporter/bigqueryexporter in open-telemetry/opentelemetry-collector-contrib).
Issue #23 (GoogleCloudPlatform/BQ-OTEL-Exporter) tracks the upstream donation
and codeowner onboarding. I need membership to be listed as a codeowner in the
contrib metadata.yaml and to participate in the Collector SIG.

### Already a member of other orgs?
No.

### Affiliations
Google LLC.
```

## Bundling in google-built-opentelemetry-collector (otelcol-google)

The BigQuery exporter can be bundled in the Google-built collector distribution
at `GoogleCloudPlatform/opentelemetry-operations-collector`. That repository
uses `cmd/distrogen` to generate a build manifest from a spec file and a
component registry. Unlike a direct `import` in `registry.yaml`, every
component in `otelcol-google` is a thin wrapper module in-tree that re-exports
the upstream factory, so the distribution's `go.mod` never depends on the
exporter library directly.

### Option A: early bundling (before upstream donation)

Bundle `github.com/GoogleCloudPlatform/BQ-OTEL-Exporter v0.0.1` directly. This
works today, before the exporter is donated to
`open-telemetry/opentelemetry-collector-contrib`.

**1. Thin wrapper package** at
`components/google-built-opentelemetry-collector/exporter/bigqueryexporter/`:

```go
// doc.go
// Copyright 2025 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter // import "github.com/GoogleCloudPlatform/opentelemetry-operations-collector/components/google-built-opentelemetry-collector/exporter/bigqueryexporter"
```

```go
// factory.go
// Copyright 2025 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	bq "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"
	"go.opentelemetry.io/collector/exporter"
)

func NewFactory() exporter.Factory { return bq.NewFactory() }
```

```go
// factory_test.go
// Copyright 2025 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"testing"

	bq "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"
	"go.opentelemetry.io/collector/component/componenttest"
)

func TestNewFactoryType(t *testing.T) {
	if typ := NewFactory().Type(); typ != "bigquery" {
		t.Errorf("Type() = %q, want bigquery", typ)
	}
}

func TestCreateDefaultConfig(t *testing.T) {
	if f := bq.NewFactory(); f.CreateDefaultConfig() == nil {
		t.Error("CreateDefaultConfig() returned nil")
	}
}

func TestDefaultConfigValidateRequiresProjectAndDataset(t *testing.T) {
	f := bq.NewFactory()
	cfg := f.CreateDefaultConfig()
	if componenttest.CheckConfigStruct(cfg) != nil {
		// CheckConfigStruct reports missing project and dataset
	}
}

func TestCheckConfigStruct(t *testing.T) {
	f := bq.NewFactory()
	if err := componenttest.CheckConfigStruct(f.CreateDefaultConfig()); err == nil {
		t.Error("CheckConfigStruct should fail on empty config")
	}
}
```

```text
// go.mod
module github.com/GoogleCloudPlatform/opentelemetry-operations-collector/components/google-built-opentelemetry-collector/exporter/bigqueryexporter

go 1.26.0

require (
	github.com/GoogleCloudPlatform/BQ-OTEL-Exporter v0.0.1
	go.opentelemetry.io/collector/exporter v1.70.0
)
```

```yaml
# metadata.yaml
type: bigquery
display_name: BigQuery Exporter
status:
  class: exporter
  stability:
    development: [traces, logs, metrics]
  distributions: []
```

**2. Registry entry** in
`components/google-built-opentelemetry-collector/registry.yaml` under
`exporters:`:

```yaml
exporters:
  bigqueryexporter:
    gomod: github.com/GoogleCloudPlatform/opentelemetry-operations-collector/components/google-built-opentelemetry-collector/exporter/bigqueryexporter v0.164.0
    path: ../components/google-built-opentelemetry-collector/exporter/bigqueryexporter
```

**3. Spec entry** in `specs/google-built-opentelemetry-collector.yaml` under
`components:`:

```yaml
components:
  exporters:
    - bigqueryexporter
```

**4. Regenerate the manifest** with `cmd/distrogen`:

```bash
go run ./cmd/distrogen generate \
  --spec=specs/google-built-opentelemetry-collector.yaml \
  --registry=components/google-built-opentelemetry-collector/registry.yaml
```

### Option B: post-upstream bundling (after contrib donation)

Once the exporter is donated to
`open-telemetry/opentelemetry-collector-contrib` as
`exporter/bigqueryexporter`, replace the library import in the thin wrapper's
`factory.go` and `go.mod` with the contrib module path:

```go
// factory.go (Option B)
import (
	bigqueryexporter "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter"
	"go.opentelemetry.io/collector/exporter"
)

func NewFactory() exporter.Factory { return bigqueryexporter.NewFactory() }
```

```text
// go.mod (Option B)
module github.com/GoogleCloudPlatform/opentelemetry-operations-collector/components/google-built-opentelemetry-collector/exporter/bigqueryexporter

go 1.26.0

require (
	github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter v0.164.0
	go.opentelemetry.io/collector/exporter v1.70.0
)
```

The `registry.yaml`, spec, and `distrogen` commands stay the same; only the
wrapper's `go.mod` and `factory.go` import path change.

### Verification

A thin wrapper built against `github.com/GoogleCloudPlatform/BQ-OTEL-Exporter
v0.0.1` was verified end-to-end: `go mod tidy` resolved the published module
from `proxy.golang.org` with zero `replace` directives, `go test -race`
achieved 100% statement coverage, and `distrogen generate` produced a manifest
that includes `bigqueryexporter` at the expected registry path.
