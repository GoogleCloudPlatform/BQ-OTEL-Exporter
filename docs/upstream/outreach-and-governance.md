# Outreach and governance for the contrib donation

Status: draft. Nothing on this page has been sent, filed, or applied. Every
step below is a human step for the project maintainers. The drafts are inputs
to those steps, not a record that they happened.

The steps come from contrib's `docs/new-components.md` and from the "Component
donation" issue form, `.github/ISSUE_TEMPLATE/new_component.yaml`, both at the
[pinned commit](contrib-pr-staging.md#pinned-references)
(`87eb65f5e96d9d70315ee401515c330c105d2a63`). Line numbers below
refer to those files at that commit. "Milestone item 5.4" is item 5.4 of the
v0.1.0 milestone issue, [#23](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/issues/23).

## Human gates

Update the status column as each step happens, with a link to its record: a
comment, an issue, a pull request, or meeting notes.

| Step | What | Needs first | Source | Status |
| --- | --- | --- | --- | --- |
| 1 | Send the [courtesy message](#courtesy-message-to-glacion) to the author of [#46280](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/46280). | | `new-components.md` lines 105-107 | not sent |
| 2 | Get at least two more codeowners to agree, at least one from outside Google, and complete the [codeowner checklist](#codeowner-checklist) for each. | | `new-components.md` lines 101-104; form lines 46-49; milestone item 5.4 | OpenTelemetry org membership issues drafted below (pending filing); @haiyuan-eng-google confirmed, @schan1031 2FA & EasyCLA verification tracked in #23. |
| 3 | Apply the [codeowner change](#codeowner-change-in-this-repository-partially-applied) in this repository. | 2 | milestone item 5.4 | partially applied (haiyuan-eng-google and schan1031 applied; <sponsor> pending sponsor acceptance). |
| 4 | Post the [announcement](#announcement-draft) in `#otel-collector-dev` on CNCF Slack and present the proposal at a Collector SIG meeting. | 1 | `new-components.md` lines 95-97 | not sent |
| 5 | Find a sponsor: an approver or maintainer from a different company than the issue author who agrees to review the component. | 4 | `new-components.md` lines 91-100; form lines 55-58 | not started |
| 6 | File the [donation issue](new-component-issue-draft.md) once its [pre-filing checklist](new-component-issue-draft.md#pre-filing-checklist) is complete and external/custom-OCB usage outside `opentelemetry-collector-contrib` is recorded in the [adopter evidence log](contrib-alpha-and-releases.md#adopter-and-production-exposure-evidence-log-42). | 1, 2, 4 | `new-components.md` lines 86-89 | not filed |
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
reading them. The library is at development stability today (published at v0.0.3, targeting v0.1.0 for the donation; BigQuery table schema v0alpha2);
the contrib component would start at development stability as a thin wrapper
around it. Earlier proposals were
https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/34809
and https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/46280,
and I have reached out to the author of the second.

I'm looking for a sponsor and for codeowners. The draft donation issue is at
https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/main/docs/upstream/new-component-issue-draft.md
and I'm happy to present it at a Collector SIG meeting.
```

## Sponsorship and external codeowner recruitment

No single-vendor cloud-destination exception exists in OpenTelemetry; current
`docs/new-components.md` rules apply to every new component donation, including
this one. Under `docs/new-components.md` and
`.github/ISSUE_TEMPLATE/new_component.yaml`, donating a component requires prior
usage outside `opentelemetry-collector-contrib` (tracked for pre-donation custom
OCB and standalone library deployments in the
[adopter and production exposure evidence log](contrib-alpha-and-releases.md#adopter-and-production-exposure-evidence-log-42)),
at least three active codeowners (at least two besides the sponsor), and a
sponsor who is a Collector approver or maintainer from a different company than
the issue author (milestone item 5.4).

Because `@haiyuan-eng-google` and `@schan1031` are both at Google LLC, two
complementary outreach paths run in parallel before PR 1 is opened:

1. **Cross-Company Collector Sponsor**: Announce the proposal in
   `#otel-collector-dev` and present at a Collector SIG meeting to recruit a
   Collector approver or maintainer outside Google who agrees to sponsor and
   review PRs 1–3.
2. **External Production Adopter Co-Codeowner**: Invite an external
   organization running `BQ-OTEL-Exporter` in production (or `@glacion` via the
   courtesy outreach above) to join as a non-Google co-codeowner with direct
   operational experience alongside the Collector sponsor.

Once the cross-company sponsor (and any additional external co-codeowner) is
confirmed, replace `<sponsor>` in `metadata.yaml`, `CODEOWNERS`, and
`docs/upstream/*.md`.

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
  call returned 404 for the proposer's handle and for `glacion`. In addition,
  `opentelemetry-collector-contrib/.github/workflows/check-codeowners.yaml`
  requires every handle in `metadata.yaml` `codeowners.active` to be **both**
  an `open-telemetry` organization member **and** a member of the
  `@open-telemetry/collector-contrib-contributors` team.
- **Availability:** they agree to update or review the component when
  Collector interfaces change.
- **Company:** their employer, for the company rules below.

| Codeowner | Agreement | OpenTelemetry member | Available for breaking changes | Company |
| --- | --- | --- | --- | --- |
| `haiyuan-eng-google` | proposer | pending filing | confirmed | Google LLC |
| `<sponsor>` | | | | |
| `schan1031` | confirmed | pending filing | confirmed | Google LLC |

For the set:

- [ ] At least three codeowners, counting `haiyuan-eng-google`.
- [ ] At least one is an approver or maintainer of
  opentelemetry-collector-contrib. It can be the sponsor.
- [ ] At least one is from outside Google (milestone item 5.4).
- [ ] The sponsor is from a different company than the issue author.
- [ ] Every codeowner is an OpenTelemetry organization member and a member of
  `@open-telemetry/collector-contrib-contributors` (enforced by
  `check-codeowners.yaml` in `opentelemetry-collector-contrib`).

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
OpenTelemetry members and `opentelemetry-collector-contrib`'s
`.github/workflows/check-codeowners.yaml` CI workflow verifies that every
handle in `metadata.yaml` `codeowners.active` is both an `open-telemetry`
organization member and a member of the
`@open-telemetry/collector-contrib-contributors` team. Copy the draft below
into a new issue at
[open-telemetry/community](https://github.com/open-telemetry/community/issues/new?template=membership.md)
under `.github/ISSUE_TEMPLATE/membership.md` ("Request to Join the GitHub
Organization"), and once added to the organization, confirm membership in
`@open-telemetry/collector-contrib-contributors` before opening PR 1.

### Draft for haiyuan-eng-google (Haiyuan Cao)

Title: `REQUEST: New membership for haiyuan-eng-google`

```markdown
### GitHub Username

@haiyuan-eng-google

### Requirements

- [x] I have reviewed the community membership guidelines (https://github.com/open-telemetry/community/blob/main/guides/contributor/membership.md)
- [ ] I have enabled 2FA on my GitHub account. See https://github.com/settings/security
- [ ] I have subscribed to the [Slack channel](https://cloud-native.slack.com/archives/CJFCJHG4Q) (use https://slack.cncf.io/ to get an invite)
- [ ] I am actively contributing to 1 or more OpenTelemetry subprojects
- [ ] I have two sponsors that meet the sponsor requirements listed in the community membership guidelines. Among other requirements, sponsors must be approvers or maintainers of at least one repository in the organization and not both affiliated with the same company
- [ ] I have spoken to my sponsors ahead of this application, and they have agreed to sponsor my application

### Sponsors

- @<sponsor>
- @<second-sponsor>

### List of contributions to the OpenTelemetry project
- Lead author and maintainer of the OpenTelemetry Collector BigQuery Exporter (`https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter`, published at `v0.0.3` and staged for donation as `exporter/bigqueryexporter` in `open-telemetry/opentelemetry-collector-contrib`).
- Staged the 3-PR `opentelemetry-collector-contrib` component donation (`docs/upstream/contrib-pr-staging.md`, `docs/upstream/contrib-alpha-and-releases.md`) and `testbed` harness (`docs/upstream/contrib-testbed-staging.md`) tracked under `GoogleCloudPlatform/BQ-OTEL-Exporter#23`.
- Requesting `open-telemetry` organization membership and addition to `@open-telemetry/collector-contrib-contributors` to serve as an active codeowner of `exporter/bigqueryexporter`.
```

### Draft for schan1031 (Spencer Chan)

Title: `REQUEST: New membership for schan1031`

```markdown
### GitHub Username

@schan1031

### Requirements

- [x] I have reviewed the community membership guidelines (https://github.com/open-telemetry/community/blob/main/guides/contributor/membership.md)
- [ ] I have enabled 2FA on my GitHub account. See https://github.com/settings/security
- [ ] I have subscribed to the [Slack channel](https://cloud-native.slack.com/archives/CJFCJHG4Q) (use https://slack.cncf.io/ to get an invite)
- [ ] I am actively contributing to 1 or more OpenTelemetry subprojects
- [ ] I have two sponsors that meet the sponsor requirements listed in the community membership guidelines. Among other requirements, sponsors must be approvers or maintainers of at least one repository in the organization and not both affiliated with the same company
- [ ] I have spoken to my sponsors ahead of this application, and they have agreed to sponsor my application

### Sponsors

- @<sponsor>
- @<second-sponsor>

### List of contributions to the OpenTelemetry project
- Co-maintainer and codeowner of the OpenTelemetry Collector BigQuery Exporter (`https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter`, published at `v0.0.3` and staged for donation as `exporter/bigqueryexporter` in `open-telemetry/opentelemetry-collector-contrib`).
- Reviewed and verified the BigQuery Storage Write API exporter architecture, schema views, and `opentelemetry-collector-contrib` donation staging tracked under `GoogleCloudPlatform/BQ-OTEL-Exporter#23`.
- Requesting `open-telemetry` organization membership and addition to `@open-telemetry/collector-contrib-contributors` to serve as an active codeowner of `exporter/bigqueryexporter`.
```

## Bundling in google-built-opentelemetry-collector (otelcol-google)

For self-deployed Google-built collectors, this project proposes adding the
exporter to **standalone `otelcol-google`**
(`GoogleCloudPlatform/opentelemetry-operations-collector`) through that
distribution's standard component-addition process **once
`exporter/bigqueryexporter` reaches `alpha` stability in
`open-telemetry/opentelemetry-collector-contrib`** — subject to
`opentelemetry-operations-collector` maintainer review and acceptance
(following the `googlecloudpubsub` precedent in
[PR #432](https://github.com/GoogleCloudPlatform/opentelemetry-operations-collector/pull/432)
while leaving separate managed cluster collector distributions untouched).

`GoogleCloudPlatform/opentelemetry-operations-collector` separates upstream
`contrib` components from local in-repo custom components: upstream `contrib`
components live in `cmd/distrogen/registry.yaml` under short component keys
without a module version tag (because `ApplyOTelVersion` stamps `"v" +
opentelemetry_contrib_version` from
`specs/google-built-opentelemetry-collector.yaml`), whereas
`components/google-built-opentelemetry-collector/registry.yaml` holds local
`path:` modules.

### Proposed post-Contrib Alpha registration in standalone `otelcol-google`

Once `exporter/bigqueryexporter` ships in an `opentelemetry-collector-contrib`
release at `alpha` stability, register the upstream `contrib` module in
`cmd/distrogen/registry.yaml` and enable the `bigquery` key in
`specs/google-built-opentelemetry-collector.yaml`:

```yaml
# cmd/distrogen/registry.yaml (post-Contrib Alpha)
exporters:
  bigquery:
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter
    docs_url: https://www.github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/bigqueryexporter/README.md
```

```yaml
# specs/google-built-opentelemetry-collector.yaml
opentelemetry_contrib_version: 0.<first-contrib-release>.0
components:
  exporters:
    - bigquery
```

```bash
make gen-google-built-otel
# Equivalent direct invocation:
go run ./cmd/distrogen generate \
  --spec ./specs/google-built-opentelemetry-collector.yaml \
  --registry ./components/google-built-opentelemetry-collector/registry.yaml \
  --templates ./templates/google-built-opentelemetry-collector
```

If an in-repo wrapper module under
`components/google-built-opentelemetry-collector/exporter/bigqueryexporter/`
were ever needed after Contrib Alpha, it delegates directly to the `contrib`
package at the first release containing the component:

```go
// factory.go (post-Contrib Alpha wrapper)
// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	contrib "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter"
	"go.opentelemetry.io/collector/exporter"
)

func NewFactory() exporter.Factory { return contrib.NewFactory() }
```

```text
// go.mod (post-Contrib Alpha wrapper)
module github.com/GoogleCloudPlatform/opentelemetry-operations-collector/components/google-built-opentelemetry-collector/exporter/bigqueryexporter

go 1.26.0

require (
	github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter v0.<first-contrib-release>.0
	go.opentelemetry.io/collector/exporter v1.70.0
)
```

### Historical pre-`v0.1.0` `cmd/distrogen` build-compatibility record (optional interim bridge)

Before `exporter/bigqueryexporter` lands in `opentelemetry-collector-contrib`
Alpha, standalone `otelcol-google` is not modified (operators today use OCB or
the container templates in `deploy/`). If a time-boxed interim custom collector
distribution is needed before Contrib Alpha ships, local `path:` wrapper
compatibility in `components/google-built-opentelemetry-collector/registry.yaml`
was checked against pre-release `github.com/GoogleCloudPlatform/BQ-OTEL-Exporter v0.0.3`
(targeting `v0.1.0` at tag) using the wrapper layout below:

```go
// doc.go
// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter // import "github.com/GoogleCloudPlatform/opentelemetry-operations-collector/components/google-built-opentelemetry-collector/exporter/bigqueryexporter"
```

```go
// factory.go
// Copyright 2026 Google LLC
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
// Copyright 2026 Google LLC
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
	bqCfg, ok := cfg.(*bq.Config)
	if !ok {
		t.Fatal("CreateDefaultConfig must return *bq.Config")
	}
	if err := bqCfg.Validate(); err == nil {
		t.Fatal("Validate must fail when project and dataset are empty")
	}
}

func TestCheckConfigStruct(t *testing.T) {
	f := bq.NewFactory()
	if err := componenttest.CheckConfigStruct(f.CreateDefaultConfig()); err != nil {
		t.Fatalf("CheckConfigStruct failed: %v", err)
	}
}
```

```text
// go.mod (historical pre-Contrib compatibility check against published v0.0.3; bump to v0.1.0 at tag)
module github.com/GoogleCloudPlatform/opentelemetry-operations-collector/components/google-built-opentelemetry-collector/exporter/bigqueryexporter

go 1.26.0

require (
	github.com/GoogleCloudPlatform/BQ-OTEL-Exporter v0.0.3
	go.opentelemetry.io/collector/exporter v1.70.0
)
```

```yaml
# components/google-built-opentelemetry-collector/registry.yaml (local thin-wrapper entry)
exporters:
  bigquery:
    gomod: github.com/GoogleCloudPlatform/opentelemetry-operations-collector/components/google-built-opentelemetry-collector/exporter/bigqueryexporter v0.0.0
    path: "../components/google-built-opentelemetry-collector/exporter/bigqueryexporter"
```

```bash
go run ./cmd/distrogen generate \
  --spec ./specs/google-built-opentelemetry-collector.yaml \
  --registry ./components/google-built-opentelemetry-collector/registry.yaml \
  --templates ./templates/google-built-opentelemetry-collector
```

### Historical workstation verification record (unverified in this repository's CI)

As an **author-reported workstation check outside this repository's CI** (not
reproduced by a standalone `go test ./...` run in this repository), the local
thin-wrapper compatibility layout above was exercised against published
pre-release `github.com/GoogleCloudPlatform/BQ-OTEL-Exporter v0.0.3` (and
previously `v0.0.2`): `go mod tidy` resolved the published module from
`proxy.golang.org` without `replace` directives, `go test -race` passed on the
wrapper package, and `distrogen generate` emitted a build manifest with the
local `gomod` and `path` entry.

## Post-PR-3 Distribution, CI & Registry Checklist ([#39](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/issues/39))

Once upstream PR 1–3 merge into `open-telemetry/opentelemetry-collector-contrib`,
complete these three follow-up steps in order:

1. **Collector Releases distribution manifest (`open-telemetry/opentelemetry-collector-releases`)**:
   After the first `opentelemetry-collector-contrib` release containing PR 3 is
   tagged, open a PR adding the `bigquery` exporter module to
   `distributions/otelcol-contrib/manifest.yaml` so the upstream
   `otel/opentelemetry-collector-contrib` container image ships the component.
2. **Version-aware CI & README cutover ([`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), [`README.md`](../../README.md))**:
   Once that `otelcol-contrib` image release is published, bump `STOCK_IMAGE`
   and set `STOCK_CONTRIB_INCLUDES_BIGQUERY_SINCE` in `.github/workflows/ci.yml`
   (`collector-example` job) to that release version so CI verifies that the
   stock contrib image validates `example/otel-collector-config.yml` with exit
   code `0`, and update the [`README.md`](../../README.md) deployment options to
   list the stock distribution alongside custom OCB builds.
3. **OpenTelemetry Registry entry (`open-telemetry/opentelemetry.io`)**:
   Populate `package.version` in
   [`docs/otel-registry-entry.yaml`](../otel-registry-entry.yaml) with the
   published `opentelemetry-collector-contrib` module version and submit the
   entry PR to `open-telemetry/opentelemetry.io`.
