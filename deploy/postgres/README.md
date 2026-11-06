# Open EPM PostgreSQL V2 deployment slice

This Compose file packages the PostgreSQL V2 platform, workspace and
multi-application MCP listeners, the lean browser inspector, worker,
migrations and database. It is an **incomplete development deployment**:
the old source runtime and launchers have been removed, but shared-service
cutover, full planning and consolidation functions, and production
qualification remain open. Do not point it at an existing application database.

This file also retains chronological implementation notes below. Individual
migration numbers and test counts in those notes describe their stated artifact,
not the current integration branch. Use the repository schema directory and the
[acceptance register](../../docs/consolidated-acceptance-register-2026-10-28.json)
for current identities and status.

All Python service, readiness and deployment-tool database startup attempts use
the server-owned two-second per-host/address connection budget. Native failover
and TLS/authentication options remain supported; DNS and total-call time are not
bounded by that setting. See [the connection contract](../../docs/postgres-v2-connection-budget.md).

MCP tools execute through a bounded reusable core-process pool: eight processes
per listener, a 30-second tool budget and one-second termination grace. A timeout
can race a commit; inspect durable status and replay the original request key.
The pool does not represent a durable queue or full production-capacity proof.
See [execution boundaries](../../docs/postgres-v2-mcp-execution.md) for configuration,
database limits, cancellation and remaining HTTP/startup/browser gates.

Each MCP listener also reserves two control executors and separate control thread
capacity for five-second authentication and 30-second pre-listen role checks.
POST requests have a 45-second cooperative envelope inherited by business tools.
Invalid identities remain401; temporary authentication failure returns503, and
an expired POST returns504 or closes an already-started response. Status/replay
guidance remains mandatory after an unknown outcome. See
[HTTP admission](../../docs/postgres-v2-http-admission.md) for exact scope and
remaining worker/browser/CPU/resource qualification.

To repeat disposable qualification on an already tested artifact, set both
`EPM_TEST_COMPOSE_APPLICATION_IMAGE_ID` and `EPM_TEST_COMPOSE_DATABASE_IMAGE_ID`
to exact available local `sha256:` IDs, together with
`EPM_TEST_COMPOSE_DISPOSABLE=1`. Otherwise the harness builds the two runtimes
once. Before setup, it pins every service/recovery utility, removes inherited
build definitions with Compose `!reset`, disables pulls and retains local tags.
Subsequent and nested recovery builds are rejected, and actual running container
image IDs are compared with the frozen artifacts. Both restored router and
workspace listeners are checked against the restored database. This is development qualification,
not an installer or permission to address an existing application. Retain local
tags before another build; mutable `:local` tags alone do not retain old artifacts.
The qualification uses Compose's
[reset merge behavior](https://docs.docker.com/reference/compose-file/merge/),
verified with the installed Compose5.5.1.

The delivered Linux ARM64 application and database images are restricted,
flattened derivatives of pinned builder images. Both exclude the retired embedded
engine, its Python drivers, native libraries, package registrations and active
Python/dependency references. All six database, bootstrap and recovery utility
services use `openepm-postgres-db:local`; build it rather than substituting the
original vendor image. No laptop runtime or unrelated application is modified.
The application omits unused desktop GUI modules, C development headers/config
scripts and SSE-Starlette's unused database example extra. Required license files
are retained. These are binary service runtimes, not general development images.

After building, audit the actual artifacts before release:

```sh
python scripts/check_delivered_runtime.py openepm-postgres-v2:local app
python scripts/check_delivered_runtime.py openepm-postgres-db:local db
python scripts/check_storage_retirement.py
```

The first two checks pin the inspected image IDs, reject retained nonempty parent
layers, examine native dependencies and verify unprivileged startup/imports.
`tests/qualify_postgres_compose_signed.py` additionally requires artifact audits,
the client-produced PDF-extraction boundary (the server stores inert PDF bytes
and validates the bounded extraction manifest without parsing the PDF), signed
service workflows, physical PITR and portable restore with signed application
readback. See
`docs/qualifications/postgres-v2-runtime-retirement-2026-10-27.md`.
Qualified runtime absence does not establish full replacement feature coverage or
production readiness. Builder caches and the host interpreter are outside the
delivered image scope.

Generic ordered writes now use `facts.numeric.sequence`: up to 500 exact
Set/Add/Clear statements, with explicit references to earlier present outputs,
one signed snapshot and one atomic durable-job commit. This works with
consolidation disabled. First-touch CAS, planning locks, current grants, event
history and lease fencing apply. The old numeric batch keeps its duplicate-target
rejection. See `docs/postgres-v2-numeric-sequence.md` and the ordered-numeric
qualification; general expression programs and convergence iteration remain open.

The bundled `pg_duckdb` extension is **not qualified for financial arithmetic**.
Its execution role is unset. The database starts with extension external access
and known-extension autoinstall/autoload off, plus a 256 MB extension memory
bound. A repeatable disposable qualification passes narrow RLS join/view,
prepared-parameter, snapshot, timeout and role-denial probes, but reproduces
incorrect decimal division and a valid high-precision multiplication overflow.
Keep calculation execution on PostgreSQL; see
`docs/qualifications/pg-duckdb-2026-10-26.md` and
`tests/qualify_pg_duckdb.py` before changing this boundary.

Migration 0058 adds immutable per-result-row raw-driver lookup lineage to the
calculated-result table. Existing generations retain an empty lineage array;
expression jobs publish the selected driver value and change ID with the
result in one transaction.

Migration 0059 adds nullable `amount`/`ratio` numeric-kind metadata to members.
Administrators set it through `metadata.member.numeric-kind.set`; new raw
`SourceValue` expressions bind `measureDimensionId` to an overridden member
whose kind matches `valueType`. Compiler v11 validates this at preview and
worker publication. Canonical older v10 queued jobs remain decodable. This
is a bounded type check, not a certified physical-unit model.
The current-schema signed Compose qualification in
`docs/qualifications/postgres-v2-compose-typed-driver-2026-10-27.md`
passes a fresh 59-migration install and two-application MCP/worker smoke,
including a typed-driver mismatch rejection and post-router-restart readback.

Migration 0060 admits the bounded `facts.planning.group.sum.bulk` calculation
in the generation function constraint. The fixed worker publishes several
explicit numeric group sums and their source lineage as one atomic generation;
see `docs/qualifications/postgres-v2-bulk-group-sum-2026-10-27.md`.

Migration 0061 adds a scoped partial lookup index for deleted-dimension
receipts. `metadata.dimension.delete` records an unused inactive axis as a
retired stable ID in that receipt and prevents a later create from reusing it.

`consolidation.full.tree.plan` now returns an explicit child-before-parent
Full sequence from a bounded active Entity tree. It requires every Full/control
decision, parent-source choice, result key and currency-alignment assertion
from the caller; the generated program still needs ordinary sequence preview
and submission. Results remain Unreviewed. See
`docs/qualifications/postgres-v2-full-tree-planner-2026-10-27.md`.

`metadata.dimension.status.set` now permits Administrator-only reversible
inactivation of an unused dimension through the application language. Active
members, coordinates and live references/work block it; duplicate active
non-Custom model roles are rejected. See
`docs/qualifications/postgres-v2-dimension-status-2026-10-27.md`.

Migration 0057 adds a durable per-workspace dispatch cursor and an index for
running-job admission. Worker claims use one database advisory transaction fence,
then the existing workspace reset fence and job lease, to rotate eligible
workspaces without allowing an older backlog to monopolize claims. The worker
tries the workspace fence before locking a job row, skips a reset-held
workspace or concurrently locked job, and probes at most 128 candidates per
claim. A slow claim can still hold the global dispatch fence; sustained
multi-worker throughput remains unqualified. The service rotates short,
medium and long work classes after each successful job. Its
defaults allow at most 32 running jobs globally, eight per workspace and two
per application; set `EPM_PG_MAX_RUNNING_GLOBAL`,
`EPM_PG_MAX_RUNNING_WORKSPACE` and `EPM_PG_MAX_RUNNING_APPLICATION` to positive
integers in descending order for a different budget. Configure every worker
process with the same limits. These are admission caps on jobs in `running`
state, not proven CPU, memory, database connection or 300-user capacity limits.
The reset primitive removes the dispatch cursor for the deleted workspace.

The application image uses `requirements-postgres.lock`, which pins every
runtime dependency and its download hashes. The Dockerfile requires those
hashes and binary wheels during installation. `requirements-postgres.txt` is
the small direct-dependency input. To deliberately refresh the lock, run
`uv pip compile --generate-hashes --python-version 3.14 --output-file
requirements-postgres.lock requirements-postgres.txt` with uv 0.9.11 in a
disposable Linux ARM64 Python 3.14 container, then rebuild the image without
cache and run `python -m pip check` inside it. This lock is packaging
reproducibility evidence, not a security or production release review.

An active Currency model-role dimension is metadata, not a fact coordinate:
numeric writes, staged loads, planning operators, version comparison and
journal balance reads require the other active fact axes. This boundary does
not itself provide a certified translation publisher. The raw Full stages
still reject Currency/Value models; a separate bounded translated Full parent
stage is described below.

Migration 0046 adds Administrator-only typed AccountType and Entity default
Currency metadata programs plus a Reader-granted policy read. A policy edit
advances the metadata revision; saving currency settings requires both rate
Accounts to have AccountType `CURRENCYRATE`.

Migration 0045 adds Administrator-only `currency.settings.save` and
Reader-granted `currency.settings.read` through the existing V2 metadata and
read tools. The configuration pins active stable-ID references and PVA/VAL
method choices, commits a policy revision and receipt, and reads as Stale after
any metadata change. Reader-granted `currency.rate.resolve` then reads the
existing numeric rate facts with Entity direct/inverse, Entity None
direct/inverse and application-currency triangulation precedence. It returns
an exact rational factor and source lineage, failing on a selected nonpositive
or text rate. Reader-granted `currency.translation.inspect` evaluates one
Entity Currency/YTD source at the configured PVA or VAL method over explicit
fiscal periods in one scoped read transaction. It returns an exact result and
source/rate lineage, checks AccountType and Entity DefCurrency, and publishes
nothing. Both reads remain Unreviewed. Migration 0047 adds a bounded
`currency.translation.publish` durable job that previews and publishes one
translated Value-stage result into the named calculation layer, with exact
PVA/VAL lineage and stale-input fencing. The worker processes its medium
resource class. Whole-unit FX translation, CTA execution and reviewed
accounting policy remain unimplemented.

Migration 0050 allows `facts.planning.scenario.copy.prepare` to stage
supporting-detail cells with their exact numeric totals and line items. The
existing signed source-batch preview/publish path validates current revisions,
target conflicts and planning locks, then writes numeric and detail events,
current rows and one receipt in the same transaction. A target detail cell can
be replaced only when the staged copy includes detail at that coordinate;
merge still rejects occupied detail. `facts.source.append` also accepts a
bounded typed `LineDetailLiteral` with exact decimal line amounts; the same
publication path atomically imports it alongside numeric and text rows.
Reader-granted `facts.export.page` returns up to 50 source-compatible typed
numeric, text and supporting-detail rows per call. Its signed cursor pins the
committed fact snapshot and metadata revision; detail is reconstructed from
immutable events at that snapshot. This is a bounded API export, not a
source-file format or production-scale streaming qualification.
Migration 0051 adds an optional, fixed-core Year/Period selection to a
replacement source batch. `facts.planning.forecast.roll.prepare` stages a
bounded, calendar-driven Actual/prior-Forecast copy across fiscal years.
Default `seed` requires an empty target window; `mode: "replace"` refreshes
that window and clears unmentioned numeric/text cells only inside its
selected fiscal periods, leaving adjacent periods untouched. Migration 0052
records immutable detail-clear events and removes unmentioned current detail
inside the selected window while retaining historical line items. Ordinary
source-batch replacement keeps its earlier detail-preservation behavior.
The signed source-batch preview/publisher remains the only fact writer.
Disposable cross-year replacement and logical restore pass; automatic roll
scheduling remains open.
`facts.planning.forecast.roll.apply` now carries one explicit advancement
through durable prepare, signed source preview and publication, returning the
stored receipt on same-subject idempotent replay. The separate staged route
remains available. See
`docs/qualifications/postgres-v2-forecast-apply-2026-10-27.md`.
`facts.source.csv.append` accepts one UTF-8 CSV text chunk with
`axis.<dimensionId>`, `literalType`, `value` and `sourceRef` columns. It parses
at most 500 typed rows and forwards them through the same staging validator;
`LineDetailLiteral` values are JSON item arrays inside a CSV field. The
server does not read a caller-provided file path. Large-file streaming and
production throughput remain unqualified.

Migration 0048 adds `consolidation.full.translated.aggregate` for one parent,
period and Account. It requires all direct children to have pinned current
translated Value-stage generations, explicit Full/control decisions and
period-specific ownership; it checks the parent default Currency, requires
POWN and 100% PCON or its labelled fallback. A present parent Entity Currency
source requires its own pinned identity translation; the worker includes it
once in the pre-NCI parent sum. Reader calculation read/scan report the source
pins and their currentness. Republishing any pinned translation makes the
parent result stale. A nonleaf child can pin its lower Full generation when
its default Currency matches the parent; read status follows lower pins to
detect a changed leaf. Migration 0049 adds a pinned cross-currency lower Full
translation job. PVA requires all fiscal-period lower Full pins and applies
each period's rate to the cumulative change; VAL requires the current pin.
The parent can consume that translated result and read-time status follows
its lower pins. Reader-granted `consolidation.nci.attribution.inspect` now
shows a candidate child-specific ownership split from a pinned current Full
generation, rechecking POWN and nested source freshness. It does not certify
the Account as an eligible NCI basis or publish a posting. Automatic
mixed/cross-currency multilevel sequencing, approved NCI policy/postings,
CTA and complete eliminations remain open.

The V2 application language now exposes Administrator-only typed member
semantic-column definitions and member/relationship attribute Set/Clear operations through
the application MCP listener. Reader-granted definition and attribute reads
share the same PostgreSQL scope and metadata-revision checks. Definition names
and descriptions can be edited; changing a populated slot's type or allowed
values still requires a future migration workflow.

Migrations 0039–0040 add the V2 generic JSON fact-table foundation for nonfinancial
applications. Table registration/update/retirement and single-value or bounded
100-change batch set/delete use fixed,
idempotent application-language programs; bounded reads are exposed through
the authenticated MCP listeners and lean browser inspector. The owner-only reset primitive and reviewed
schema fingerprint include these tables. The V1 source routes were retired;
remaining product coverage must be implemented through the V2 language.
The unrelated research catalogue and ingestion website were retired under input 445.
Generic browser pages use a signed cursor pinned to one committed revision.

Migration 0041 permits a bounded `consolidation.full.contribute` result
generation. A write-granted client previews and submits one uniquely placed
direct-child, PCON-100 Full contribution; the fixed worker publishes its exact
source amount at the parent coordinate with ownership lineage and an
Unreviewed/pre-NCI stage label. This does not finish the consolidation engine.

Migration 0042 adds `consolidation.full.aggregate`: a fixed worker sums all
explicitly decided active direct Full children at one parent coordinate, with an
explicit choice to include a present parent source. It rejects incomplete
relationship coverage and stores each source/ownership input in the receipt.
The result remains an unreviewed pre-NCI layer, not a complete group close.
The required `sourceLayer` selects raw numeric cells, raw plus posted manual
journals, raw plus current parent-scoped IC elimination, or the explicit
`raw_plus_manual_journal_plus_ic_elimination` composition. The journal paths
record contributing journal IDs/lines; the journal-only path accepts a child
with no raw numeric cell when its net adjustment is nonzero. The IC paths
require current two-source IC lineage and same active Entity currency. The
combined path adds journal lines to the raw-based IC offset; it does not
rematch a journal-adjusted IC pair. A distinct unreviewed accounting stage
prevents an IC-only parent from consuming a lower combined-stage generation.
The Reader IC pair inspector reports both the raw match/residual used by the
elimination preview and a separate raw-plus-posted-journal match/residual at
the same committed state. If the adjusted sides have incompatible signs or
exceed the numeric-cell range, the layered match is unavailable with an
explicit issue code. This diagnostic does not republish an IC offset.
In a Value/View/Currency finance model, the IC pair, adjusted balance and Full
source layers require current currency settings and the configured Entity
Currency Value plus YTD View members. Same-currency IC and journal-plus-IC
Full results publish at that local grain. The versioned calculation FX bridge
can now explicitly pin one of those lower Full source layers by fiscal period
and publish an exact-rational Value-target result at a distinct unreviewed
IC-aware stage; previously admitted v1 bridge jobs retain their original
compiler identity. The translated Full parent publisher does not yet consume
the new stages. See `docs/qualifications/postgres-v2-value-ic-stage-2026-10-27.md`
and `docs/qualifications/postgres-v2-ic-fx-bridge-2026-10-27.md`.
Posted reversals are
included; changed journal data makes queued previews stale. Published
generations are retained as historical output. Calculation reads and scans
include a conservative pinned-versus-observed input revision status that turns
false after a journal reversal.
An optional `publishedChildren` list replaces a selected direct child's raw
or journal-adjusted amount with that child's current, pinned published Full
aggregate generation at the identical coordinate. A three-level fixture
published 310 at Intermediate and 380 at Grandparent without counting the
Intermediate raw 10 twice. Preview, queue admission and worker publication
reject a stale child pointer; read and scan flag an older parent result when
the child is republished. Bounded per-level checks follow pinned descendants,
so a changed grandchild also invalidates an unchanged intermediate pointer.
This is explicit staging, not automatic dependency
sequencing or accounting certification.
Published arithmetic expressions also expose read-time dependency status.
Their preview, admission and worker recheck the pinned generation and its
nested expression or Full-aggregate dependencies; the lean inspector shows
the status and expandable source context. A matching status is an observation
at read time, not a lasting close certification.
A disposable data-bearing logical dump/restore through migration 0042 matched
source and restored full-row digests for 14 tables and read back the aggregate
through the V2 language; see
`docs/qualifications/postgres-full-aggregate-restore-2026-10-26.md`.
The earlier migration-0050 logical restore also matched 13 source/detail
tables and 14 Full-aggregate tables, verified all migration checksums and
read back current and historical detail plus the 850 aggregate through V2;
see `docs/qualifications/postgres-v2-0050-restore-2026-10-27.md`.
Migration 0051 was then verified with three current-schema logical restores,
including a populated rolling-forecast window with a persisted three-period
replacement scope; see
`docs/qualifications/postgres-v2-0051-forecast-window-2026-10-27.md`.
Migration 0052 repeats those three restores with supporting-detail clearing
and historical readback; see
`docs/qualifications/postgres-v2-0052-forecast-detail-clear-2026-10-27.md`.
At the migration-0056 checkpoint, seven populated logical restore paths
match selected table signatures, reverify all 56 checksums and read results
through V2. One restored worker completes an accepted two-step Full sequence;
another restore preserves an IC withdrawal and its absent current pointer;
the seventh preserves explicit grouped-sum source lineage and readback;
see `docs/qualifications/postgres-v2-current-schema-logical-restore-2026-10-27.md`.
A fresh isolated migration-0056 Compose stack also applied all 56 migrations,
bootstrapped six non-owner roles and an operator, reached healthy status for
the database, MCP listeners, web and worker, and rejected unsigned router/web
requests. It was removed with its volumes after the check; see
`docs/qualifications/postgres-v2-explicit-group-sum-2026-10-27.md`.
Fresh signed routed MCP clients then exercised rolling-forecast replacement
and two unlike planning/finance application models; see
`docs/qualifications/postgres-v2-two-unlike-models-2026-10-27.md`.
Production backup/PITR and role/secret recovery remain unqualified.
A fresh isolated Compose project also built this 0042 image, applied all 42
migrations, bootstrapped the service roles/operator and brought all six
services healthy; see
`docs/qualifications/postgres-v2-compose-0042-2026-10-26.md`. That check
covered readiness and unsigned 401 gates, not authenticated business work.
A separate fresh isolated Compose project repeated the qualification with all
44 migrations and the sequence-aware worker: all six services were healthy,
and four unsigned endpoints returned 401. See
`docs/qualifications/postgres-v2-compose-0044-2026-10-27.md`. Its stack,
volume and private environment file were removed after the check.

Migration 0036 and the application/router MCP listeners include immutable,
balanced manual journals and linked reversals. They are a separate adjustment
layer with snapshot-pinned coordinate balance readback and planning-lock
enforcement. `facts.numeric.adjusted.read` can also read one source amount
plus its manual-journal adjustment at a committed revision. Broad reporting,
whole-statement calculation and policy integration are still pending. The bounded
`facts.numeric.adjusted.scan` MCP read pages raw numeric and net journal
adjustment across coordinates with a signed snapshot cursor; it excludes
calculated generations.
Migration 0038 permits typed `facts.expression.calculate` generations. The
bounded compiler accepts only declared arithmetic nodes, exact decimal
literals and references to up to eight published results. Each published
reference can declare up to four active alternate dimension members, with at
most eight distinct coordinate lookups. An optional `targetMembers` mapping
publishes to active target members on up to four source-fixed axes; the worker
materializes target coordinates and keeps the arithmetic set-based. Calculation
read and scan expose the source-to-target mapping for review.
The v6 expression compiler also permits per-coordinate division by a computed
ratio or amount, with amount/amount producing a ratio for use in a larger
amount formula. A zero or missing evaluated denominator fails both preview and
worker publication. Dynamic division is supported inside comparison operands
with the same exact numeric type rules.
Migration 0043 packages immutable saved expression-rule versions, a separate
published-version pointer, signed rule-run previews and durable expression jobs
that pin rule provenance and recheck the rule-run grant at publication. This
is a single-rule path. Migration 0044 adds a bounded, durable 2–8-rule
sequence. The worker uses the shared server preview secret to admit one pinned
rule job after the previous job publishes, reconciles admissions after restart,
and stops on stale revisions, lost grants or failed steps. A caller-owned
application-language function cancels the sequence and fences its current job.
If the last job has already published, settlement retains that historical
success even when a source or grant changes before the sequence row is updated;
calculation reads separately report current input freshness. Cancellation
reconciles an admitted job whose ID was not yet recorded before a crash, fences
pending work, and preserves an already published last job.
Migration 0054 adds a bounded, durable `consolidation.full.sequence.run` for
2–8 explicit Full aggregate steps in one connected Entity tree. Each step
contains an ordinary `consolidation.full.aggregate` program and a
`publishedChildrenFromSteps` list mapping its direct-child relationship to
an earlier step index. The signed preview pins the target publication
revisions and current application revisions. The worker admits one existing
fixed-core Full job at a time, derives lower publication pins only after the
preceding job publishes, and recovers an already admitted job after restart.
It rejects changed source revisions, republished targets/children, lost grants
and unrelated jobs occupying its deterministic idempotency key. Caller-owned
`consolidation.full.sequence.read` and `.cancel` expose progress and fence
pending work. Published stages remain `Unreviewed`; cancellation does not
reverse a stage that has already published. The sequence does not discover
the hierarchy, perform policy-certified close, or replace the accounting
functions still listed as open in the migration plan.
This does not yet implement a complete application close.
Referenced generations are pinned in the signed preview and checked at
admission and publication; a missing result cell or republished dependency
fails closed. Publication uses the existing fixed worker and receipt
transaction. A bounded explicit member-set sum now publishes one many-to-one
planning result with per-source lineage; arbitrary expression grouping and conditional, parameterized
or cross-application rule orchestration remain open.
`facts.calculation.scan` separately pages a named published generation through
the same bounded read API. Its signed cursor pins the generation across a
republish; the inspector offers source and published-calculation views.

The pinned application and `pg_duckdb` images currently target Linux ARM64.
The database has a persistent named volume and no published database port.
The three MCP ports are published on the host loopback interface only:
platform 5193, workspace 5192 and application router 5194. The web inspector
is also loopback-only on 5195. Put an
authenticated reverse proxy in front of them for remote clients; the MCP
listeners require valid Keycloak-issued access JWTs. Production HTTP services
require `EPM_AUTH_MODE=oidc`, an exact HTTPS issuer and an administrator-
configured HTTPS JWKS endpoint. Clients send `Authorization: Bearer <token>`;
the token must be an RS256 [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html)
access JWT (`typ=at+jwt`), with the configured issuer, audience, subject,
expiry/issued-at, and a verified email claim. Cloudflare assertions are not
accepted as identity credentials. The browser requires a separate web-audience
JWT on every request. Each listener has
a container readiness probe that expects the unauthenticated MCP endpoint to
reject it with HTTP 401; this proves the HTTP/auth gate is serving but does
not prove an authenticated business operation or database end-to-end health.
The worker has a separate healthcheck that opens both its non-owner database
credentials, verifies their assigned service roles and required table access,
and fails if either database path is unavailable. It does not prove that a
queued business job can publish successfully.

From the project root, copy `deploy/postgres/.env.example` to a private file
outside the repository and set mode `0600`. Supply unique random passwords of
at least 24 characters for all seven database password fields. Set
`EPM_PG_PREVIEW_SECRET_HEX` to at least 64 random hexadecimal characters.
Set `EPM_OIDC_ISSUER` to the
exact HTTPS issuer claim, `EPM_OIDC_JWKS_URL` to that issuer's HTTPS signing-key
endpoint, and `EPM_OIDC_AUD_MCP`/`EPM_OIDC_AUD_WEB` to two distinct resource
audiences. Configure the provider to emit a verified `email` claim in access
tokens. The browser inspector's same-origin fetches do not collect tokens;
an OIDC deployment needs a trusted authentication proxy that injects the
web-audience bearer on every upstream request, including static assets and
API calls. That proxy must discard any client-supplied upstream authorization
header before injection. Keys are fetched only from the configured URL without
following redirects, never a token header;
the services still check current application grants for each operation. A
disposable Compose qualification with a local HTTPS JWKS fixture completed
signed workspace/application creation, generic fact CRUD, one worker-published
numeric job and signed web discovery; see
`docs/qualifications/postgres-v2-compose-authenticated-2026-10-27.md`.
A production identity-provider integration remains unqualified.
The earlier 57-migration image also passed a disposable signed Compose
business run: platform/workspace creation, a worker-published exact numeric
fact, a member-bound saved-rule job and rule discovery, readback after router
restart, and MCP/web audience separation. The repeatable opt-in harness is
`tests/qualify_postgres_compose_signed.py`; set
`EPM_TEST_COMPOSE_DISPOSABLE=1` to run it only on a host with Docker Compose
and a user-level Python environment containing the test dependencies. It
creates unique temporary credentials and removes its isolated volumes. See
`docs/qualifications/postgres-v2-compose-signed-current-2026-10-27.md`.
Set `EPM_TEST_COMPOSE_CAPACITY_IDENTITIES=300` with that flag to opt into a
300-distinct-signed-Reader session burst against the disposable packaged
router. All 300 returned the published result in the local qualification;
the read p95 was 1.369 seconds. This does not cover sustained mixed traffic
or a production identity proxy.
Add `EPM_TEST_COMPOSE_READS_PER_IDENTITY=10` and
`EPM_TEST_COMPOSE_PUBLISHED_WRITES=5` for the bounded mixed run; a separate
fresh stack returned 3,000 correct historical-result reads while five
authorized source jobs published. The calculation correctly became stale
after source changes. This 12.317-second phase is not a sustained capacity
certificate.
`EPM_PUBLIC_WEB_ORIGIN` is the externally visible HTTPS origin (or
loopback HTTP for local development) used to protect cancellation requests.
Set the initial operator issuer and stable subject to the
verified identity that will create workspaces. Choose a workspace ID for the
workspace-bound listener. Do not commit or print this environment file.
The router and workspace listener use a separate `epm_security_login`
credential to execute typed application and workspace grant/revoke programs;
the runtime, lifecycle and discovery credentials do not receive grant-write
privileges.
The workspace listener also uses the server-owned secret for its signed reset
inventory and reversible Maintenance transition. A verified platform operator
who is also a workspace Administrator can prepare a manifest, then call the
typed quiesce tool with its exact digest, expiry and signature. The fixed
transaction rejects stale or tampered manifests and writes an idempotent
receipt and audit. Under Maintenance, prepare a fresh manifest and call
`workspace.reset.settle` to fence and cancel outstanding jobs without receipts
and mark unpublished source batches failed. A receipt attached to a still
unpublished batch aborts settlement for inspection; job receipt anomalies
remain `needs_inspection`. Resume requires a reason. These operations retain
staged rows and do not delete a workspace. Migration 0037 adds an owner-only,
transactional deletion primitive and retained audit/receipt; no ordinary
service role has EXECUTE. A separate, disabled-by-default `reset-apply` Compose
profile now exposes the fixed `workspace.reset.apply` program on loopback port
5196 using the migration-owner credential. It starts only when
`EPM_RESET_APPLY_ENABLED`, `EPM_RESET_REPLACEMENT_READY`, and
`EPM_RESET_ENDPOINTS_RETIRED` are each `1`. The executor rechecks the signed
five-minute Maintenance manifest, current operator and workspace Administrator
grants, expected schema graph, declared endpoint inventory and unsettled work
under the workspace fence before calling the fixed delete primitive. Replays
return the retained exact operation receipt. These deployment flags are
operator attestations, not independent proof that a shared V1 listener, proxy,
tunnel or external data root has been retired. Do not start this profile for
the current shared application while replacement coverage and endpoint
retirement remain unverified.
`EPM_RESET_ENDPOINT_INVENTORY_JSON` may declare up to 100 V2 endpoint bindings
for the workspace listener's signed manifest. Use one JSON object with an
`endpoints` array; each row has `kind`, `url`, `workspaceId`, and
`applicationId`. Valid kinds are `platform_mcp`, `workspace_mcp`,
`application_mcp`, `router_mcp`, and `web_inspector`. Workspace/application
bindings must name the listener's exact workspace; global surfaces use empty
scope IDs, and application bindings must name an application present in the
same workspace. URLs must use HTTPS or loopback HTTP. The declaration is sorted
and included in the signed digest, so a changed declaration invalidates an
earlier reset preview. It remains self-declared configuration, not proof that
all reverse proxies, tunnels, old listeners, or external data roots are known.
The ordinary workspace listener still reports `applySupported:false`; the
separate owner-credential listener is the only apply surface.
The signed preview also includes a PostgreSQL schema-coverage fingerprint,
all 61 workspace-scoped and four global tables, and the 90 reviewed foreign
keys. Unreviewed schema drift or an external foreign key becomes a reset
blocker. A registry application missing its state row is shown and blocks
apply rather than disappearing from the inventory. This inventory alone does
not authorize reset apply or identify endpoints outside this V2 deployment.
Active expression-rule and Full-aggregate sequences appear in the signed
manifest and block reset apply; the owner-only deletion primitive
independently rejects either unsettled sequence.

The commands below use standalone `docker-compose`, which is available on the
development host. Set `EPM_DEPLOY_ENV_FILE` to the private file path. Use a
unique Compose project name for each disposable qualification run.

```sh
docker-compose -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" config --quiet
docker-compose -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" --profile setup up -d --build db
docker-compose -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" --profile setup run --build --rm migrate
docker-compose -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" --profile setup run --rm bootstrap-roles
docker-compose -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" --profile setup run --rm bootstrap-operator
docker-compose -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" --profile v2 --profile workspace up -d --build db platform router web worker workspace
docker-compose -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" --profile v2 --profile workspace ps
```

Migration application, role setup and initial operator enrollment are
repeatable. They verify existing state and reject schema drift or a different
initial operator. Role setup does not rotate an existing login password; keep
the same private environment file for reruns. All business workspace,
application, metadata and fact changes go through the authenticated MCP
programs and fixed Python validation. The setup commands are deployment-only
control-plane operations.

The web inspector at `/` lists only granted applications, reads bounded
dimension/member metadata and cube pages, displays typed member/relationship
attributes and mapped source/target calculation coordinates, shows the
signed-in user's job
events and status, and lets an Editor
request cancellation of their own job. It cannot submit a business mutation.
The authenticated session proxy must inject `Authorization: Bearer <token>`
for the Keycloak web audience and forward the browser's `Origin` header. It
must discard any client-supplied upstream authorization header first. The web service
verifies both the token and, for cancellation, the exact public origin.

### Physical backup and isolated recovery

The database service now enables PostgreSQL WAL archiving. A one-shot volume
initializer gives the database user access to separate `epm_pgarchive` and
`epm_pgbackups` volumes. `archive_timeout=60s` bounds the delay for an active
WAL segment to become archivable; it does not make an unarchived transaction
recoverable. The archiver accepts an already archived segment only when its
bytes match. Monitor `pg_stat_archiver` and archive capacity; archiving failure
must be treated as a backup incident.

Run an online physical base backup from the database service:

```sh
docker-compose -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" exec -T db bash /usr/local/bin/openepm-backup
```

The command stages the base backup, streams required WAL, runs
`pg_verifybackup`, then atomically exposes a `base-...` directory and prints
its name. Keep the matching archived WAL segments and a protected copy of
the private deployment environment and identity/bootstrap records.

Export one verified base backup and the currently available archived WAL to
a host-shared, private directory. The sentinel must be created on the host;
the exporter refuses a Docker VM path that does not show that file. `BACKUP_NAME`
is the `base-...` name printed above.

```sh
mkdir -m 700 "$EPM_BUNDLE_DIR"
touch "$EPM_BUNDLE_DIR/.openepm-host-visible"
docker-compose -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" --profile backup-transfer run --rm --no-deps -v "$EPM_BUNDLE_DIR:/bundle:rw" -e "EPM_BUNDLE_UID=$(id -u)" -e "EPM_BUNDLE_GID=$(id -g)" backup-export BACKUP_NAME
```

The resulting `openepm-BACKUP_NAME` directory includes the base backup,
available WAL, a format manifest and SHA-256 file list. Copy that directory
and the host sentinel to protected independent storage. SHA-256 detects
accidental changes here; it does not authenticate a hostile storage provider.
Keep later WAL archives if a later recovery target is required. An export
does not claim that transactions in an unarchived segment are recoverable.

In a **new Compose project with fresh volumes**, import the copied bundle
before starting any database service. The importer checks the exact layout,
recomputes every file hash, runs `pg_verifybackup`, and refuses existing data
in the target backup or WAL volumes. Then run `recovery-init` and
`recovery-db` as shown below in that new project.

```sh
docker-compose -p NEW_RECOVERY_PROJECT -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" --profile backup-transfer run --rm --no-deps -v "$EPM_BUNDLE_DIR:/bundle:ro" backup-import openepm-BACKUP_NAME
```

The transfer was verified between two independent disposable Compose
projects, including corrupted-manifest and checksum-list rejection; see
`docs/qualifications/postgres-v2-portable-recovery-2026-10-27.md`. No backup
schedule, retention policy or automatic independent-storage copy is installed
by this slice.

To inspect a recovery **in a disposable project with populated backup and
archive volumes**, initialize a fresh recovery volume and start the isolated
recovery service. A UTC target is optional; omitting it replays all available
archived WAL. The initializer rejects a nonempty target volume.

```sh
docker-compose -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" --profile restore-init run --rm --no-deps recovery-init BACKUP_NAME 2026-10-27T02:04:14Z
docker-compose -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" --profile recovery up -d recovery-db
docker-compose -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" --profile recovery exec -T recovery-db pg_isready -U postgres
```

The recovery service binds only loopback port 55499, uses a separate data
volume, mounts backup/archive volumes read-only, and refuses startup unless
the verified restore initializer completed and left its ready marker. Validate restored
schema, application-language readback, migration checksums and identity grants
before any promotion to a real endpoint. A disaster restore on another host
requires the bundle and all WAL through the desired target, plus separately
protected deployment secrets and identity/bootstrap records. Independent-host
operation and production PITR remain unqualified. See
`docs/qualifications/postgres-v2-physical-pitr-2026-10-27.md`.

For a disposable stack only, stop and delete its isolated volume after tests:

```sh
docker-compose -p YOUR_DISPOSABLE_PROJECT -f deploy/postgres/compose.yaml --env-file "$EPM_DEPLOY_ENV_FILE" --profile setup --profile v2 --profile workspace down -v --remove-orphans
```

Do not use `down -v` for a deployment whose data must be retained. This
slice still needs broader business-operation health checks, scheduled and
off-host backup/recovery operation, full authentication-provider and client
qualification, complete feature parity, dependency vulnerability review and
an operational cutover before production use.
