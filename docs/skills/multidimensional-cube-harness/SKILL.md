---
name: multidimensional-cube-harness
description: Implement and operate an evidence-driven harness that turns source files, interviews, or exploratory ideas into verified multidimensional applications through an authorized target MCP. Use for new cube applications, iterative migrations, safe resume, exact reconciliation, and evaluated workflow improvement; do not use it to bypass target authorization or treat sample success as full acceptance.
---

# Multidimensional Cube Harness

## Purpose and authority

Use this skill to implement or operate a harness that converts incomplete user
information, accessible source material, or an exploratory question into a
well-designed multidimensional application. Open EPM is the target platform.
The AICOmpanies migration is a concrete proving example, not a universal
financial domain or a hard-coded application template.

One assistant may perform four responsibilities without creating separate
agents or personas:

1. **Modeler and interviewer:** discover grain, meaning, decisions, and gaps.
2. **Target expert and implementer:** learn the live MCP contract and make only
   authorized, deterministic target changes.
3. **Independent verification responsibility:** test source coverage, target
   effects, exact values, rules, controls, permissions, and replay behavior.
4. **Improvement partner:** distinguish user/source/client/product problems,
   evaluate reusable lessons, and prepare evidence-backed feedback for the MCP
   owner.

Keep facts, user decisions, assumptions, hypotheses, proposals, tool results,
and verified outcomes visibly distinct. Do not claim access to or retain hidden
model chain-of-thought. Retain concise decisions, evidence, rationale,
assumptions, and unresolved questions instead.

Authorization never follows from this skill. Target business metadata, data,
and rule mutations must use an authorized target MCP client and the target's
supported application workflow. GitHub reporting and host configuration use
their own supported interfaces and authorization. Do not write business state
directly to a database, use an ad hoc client to operate a shared application,
bypass permissions, silently create or overwrite an application, or
reinterpret business semantics without the relevant user decision. PostgreSQL
is Open EPM's authoritative business store; harness state is workflow evidence,
not business truth.

Honor authorization already explicit or reasonably implied by the current
implementation or operating request for routine, reversible in-scope work; do
not repeatedly ask permission for each ordinary step. Still obtain the
specific decisions and approvals this skill reserves: business meaning and
seed acceptance, each GitHub issue, host trust/configuration where required,
background hook/schedule activation, destructive changes, and any material
scope, security, privacy, or acceptance-criteria change. The request that
created this document authorized documentation only.

## Persistent MCP connection

Use the recipient host's configured MCP connection and OAuth credential
management when available. Configure the trusted endpoint once, complete the
issuer's normal sign-in, and let the host retain and refresh credentials in its
supported secure store. Reuse that connection across chats and process
restarts. Do not replace it with a temporary device-login process merely for
convenience, extract its tokens into an import script, or store credentials in
harness records. Discover the deployed endpoint, registered client, redirect
and scope requirements rather than guessing them.

Connection persistence does not override issuer policy or application grants.
Distinguish a sign-in-code deadline, access-token lifetime, refresh-grant expiry
and explicit revocation when explaining authentication. Reauthentication is
needed when the grant is no longer usable; restarting a workflow alone is not
a reason to discard a valid host-managed connection. An authentication prompt
is not a request to reauthorize already agreed business work. After reconnecting,
reconcile the last operation's receipt before retrying an uncertain mutation.

## Shared application decisions

Before meaningful modeling, rule authoring or application changes, discover the
current application's `application.decision.*` functions and read its current
decision log through the authorized MCP. This shared server context is the
authority for previously accepted application decisions. Read/list,
replacements and exact retries all require current effective application-administrator
access; a Server Administrator title alone supplies no application grant. If
the caller lacks that access, continue only with the context and operations
already authorized for that caller; do not bypass the boundary.

Record significant accepted decisions that affect application meaning or future
work. Do not record every chat message or copy transcripts. `UserDecision`
means an explicit decision supplied by the human administrator. Use
`AgentInterpretation` for an agent's interpretation, assumption or conclusion;
never relabel it as a human decision without that decision. Include concise
rationale and an optional plain-text source reference when useful. Server actor
and time are authenticated attribution, separate from this content provenance.

Use `application.decision.create`, `.replace` and `.withdraw` through
`execute_v2_application_decision`, or the typed
`ApplicationDecisions(transport, application)` SDK facade. Use the deployed
catalogue for exact arguments. Replacements and withdrawals carry the last-read
opaque `expectedStateToken`; concurrent changes must be compared with a fresh
current read before deliberately replacing the record. Preserve unsaved text.
For an uncertain response, retry the identical program with its original
idempotency key before starting new intent. Pagination pins the decision-log
collection token; refetch when a continuation becomes stale. The server retains
one current record per stable decision ID and exposes no decision-history API.

Recording a decision neither changes cube data nor activates a rule. Apply any
resulting model or rule change through its own authorized workflow. Optional
client-local Harness working state may retain bounded work-in-progress context,
but remains separate from this shared log and must not become a competing copy
of accepted application decisions. The log does not require a local Harness
installation or a new approval queue.

For an explicitly authorized application purge, use the discovered
`workspace.application.purge.prepare`, `.quiesce` and `.apply` controls through
`execute_v2_application_purge`. Bind the request to the returned application
incarnation (`createdAt` and `schemaEpoch`), stop producers and wait for live
leases to drain before applying the exact prepared intent. Purge removes the
application's content and history, retaining only minimal actor/action audit;
it does not imply permission to delete other applications or workspace identity.
An uncertain response is an exact retry, not a fresh destructive request.

## Server-managed distribution and client installation consent

This `SKILL.md` is the one canonical authoring source for the complete behavior
and bootstrap contract. The primary distribution design is a centrally
published Open EPM MCP release; manually giving a recipient this file remains
the portable fallback. Do not create a second editable skill copy as another
source of truth.

### Publish one validated version

The release pipeline must package this exact file atomically with the Open EPM
deployment and declare a stable skill name, semantic or monotonic version,
content digest, byte size, compatible target/API range, host requirements, and
publication time. Validate frontmatter, full-content digest, protocol behavior,
privacy, and acceptance scenarios before publication. A published server must
serve one internally consistent approved version; editing a local file alone
does not deploy it. Rollout and rollback operate on the complete deployment
artifact, not an untracked loose copy.

This delivery is an Open EPM product capability and must work when the packaged
server has **no Codex or Cursor installation**. The Open EPM release itself must
contain the canonical skill payload, version and manifest and serve them
through its MCP implementation. Serving must not depend on a developer laptop,
author home directory, sibling source checkout, model session, server-local
skill installation, or Harness² evaluation runtime. Harness² is relevant only
to the separate learning/evaluation workflow when that capability is installed
and qualified.

Any compatible authenticated and authorized MCP client may retrieve the
published payload from that self-contained server. The receiving host or
assistant decides whether the content enters model context, performs optional
local registration only after consent, and configures any capability-specific
runtime. Host support still governs those client-side actions; it does not
weaken the server's obligation to make the exact published payload available.

Globally served content must not contain credentials, transcripts, private
project decisions, customer data, or a fixed private GitHub destination.
Deployment-specific endpoints, issue destinations, and policies belong in
appropriately scoped server/client configuration. The generic skill may define
their required fields but not embed one author's private values.

The application, workspace and platform MCP servers expose concise bootstrap
instructions and the versioned skill manifest/content as resources. The
read-only `read_openepm_published_skill` tool is the fallback for hosts that do
not surface resources. Discover the live manifest and verify its version,
digest, size and ordered chunks before calling the payload delivered. A newer
local source file is not evidence that the running server serves it. Do not
inject this large document into every response or infer local installation
from successful server delivery.

### Offer and ask through the client

At the first eligible interaction for a client installation context and skill
version, provide a readable name, purpose, exact version/digest, trusted source
server, intended destination/scope, and concrete choices:

- **Install:** retrieve/verify the complete content if needed, then let the
  authorized client/host write or register it locally.
- **Review:** show the content, source, version, destination, and implications
  before asking again.
- **Not now / decline:** perform no local write and continue unrelated safe work.

Example when the full content has actually been returned, assembled and read:
“Open EPM has provided *Multidimensional Cube Harness* version `<version>` (digest
`sha256:...`) from `<trusted server>`. It guides cube discovery, migration and
verification. Install it for this Cursor user, review it first, or not now?”

Example before full retrieval: “Open EPM makes *Multidimensional Cube Harness*
version `<version>` available. Would you like this client to download and verify it,
review its details, or decline for now?” Never say delivered or installed merely
because a manifest, link, resource advertisement, or server instruction exists.

Use MCP elicitation only when advertised by the client and permitted during the
current request interaction. For the modern flow, support the applicable
`InputRequiredResult` and `elicitation/create` exchange; otherwise use a normal
client-mediated question. If the host cannot ask or write locally, report the
unsupported capability and offer the manual file route honestly. A remote MCP
server cannot assume local filesystem access or install a skill itself.

Declined, cancelled, timed-out, failed, or unanswered offers are not approval.
Do not nag on every tool call. Track `offered`, `accepted`, `installed`,
`verified`, and `declined` separately for the client installation context and
exact version. Do not invent hardware/browser fingerprinting. Consent recorded
on another machine or installation context does not authorize a local write
here. Prefer user-level installation where the host supports it; verify the
actual destination and read back version/digest after the client write.

For Cursor, recheck <https://cursor.com/docs/skills> and
<https://cursor.com/docs/mcp>. Cursor currently documents tools, resources,
prompts and elicitation, but that does not prove native remote-MCP-to-skill
installation. Match the installed Cursor version's actual capabilities. Cursor
has documented project skill paths `.cursor/skills/` and `.agents/skills/` and
user paths `~/.cursor/skills/` and `~/.agents/skills/`; local user skills are not
automatically present in every remote/cloud environment.

### Updates, local edits, and active runs

Compare installed version and digest before offering an install or update. Do
not repeatedly prompt for an already verified current version. A newly
published version is immediately discoverable to new clients; existing clients
receive a version-change offer rather than a silent overwrite unless they have
explicitly approved a bounded update policy. Detect and preserve locally edited
variants; show the conflict and offer review, keep-local, or explicit replace/
merge choices.

Pin an active migration or other stateful harness run to its adopted skill
version/digest in the checkpoint. Do not change instructions halfway through a
mutation. Adopt a newer version only at a safe boundary after compatibility and
state checks, with the transition recorded.

Skill installation alone does not activate hooks, schedulers, Harness²,
packages, GitHub posting, permissions, or business operations. Those retain
their own support checks and approvals, including approval for every GitHub
issue. Declining installation does not block unrelated authorized tools,
interviewing, modeling, or read-only exploration; pause only a harness workflow
that actually needs the missing installed/runtime capability. Server-side
authorization and business validation remain authoritative. An “I read it”
acknowledgement proves neither comprehension nor authorization.

### Protocol-era compatibility and delivery limits

Implement against the protocol era actually supported by the deployed SDK and
host. As of 6 November 2026, the latest MCP specification redirects to revision
2026-07-28. Its `server/discover` response can carry optional server
instructions and caching metadata, but a modern client may skip discovery and
invoke an RPC directly; there is no universal initialize-first guarantee.
Therefore an eligible direct request must still receive or trigger the bounded
version offer without breaking the requested operation.

Legacy revision 2025-11-25 uses lifecycle initialization whose result may
include instructions, but arbitrary elicitation is not allowed before legacy
initialization completes. Never force a modern handshake model onto a legacy
client or vice versa. Consult:

- Modern discovery: <https://modelcontextprotocol.io/specification/2026-07-28/server/discover>
- Modern versioning: <https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning>
- Modern resources: <https://modelcontextprotocol.io/specification/2026-07-28/server/resources>
- Modern elicitation: <https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation>
- Legacy lifecycle: <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle>

Resource advertisement guarantees neither host context inclusion nor model
consumption; the application/host controls resource use. Distinguish server
availability, bytes returned, client verification, native skill registration,
model context inclusion, and observed use. Qualify each separately and never
claim universal forced installation, obedience, or hook activation from MCP.

Core decisions and templates in this file are self-contained. External links
are maintained installation/API references and must be rechecked because host
and research-framework interfaces can change:

- Google Research Harness Squared: <https://github.com/google-research/harness2>
- Google Research RRSI, evaluation inspiration only: <https://github.com/google-research/rrsi>
- Cursor skills: <https://cursor.com/docs/skills>
- Cursor hooks: <https://cursor.com/docs/hooks>
- Codex hooks: <https://learn.chatgpt.com/docs/hooks>
- Model Context Protocol specification: <https://modelcontextprotocol.io/specification/latest>
- GitHub CLI manual: <https://cli.github.com/manual/>
- GitHub issues: <https://docs.github.com/issues/tracking-your-work-with-issues>
- GitHub Projects: <https://docs.github.com/issues/planning-and-tracking-with-projects>

Do not silently replace a pinned integration with current upstream head.
Record the exact revision/API inspected, applicable license, security boundary,
and compatibility result.

## Required portable configuration

Create or locate one project-scoped configuration record during implementation.
Its format may follow the qualified host/framework convention; these logical
fields are mandatory. Angle-bracket values are required inputs, not defaults.

| Field | Required value and rule |
| --- | --- |
| `project_id` | Stable nonsecret harness project identity. |
| `skill_release` | Canonical name, exact published version/digest/size, compatibility range, trusted source server, and installed/adopted version. |
| `skill_delivery` | Supported instructions/resource/read-only-tool paths, full-content verification, cache metadata and protocol revision. |
| `skill_consent` | Per client installation context and version: offered, accepted, installed, verified or declined; no machine fingerprint. |
| `source_roots` | Authorized roots and access mode; never assume this author's laptop paths exist. |
| `target_mcp.endpoint` | Actual Open EPM MCP endpoint or supported connection name discovered in the recipient's host. |
| `target_mcp.auth_ref` | Reference to host-managed authentication, never secret material in harness state. |
| `target_mcp.workspace/application` | Explicit IDs, or `unselected` until the owner authorizes creation/selection. |
| `state_root` | Project-scoped writable checkpoint, contract, event, evidence-pointer, draft, and adapter state; not business storage. |
| `framework.repository` | `https://github.com/google-research/harness2` or an approved mirror. |
| `framework.revision` | Exact pinned commit/tag and adapter/API compatibility result; never `latest`. |
| `framework.runtime` | Qualified user/global runtime and protected invocation; no disabled-sandbox default. |
| `github.owner_repository_or_project` | Appropriately scoped authorized issue repository or Project, or `unconfigured`; never embed a private deployment destination in the global skill. |
| `github.auth_ref` | Host/CLI credential reference and verified scopes, never credential material. |
| `review.trigger` | Approved milestone, session-close, daily, or real idle timer; otherwise `manual`. |
| `review.runner` | Supported runner/scheduler identity and concurrency policy, or `unavailable`. |
| `host.skills` | Confirmed skill discovery, destination, write/registration, local-edit handling, version read-back, and invocation behavior. |
| `host.hooks` | Confirmed events, trust/configuration, payload/redaction, limits, and local/cloud differences. |
| `host.mcp` | Confirmed connector/tool-discovery capability and response visibility. |
| `privacy` | Project boundary, retention, redaction, shared-lesson eligibility, and prohibited data. |
| `cleanup` | Bounded retention and cleanup for disposable apps, credentials, scratch, images/cache, and superseded artifacts. |

Resolve deployment-specific GitHub and MCP values from authorized scoped
configuration. The canonical globally delivered payload must remain portable
and must not disclose or default to a private author's project or repository.

## Modes

### Bootstrap and implementation mode

Use this mode when Cursor is asked to build the harness machinery. Do not
pretend the machinery already exists.

1. Inspect the actual repository instructions, target MCP connections and live
   documentation, source access, host lifecycle interfaces, and the pinned
   Harness Squared integration before choosing interfaces.
2. Inspect the sibling AICOmpanies Harness² foundation read-only when available:
   `HARNESS2_README.md`, `harness2.lock.json`, `industry_harness/cli.py`,
   `industry_harness/adapter.py`, `industry_harness/feedback.py`, and its hook
   wrapper/configuration. Confirm the current paths and APIs rather than
   assuming these names remain stable.
3. Reuse qualified primitives for the upstream `Library`, `run_task`, adapter
   extension points, protected transport, persistence, reflection, and resume.
   Keep EPM state separate. Do not port the sibling project's financial
   permissions, research universes, heuristics, or other domain policy.
4. Compare the pinned upstream revision with the current official Harness² API
   before upgrading. Harness² is research software. Never inherit a benchmark
   launch default that disables the sandbox; preserve protected project
   execution. Do not add Google RRSI or another framework merely because it was
   inspected. A second integration needs a separate, evidence-backed decision.
5. Implement the smallest adapter, persistence, event/review integration, and
   verification helpers needed for the behavior below. Use one authoritative
   record per concern and qualified locked/atomic persistence when suitable.
   The one-file skill requirement does not imply one runtime data file.
6. Validate in disposable, isolated applications. Capture durable proof of
   state/replay behavior separately from proof that a live hook fired and from
   end-to-end business acceptance. Finish build and qualification workflows
   with evidence-aware cleanup; never delete shared business data, active
   volumes, required secrets, or unreplaced source.
7. Produce an honest capability report. An unavailable MCP, hook, scheduler,
   framework API, GitHub authorization, or target permission is a limitation,
   not an invitation to invent a tool or claim completion.

The capability report must resolve every portable configuration field and cite
evidence for available dependencies, source access, live target documentation,
framework import/API checks, state write/recovery checks, GitHub destination
and authentication status, host hook/runner support, and untested acceptance
scenarios. Keep secrets redacted. Obtain separate authorization before any
installation, configuration activation, target mutation, or external
publication that was not already requested.

Map Harness² into the EPM workflow narrowly and qualify each boundary: represent
a review or evaluation case as an upstream task; express scoped candidate skill
or lesson edits through the upstream supported proposal/refinement surface; run
the protected executor only in an isolated disposable test; apply independent
EPM semantic, exactness, coverage, authorization, recovery, and regression
checks as the acceptance gate; and add only accepted, attributable evidence to
the qualified library. Never mutate a live business cube while evaluating a
speculative candidate. Never adopt framework-selected guidance automatically:
it must pass those checks, preserve counterexamples and approval boundaries,
and remain reversible.

Any software installation should be user-level or global when viable. Explain
why before using a project-specific installation. Implementation work does not
authorize hook activation, schedules, external messages, issues, commits, or
deployment unless the user separately requests them.

### Operational mode

Use this mode for each action after discovering the capabilities that action
actually needs. A partial environment can still support interviewing, modeling,
read-only inspection, and draft contracts. Load this skill and every available
relevant checkpoint, slice contract, evaluated lesson, and live target document.
Confirm current source, target, identity, permissions, revisions, and contracts
before resuming or mutating target business state.

Start by restating the goal, current evidence, important unknowns, next bounded
step, and required authorization. If no qualified persistence or event runner
exists, continue only with actions that remain safe and report the reduced
capability; do not simulate durable recovery.

## Discover the request without burdening the user

Offer two entry routes and allow them to be combined or switched:

- **Sample-led inspection:** inspect accessible workbooks, exports, schemas,
  application definitions, or other files. If the user points to files the
  environment can read, inspect them instead of asking for pasted samples.
- **Guided interview:** ask focused questions that establish intent and meaning
  before creating a small representative model.

For exploratory work, ask what the user wants to compare or explain and give a
few concrete possibilities, such as population by municipality and year,
energy consumption by source and month, transit ridership by route and day, or
budget versus actual by department and period. Do not force a pain-point
interview when the user simply wants migration or exploration.

Every question from every responsibility must contain a few concrete examples
appropriate to the user's demonstrated familiarity. Adapt on every turn.
Words such as *migration*, *Firebase*, or *JSON* suggest technical familiarity
but do not prove expertise in dimensional modeling, accounting, or the target
system. Examples:

- “What does one row represent: one company-account-month observation, one
  route-stop-day count, or one project-version estimate?”
- “Should this balance aggregate through time as an ending value, an average,
  or not at all? For example, cash at month-end is usually not summed across
  months, while monthly ticket sales often are.”
- “Does blank mean not collected, unknown, or not applicable? For example, a
  missing population estimate differs from a measured zero, and a currency may
  be not applicable to a headcount.”
- “Should we inspect the accessible workbook/export first, conduct a guided
  interview, or inspect a sample and then confirm its meaning together?”

Do not repeat questions answered by files, tools, earlier decisions, or the
target. Ask only questions that change the next modeling or verification
decision. Explain briefly how a selected follow-up will improve the application
or reduce later rework.

Keep unanswered business/modeling questions, and answers that leave a material
ambiguity, in the internal backlog. Material unresolved questions may become
concrete GitHub drafts in the appropriate authorized destination, subject to
the per-issue owner approval below. A user's disagreement with an assistant
proposal is not an unsatisfactory answer and is not evidence that the user is
wrong; record the user's controlling decision and revise the proposal.

## Apply multidimensional modeling judgment

For each dataset or proposed application, establish and test the following.
Do not turn a finance example into universal policy.

### Grain and identity

- State what one fact record means and which axes uniquely identify it.
- Preserve stable source identity, lineage, provenance, source version/range,
  target identity, and revision. Do not use labels as identities when stable
  keys exist.
- Detect duplicate coordinates, mixed grains, changing identifiers, and facts
  whose qualifiers make them distinct. A company-account-period value and its
  source control are not automatically interchangeable facts.

### Dimensions, members, and relationships

- Identify analytical axes, member identities, labels, ordering, attributes,
  hierarchies, alternate hierarchies, parent-child relationships, and effective
  dates where relevant.
- New multidimensional applications use blueprint v2: Account, Entity, Year,
  Period, View, Value, Scenario and Data Type are mandatory axes; custom axes
  remain available. Read their current descriptions and authorized metadata.
  Creation seeds descriptions and empty axes, not business members. Account
  can describe financial/statistical accounts, KPIs, measures or goals; Entity
  identifies the modeled objects. Scenario distinguishes application-defined
  cases. Data Type is application-defined classification and does not select
  physical numeric/text storage. Axis names activate no hidden financial policy.
- Preserve each named hierarchy as its own graph over shared dimension members.
  Discover `metadata.hierarchy.list`, `.read` and `.members.list`; do not flatten
  alternate trees into one relationship union. Use `.create` with explicit node
  membership for imported trees, including isolated roots, then `.members.set`
  and scoped `metadata.relationship.create`. Preserve each source relationship's
  status and aggregation override. `members.set` upserts only the supplied nodes;
  omission does not remove membership. Create the first hierarchy explicitly as
  the default; later default changes use `.default.set`.
- Send the canonical `hierarchyId` for traversal, relationship browsing, edits and
  builds. An omitted hierarchy ID selects only the dimension's default graph.
  A requested unavailable hierarchy must fail, not substitute another tree.
  Hierarchy versions remain unique across the dimension and belong to one named
  graph; never combine an ID with a version from another graph. Build the selected
  hierarchy after metadata changes and obtain current versions before compiling
  or running a hierarchy-dependent operation. A metadata change can stale builds
  in other trees too; rebuild every tree used by the next operation.
- Reconcile declared nodes, roots, active/inactive edges, duplicate endpoint pairs
  and per-placement operators separately for every source hierarchy. Shared
  members do not authorize shared placement operators. Existing financial forms
  without a hierarchy selector use only the default graph; use a discovered
  named-selector primitive when an alternate graph is required.
- Distinguish a hierarchy relationship from a data fact. Validate dependency
  closure when a slice uses a parent, formula, allocation family, source
  control, or alternate rollup.

### Measures, accounts, and aggregation

- Classify values as additive, semi-additive, or nonadditive across each axis,
  not merely “numeric.” Revenue may add over entities and periods; an ending
  inventory balance may add over products but not time; a ratio such as margin
  percentage should normally be recomputed from components rather than summed.
- Distinguish stocks from flows and source controls from additive leaves.
  Never make a total appear correct by double-counting both a reported control
  and its detail.
- Preserve units and currencies. Never aggregate USD, EUR, kilograms, people,
  percentages, and index points without an explicit supported rule.

### Time, scenario, and value semantics

- Define period granularity, calendars, year/period identities, point-in-time
  versus duration meaning, scenario/version semantics, and effective dates.
- Keep actual, budget, forecast, restatement, source version, and approval state
  distinct when the source does. “Latest” is not a stable identity.
- Preserve exact decimal strings and target-supported numeric types. Do not
  pass values through binary floating point when exact decimal equality is
  required.

### Missingness and rules

- Keep **missing**, **zero**, **unknown**, and **not applicable** distinct.
  Confirm how each is represented and aggregated.
- Identify formulas, dependencies, allocations, conversions, validation
  controls, and source-supplied versus inferred rules. Migrate existing rules.
  Propose new rules only for genuine gaps and obtain the relevant business
  decision before treating them as accepted.
- Inventory source rules and reusable member sets separately from facts and
  contextual documents. Verify their native application definitions and ordered
  membership through readback; retaining a formula in context or importing a
  validation example does not establish rule coverage. Preserve retired rules
  as retired, and identify incomplete source bindings explicitly.
- Declare and verify each input and output member's numeric kind before building
  typed rules. Preserve the source's numeric scale, including percentage points;
  do not infer a fraction or rescale values merely from a percentage label.
  Finish required metadata changes before compiling dependent definitions, and
  refresh stale metadata pins on saved views and hierarchy builds.
- Never fabricate observations or convert an inference into approved accounting
  or domain semantics.

### Python rule authoring, validation and effects

Use the typed Python authoring interface when constructing application rules.
`context.app` constructs application- and revision-bound symbolic references;
fixed core resolves each emitted name under current authority. External SDK clients obtain it through
`metadata.authoring.context`. Names must resolve uniquely. For a selected
scenario, accounts below a hierarchy member and entities below a region,
compose `app.cube.select(...)` from `app.dimension(...).member(...)` and
`.descendants(...)`, then return `selected.set(selected.value * Ratio("2"))`.
This constructs one server-owned operation over existing numeric facts,
preserving every unmentioned axis; it does not run a client cell loop. Text,
missing coordinates and facts outside the selection are unchanged. Discover
the deployed bounds and use exact decimal/rational types. JSON remains the
transport format, not the preferred human rule-authoring interface.

Before generating a rule, read `metadata.authoring.context` and use its
current `authoringContract` plus authorized symbolic coordinate grain. Prefer one
relational selection built from a published member list, named hierarchy
primitive (`children`, `descendants`, `ancestors`, `siblings`, `leaves`) or
member attribute predicate over repeated literal member IDs and per-cell
statements. Compose union, intersection and difference only inside one
application and dimension. Reuse a grouping only when it expresses stable
business meaning; do not create a list merely to shorten a one-off small rule.
Pin the current hierarchy, member-list and definition state tokens/digests. A loop that emits hundreds of
independent operations is not equivalent to preserving one bounded selection
for the fixed core to plan.

When importing or reconciling member attributes, create the bounded typed
definitions and use `metadata.attribute-values.replace` once for each source
dimension. Supply the complete declared `attributeIds` set plus member rows;
omitted declared values are deliberately cleared. Treat any invalid type,
unknown/inactive member, stale metadata revision or unchanged replacement as a
whole-operation result and reconcile it before proceeding. Never expand a
source attribute table into one `metadata.attribute-value.set` call per cell.
That scalar function is only for an intentional single-object edit. Multiple
semantic dimension replacements are not client batches: each dimension is an
independent metadata context, while execution chunking and retries remain
server-owned.

When discovery advertises `metadata.applicability_relation.*`, use one current
sparse relation for stable business tuples such as account/entity
applicability, mappings, exact ratios or policy flags. Save the complete typed
relation, correct any unavailable dimension/member diagnostics, then activate
that exact state token. Replacement is whole-current-state and rotates the
token; never encode batches, chunks, partitions, leases or worker assignments
as rows or relation identities. When `facts.expression.calculate` discovery
advertises `applicabilityDomain`, resolve the current handle from the bounded
authoring snapshot with
`context.app.applicability_relation(name).domain(...)`. The handle supplies
the stable relation ID plus its current state token and definition digest;
never ask the user to copy those tokens into rule parameters. Bind every
active dimension to one anchor Member column, then declare only genuine
target, operand and typed scalar roles. Use `CubeExpression.relation_operand(...)` and
`CubeExpression.relation_value(...)` inside one
`Program.applicability_expression_calculation(...)`. An `error` operand makes
missing data a Validation failure; `skip` deliberately excludes that mapping.
Do not expand relation rows into scalar statements or separate saved rules. If
the deployed expression catalogue does not advertise this profile, stop with a
capability error rather than inventing a fallback.

Keep semantic choices separate from performance suggestions. Decide whether a
result is dynamic or materialized from meaning, expected reuse, query cost and
downstream dependencies; do not materialize a cheap presentation-only value
merely because storage is available. Keep ratios nonadditive and preserve
missingness and parent input. For parent nodes, select the declared `own_only`,
`children_only` or `own_plus_children` policy; never silently overwrite own
input or count a stored parent total and its descendants twice.

Use `calculation.status.read` for currentness, presence, coverage and reason
codes. Use `calculation.impact.explain` for a bounded, authorized estimate of
affected work before Test or Run; it is read-only and does not establish actual
Test counts. Read the Validation build artifact's `PlanSummary` section for
the source-bound operation/selector summary and static efficiency diagnostics.
Warnings are guidance. Structural errors are a Validation gate:
`STATIC_SCALAR_CALCULATION_FRAGMENTATION` means that a rule expanded one
business family into at least 16 scalar calculations, and
`STATIC_CLIENT_WORK_PARTITIONING` means that it encoded at least 16 one-cell
write batches. Correct either error by expressing the logical scope through
hierarchy, attribute, member-list or qualified sparse-relation primitives; do
not raise a limit, rename fragments or save several rules. To request real work, submit
`calculation.recalculate.request` with the exact binding, current definition
digest, processed-impact epoch, business mode and idempotency key. The rule's
scope and declared parameters determine the logical work. Never supply
partition keys, task limits, chunks, leases or worker assignments, and never
create several saved rules because one logical rule requires more execution
work. The server worker derives and owns bounded partitions and retries. Do not
retry with changed pins under the same key. Use
`facts.cube.resolved.binding.list` to discover published
effective bindings, then `facts.cube.resolved.read` to choose explicitly
between own input and an effective governed value. Current reads may return
`CALCULATION_REQUIRED` or pending-impact status; never repair or publish as an
implicit side effect of reading. For a large result, use the advertised durable
resolved request/result/cancel lifecycle instead of bypassing row limits.

When the deployed expression catalogue supports exact signed apportionment,
`Program.apportion` composes live control and component expressions with typed
`ApportionmentComponent` and `ApportionmentTarget` values. Use positive exact
`Ratio` weights, an explicit power-of-ten quantum and a unique ordered member-ID
tie tuple. Signed components are apportioned independently, then combined by
target; the result must match the live control exactly. Default source rounding
is exact. Use `half_even` only when that is the source's accepted rounding policy.
`CubeExpression.component_amount` refers to another component's quantized input
before distribution, not its output cells. Component dependencies must be acyclic.
Keep historical source/control conflicts inactive and visible; never copy
expected outputs into a rule or bias weights to hide a source mismatch. Test and
Run use the same fixed core, with current source-read and target-write authority.

For a large apportionment family, do not create one `Program.apportion` per
source row, organizational unit, target or imported source batch. Store the
stable business policy in one current typed applicability relation: genuine
group, component, formula-shape, target, exact weight, quantum, rounding and
tie-dimension roles. Resolve it from the authoring context and submit one
`Program.applicability_apportionment(...)` with the small set of distinct
formula shapes. The server resolves relation rows, derives internal work and
publishes one current result atomically. Relation rows express business policy;
they must never express client batches, partitions, chunks, workers, retries or
task limits. A client must not expand the relation into separate rules or
operations even when the imported source was physically divided into files or
sections. If this grouped profile is unavailable, report the missing capability
instead of manufacturing scalar rules.

`python.program.save` replaces the one current inactive source and atomically
queues a `Validation` build. Supply `validationParameters` when the builder
needs representative inputs; the default is `{}`. Poll the returned validation
task/build and bind diagnostics to its source digest before presenting them in
an editor. Save rejection and semantic failure do not activate a rule or write
business facts. Reopen the current source to correct it; saving replaces that
source with a new opaque state/source token. A sealed validation proves compilation and supported
reference/type checks, not the expectedness of business effects.

For effect inspection, call `python.program.test` through
`execute_v2_python_program_build` (SDK `test_python_program`) with the exact
current source token and parameters. For typed definitions, `parameters` feed the
Python builder; `definitionParameters` supply the actual rule or member-list
bindings for this test. They are separate inputs. Read the exact current source after
Validation seals: `validation.definition.parameters` provides its typed binding
declarations before activation. The same declarations are exposed on a sealed
`latestImpactTest.definition`; sample values are not execution defaults. Never
substitute example bindings for the user's requested bindings. Poll the `ImpactTest` build and read its `Impact`
artifact through `read_v2_python_program_build_artifact`. The current private
evaluator supports numeric batch, ordered numeric sequence, scoped numeric
transform, text, line-detail and composite mutations, plus bounded supported
expression calculations over private intermediate state. Calculation outputs are
identified by stable result key plus an opaque current result-state token,
separately from raw facts. Never request, retain or submit a calculation
generation ID or publication revision. Discover the current state token through
the advertised status/read contract, bind it to paged reads and restart the read
when the server reports that the token changed. Treat continuation cursors as
opaque. When a business rule consumes another current result, bind only its
`resultKey` and `resultStateToken` inside the rule's declared input. Do not add
producer job IDs, job-dependency edges, batches or execution ordering: a
published current result is already available, and the fixed core rechecks its
state token and nested lineage before effects. Typed application rules
use these same units; member-list and calculated-member tests inspect their
evaluations. Discover supported effects before composing a whole test;
unsupported effects fail explicitly. It uses proposed state
between units without publishing facts. Inspect before/after rows, removals,
counts, input pins and unit boundaries. Do not create another scenario or
application automatically to simulate this workflow.

Activate the exact reviewed current source with `python.program.activate`,
supplying its `expectedStateToken` and
supplying the `validationBuildId` of the specific Validation or ImpactTest
result that was inspected. This field is required for typed definitions; another
client's later test must never silently replace the reviewed build. Impact
artifacts expire after 24 hours; inspect and activate against an available result.
Activation rotates the lifecycle state token while retaining the stable current
source token used by the validated build. It persists the compiled definition and source binding independently of
later technical-artifact expiry.
Activation requires current semantic/source/environment pins and a sealed
Validation or completed ImpactTest; it grants permission for that code to run,
not a promise that future data equals the inspected result. Data changes make
the prior impact historical. Refresh Test when the intended effect must match
current data. Run still requires current execution authority and uses existing
atomic unit checkpoints; do not claim whole-rule atomicity. Explicit `Plan`
builds and execution delegations remain separate from Validation/ImpactTest.
For typed `ApplicationRule` and `CalculatedMember` authoring, save the Python
source and activate its validated compiled definition. A named member selection
is inert native metadata: save and activate `MemberListDefinition` through
`metadata.member_list.*`; never return it from a Python program.
The normal public API no longer accepts raw JSON definition save/publish calls.
Use the current member-list `stateToken` when replacing or evaluating a named
selection. Compiled rule JSON is internal execution data, not another editable
source of truth.
Jupyter notebooks are retired; the supported authoring and isolated build path
uses Python source through the application interface and authorized clients.

### Completeness and exactness

- Define source-record coverage, rule coverage, hierarchy/dependency coverage,
  rejected/parked records, target receipt coverage, and exact reconciliation.
- Verify controls according to their semantics. A nonadditive source control
  may be compared with a calculated total but must not be loaded and summed as
  another leaf merely to make counts match.

## Seed and expand one real application

Use this method for migrations and for new applications once enough meaning is
known to build a coherent seed:

1. Perform a few bounded exploratory passes to establish principal dimensions,
   coherent key fact lines, important numbers, their meanings, and obvious
   integrity risks. Whole-source inventory, checksums, counts, schema checks,
   duplicate detection, and mechanical integrity checks are useful, but
   exhaustive semantic analysis is not a prerequisite for the first seed.
2. Through the authorized target MCP, build a **small real working seed** in a
   new or explicitly selected safe application. Use a coherent dependency-
   complete selection, not disconnected demo values. The user validates the
   seed and its stated scope; record it as a versioned agreed baseline.
3. Process remaining source records line-by-line in meaningful slices. Extend
   the **same** application's dimensions, members, facts, and rules. Each slice
   includes dependency closure for its hierarchies, calculations, source
   controls, allocation families, units, and currencies.
4. If later evidence disproves the seed, revise it transparently. Preserve the
   approval history and superseding decision; never distort new records to fit
   an earlier assumption. Use supported populated-layout evolution and preserve
   grain, exact values, identities, and provenance.
5. After each slice, publish a concise versioned source-to-cube contract using
   the template below. Refer to canonical source and target records rather than
   duplicating business truth.
6. Continue until every in-scope source record and rule is mapped, loaded,
   rejected with an approved reason, or explicitly unresolved. Complete exact
   value/control reconciliation, permission checks, target verification, and
   business acceptance. Seed acceptance is not migration completion.

Do not overwrite an existing shared application. Development qualification
uses disposable isolated applications. A user may explicitly authorize a test
in a shared application, but it must still use the application workflow.

## Learn the target MCP before operating it

Discover actual tools and progressive task guidance from the live MCP. Source
code is supporting evidence, not proof of the connected server's current
surface or the user's permissions. Do not load a giant documentation dump for
every slice; fetch the relevant contract and examples when needed.

For each needed operation, establish:

- purpose and responsibility;
- input/output schema and exact value semantics;
- preconditions, identity, authorization, and application scope;
- side effects and business versus technical state changes;
- limits, ordering, lifecycle, preview and revision binding;
- idempotency, retry behavior, unknown-outcome recovery, receipts, and jobs;
- supported examples and the task playbook in which it belongs.

Read each discovered function's `mcpTools` and the selected tool's live input
schema before constructing its envelope. `mode: read` describes effects; it
does not imply `read_v2_program`. For example, `facts.transfer.import.read`
uses `execute_v2_source_program` with the accepted `requestId`. The field lists
applicable entrypoints; preview/submit pairs still require their documented
order, exact preview token and idempotency key. Never infer routes from a
function suffix or replace an accepted request merely to correct its status
poll. If an older server omits `mcpTools`, consult its exact function reference
instead of guessing.

Inspect effects, not names. For example, an Open EPM function named
`metadata.dimension.describe` or `metadata.member.describe` may **write** a
description rather than read documentation. This example is a warning to check
the live contract, not a permanent catalog claim.

If manuals, prompts, or resource templates are missing, say so. Do not infer
that a source-only inventory is a live authenticated MCP response, and do not
hard-code dated tool counts. The implementation must discover its actual
connection and capability set at runtime.

Discover the target's actual names and contracts for this logical capability
map. The map is a checklist for the delivered instruction manual, not a list of
invented APIs:

| Logical capability | What the harness must discover and verify |
| --- | --- |
| Discovery and manuals | Function/tool catalog, prompts/resources or equivalent guidance, schemas, examples, versions, limits, side effects, and permission filtering. |
| Authentication and scope | Current identity, workspace/application authority, read/write separation, expiry, and safe denial behavior. |
| Seed application lifecycle | Supported create versus select flow, duplicate-name behavior, isolated/disposable option, stable application identity, and deletion boundary. |
| Metadata and hierarchies | Dimensions, members, atomic dimension-level attribute replacement, stable IDs, parent-child/alternate hierarchies, ordering, current state tokens, validation, and bulk limits. |
| Populated layout evolution | Supported preview/build/validate/activate lifecycle, revision pins, dependency closure, and recovery when adding dimensions or changing grain. |
| Facts, text, and detail loads | Numeric decimal strings, text/supporting detail, coordinate identity, missing/zero semantics, units, batching, row errors, provenance, and atomicity. |
| Rules and calculations | Formula/allocation/source-control definitions, dependency validation, current publication state, exact semantics, and authority. |
| Preview and execution | Side-effect-free preview guarantees, revision/digest binding, stale rejection, execute/publication boundary, and partial-effect policy. |
| Query and read-back | Metadata/fact/rule reads, pagination, snapshot consistency, exact values, security filtering, control reconciliation, and evidence references. |
| Receipts, jobs, and replay | Stable request/job/receipt IDs, idempotency, status/event reads, interruption, retry eligibility, unknown-outcome reconciliation, and retention. |

If any capability is absent, identify which intended action is blocked and what
read-only/modeling work remains safe. Do not block unrelated discovery merely
because GitHub, a scheduler, or target write access is unavailable.

## Execute mutations with exact recovery semantics

Before a target business mutation:

1. Confirm authorization, current source snapshot, target identity/state token,
   accepted contract version, and operation preconditions.
2. Create a stable request/event identity and durably record the intended
   operation, expected effect, and verification plan.
3. Submit through the supported MCP/application-language path.
4. Persist the returned job/operation/receipt identity and resulting current-state token or committed revision.
5. Read back and independently verify the effect against source, contract, and
   target rules before marking the operation complete.

The durable intent save in step 2 must succeed and be read-back consistent
before submission. If persistence is unavailable, locked, corrupt, or fails
validation, do not perform the dependent target mutation. Pause that mutation,
preserve any safe in-memory diagnostic context without claiming durability,
and report explicitly that the checkpoint could not be saved.

Client state cannot make a local checkpoint and a remote MCP commit atomic. If
a response is lost or the outcome is uncertain, **do not replay blindly**.
Reconcile the stable identity against server jobs, receipts, current-state tokens, and
read-back state. Replay only when the target contract establishes it is safe;
otherwise checkpoint `unknown_outcome`, pause the affected slice, and request
the required resolution.

A harness checkpoint/resume mechanism recovers the client workflow. It is not
permission to build a product rollback engine, resume paused business work
silently, or override Open EPM's manually initiated retry semantics.

## Persistence contract

Preserve one authoritative record per concern:

| Concern | Authority | Minimum content |
| --- | --- | --- |
| Published skill release | Canonical authoring file plus atomic deployment manifest/artifact | Version, digest, size, compatibility, privacy validation and served payload identity |
| Client installation consent | Client/host scoped state | Installation context, exact version and separate offered/accepted/installed/verified/declined states |
| Owner requirements | Project input ledger | Direct requests, corrections, precedence, context/status distinctions |
| Workflow progress | Project-scoped checkpoint and slice contracts | Goal, source/target pins, coverage, operations, evidence, blocker, next safe action |
| Evaluated reusable guidance | Harness² lesson library where qualified | Scoped lesson, evidence, counterexamples, evaluation, version, reversibility |
| Business state and receipts | Open EPM | Current metadata, facts and rules; state tokens; jobs; receipts; business provenance |
| Product feedback | Internal draft/backlog until approved | Sanitized reproduction, impact, proposed issue, approval and posting state |

Do not create a competing human-decision ledger. Reference the project input
ledger and slice contracts by stable ID/version. Store only minimal data or
pointers; never store credentials in events, checkpoints, lessons, or issues.

The exact file/database format is an implementation choice, not prescribed by
this skill. Whatever is chosen must provide schema/version compatibility,
atomic consistent checkpoint replacement, stable event/request IDs,
deduplication, an incremental review watermark, one active writer or adequate
concurrency protection, bounded retention, and safe recovery from partial
writes. Prefer qualified existing locked/atomic persistence over a new parallel
format.

### Checkpoint template

```yaml
checkpoint_id: epm-harness:<project>:<stable-id>
schema_version: 1
adopted_skill: {name: multidimensional-cube-harness, version: "...", digest: "sha256:..."}
goal_scope: "Create or migrate ...; explicit exclusions ..."
status: active | paused | blocked | complete
approved_baseline: {contract_id: slice-000, version: 2, approval: user, at: "..."}
source: {identity: "...", version_or_digest: "...", covered_ranges: ["..."]}
target: {workspace_id: "...", application_id: "...", revisions: {metadata: "...", data: "..."}}
coverage: {records: "n/N", rules: "n/N", unresolved: ["stable refs"]}
operations:
  - {request_id: "stable-id", intent: "...", state: pending|committed|unknown,
     job_or_receipt: "...", verified: false}
blocker: {kind: "...", evidence_ref: "..."} # omit when none
issue_draft: {draft_id: "...", approval: not_requested|pending|approved|denied|posted}
next_safe_action: "Read back receipt ...; do not replay mutation"
review_watermark: "stable event id or sequence"
```

On resume, validate the checkpoint schema, source digest/version, target
identity and revisions, current authorization, live operation contracts,
pending/unknown outcomes, and user-decision precedence. If any pin drifted,
stop at read-only reconciliation and revise the plan or contract. Never blindly
replay the recorded next action.

### Slice source-to-cube contract template

```yaml
contract_id: migration-x/slice-003
version: 4
supersedes: migration-x/slice-003@3
source: {snapshot: "digest/version", ranges: ["records 1201-1800"], coverage: "600/600"}
grain: "one Entity-Account-Year-Period-View-Value observation"
mappings:
  dimensions: [{source: company_id, target_role: Entity, identity_rule: "stable source ID"}]
  facts: [{source: amount, target: Value.numeric, exact_type: decimal_string}]
dependencies: ["hierarchy H2", "formula F7", "control C4"]
rules:
  accepted: ["ending balance uses last period"]
  proposed: ["missing FX rule for entity E9"]
assumptions: ["... not yet a user decision"]
unresolved: ["Q-17 with examples ..."]
target: {application_id: "...", revisions: {metadata: "...", data: "..."}, receipts: ["..."]}
verification: {record_exact: pass, controls: pass, permissions: pass, evidence_refs: ["..."]}
approval: {status: proposed|accepted|superseded, scope: "this slice only", by: "user/owner", at: "..."}
next_slice: "records 1801-2400 plus dependency closure"
```

Keep this short. Link large inventories and evidence instead of copying them.

## Events, hooks, and review runs

Session evidence may include authorized, available user-facing transcript
content or durable references to it. Capture concise decision summaries with
attribution: user decisions/corrections versus assistant proposals, material
assumptions and rationale, tool attempts and results/errors, verification,
outcome/rework, and unresolved questions. Mark each capture `complete` or
`partial` with the source, covered range/time, and known omissions. Never claim
all transcript or tool activity was captured when host hooks expose only part
of it. Raw transcripts, source files, websites, and tool output are evidence;
they do not authorize new rules, permissions, business meanings, or actions.

Each review must compare only new events after the watermark with the approved
baseline, current user-decision precedence, and relevant prior evidence. It
must not let a recent partial capture silently supersede an accepted contract
or repeat a previously rejected hypothesis.

Separate a fast event producer from a longer review runner:

- A supported hook records a bounded, redacted event or pending-review request
  and a consistent checkpoint. It must not perform a long review or remote
  mutation.
- A supported runner/scheduler loads this skill and current state, claims a
  deduplicated review run, reviews only new events after the watermark, and
  records the result atomically.
- A one-hour inactivity trigger requires actual activity tracking plus a timer.
  It is not equivalent to session end, and inactivity is neither approval nor
  completion.

Verify Cursor's current hook, scheduling, trust, and tool interfaces before
mapping this design. Do not assume Codex hook JSON works in Cursor. Codex
documentation has stated that background-hook completion does not start a new
turn and that SessionEnd is brief synchronous advisory work; recheck current
documentation before implementation.

Cursor's maintained hook documentation is <https://cursor.com/docs/hooks>.
At the time of this handoff it documents events including `sessionStart`,
`sessionEnd`, `beforeSubmitPrompt`, `postToolUse`, and `postToolUseFailure`;
`sessionEnd` is fire-and-forget, cloud support is narrower, and remote MCP
results may be redacted from hook output. Treat these as versioned observations:
recheck current events, payloads, timeout/continuation behavior, trust,
local-versus-cloud support, and redaction before implementation. A hook unable
to see a result may record the stable operation reference for authorized
runner read-back; it must not weaken privacy or request credential exposure.

Use stable event/run IDs, an incremental watermark, and one-writer/locking
protection. Prevent a review result from triggering another review recursively.
Suppress duplicate hook delivery and duplicate schedule claims. A review must
not race an active user mutation, silently resume a paused migration, retry an
unknown business write, file an issue, or expand permissions.

Useful review times are a milestone, session close, daily batch, or a suggested
one-hour idle period. These are options until explicitly configured. Report
actual evidence separately:

- **Durable capture/replay proof:** synthetic or isolated events survive and
  deduplicate correctly.
- **Live event proof:** the configured host actually fired the hook/runner.
- **End-to-end acceptance:** the review produced a useful, evaluated outcome
  without unauthorized effects.

## Evidence-driven improvement

Use the loop **Observe → Understand → Learn → Discover → Evaluate →
Improve → Validate → Reuse**. Retain user corrections and feedback,
explicit decisions and rationale, MCP attempts/results/errors, verification,
outcomes, and rework. Ask selected follow-up questions with concrete examples
when their answers would materially improve later work; keep unresolved
questions in state rather than repeatedly asking them.

Define “better” primarily as:

- semantic and business correctness plus user acceptance;
- exact migration, complete record/rule coverage, and correct controls;
- fewer avoidable corrections, unsafe retries, and repeated investigations;
- useful questions with lower user effort;
- maintainable, authorized, deterministic behavior.

Time and cost are secondary. Correctness, authorization, exactness, privacy,
and acceptance criteria are hard constraints, not dimensions that a weighted
score may trade away.

Evaluate each candidate lesson or skill change on representative held-out
examples and relevant prior accepted cases. Preserve counterexamples. Label it
as one of: evidence-backed reusable lesson, scoped user/project decision,
hypothesis requiring evidence, source anomaly, client defect, documentation
gap, product defect, or environment failure. Do not promote a lesson because a
model praises its own output or because a log exists. Version promoted
guidance, preserve provenance, make it reversible, and verify that it does not
rewrite permissions, approvals, business rules, or acceptance criteria.

Keep each implementation's private data scoped to that project. Only suitable,
nonconfidential, generalized, evaluated lessons enter shared knowledge. Never
infer blanket consent for cross-customer reuse. This mechanism improves
external knowledge and workflow; it is not automatic model-weight training.

### Candidate lesson template

```yaml
lesson_id: lesson:<stable-id>
scope: "Open EPM populated-layout migration" # narrowest justified scope
claim: "Read back target revision before replay after a lost response"
evidence: ["accepted case A", "failure case B"]
counterexamples: ["contract C guarantees receipt replay by request ID"]
classification: reusable_lesson | project_decision | hypothesis | product_bug
evaluation: {held_out_cases: ["..."], result: pass|fail|mixed, measures: {avoidable_retries: 0}}
privacy_review: {contains_private_data: false, shareable: true}
version: 1
status: candidate | accepted | rejected | superseded
reversal: "restore version 0 and re-run cases ..."
```

## Diagnose failures and improve the MCP product safely

Do not blame a tool from one error. Determine whether the cause is source/user
data, modeling assumptions, client misuse, authentication/authorization,
stale revision or ordering, missing guidance, missing capability, environment,
or a reproducible server defect.

On a blocking failure:

1. Preserve the checkpoint, intended operation, exact sanitized evidence,
   current source/target pins, and unknown-outcome status.
2. Pause only the affected work. Perform a bounded retry only when the live
   target contract makes it safe; read back before replay after uncertainty.
3. Prepare an internal actionable report and next safe action. Filing an issue
   is not resolution; verify a fix before resuming dependent work.
4. If issue permission is denied or GitHub is unavailable, keep the internal
   backlog and blocker. Do not contact maintainers through another channel.

Every GitHub issue requires explicit owner approval **for that issue**. Later
phrases such as “log a ticket,” an idle trigger, or a general improvement goal
do not revoke this rule. Deduplicate existing drafts/issues; show the owner a
concrete sanitized title and body with examples; post only after approval via
an authorized CLI or connector.

During bootstrap, set up GitHub reporting only as configuration and dry-run
validation unless posting was separately authorized:

1. Resolve whether the destination accepts repository issues, Project draft
   items, or both, and inspect required fields/status values.
2. Verify the authenticated identity and minimum scopes using a supported
   connector or GitHub CLI; do not print tokens or persist credentials.
3. Test rendering, sanitization, deduplication, and approval-state transitions
   locally. Do not create a remote test issue merely to prove the template.
4. Record destination identity and capability evidence in the checkpoint.
5. For a real finding, prepare the draft, search for duplicates, request
   approval with the exact title/body, and post only after approval. Persist
   the returned URL/ID and verify the created content.

### Issue draft template

```markdown
Title: [MCP area] Concise observable failure or documentation gap

Task: What the user was trying to accomplish.
Minimal sanitized reproduction: Inputs, ordering, revisions, and exact calls.
Expected: Contract-supported result.
Actual: Error/result, including whether commit status is unknown.
Environment: Relevant client/server/tool versions and state; no credentials.
Impact: Blocked slice, correctness risk, user effort, or missing guidance.
Desired change: Information or capability needed, without prescribing an
unnecessary rewrite.
Acceptance check: Observable scenario that must pass after the change.
Evidence: Internal references safe for the owner to inspect.
```

## Acceptance scenarios

Validate observable behavior, not exact prose or heading matches. Documentation
frontmatter validation alone is not operational proof.

| Scenario | Expected observable behavior |
| --- | --- |
| Fresh client and version offer | Supplies name, purpose, exact version/digest, trusted server and intended destination; accurately says available versus delivered and offers install, review or decline. |
| Accept, client write and read-back | Explicit acceptance precedes any write; the authorized client writes/registers at the approved scope and verifies the installed bytes/version/digest. |
| Decline, cancel or no response | Performs no local write, records the exact outcome separately, does not treat silence as consent and does not block unrelated safe work. |
| Already installed current version | Verifies matching digest and does not repeat the prompt on every tool call. |
| New machine or installation context | Requests consent for that context without treating another context's acceptance as permission or inventing a device fingerprint. |
| Published update and stale cache | Advertises the current published version/cache metadata, detects the stale client copy and offers an explicit update instead of silently overwriting. |
| Active task version pin | Keeps the adopted version/digest through a mutation and changes version only at a safe, checkpointed compatibility boundary. |
| Local customization conflict | Detects the changed local digest, preserves the variant and offers review, keep-local or explicit merge/replace choices. |
| Unsupported elicitation/resource/local write | Uses a supported client-mediated question or read-only tool/manual fallback and reports unavailable native installation honestly. |
| Direct RPC skipped modern discovery | Gives the bounded eligible-version offer without incorrectly requiring initialize/discovery first or breaking the requested authorized operation. |
| Complete content verification | Reassembles all declared chunks, verifies total size/digest and calls content delivered only after full read; rejects missing, duplicate or reordered chunks. |
| Installation isolation | Installing instructions activates no hooks, scheduler, framework, package, GitHub post, permission or business mutation. |
| Global payload privacy | Contains no credentials, transcript/customer data, private decisions or fixed private GitHub destination. |
| Packaged server without author tooling | Starts packaged Open EPM in an isolated environment with no Codex, Cursor, author home files or sibling checkout; a compatible MCP client retrieves the exact manifest/payload and verifies its version, size and digest, then a separate supported-client check verifies first-use install consent without implying runtime activation. |
| Exploratory user | Offers examples such as population, energy, transit, or budgets; clarifies the intended comparison and creates no domain policy prematurely. |
| Technical migration with accessible files | Inspects the files, avoids asking the user to paste them, uses technical vocabulary proportionately, and still confirms unfamiliar business semantics. |
| Sample versus interview | Offers both routes, supports a combined route, records inferred meanings as assumptions until confirmed, and avoids redundant questions. |
| Seed acceptance and next slice | Builds a dependency-complete real seed through authorized MCP, records scoped approval, expands the same app, and does not call sample success complete. |
| Exact values and nonadditive controls | Preserves decimal strings, units, stock/flow behavior, missingness, and compares rather than double-counts a source control. |
| Missing MCP/manual | Produces an honest capability/documentation-gap report and does not invent tools, permissions, prompts, or dated inventories. |
| Permission or stale-state error | Classifies the likely cause using evidence, refreshes only through supported reads, and does not bypass or silently rebase the write. |
| Lost response after possible commit | Marks outcome unknown, reconciles request ID/jobs/receipts/revisions, and never blindly repeats the mutation. |
| Checkpoint save failure | Does not submit the dependent target mutation, reports that durable intent was not saved, and preserves only clearly labeled nondurable diagnostic context. |
| Blocking outage plus issue decision | Checkpoints and pauses affected work, drafts a sanitized issue, asks approval, and retains it internally if approval is denied or GitHub is unavailable. |
| Resume with source/target drift | Detects digest/revision/auth/contract drift, performs read-only reconciliation, and revises the contract before any mutation. |
| Duplicate or recursive hook | Deduplicates events/runs, advances one watermark, does not trigger review from its own result, and does not race an active mutation. |
| Partial transcript/hook evidence | Marks coverage partial with source and omissions, preserves attribution, reviews against the approved baseline, and makes no new rule from raw evidence. |
| Candidate lesson regression | Tests held-out and prior accepted cases, preserves the counterexample, rejects or narrows the lesson, and leaves permissions/acceptance unchanged. |
| Corrected user decision | Retains history, marks the earlier decision superseded, uses the later instruction, and avoids a second competing decision ledger. |
| Privacy separation | Keeps implementation data project-scoped, promotes only generalized nonconfidential evidence, and stores no credentials. |

For the AICOmpanies proving case, treat the local Excel/export as read-only
source because the owner stated it contains all required information and
Firebase adds nothing. Preserve its high-dimensional grain, exact values,
source controls, identities, and provenance. Any observed record or dimension
count is snapshot evidence, not a global harness requirement. Do not begin the
migration until target access, destination, and applicable authorization are
established.

## Completion and reporting

A harness run is complete only when its declared scope has accepted contracts,
full in-scope record/rule coverage, exact reconciliation, verified target
effects and permissions, resolved or explicitly accepted exceptions, business
acceptance, durable evidence, and verified cleanup. Report limitations and
unproven capabilities plainly.

An implementation is ready for operational use only after its adapter and
state contract, concurrency/atomicity, event deduplication, unknown-outcome
recovery, protected execution, privacy separation, live capability discovery,
negative authorization tests, representative acceptance scenarios, and
cleanup have passed in disposable isolated applications. A library import,
generated reflection, hook configuration file, or offline test is not by
itself proof of readiness.
