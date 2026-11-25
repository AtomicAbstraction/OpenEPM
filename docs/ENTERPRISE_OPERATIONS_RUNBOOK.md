# Open EPM enterprise operations runbook

This runbook is the current response authority for the release signals in
`deploy/operations/alert-rules.json`. Telemetry is technical and self-hosted.
Never export credentials, bearer tokens, business payloads, SQL text, member
values, free-form errors, or principal names. Correlate work with the bounded
`x-correlation-id`, trace ID, application-scoped receipt, and durable work ID.

## Initial triage

Open this runbook from the verified release bundle and use its `epmctl` on the
configured host. The diagnosis command needs the configured Docker project,
systemd observations and release trust configuration. It uses no application
credentials or business-data grants.

1. Freeze deployment changes and record the exact release manifest digest,
   image digests, architecture, configuration profile, UTC interval, and alert
   ID. Do not copy secrets into the incident record.
2. Run `epmctl status --diagnose` on the installed host. Use `epmctl status --json`
   to capture the release manifest and inventory digests, observation time, and
   component results for the incident record. Follow the decision table below.
3. For the affected component, follow the reported dependency and readiness
   checks. When queue, lease or publication evidence is needed, give the
   authorized application operator the observation time, component, fixed
   failure code and original task or receipt reference if known. Use the
   scoped checks in Worker starvation.
4. Use correlation IDs to join proxy, browser/MCP, worker, and publication
   events. Absence of a receipt means the outcome is uncertain, not failed;
   reconcile before retrying.
5. Preserve bounded logs and exact technical evidence. Do not retain database
   snapshots during the build phase. Use disposable recovery copies and remove
   them after evidence capture.

## Read the component diagnosis

The host operator can run this check with access to the installed release and
its Docker and systemd observations. Application grants are separate. Start
with the reported service purpose, dependency observations and next action.

Diagnosis includes an optional workspace listener when the configured Compose
project contains one. It reports a stopped workspace instance and checks a
running instance against the verified release image and its current listener
probe. An installation with no workspace container can still pass its baseline
checks. JSON reports `observedOptionalProfiles` as `[]` for a confirmed absence
and `null` if the Compose observation could not be verified. Diagnosis needs no
workspace identifier.

Diagnosis gives Docker and Compose discovery a shared eight-second budget.
If the daemon or Compose frontend cannot be checked, the command returns the
specific startup reason before a component report can be produced. The signed
manifest check uses the installed operations image with image pulls disabled.
If Docker cannot run that local verifier, confirm the installed image and the
configured daemon before collecting component observations.

| Observation | What to check next |
| --- | --- |
| `composeObservation.status` is `unavailable` | Follow the stated Docker or Compose reason and rerun the diagnosis. Component readiness is `not-observed` until the configured project can be read. |
| The launcher is `inactive`, `socket-unavailable` or `unavailable` | Check the unit and journal, the configured socket, or access to systemd, respectively. Read the Compose result separately. |
| A component is `missing`, `unavailable` or `not-confirmed` | Check the declared release profiles for a missing service. For an unavailable service, check the named dependencies and service logs. For an unconfirmed service, inspect health check startup or the missing health observation. |
| A component is `unexpected-instances` | The release expects one regular Compose container for this service. Check for extra replicas or one-off containers. Reconcile original tasks and receipts before changing the service. |
| `unclassifiedContainerCount` is greater than zero | Confirm the Docker context and project named in the report. Use `docker ps --all --filter 'label=com.docker.compose.project=<project>'` locally, substituting the exact project name. Compare the observed services with `release-inventory.json`. Reconcile any pending work before changing services. |
| An instance has `instanceObservation: compose-only` | Use its Compose state as an initial observation. Check whether the instance stopped, changed, or became inaccessible before Docker inspection. Rerun diagnosis before treating the component as ready. |
| The worker reports `loop-marker-unavailable` or `loop-marker-stale` | Check startup and the last loop signal, then inspect the worker logs. A long operation can delay that signal. Check the original task or receipt in an authorized client before retrying its work. |
| `lastWorkerCheck.status` is `stale` | The last recognized probe finished more than 30 seconds ago. Check whether Docker is still running the worker health probe, then rerun diagnosis. A healthy Docker state alone cannot confirm the worker. |
| `lastListenerCheck.result` is `LISTENER_CONFIGURATION_NOT_READY`, `LISTENER_NOT_REACHABLE` or `UNSIGNED_DENIAL_NOT_CONFIRMED` | Check the configured health port and path, service startup, or local unsigned-request denial, respectively. An HTTP redirect does not prove denial at the listener. |
| `lastListenerCheck.result` is `OIDC_DEPENDENCY_NOT_READY` or `DATABASE_DEPENDENCY_NOT_READY` | Check the listener's audience settings and signing-key access for the first result. Check database connectivity, its configured roles and the expected schema revision for the second. |
| The worker reports `database-role-check-unavailable` or `configuration-unavailable` | Check database reachability and the worker and runtime roles for a role-check failure. Check the release configuration and mounted secret availability for a configuration failure. |
| `lastBrokerCheck.result` is `listener-unavailable` or `configuration-or-database-roles-unavailable` | Check the private broker listener for the first result. For the second, check mounted configuration, PostgreSQL reachability and current runtime and coordinator roles. A recent failed probe with Docker still reporting healthy leaves broker readiness `not-confirmed`. |
| `lastBrokerCheck.status` is `stale` or `not-observed` | Check that the verified broker is running its packaged health command. Diagnosis uses a recognized probe from the current container start and withholds results older than 30 seconds. |
| `browserGatewayCheck.result` is `session-store-unavailable` or `not-confirmed` | For a session-store failure, check the gateway connection to the configured store. For an unconfirmed result, check that both the browser gateway and web containers match the release and share its internal application network. Rerun diagnosis after resolving the cause. |
| Keycloak serves HTTPS while Compose reports it unhealthy | Compare the identity service's current health probe and management settings with the release. The probe uses HTTP on `127.0.0.1:9000` inside the container. Browser sign-in and signing-key requests use HTTPS on port `8443`. |
| `releaseImageCheck` is `different` or `not-confirmed` | Check which release started the service or whether its pinned image can be inspected locally. Reconcile its original pending work before retrying it. |
| Exit code `0` | Each declared service has one regular instance, the component checks passed and the observed local image IDs match the verified release. Use the separate application and queue signals to assess the incident. |
| Exit code `69` | Use the report's current observations if present. If startup stopped before producing a report, resolve the indicated Docker, Compose or local-verifier availability problem and rerun diagnosis. |
| Exit code `78` | The host or release configuration failed a prerequisite or the release could not be authenticated and validated. Resolve the stated configuration or trust error before judging component health. |

Compose locates the configured service instances. The reader obtains each
instance's state, health, image and Compose instance type from one Docker
inspection. Its report records the source as `container-inspect` or
`compose-only` for each instance. A verified one-off instance has
`oneOff: true` in JSON and is identified in the text report.

The ingress proxy checks its configured Traefik ping. The Python build broker
checks its local HTTP listener, mounted configuration and current database roles.
When Docker has no gateway health result, diagnosis reads the pinned OAuth2 Proxy
`/ready` endpoint from the verified web container. It confirms both containers
are on the release's internal application network before the read and rechecks
their identities and endpoints before using the result. The report records the
gateway result separately from Docker health and includes only fixed status and
guidance. [Traefik ping](https://doc.traefik.io/traefik/operations/cli/),
[OAuth2 Proxy readiness check](https://raw.githubusercontent.com/oauth2-proxy/oauth2-proxy/v7.15.5/pkg/middleware/readynesscheck.go)

Component diagnosis measures local container and release observations. Queue
saturation, application availability, throughput, business outcomes and recovery
objectives require their own evidence. Reconcile uncertain business effects using
their original task or receipt in an authorized client.

`lastWorkerCheck` is the latest completed release health probe from the current
start of the verified worker container. The JSON report includes its completion
time and a fixed result while the observation is current. Once the completed
probe is more than 30 seconds old, the report shows its time and withholds its
old result from the readiness check. A recent failed probe can leave Docker health marked
healthy while Docker counts retries. Diagnosis reports the component as
`not-confirmed` during that discrepancy. When the worker image matches the
release, diagnosis requires a recognized probe from the current container
start before confirming readiness. `lastBrokerCheck` applies the same current
probe rules to the verified Python build broker. A ready broker probe confirms
its own coordinator role check. The worker's coordinator dependency still needs
its own evidence.

`lastListenerCheck` applies the same current-start rule to the platform,
router and web listeners and to an observed workspace listener. Docker may still show healthy
while counting retries. A recent failed listener check withholds component
readiness and reports the stage to investigate. A database-stage failure
records the signing-key check as passed for that listener in that probe.
Inspect the `identity-jwks` observation on each affected service. The local
probe reports fixed outcomes and retains no key material or credentials.

## Authentication failure

- Confirm issuer and JWKS reachability, TLS trust, audience separation, clock
  synchronization, Keycloak health, and JWKS refresh/negative-cache behavior.
- Distinguish expected denied requests from a provider outage. Never disable
  signature, issuer, audience, expiry, session-revocation, or origin checks.
- If keys rotated, verify the newly fetched key and retry only authentication;
  do not replay a business mutation without outcome reconciliation.

## Worker starvation

- With an application administrator grant, use **Monitor → Application queue
  and leases → Show queue** in the selected application or call
  `read_v2_capacity_metrics` through MCP with that workspace, application and
  `view: "queues"`. Both read the same application-scoped counts and can run
  when local memory or scratch-disk probes are unavailable. Use per-family
  depth and age to locate unsettled work, then check live and expired leases.
  The Browser displays the database observation time in UTC. Refresh the
  queue to check whether those observations still hold. Check lock waits,
  connection saturation, deadlines, and terminal failure settlement.
- Verify unrelated applications and work families still progress. Scale only
  inside the frozen connection/resource budget. Do not bypass current
  authorization or dependency fences.
- Reconcile an uncertain publication receipt before permitting another claim.

The queue snapshot covers Job, aggregate, Python build/workflow/schedule,
application rule/schedule, import execution, export production, layout
replacement/activation, the two sequence coordinators, and calculation impacts. Depth counts
durable units in unsettled states. Age tracks the oldest such unit from its
recorded availability, including time spent executing or waiting on a child.
Check state and retry policy before treating an old unit as starved. A parent
and its executable child can appear in separate families.

`queueObservedAt` is the UTC timestamp of the PostgreSQL statement that read
queue depths, oldest ages, lease counts and calculation impact status. Both
metrics views include it. Full-view host and database resource measurements
are collected separately.

Both views recheck the administrator's current application access after
collection, including after host probes in the full view. If the server reports
`CAPACITY_READ_AUTHORIZATION_STALE`, check current application access and
repeat the scoped read. Monitor clears the previous snapshot when a refresh
fails.

Calculation impacts can accumulate with an empty business job queue. Read
`queueDepths.calculationImpact` for the unsettled count and
`queueOldestAgeSeconds.calculationImpact` for the oldest event's creation age.
`calculationImpact.status` reports `clear`, `pending` or `failed`. A failed
head delays later events in that application. Use its fixed `failureCode` to
locate worker diagnostics, check the application's processing mode, and refresh
the queue to confirm recovery. The worker rechecks eligibility before retrying.
These events use a transaction lock and contribute zero leases.

`workers.liveClaims` counts leases still valid at the snapshot time.
`workers.expiredClaims` counts leases that expired while their claimant
record is still present. The existing `activeClaims` field counts all retained
claimant records. Schedule materialization and private layout phase leases
count under their owning family. An idle schedule adds no lease or queue entry.
The sequence coordinators use child Jobs for leased execution.

Omit `view` or use `view: "full"` for first-claim latency samples from the five
families that persist those timestamps, PostgreSQL connection and temporary-file
counters, and the serving container's memory and scratch-disk readings. Resource
readings require the configured probes. Assess worker readiness separately
through `epmctl status --diagnose`.

## Release maintenance coordination

Run release changes through the packaged controller. Install, start, stop,
backup, restore, restored activation, certificate renewal, upgrade and
uninstall share one maintenance lock on the host. A competing command exits
with status `75` before issuing Docker operations. Record the first command's
outcome before retrying the second. `epmctl status --diagnose` and logs remain
available during maintenance.

The controller holds the lock on `/run/openepm-release-maintenance` while it
or an in-flight child command retains the open descriptor. Leave the protected
directory in place during maintenance. Keep direct Docker changes coordinated
with the same maintenance window.

Restore requires a fresh Compose target. The controller checks for existing
containers, networks and volumes, including stopped projects and volumes at
the expected names. It compares the resolved service inventory, pinned images,
and architecture with the authenticated manifest before pulling images or
starting recovery. Use the release environment file for Compose resource
settings. Shell overrides that change the effective model cause a refusal.
The controller rechecks the release and configuration throughout recovery.
Each restore uses a private configuration directory on the encrypted backup
export filesystem. Staging preserves the serving proxy routes, runtime
directories and the export directory's existing permissions. Verification
publishes the restore-ready record atomically and reports the recovered
configuration path for operator review. When a phase or publication fails,
cleanup removes the resources and configuration
owned by that run after verifying its Docker teardown. When cleanup is
unverified, inspect the reported run ID and its remaining target resources
before retrying.

The restore-ready record binds the exact restored database containers, their
named volumes, the recovery manifest, and the effective Compose configuration.
`epmctl activate-restored` first captures the prior containers, images, service
configuration and volume bindings on the current Docker daemon. It checks that
only the proxy can publish host listeners. It runs the fixed restore verifier
against the target, authenticating the original backup and checking the
restored migration ledger, service privileges and recovered configuration.
The controller then rechecks the ready record and database identities. A
refusal leaves the prior release serving and the staged target available for
review. After a successful recheck, it stops the prior proxy and mutable
services by container ID while the prior databases and identity remain
available privately. The target carries forward the active workspace listener
when its scope matches the release configuration. It starts internal services against
its original database instances and Compose network. The worker and public
proxy stay stopped while the controller checks internal health and compares
the exact running instances before and after the probe. The worker stage
must retain those instances before the proxy may publish host ports. Run
activation from the Linux host that owns the published HTTPS binding. Once
the proxy starts, the controller checks that binding using the configured
public hostname and release certificate. It verifies unsigned Browser and MCP
responses and the resource metadata for the active MCP listeners. The final
check binds the full service set, pinned images, Compose fingerprints,
container IDs and start times to the activation record.

Save the transcript with the recovery evidence. It reports
`activated_runtime_sha256` after verification and publication. On activation
failure the controller stops the target proxy first, then pauses remaining
target workloads by Docker identity, including target identity service. It
preserves the two verified target databases for retry. The prior release is
restarted only after Docker confirms the target workloads stopped on the
captured daemon. Recovery starts the original containers by ID, verifies
private service health and the platform readiness probe, and then starts the
original worker and proxy when they were previously active. A replaced
container, changed ownership or unconfirmed readiness requires manual
recovery. If target pause cannot be confirmed, use the host maintenance
procedure before bringing either project back into service. A retry rechecks
the target database binding.
For a legacy version-2 ready record, restore the same authenticated bundle
into a fresh project to obtain a bound record.

## Migration failure

- Start `epmctl upgrade` from a serving release. The controller verifies the
  project's platform, application database, control database, and identity
  containers. The controller honors an explicit context or endpoint and pins
  the current Docker context by default. It checks the captured daemon
  identity before Compose operations and during activation. If only the
  databases and identity are running after an earlier attempt, reconcile its
  recorded phase and recovery bundle before retrying.
  A running optional workspace listener is stopped and restarted with its
  original workspace binding. Supply that same `EPM_PG_WORKSPACE_ID` in the
  candidate environment.
- Before stopping services, the controller resolves the candidate Compose
  configuration and checks each service image and platform against the signed
  manifest. If inherited shell variables change the resolved model, use the
  verified release environment file and retry from the serving release.
  The controller fingerprints the resolved model together with the proxy
  route template, Traefik configuration and telemetry collector configuration
  bytes. It verifies the two static bind sources and rechecks the fingerprint
  at each Compose step. A change before route publication preserves the source
  routes. A change during activation stops the candidate. Use the recorded
  upgrade phase to reconcile the installation before restarting services.
- Upgrade preflight verifies that the candidate operations image contains the
  exact final migration named by the signed release manifest. It also verifies
  the full installed migration history before service shutdown. For
  `UPGRADE_MIGRATION_CHAIN_MISMATCH`, capture the release digest and use the
  approved migration package. Check the installation history for missing rows
  or checksum drift. The migration runner verifies the same history again under
  its migration lock before applying the first pending migration.
- The controller repeats preflight after stopping the release's producer
  services, verifies that the application database identity and migration ledger
  are unchanged, and checks that
  only the original database and identity containers remain running. It
  verifies the mounted database storage before backup and again after the
  backup is authenticated, before control bootstrap. If this check refuses
  the upgrade, inspect the existing release and resume it under
  its original configuration to reconcile and drain work before trying again.
  A pending calculation impact requires a drain even when the task list is
  empty. A failed impact needs investigation and recovery before migration.
  One-shot operations run without starting dependencies during upgrade, keeping
  the telemetry collector stopped until the controller restarts services.
- The serving proxy route file stays in place through both preflight checks and
  recovery bundle creation. The controller renders candidate routes only after
  authenticating the source backup and rechecking the stopped source. It stages
  the file under a temporary name, publishes it atomically, and then
  checks the published bytes at each remaining upgrade step. A standalone
  `epmctl backup` also preserves the current routes.
- Save the controller transcript with the maintenance evidence. Before
  migrations, the controller reports `pre_upgrade_backup_bundle`,
  `pre_upgrade_backup_manifest_sha256`, `candidate_release_manifest_sha256`,
  `candidate_effective_compose_sha256`, `source_project`, `source_docker_daemon`,
  `source_runtime_sha256`, `source_database_volumes_sha256`,
  `source_application_database_sha256`,
  `source_schema_version`, `source_migration_chain_sha256`, and
  `candidate_schema_migration`. The database volume fingerprint binds each
  named mount to its Docker volume metadata and the backing directory observed
  inside the database container. This includes the application database's WAL
  archive and base-backup mounts. The backup manifest identifies the archived
  schema and protected configuration. Backup creation uses one set of
  connection parameters for the application database, checks the recorded
  identity before and after its dump, and checks it again before publishing
  the bundle. The controller transcript binds that identity to the resulting
  manifest digest. Before database bootstrap or migration,
  the operations image checks the exact manifest digest returned during backup
  creation, authenticates the manifest, verifies the encrypted payload
  checksums, and matches the archived schema to the stopped source. If backup
  authentication fails, preserve the transcript and inspect the named export
  and recovery key using the original maintenance configuration. Use the exact
  bundle and digest from this transcript when investigating a later failure.
  The migration runner checks the recorded application database identity,
  source version and chain digest under its PostgreSQL advisory lock before
  applying any pending migration. `MIGRATION_SOURCE_DATABASE_CHANGED` means
  the migration connection reached a different PostgreSQL cluster or
  application database. Keep admission closed and check the approved
  configuration and `source_application_database_sha256` in the transcript.
  `MIGRATION_SOURCE_LEDGER_CHANGED` means the database no longer matches the
  source recorded for this upgrade. Keep admission closed and inspect the
  current ledger and the archived backup. Reconcile any committed stages and
  qualify a fresh maintenance attempt against the new source.
  Before restarting services, the controller verifies that the same
  application database contains the complete target ledger and reports
  `installed_schema_version` and `installed_migration_chain_sha256`.
- After migration, the controller stages internal services while keeping the
  worker and public proxy stopped. Only the proxy may publish host ports. The
  controller verifies the candidate image IDs, Compose service fingerprints and
  source database volume fingerprint before and after the internal liveness,
  readiness and unsigned-access checks. It starts the worker, verifies it on
  the same internal runtime, then opens the proxy. The controller checks the
  published HTTPS binding using the same Browser and MCP checks as restored
  activation. It verifies the running proxy's read-only route directory mount
  and rechecks the exact rendered route bytes after the public probe. The
  activated runtime fingerprint binds those bytes and the verified instances
  before recording
  `installed_runtime_sha256` and `upgrade=complete`.
- If activation fails after internal startup begins, the controller pauses the
  candidate using the captured project scope and Docker daemon. It stops the
  proxy first, then the remaining workloads using their local container IDs. The
  controller checks that they actually stopped. Inspect `epmctl status
  --diagnose`, the recorded migration ledger, and the exact pre-upgrade backup
  before recovery. The database schema may already have advanced even though
  the cutover failed. A diagnostic that the candidate could not be confirmed
  stopped calls for manual recovery under the host maintenance procedure. If
  Docker's daemon identity changed, use the transcript to identify the original
  maintenance target before taking a recovery action.
- Keep incompatible application admission closed. Capture the migration ID,
  immutable checksum, schema fingerprint, role, timeout class, and exact
  transactional outcome.
- `UPGRADE_DEFINITION_OWNER_0366_REQUIRES_REVIEW` means read-only preflight
  found a stored rule that pending migration 0366 cannot classify. If the first
  preflight reports it, the source release is still serving. If it appears
  after quiescence, use the original release configuration and the recovery
  procedure above. `DEFINITION_OWNER_0366_UNKNOWN_RULE_KIND` is the refusal
  from the migration itself. Preserve the source application and review the
  affected definitions before retrying. A saved ordered sequence can require
  re-authoring under the current ApplicationRule contract. Keep the original
  definition, consumer references, authorizations, and execution evidence
  available for that review. Give the application owner the refusal code and
  source schema version. The owner can inspect definitions under their existing
  application access. The host transcript carries the operational blocker.
- Pending migration 0368 also checks producer identity before services stop.
  `UPGRADE_PRODUCER_0368_AMBIGUOUS_CHILD` identifies a stored execution linked
  to multiple workflows. `UPGRADE_PRODUCER_0368_CURRENT_HEAD_JOB_UNPROVEN`
  identifies a current calculation result whose published job or provenance
  cannot be confirmed. Preserve the affected results, work and receipts for
  owner review. `UPGRADE_PRODUCER_0368_ACTIVE_LEGACY_WORK` requires settling
  the remaining work through the supported workflow before retrying.
- Do not edit an applied migration or manually repair shared schema. Correct
  the migration/orchestration, prove fresh-build and supported-upgrade
  equivalence on disposable infrastructure, then retry under maintenance
  admission.

## Disk pressure

- Determine whether pressure is PostgreSQL data/WAL, bounded temporary space,
  container logs, build cache, or expired qualification material.
- Stop new expensive technical work before exhaustion. Clean only owned,
  reproducible artifacts according to lifecycle policy. Never delete active
  database volumes, source, required secrets, or unexported evidence.
- PostgreSQL or backup corruption risk requires recovery verification before
  reopening writes.

## Recovery failure

- Keep the target isolated and the source unchanged. Record the failed phase,
  bundle and manifest digests, service UID, capacity preflight, roles, schema,
  and cleanup result.
- Never activate a partially verified target. Remove the disposable target and
  owned staging material after evidence capture, correct the root cause, and
  restart from a clean target.

## Signing key unavailable

- Stop release installation and signed-publication admission. Verify mounted
  trust material is regular, non-symbolic, readable only by its service, and
  independently provisioned.
- Do not accept a key supplied only by the candidate bundle. Restore the
  approved key through the operator trust channel and reverify the exact
  detached manifest signature before executing release code.

## Certificate renewal

Renewal is an explicit bounded maintenance operation; replacing mounted files
alone is not a supported reload. Prepare a root-owned `0700` staging directory
containing root-owned, non-symbolic `0400` or `0440` files named `tls.crt`,
`tls.key`, `keycloak_internal_tls_certificate`,
`keycloak_internal_tls_private_key`, and
`keycloak_internal_ca_certificate`. The public certificate must identify the
configured application and identity hosts (and the Hub host in managed mode).
The internal certificate must identify `identity`, match its private key, and
verify under the staged internal CA.

Run `epmctl renew-certificates --staging-dir /absolute/protected/path` during a
declared maintenance window. The controller rejects malformed, mismatched,
untrusted, incorrectly named, or soon-expiring material before downtime. It
also refuses renewal while external Python or notebook sandboxes are active.
After validation it preserves the current set on the encrypted TLS volume,
stops the release, promotes all five files, restarts the fixed long-lived
inventory, and proves platform readiness including signing-key access. If
promotion or readiness fails, it restores the prior set and restarts the prior
release. A success result includes `release_health=verified` and confirms that
rollback material was removed.

After success, independently exercise the native Chrome login and MCP token
flow, record the presented public and internal certificate fingerprints and
expiry, and verify no retired certificate is still served. The source-level
controller tests do not replace this final-artifact renewal exercise on each
supported architecture.

## Closure

An incident closes only after the triggering signal is healthy, exact business
outcomes are reconciled, authorization remains correct, cleanup is verified,
and a regression or qualification case preserves the learned failure mode.
