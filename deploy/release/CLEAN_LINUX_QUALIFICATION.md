# Headless runtime and clean-Linux release qualification

Local implementation, isolated qualification and an owner-authorized local
cutover can proceed while external distribution is deferred (owner inputs
574–575). A local candidate is not a signed, qualified multi-architecture
release. Keep those evidence boundaries explicit.

The product ships a browser editor and a credential-free headless Python
builder. The fixed core, durable worker, capability broker, PostgreSQL, bundled
identity, proxy and browser gateway remain required. The workspace listener is
packaged as an optional profile and is enabled only after a workspace is
configured. Use `release-inventory.json` v2 to resolve packaged versus enabled
services; never treat that optional listener as a retired service.

## Freeze and build a private candidate

Freeze one clean tracked source revision, including new migrations, the
browser build helpers and the relocated `deploy/python-build` inputs. Preserve
the working checkout separately if it contains unrelated work. Never relax the
source archive's clean/tracked/COPY-source checks to package a dirty snapshot.
Run the following from that frozen checkout, with a new output directory outside
it. These commands create local artifacts and do not push to a registry:

```sh
release_revision=$(git rev-parse HEAD)
release_tree=$(git rev-parse 'HEAD^{tree}')
release_epoch=$(git show -s --format=%ct HEAD)
release_name=product-refinement-candidate
release_output=/absolute/private/candidate
python3 scripts/prepare_openepm_release_candidate.py \
  --release "$release_name" --source-date-epoch "$release_epoch" \
  --output-directory "$release_output"
python3 scripts/build_openepm_sandbox_launcher.py \
  --root "$PWD" --output "$release_output/openepm-sandbox-launcher.pyz"

# Execute on the intended native build architecture. A cross-build is not
# native execution evidence. Set release_arch to linux/arm64 or linux/amd64.
docker buildx build --platform "$release_arch" --load \
  --build-arg SOURCE_COMMIT="$release_revision" \
  --build-arg SOURCE_TREE="$release_tree" \
  -f deploy/postgres/Dockerfile -t "openepm-core:$release_name" .
docker buildx build --platform "$release_arch" --load \
  -f deploy/postgres/Dockerfile.db -t "openepm-database:$release_name" .
docker buildx build --platform "$release_arch" --load \
  -f deploy/python-build/Dockerfile.builder -t "openepm-builder:$release_name" .
docker buildx build --platform "$release_arch" --load \
  -f deploy/operations/Dockerfile -t "openepm-operations:$release_name" .
docker buildx build --platform "$release_arch" --load \
  --build-arg KEYCLOAK_BASE_IMAGE="$qualified_keycloak_base" \
  -f deploy/identity/Dockerfile -t "openepm-identity:$release_name" .
docker buildx build --platform "$release_arch" --load \
  -f deploy/proxy/Dockerfile -t "openepm-proxy:$release_name" .
```

`qualified_keycloak_base` must be an independently verified immutable
`repository@sha256:...` reference, never a floating tag. Record each resulting
image identity and the three upstream runtime images (browser gateway, browser
session store and telemetry collector). The final v3 manifest requires all nine
roles. Local image IDs are useful candidate identities; do not misrepresent them
as registry publication or multi-architecture manifest digests.

The application image runs `npm ci` against `web-ui/package-lock.json` and builds
its browser assets. Its `third-party-notices.txt` and
`third-party-license-evidence.json` bind the exact installed runtime dependency
license texts, versions, lock integrity values and text hashes. These assets are
copied into the shipped browser distribution; they assert no legal approval.

## Local headless qualification before cutover

The 2026-11-08 local preparation created a separate native ARM64 Colima VZ VM,
profile `epm-refinement`, with 4 CPUs, 8 GiB RAM and a 32 GiB data disk. Its
Ubuntu 24.04.4 guest has no host directory mounts, SSH agent forwarding or
Rosetta emulation. The default Colima daemon and Docker context remain active
and unchanged. Select this qualification daemon explicitly in every command:

```sh
export COLIMA_HOME=/private/tmp/epm-q1108/colima
export LIMA_HOME=/private/tmp/epm-q1108/lima
export DOCKER_CONFIG=/private/tmp/epm-q1108/docker
export DOCKER_HOST=unix:///private/tmp/epm-q1108/colima/epm-refinement/docker.sock
docker info --format '{{.Architecture}} {{.ServerVersion}}'
colima --profile epm-refinement ssh -- runsc --version
```

The isolated Docker configuration uses the existing global Homebrew Buildx and
Compose plugins. It contains no registry credentials. Build contexts must be
sent through Docker; a guest path cannot refer to a host checkout because no
host directory is mounted. Files needed by the host launcher must be copied
explicitly through the VM's SSH connection into protected guest paths.

The official signed gVisor APT repository supplied ARM64 package
`20261102.0`; the package includes its required sidecar binaries. Installation
follows the [upstream instructions](https://gvisor.dev/docs/user_guide/install/).
The restricted `hello-world` check passed under runsc as UID 10001 with no
network, a read-only root, no capabilities and no-new-privileges. Its container
and image were removed. This establishes host availability only; current target
images and the public source/build/run flow still require qualification. Exact
version, hashes and boundaries are recorded in
`docs/qualifications/product-refinement-arm64-runsc-host-2026-11-08.json`.

Retain this VM only while the current candidate qualification needs it. After
the acceptance evidence and candidate handoff are complete, remove this exact
profile with the same isolated environment using
`colima --profile epm-refinement delete --force --data`, verify it has no running VM,
and remove `/private/tmp/epm-q1108`. Do not run deletion with the default
environment or retain its databases as build-phase rollback snapshots.

Use a dedicated disposable Linux VM or host. Do not replace the Docker daemon
configuration of a shared active runtime to run a test. The retained daemon
configuration at `deploy/macos-pilot/docker-daemon-runsc.json` registers
`/usr/bin/runsc`; provision the reviewed gVisor package and verify its publisher,
version and architecture on the disposable host. Confirm both `runsc --version`
and Docker runtime registration before starting any candidate sandbox.

Build the launcher from the frozen source above. Its installed contract is:

- `deploy/release/install-sandbox-launcher` installs the root-controlled host
  service; the launcher is outside application containers.
- `deploy/release/host/openepm-sandbox-launcher.service` and
  `sandbox-launcher.env.example` define the service and protected configuration.
- The control socket is `/run/openepm-sandbox/sandbox-launcher.sock`.
- Profiles and the control key are protected files under `/etc/openepm/secrets`.
- The internal broker endpoint is
  `http://172.30.252.2:5198/internal/python-build/read` in the supplied network
  profile. It is not an external API or a source of database credentials.
- Application containers receive the narrowly scoped launcher socket, never the
  Docker socket. The headless builder receives no core modules, database DSN,
  workspace source mount or arbitrary network authority.

A quick native smoke check may run the exact local builder image with these
same restrictions:

```sh
docker run --rm --runtime runsc --network none --read-only \
  --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 128 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
  --entrypoint python "$builder_image" -I -c \
  'import os,openepm; assert os.getuid() == 10001; print("headless SDK import passed")'
```

This smoke check is not the isolation or public workflow certificate. The real
`runsc-headless-python` phase also proves read-only root, writable temporary
storage, blocked networking and the expected failing negative probe.

For the complete public workflow, provision a **new isolated qualification
application** through authorized workspace/application APIs, with all eight
required axes and application-global unique member IDs: `Account-Qualification`,
`Entity-Qualification`, `Year-Qualification`, `Period-Qualification`,
`View-Qualification`, `Value-Qualification` and `DataType-Qualification` in
their matching dimensions; `Plan` in Scenario. Start with no fact at that exact
coordinate. Register only the deployment-approved environment
for the exact target builder image. The dedicated execution identity must have
the current source-design/publication and execution-delegation permissions.

The immutable source is
`deploy/release/qualification/python_publication_program.py`. The public probe
saves it, waits for automatic Validation, activates that exact validation build,
builds a fresh delegated Plan, reads its sealed artifacts and isolation
observation, executes it, verifies receipt/result readback, verifies replay and
checks denied execution authority. It never uses a database client:

```sh
python3 scripts/openepm_python_build_publication_probe.py \
  --config "$publication_probe_config" --token-file "$protected_token_file" \
  --source-file deploy/release/qualification/python_publication_program.py
```

The configuration must be `openepm-python-build-publication-probe-v3`, bind the
exact source SHA-256 and builder image, and use the full eight-axis coordinate
for the result read. Keep credentials in protected files, not configuration
JSON, shell arguments containing token values or evidence. Retain real launcher
attestations for the exact Plan build; a trusted in-process test launcher cannot
replace gVisor execution evidence.

`tests/qualify_release_backup_restore.py` requires the three current image inputs
(`EPM_RELEASE_RESTORE_DATABASE_IMAGE`, `EPM_RELEASE_RESTORE_OPERATIONS_IMAGE`,
optionally `EPM_RELEASE_RESTORE_APPLICATION_IMAGE`) and
`EPM_RELEASE_RESTORE_DISPOSABLE=1`. It owns its containers, private network,
volumes and a separately named disposable database. Its eight-axis population
uses real automatic Validation before activation. Its source-runtime fixture is
explicitly a fixed-core test and is not runsc proof. Use the packaged application
initializer by supplying the exact current application image for release
qualification. The helper alone is qualified by
`tests.test_release_restore_source_fixture_postgres`.

## Distribution evidence and signing

The source-only compliance generator covers pinned Python dependencies, not
base operating systems or browser bundles. Acquire and verify exact locked
wheel evidence for both architectures without installing it:

```sh
python3 scripts/acquire_openepm_license_artifacts.py plan \
  --acquisition-root "$wheel_evidence_root" --plan "$acquisition_plan"
python3 scripts/acquire_openepm_license_artifacts.py execute \
  --acquisition-root "$wheel_evidence_root" --plan "$acquisition_plan"
python3 scripts/acquire_openepm_license_artifacts.py verify \
  --acquisition-root "$wheel_evidence_root" --plan "$acquisition_plan" \
  --output "$wheel_evidence_manifest"
```

Regenerate source SPDX/notices and complete per-image SPDX/notices from the
frozen target, including the retained builder and browser assets. Never reuse
removed dependency inventories as current evidence. The retained decision packet
records unresolved certifi and cffi file-scope interpretations with extracted
text/hashes; formal distribution requires the external reviewer attestation
fields, not another owner selection of the product license. Already recorded
private SDK/version/registry/signing choices remain authoritative. Missing
external publication bindings do not stop local implementation or qualification.

The signed SDK is built with `scripts/build_openepm_sdk_release.py`; use
independently provisioned signing/trust paths. Assemble the final materials with
`scripts/assemble_openepm_release_candidate.py` only after their exact source,
image, SDK, configuration, compliance and qualification bindings are complete.
Source-only SPDX/notices cannot substitute for full image coverage.

## Formal clean-host execution

The formal runner requires clean **Ubuntu 24.04 on native AMD64 and native
ARM64**, each independently tested against the same frozen release. Emulation,
a macOS host, an existing development VM, or a local ARM64 smoke run does not
satisfy both architecture gates. Sustained capacity is a separate gate: retain
300 concurrent sessions, the existing 30-minute workload/window requirements,
eight mixed workloads, at least three applications and the specified host
resources. Do not claim that capacity from a small development VM.

The `sustained300Sessions` gate binds a separate `measurementEvidence` record
through its local artifact path, SHA-256 digest and format
`openepm-sustained-session-measurement-v1`. The record carries `passed: true`,
the exact `qualificationBinding` from the gate and the reviewer's recorded
`approval` with `accepted: true` and their identity in `reviewer`.

Record the post-warm-up UTC `startedAt` and `finishedAt` under `observation`.
Use `minimumConcurrentSessions` for the lowest measured concurrent count during
that window. Include the exact scoped `applications` examined with `workspaceId`
and `applicationId`, and every measured workload under `workloads` with its
bound `scenarioId` and positive `completedOperations` count. The recorded review
checks the workload mix, host resources and measured outcome against the
approved profile. `check_enterprise_readiness.py --scope enterprise` checks the
candidate binding, the measured minimum, the time window and the coverage.

Provide public HTTPS for MCP, the browser and bundled OIDC; the private CA mounts
for platform/workspace/router/web/proxy must remain configured. Prepare separate
protected MCP/build tokens, the browser identity secret directory, an independent
backup export root and the source backup attestation/key. Configure independent
`EPM_SIGNING_OFFLINE_ROOT_FILE`, `EPM_SIGNING_TRUST_POLICY_FILE`,
`EPM_SIGNING_TRUST_POLICY_SIGNATURE_FILE` and
`EPM_RELEASE_MANIFEST_SIGNATURE_FILE` paths. The offline root and the minimum
accepted trust-policy sequence must come from the approved trust channel, not
from the candidate they verify. The controller persists the highest
authenticated sequence and rejects rollback on subsequent operations.

Generate a v2 execution-required plan for each architecture, then the headless
and publication profiles and non-secret context:

```sh
python3 scripts/qualify_openepm_clean_linux_release.py \
  --final-manifest "$final_manifest" --architecture "$release_arch" \
  --output "$qualification_plan"
python3 scripts/build_openepm_clean_linux_profiles.py \
  --plan "$qualification_plan" --publication-contract "$publication_contract" \
  --output-directory "$runtime_profiles"
python3 scripts/build_openepm_clean_linux_context.py \
  --plan "$qualification_plan" --output "$qualification_context" \
  --mcp-endpoint "$mcp_endpoint" --mcp-token-file "$mcp_token_file" \
  --python-build-token-file "$python_build_token_file" \
  --browser-identity-secrets-directory "$identity_secrets_directory" \
  --source-backup-attestation "$source_backup_attestation" \
  --source-attestation-key-file "$source_attestation_key_file" \
  --backup-export-root "$backup_export_root" \
  --backup-maximum-bytes "$backup_maximum_bytes" \
  --minimum-trust-policy-sequence "$minimum_trust_policy_sequence"
```

Use `scripts/assemble_openepm_clean_linux_bundle.py` to bind that plan/context,
final manifest, browser probe configuration, generated
`python-build-publication-probe.json` and `headless-runsc-profile.json`, populated
and restored verifiers, the exact authenticated MCP request, immutable release
environment, manifest signature, release inventory, independently distributed
offline-root public key, root-signed trust policy and its signature. The
assembler also includes the host bootstrap verifier, the operations runbook,
both release Compose definitions, and the proxy and telemetry configuration.
The bundle manifest records the three configuration files under
`release-assets/`. The controller resolves those files inside the bundle
before verifying images or starting services. It creates
`qualification-runner-config.json` and a digest-bound bundle index. The runner
also includes the transitive, digest-verified artifact closure referenced by the
final manifest and its JSON evidence (including nested SDK and legal-review
artifacts). It rejects traversal, symlinks, collisions, missing content and
digest mismatches instead of copying unrelated files from the assembly
directory. The runner
executes only the fourteen exact current phases: host attestation, bundle
integrity, doctor/install, authenticated MCP/browser, headless isolation, Python
build/publication, database version, restart, populated backup, independent-host
restore, storage retirement and native architecture proof.

Before doctor or install, the runner checks the target's Ubuntu version,
native architecture, runsc registration and clean-host attestation. It
authenticates the transferred source attestation and rejects a target whose
machine identity matches the source. This preflight reads the attestation and
key. The populated-backup phase verifies the encrypted payloads and must
report the same source host before restore can start. The runner also resolves
the bundled service inventory and checks its digest against the release
manifest and the qualification plan.
The controller uses the bundle’s manifest, signature, inventory, Compose
files and release environment for all of its phases. The certificate records
the measured inventory as `releaseInventorySha256` and binds the full
resolved inventory through the evidence digest.

After `epmctl install` and on both sides of `epmctl stop` followed by `epmctl up`,
the runner collects `epmctl status --json` from the configured project. Each
observation must bind the same release manifest and base service inventory
used by the plan. The launcher must be active, and every expected service
must have exactly one running, ready container inspected against its signed
image for this host architecture. Optional profiles, unclassified containers
and an unverified image fail the base qualification. The restart must retain
the installed project, Docker daemon, service identities, Compose fingerprints,
and application and control database volume generations. The running generation
must change across the restart and remain stable through the authenticated MCP
readback. The runner and offline verifier check the three observations in
`restartContinuity`. Earlier output that lacks these observations requires a
new host run.

The initial MCP check runs before the browser provisions an application. The
bundle request uses the public session-identity read, which works on a fresh
installation and returns the server-verified caller. Supply this request as
`mcp-request.json` and keep the access token in the protected host file.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {"name": "read_v2_session_identity", "arguments": {}}
}
```

Both probes require unsigned refusal and the authenticated identity object,
from structured content or the tool's single JSON text item.
The runner records a digest binding the endpoint and request, plus a digest
of the returned identity. A change after restart stops the run before
populated backup and restore. The publication and restored readback phases
separately verify the application operations and exact saved values.

```sh
EPM_CLEAN_LINUX_RUN=EXTERNAL_HOST_EXECUTION_AUTHORIZED \
  python3 scripts/run_openepm_clean_linux_qualification.py \
  --plan "$qualification_plan" --config "$runner_config" \
  --output "$executed_evidence" --run
python3 scripts/qualify_openepm_clean_linux_release.py \
  --final-manifest "$final_manifest" --architecture "$release_arch" \
  --evidence "$executed_evidence" --output "$verified_evidence"
```

Independent restore verifies an empty owned target while the source remains
active. The bundle-bound restored population verifier runs with
`--target-project` before activation. After `epmctl activate-restored` returns,
the runner supplies the same target and `--serving-runtime-sha256` to the
verifier. Both calls check the stored population against the source attestation.
The second also checks the served application through the rendered Browser and
the public MCP endpoint.

On the source host, read the same qualification fixture through both public
entry points before backup. Normalize the exact values, issuer and subject,
workspace and application, and the selected business object into one JSON
projection. Use UTF-8, sorted keys and compact separators for its SHA-256.
Keep decimals as exact strings. Both clients must produce the same projection.
Pass that digest to `create_openepm_source_backup_attestation.py` as
`--public-read-signature` alongside `--population-signature`. The v4 attestation
authenticates both digests and the encrypted transfer together.

In serving mode, the verifier returns its usual `status`, `populated` and
`signature` fields plus `publicReadback`. That record contains `targetProject`,
`activatedRuntimeSha256`, `browser` and `mcp`. For each client, perform an
authenticated read of the restored fixture and an unauthenticated refusal
check. Report `authenticated`, `unsignedDenied`, the normalized `signature`
and the exact `responseSha256`. Use the restored actor’s protected credentials.
Keep credentials and raw responses out of the qualification certificate. The
runner requires both normalized digests to match the attested source digest.

For a populated saved-view fixture, use the bundled `browser-probe` in
read-only mode on both the source and the activated target.

```sh
./browser-probe --config browser-probe.json \
  --identity-secrets-directory "$restore_actor_credentials" \
  --saved-view-readback "$saved_view_probe_config"
```

The saved-view config contains `workspaceId`, `applicationId`, `viewId` and
the public HTTPS `mcpEndpoint`. The protected credential directory contains
`restore_username`, `restore_password` and `restore_mcp_token` for the same
application actor. Playwright needs the host's trusted Browser certificate
chain. The public Python SDK uses the host trust store or the CA supplied with
`--mcp-ca-file`. The probe captures the same view through the rendered session
and typed MCP reads. It returns the `browser` and `mcp` records for the verifier
without recording credentials, identity bindings or cell contents. Use the
common `signature` as the source digest and include both records in the
target's serving evidence. The response digests cover the complete decoded
saved-view and data-read results for each client.

The runner passes the attested backup manifest digest to `epmctl` for both
restore and activation. Import verifies the manifest and the encrypted bytes
it reads. Both controller phases report `backup_manifest_sha256`, and both
reports must match the attested transfer. The certificate records the backup
digest as `restoredBackupManifestSha256`, the serving fingerprint as
`activatedRestoreRuntimeSha256`, and the public projection digest as
`restoredPublicReadSignature`.

`epmctl activate-restored` rejects stale evidence, unexpected services and
active external builders before stopping the source, and restores source service
on target startup, health or marker failure. A failed population check after
activation invalidates the qualification and leaves the activated fixture
available for investigation. Never use a historical software/schema snapshot as
a rollback path for this redesign. Stable backup retention starts only after
owner acceptance of the stable sample application.

## Qualifying a packaged schema upgrade

The fourteen-phase installation and restore run and the in-place migration exercise answer different questions. For IP-14-AC-03, use a disposable installation of a supported, signed earlier release with a populated application. Select a signed candidate with a higher migration number. The same-schema software upgrade remains a supported operation. Record the following observations for the forward schema change.

1. Identify both release packages, their independently verified manifest digests, source and tree identities, final migration names, native image digests, and release configurations. Keep credentials in the protected files. Use the actual publisher and trust policy applicable to the run. The source-wheel review and a local signing fixture provide component evidence only.
2. With the earlier release serving, capture its `epmctl status --json`, the fixture's independently computed population signature, and the paired saved-view readback shown above. Record the subject and scope through the probe's digest. Choose a view with at least one stored value and record which retained business facts, roles or historical receipts the population witness covers. For an older group-assigned application, capture its existing delegation rights, including any absent planning-policy delegation rights. Hold business writes on the disposable fixture through the comparison so that a change can be attributed to the upgrade.
3. Use the candidate bundle's `epmctl upgrade` against the **same** serving project, Docker daemon and persistent volumes. Preserve the controller's exit status and transcript. Match `candidate_release_manifest_sha256` and `candidate_schema_migration` to the selected candidate. Preserve the source runtime, application database and volume identities, effective Compose digest, before/after migration versions and chain digests, and the pre-upgrade backup identifier and manifest digest. Verify source and target versions against their respective migration chains. A partial transcript is useful for recovery. Acceptance requires the installed runtime digest and the controller's final completion record. Follow the packaged enterprise runbook's migration-failure procedure for an interrupted run.
4. Capture the candidate's `epmctl status --json`. Run the same population witness and the same saved-view readback with the same actor through browser and MCP. Compare the normalized business signatures to the source, retain the per-client response digests, and verify unsigned requests are denied. Recheck any fixture-specific historical receipt, role and delegation assertions. In a schema-410 group-assigned application, verify schema 411 preserved the original group, role, assignment scope and delegation rights, even when both new policy delegation rights were absent. Exercise the applicable current application contract on the installed release. Retain the server and installed extension versions observed by the `database-version-read` phase.
5. Preserve the verified report, signed identities, controller transcript digests and cleanup result according to the evidence policy. Reconcile the exact disposable containers, databases, volumes, temporary credentials, exports and scratch by run ownership as described below. Record surviving resource IDs and why any retention is required. An independent reviewer compares the source and installed observations, the retained business data and the cleanup outcome before accepting the migration criterion.

### Binding the serving source to its signed release

The earlier release's `epmctl status --json` checks its signed manifest and running images. The candidate controller records the source runtime fingerprint at the start of the upgrade. To connect the observations, bracket the earlier status and business readback with the candidate's read-only project observer. Use the same Docker endpoint, Compose project and workspace ID throughout. Select the earlier bundle's configuration and trust files when invoking its controller. Set `source_bundle` and `candidate_bundle` to the unpacked bundle directories, and `evidence_dir` to a private, empty directory for this run.

```sh
set -eu
observe_source() {
  python3 -B "$candidate_bundle/openepm_release_upgrade.py" \
    --inventory "$candidate_bundle/release-inventory.json" \
    --project "$release_project" --workspace-id "${workspace_id:-}"
}
observe_source > "$evidence_dir/source-before.txt"
"$source_bundle/epmctl" status --json > "$evidence_dir/source-status.json"
"$source_bundle/browser-probe" --config "$source_bundle/browser-probe.json" \
  --identity-secrets-directory "$restore_actor_credentials" \
  --saved-view-readback "$saved_view_probe_config" > "$evidence_dir/source-readback.json"
observe_source > "$evidence_dir/source-after.txt"
cmp "$evidence_dir/source-before.txt" "$evidence_dir/source-after.txt"
```

Verify that the source status reports the intended project, the independently verified source manifest digest, matched images and passing components. Each observer record contains the profile, three persistent container IDs, runtime fingerprint, volume fingerprint and Docker daemon identity, in that order. Match the last three fields to `source_runtime_sha256`, `source_database_volumes_sha256` and `source_docker_daemon` in the candidate's upgrade transcript. A difference means the earlier status or public readback cannot establish the starting state of this migration. Retain the actual mismatching observations and qualify a new, stable disposable run. Use the installed runtime and target checks in step 4 for the other end of the migration.

## Evidence and cleanup

Bind each acceptance gate to the exact candidate/source tree, migration chain,
schema fingerprint, configuration, named image digests, native architecture,
host identity and executed scenarios. Keep gates false until real execution and
review; never hand-edit a pass assertion. `scripts/check_enterprise_readiness.py`
checks those bindings.

After each run remove its stopped containers, disposable databases/roles,
volumes/networks, temporary credentials, build scratch and unused cache/images.
Verify their absence and retain only necessary acceptance evidence and the
current active release. Never remove shared business data, active volumes,
required secrets or unreplaced authored source. Runtime retirement is complete
only after the exact cleanup inventory has been verified.


## Operator component diagnosis

Use the packaged `epmctl status --diagnose` for a readable component report or
`epmctl status --json` for the same bounded `openepm-operator-status-v1` record.
These commands retain the existing signed release/configuration and stored
antirollback-minimum checks, using the existing ephemeral `--rm`, read-only,
network-disabled verification container. Diagnosis does not persist the trust
policy sequence or modify a running service. They read the current declared services and health dependencies from the release
inventory and show launcher failure as an observation, so a failed launcher
does not hide the other component states. The existing plain `status` command
continues to provide its original Compose listing.

The host operator does not need an application business-data grant for this
report. It runs no database query, job, restart, deployment or recovery action.
Container commands, environment values, ports, health-log output and business
payloads are excluded from the projection. Diagnosis checks local image identity
with [Docker image inspection](https://docs.docker.com/reference/cli/docker/image/inspect/)
and [container inspection](https://docs.docker.com/reference/cli/docker/inspect/).
The report exits with code 69 when component checks or image matching are
incomplete and retains the diagnosis details.

Read the component’s purpose, reported container state and dependency
observations together. The report distinguishes missing or stopped components,
failed checks, checks that are starting and containers with no reported health
check. The packaged baseline expects one regular instance per declared service.
An extra replica or a one-off container for a declared service leaves that
service at `unexpected-instances` even when its reported health and image match.
`dependencyObservations` identifies whether each dependency signal comes
from a container or the host launcher. A dependency such as the identity
signing-key endpoint or Python coordinator database role is a check inside a
service. The report marks it `not-observed` and names where to investigate.
Several signals can disagree during an incident, so inspect the named dependency
before drawing a conclusion from a component’s own check.

The launcher diagnosis distinguishes a stopped or failed unit, an active unit
with its configured socket absent, and a result that could not establish the
launcher state. After release verification, the systemd query has a three-second
limit and the Compose listing has an eight-second limit and a one-MiB output cap.
Either observation can fail independently. On Compose failure or unusable
output, `composeObservation` gives the reason and a next action. Container
states are `not-observed`, the unclassified-container count is unknown, and the
report still includes the launcher state and verified release digest. A successful
empty listing reports `missing` components and a zero container count. All these
incomplete reports exit 69. See [systemctl unit states](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

The release-manifest and inventory digests identify the configuration selected
for diagnosis. For each declared service, the report resolves that release's
pinned local image for the host architecture and compares its image ID with
the exact observed container. A healthy worker can report a different image.
A missing pinned image, unavailable inspection or missing container leaves
the image check unconfirmed. Each case has an operator action. The image
comparison uses only local metadata and has a shared inspection time limit.
The report excludes raw image references, image and container IDs, and Docker
diagnostic output. Application and business acceptance are separate checks.

The worker diagnosis uses a recognized health probe from the current container
start. An observation more than 30 seconds old is stale. Its completion time
remains visible and diagnosis withholds readiness until a current probe passes.

Inspect the named dependency and service logs using existing operator tooling.
When an operation may already have been accepted, reconnect through its normal
authorized browser/MCP client and reconcile its original task/receipt before
starting new work. Restarting a worker is not proof that a business operation
failed or that it is safe to repeat it.

The projection deliberately marks application-specific availability, queue
saturation, throughput, business outcomes and recovery objectives as not
measured. Container health checks alone cannot establish those claims. Current
source tests cover absent launcher sockets, unavailable systemd, payload
filtering and standalone packaging. Real Compose fixtures exercise the packaged
reader with running and stopped containers. Installed-release qualification
must bind the actual delivered candidate separately. Compose observation parsing follows
[Docker's documented project status interface](https://docs.docker.com/reference/cli/docker/compose/ps/),
including stopped containers and JSON Lines output.
