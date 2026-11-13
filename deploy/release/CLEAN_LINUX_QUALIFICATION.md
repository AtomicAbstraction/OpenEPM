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
assembler also includes the host bootstrap verifier and the two
release Compose definitions. These are mandatory inputs: a clean host must not
depend on files left behind by an earlier installation. It creates
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
active. `epmctl activate-restored` rejects stale evidence, unexpected services and
active external builders before stopping the source, and restores source service
on target startup/health/marker failure. Never use a historical software/schema
snapshot as a rollback path for this redesign. Stable backup retention starts
only after owner acceptance of the stable sample application.

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
