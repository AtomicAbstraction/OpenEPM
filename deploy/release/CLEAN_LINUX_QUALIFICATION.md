# Clean-Linux release qualification

This runbook prepares and executes the fail-closed qualification bundle. It
does not turn a candidate release into a qualified release merely by building
the bundle. A passing evidence file must bind the same final manifest, source
commit, schema, image digests and resolved release policy on each advertised
native architecture.

## Required host state

- Ubuntu 24.04 on native AMD64 or ARM64, as selected by the plan.
- Docker Engine with gVisor `runsc` registered.
- The exact release installed in managed-notebook mode through `epmctl`.
- Public HTTPS for MCP, the inspector, OIDC and JupyterHub.
- The trusted sandbox and notebook launcher services active.
- Two dedicated qualification identities with no existing notebook servers.
- Protected token, attestation and backup paths on encrypted storage.
- An operator-provisioned release public key and SDK public key obtained
  independently of the release bundle, plus the detached signature over the
  exact `release-manifest.json` bytes.

Do not run this procedure on a shared user identity or an environment whose
notebook server may contain user work. The idle-stop phase deliberately starts
and removes the dedicated qualification user's server.

## Prepare the notebook qualification identity

1. Create a dedicated identity in the selected OIDC provider and grant only
   the access required for the qualification deployment.
2. Log in to JupyterHub once. Record the resulting Hub username. It must match
   `u-` followed by 32 lowercase hexadecimal characters.
3. Prepare one bounded Hub-administration token used only to inspect, start and
   stop the two qualification servers. Prepare a distinct single-user API token
   for each user's Contents API. The second user's token is deliberately used
   against the restored first user's route to prove denial.
4. Store each token value in a separate root/operator-owned regular file, set mode
   `0600`, and place it outside the qualification bundle. Never put it in the
   context JSON, shell history, source archive or evidence output.

Configure `EPM_RELEASE_TRUST_ROOT_FILE`, `EPM_SDK_TRUST_ROOT_FILE`, and
`EPM_RELEASE_MANIFEST_SIGNATURE_FILE` as absolute paths to regular,
non-symbolic, operator-controlled files. The public keys must be provisioned
from the approved publisher trust channel, not copied from the candidate
bundle. `epmctl` mounts these files read-only into the operations verifier;
installation fails before service startup when a key is missing, the manifest
signature is invalid, or the bundled SDK key differs from its independent
trust root.
5. Confirm that the installed launcher profile is a root-controlled regular
   file and that its immutable notebook image reference ends in the exact
   notebook digest from the qualification plan.

Revoke the temporary Hub token and securely remove its host file after both
architecture runs and evidence transfer are complete.

## Build the non-secret context

Run `scripts/build_openepm_clean_linux_context.py` with every required option.
Set `--browser-identity-secrets-directory` to the absolute installed release
secrets directory containing protected `keycloak_admin_username` and
`keycloak_admin_password` files. The browser probe uses them only to create
and delete its run-owned native identity; it does not accept a browser bearer
token and never records credential contents.
The notebook-specific options are:

```text
--notebook-hub-api-endpoint https://<notebook-host>/hub/api
--notebook-hub-api-token-file /run/openepm/qualification/hub-api-token
--notebook-qualification-username u-<32-lowercase-hex>
--notebook-isolation-username u-<different-32-lowercase-hex>
--notebook-restored-user-api-token-file /run/openepm/qualification/restored-user-token
--notebook-isolation-user-api-token-file /run/openepm/qualification/isolation-user-token
--notebook-restored-server-api-endpoint https://u-<first-key>.<notebook-host>/user/u-<first-key>/api
--notebook-launcher-profile-file /etc/openepm/notebook-profile.json
```

The context records paths, endpoints and identities—not secret contents. The
builder and bundle assembler reject a non-HTTPS Hub endpoint, a username of a
different shape, relative/symbolic host paths and an unexpected launcher
journal unit.

## Idle-stop evidence behavior

The `managed-notebook-idle-stop` phase:

1. Refuses to continue if the dedicated user already has a server.
2. Starts the server through the real JupyterHub API.
3. Requires the planned-image container to be live under `runsc`.
4. Observes it still live after startup settlement.
5. Sends no activity for the installed 300–3,600 second idle interval.
6. Requires the container to be absent after the interval and reaper grace.
7. Requires exactly one matching canonical event from
   `openepm-notebook-launcher.service`.
8. Attempts Hub cleanup after every successful start, including failures.

Container disappearance without the matching journal event fails. A journal
event without a previously live runsc container also fails.

## Independent restore activation and notebook recovery

The independent-host restore phase first restores and verifies a fresh target
project while the source release remains active. It then invokes
`epmctl activate-restored` for that exact bundle and target. Activation refuses
stale evidence, unexpected target services, active Python builders or active
managed notebooks; it stops the source only after those checks and restarts the
source if target startup, health checking or activation-marker publication
fails.

The immediately following `managed-notebook-restored-content` phase requires
the activated marker and binds the live target Hub and proxy to the restored
Compose project, exact release images, protected internal notebook network and
public notebook origin. It starts both dedicated users through the target Hub,
reads the source-attested notebook from the production bind mount, proves the
second user's token is denied, and removes both servers before passing.

## Execute and retain evidence

Use the bundle's generated runner configuration. Execution is enabled only
when both `--run` is supplied and `EPM_CLEAN_LINUX_RUN` has the exact value
`EXTERNAL_HOST_EXECUTION_AUTHORIZED`. Keep the output file, bundle index,
release manifest, resolved policy, host identity and all referenced digests
together. Do not edit evidence JSON after execution.

Repeat the full plan independently on native AMD64 and ARM64. Do not use
emulation as architecture evidence. P23, P26 and P27 remain open until both
runs, independent recovery and the other release gates pass against the same
frozen release identities.

## Enterprise release-gate evidence

A completed architecture run is necessary but does not by itself set an
enterprise release gate. Each gate asserted in
`docs/enterprise-readiness-acceptance-register.json` must reference an
immutable JSON evidence file under `docs/qualifications` by exact SHA-256. The
evidence must assert its exact gate and include a `qualificationBinding` with:

- the candidate, source-tree, migration-chain, schema-fingerprint and resolved
  configuration-profile digests;
- the complete named image-digest inventory used by that gate;
- the native architecture or architectures actually executed;
- a non-secret host fingerprint, execution timestamp and non-empty exact
  scenario inventory.

All passed gates must name the same candidate, source tree, migration chain,
schema fingerprint and resolved configuration. The AMD64 and ARM64 gates must
include their respective native architecture. `scripts/check_enterprise_readiness.py`
rejects missing fields, substituted artifacts, digest changes, architecture
mismatches, self-asserted pass files without this binding, and evidence from a
different candidate. Keep gate evidence false/null until the executed
qualification result has been independently converted and reviewed; never
hand-edit a pass assertion merely because a lower-level runner succeeded.
