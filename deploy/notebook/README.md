# Managed notebook compatibility foundation

This directory is a source-pinned, fail-closed build and managed-deployment
foundation, not a release-qualified Jupyter service. Jupyter Server 2.21.1 is pinned to its official source archive
and target-file hashes. The maintained context patch has been applied and its
post-patch hash recorded. `verify_jupyter_patch.py` rejects another archive,
changed target, fuzzy patch, unsafe archive layout or unexpected output.

The direct requirement inputs pin official wheels. The checked-in transitive
locks pin and hash every resolved distribution and include compatible Linux
AMD64 and ARM64 wheel hashes. The Dockerfiles consume only those locks and
fetch each reviewed source archive with an inline SHA-256 checksum.
The notebook trust and Hub PostgreSQL-only adaptations are also source-pinned
and patch-verified. The initial Hub wheel audit found fourteen references across
live compatibility code, migrations and packaged tests; the patch removes live
fallbacks, enforces PostgreSQL state, and the image recipe removes upstream test
fixtures before the final scan.

Initial 28 October 2026 ARM64 attempts correctly failed the absolute retirement
gate. Later reviewed adaptations removed those executable and metadata paths.
The recorded ARM64 notebook-user image passed complete-filesystem retirement,
Lab/server/kernel execute-save-reopen smoke, disabled persistent history and
memory-only trust behavior. The recorded ARM64 Hub image passed retirement and
fresh/repeated PostgreSQL initialization. Exact artifact identities and source
transform evidence are in `upstream-evidence.json`. These are local development
artifacts, not final release images or amd64/multi-architecture qualification.

The builder Dockerfile now compiles checksum-pinned CPython 3.14.9 with the
retired extension, generated module inventory, ensurepip and test modules
absent. It copies only the public `openepm` SDK, not trusted core modules. The
28 October ARM64 development image passed the unchanged complete-filesystem
scanner (4,970 files, zero findings), runtime module/native-library probes and
an SDK import smoke. Its local image identity is
`sha256:a35b7c91047b4c47316ab1617c6c8762f9613fb8abc00806a05f5e3467096b04`
(64,705,138 bytes). This is stated-scope development evidence, not a signed or
multi-architecture release qualification.

The target profile has four non-negotiable properties:

- Hub state uses a separate PostgreSQL control database and role with no EPM
  business-table privilege.
- Notebook session bookkeeping is bounded process memory with no persistent
  fallback. Restart loses bookkeeping and authenticated reconciliation owns
  cleanup.
- Persistent IPython command history is disabled by administrator-owned config.
- Notebook trust uses a process-memory signature store; after restart, unknown
  rich output is untrusted until the user explicitly trusts or reruns it.

Managed kernels have no database network or database credentials. In managed
mode, the public Open EPM and identity hostnames resolve on the protected
notebook network only to the existing TLS proxy. The private SDK's
`OidcDeviceTokenProvider` uses the native `openepm-mcp` public client to show a
short-lived browser verification prompt, keeps access and refresh tokens only
in kernel memory, refreshes through the same public identity boundary, and is
passed directly to `HttpsMcpTransport`. Closing the provider or terminating the
kernel forgets its credentials. The flow does not distribute Hub, Keycloak
administrator, browser-session, or database credentials to kernels.

```python
from openepm import HttpsMcpTransport, OidcDeviceTokenProvider

identity = OidcDeviceTokenProvider(
    "https://identity.example.invalid/realms/openepm")
prompt = identity.begin()
print(prompt.verification_uri_complete or prompt.verification_uri,
      prompt.user_code)
identity.await_token()  # complete the native login in the displayed browser URL
transport = HttpsMcpTransport("https://epm.example.invalid/mcp", identity)
# Pass transport to EpmClient; call identity.revoke() for explicit logout.
```

Every Hub, notebook-user and builder image must execute the retirement verifier
against its complete final filesystem and current interpreter. The verifier
rejects named artifacts, imports, native libraries, package metadata,
configuration URLs, and memory-backed use of the retired engine.

Operational acceptance remains open: rebuild and rescan the current integrated
Hub/runtime sources, qualify dynamic per-user spawning, browser-origin and
WebSocket isolation, Linux runsc enforcement, two-user token/file/kernel
isolation, mode-aware independent recovery, amd64 artifacts and the exact final
release images.
