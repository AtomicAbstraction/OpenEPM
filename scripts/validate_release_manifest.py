"""Fail-closed validation for a frozen Open EPM release manifest.

This module intentionally uses only the Python standard library so the
qualified operations image can validate a bundle before any service starts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import tomllib
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
import sys
from urllib.parse import quote, urlsplit

try:
    from scripts.build_openepm_sdk_release import (
        CHECKSUMS as SDK_CHECKSUMS,
        MANIFEST as SDK_MANIFEST,
        SIGNATURE as SDK_SIGNATURE,
        verify_release as verify_sdk_release,
    )
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from build_openepm_sdk_release import (  # type: ignore[no-redef]
        CHECKSUMS as SDK_CHECKSUMS,
        MANIFEST as SDK_MANIFEST,
        SIGNATURE as SDK_SIGNATURE,
        verify_release as verify_sdk_release,
    )
try:
    from scripts.openepm_release_policy_contract import validate as validate_policy
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from openepm_release_policy_contract import validate as validate_policy  # type: ignore[no-redef]
try:
    from scripts.openepm_signing_trust_policy import (
        TrustPolicyError, eligible_keys, select_key, verify as verify_trust_policy,
    )
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from openepm_signing_trust_policy import (  # type: ignore[no-redef]
        TrustPolicyError, eligible_keys, select_key, verify as verify_trust_policy,
    )
COMPONENTS = (
    "application", "database", "builder", "identity",
    "proxy", "operations", "browser_gateway", "browser_session_store",
    "telemetry_collector",
)
ENV_KEYS = {name: f"EPM_{name.upper()}_IMAGE" for name in COMPONENTS}
ENV_KEYS["telemetry_collector"] = "EPM_OTEL_COLLECTOR_IMAGE"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
MIGRATION = re.compile(r"^[0-9]{4}_[a-z0-9_]+\.sql$")
BROWSER_CONFIG = Path("/run/secrets/browser_gateway_config")
BROWSER_ALPHA = Path("/run/secrets/browser_gateway_alpha_config")
BROWSER_STORE = Path("/run/secrets/browser_session_store_config")
RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
REQUIRED_SCENARIOS = frozenset({
    "fresh-install", "authorization", "metadata", "cell-semantics",
    "calculations", "transfer", "human-workflow", "draft-safety",
    "concurrency", "recovery", "sandbox", "capacity",
    "evidence-integrity",
})


class ManifestError(ValueError):
    pass


def validate_execution_evidence(value, *, architectures, source_commit,
        schema_migration, images, configuration_profile_sha256,
        artifact_loader, json_loader, error_type):
    """Validate checksum-confined evidence from final qualification."""
    fields = {"format", "runId", "sourceCommit", "schemaMigration",
        "migrationChainSha256", "schemaFingerprintSha256",
        "configurationProfileSha256", "images", "hosts", "scenarios",
        "cleanup"}
    if not isinstance(value, dict) or set(value) != fields:
        raise error_type("executed qualification evidence fields are invalid")
    run_id = value.get("runId")
    if (value.get("format") != "openepm-executed-release-evidence-v1"
            or not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id)
            or value.get("sourceCommit") != source_commit
            or value.get("schemaMigration") != schema_migration
            or value.get("images") != images
            or value.get("configurationProfileSha256") !=
                configuration_profile_sha256
            or any(not isinstance(value.get(name), str)
                   or not SHA256.fullmatch(value[name]) for name in (
                       "migrationChainSha256", "schemaFingerprintSha256",
                       "configurationProfileSha256"))):
        raise error_type("executed qualification evidence identity mismatch")
    hosts = value.get("hosts")
    if (not isinstance(hosts, list) or len(hosts) != len(architectures)
            or {item.get("architecture") for item in hosts
                if isinstance(item, dict)} != set(architectures)):
        raise error_type("executed qualification host coverage is incomplete")
    for host in hosts:
        if (set(host) != {"architecture", "hostFingerprintSha256",
                "startedAt", "finishedAt"}
                or not SHA256.fullmatch(host.get("hostFingerprintSha256", ""))
                or not UTC.fullmatch(host.get("startedAt", ""))
                or not UTC.fullmatch(host.get("finishedAt", ""))
                or host["finishedAt"] < host["startedAt"]):
            raise error_type("executed qualification host evidence is invalid")
    scenarios = value.get("scenarios")
    if (not isinstance(scenarios, list)
            or len(scenarios) != len(REQUIRED_SCENARIOS)
            or {item.get("scenarioId") for item in scenarios
                if isinstance(item, dict)} != REQUIRED_SCENARIOS):
        raise error_type("executed qualification scenario coverage is incomplete")
    seen_artifacts = set()
    for scenario in scenarios:
        if (set(scenario) != {"scenarioId", "status", "assertionCount",
                "architectures", "evidence"}
                or scenario.get("status") != "passed"
                or type(scenario.get("assertionCount")) is not int
                or scenario["assertionCount"] < 1
                or scenario.get("architectures") != architectures):
            raise error_type("executed qualification scenario result is invalid")
        path = artifact_loader(scenario["evidence"],
                               "executed scenario evidence")
        identity = scenario["evidence"]["sha256"]
        if identity in seen_artifacts:
            raise error_type("executed qualification evidence is reused")
        seen_artifacts.add(identity)
        detail = json_loader(path, "executed scenario evidence")
        expected = {"format": "openepm-executed-scenario-result-v1",
            "runId": run_id, "scenarioId": scenario["scenarioId"],
            "status": "passed", "assertionCount": scenario["assertionCount"],
            "architectures": architectures, "sourceCommit": source_commit,
            "schemaFingerprintSha256": value["schemaFingerprintSha256"],
            "migrationChainSha256": value["migrationChainSha256"],
            "configurationProfileSha256": configuration_profile_sha256}
        if detail != expected:
            raise error_type("executed scenario evidence content mismatch")
    cleanup = value.get("cleanup")
    if (not isinstance(cleanup, dict)
            or set(cleanup) != {"status", "ownedResourcesRemaining", "evidence"}
            or cleanup.get("status") != "verified"
            or cleanup.get("ownedResourcesRemaining") != []):
        raise error_type("executed qualification cleanup is incomplete")
    cleanup_path = artifact_loader(cleanup["evidence"],
                                   "executed cleanup evidence")
    if cleanup["evidence"]["sha256"] in seen_artifacts:
        raise error_type("executed qualification evidence is reused")
    cleanup_detail = json_loader(cleanup_path, "executed cleanup evidence")
    if cleanup_detail != {"format": "openepm-executed-cleanup-result-v1",
            "runId": run_id, "status": "verified",
            "ownedResourcesRemaining": [], "architectures": architectures}:
        raise error_type("executed cleanup evidence content mismatch")
    return value


def _bounded_secret_file(path: Path, maximum: int = 64 * 1024) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise ManifestError("browser gateway configuration is unavailable")
    value = path.read_bytes()
    if not value or len(value) > maximum or b"\0" in value:
        raise ManifestError("browser gateway configuration is invalid")
    return value


def _browser_origin(value: str, *, issuer: bool = False) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise ManifestError("browser gateway origin is invalid") from error
    expected_path = "/realms/openepm" if issuer else ""
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or parsed.path.rstrip("/") != expected_path):
        raise ManifestError("browser gateway origin is invalid")
    return parsed.scheme + "://" + parsed.netloc + expected_path


def _browser_secret(value: object) -> str:
    if (not isinstance(value, str) or not 32 <= len(value.encode()) <= 256
            or any(ord(character) < 33 for character in value)):
        raise ManifestError("browser gateway secret is invalid")
    return value


def _browser_alpha_contract(issuer: str, web_origin: str) -> str:
    logout = (issuer + "/protocol/openid-connect/logout?id_token_hint={id_token}"
              + "&client_id=openepm-web&post_logout_redirect_uri="
              + quote(web_origin + "/", safe=""))
    return """server:
  bindAddress: 0.0.0.0:4180
metricsServer:
  bindAddress: 0.0.0.0:44180
providers:
  - id: openepm-keycloak
    provider: keycloak-oidc
    clientID: openepm-web
    clientSecretFile: /run/secrets/keycloak_web_client_secret
    backendLogoutURL: {logout}
    code_challenge_method: S256
    scope: openid profile
    oidcConfig:
      issuerURL: {issuer}
      emailClaim: preferred_username
      userIDClaim: preferred_username
      insecureAllowUnverifiedEmail: true
      insecureSkipNonce: false
upstreamConfig:
  upstreams:
    - id: openepm-platform-browser
      path: ^/api/platform/browser/(.*)$
      rewriteTarget: /browser/$1
      uri: http://platform:5193
    - id: openepm-fixed-core-web
      path: /
      uri: http://web:5195
injectRequestHeaders:
  - name: Authorization
    preserveRequestValue: false
    values:
      - claimSource:
          claim: access_token
          prefix: "Bearer "
""".format(logout=json.dumps(logout), issuer=json.dumps(issuer))


def validate_browser_gateway(issuer: str, web_origin: str, *,
        config: Path = BROWSER_CONFIG, alpha: Path = BROWSER_ALPHA,
        store: Path = BROWSER_STORE) -> None:
    issuer = _browser_origin(issuer, issuer=True)
    web_origin = _browser_origin(web_origin)
    try:
        stable = tomllib.loads(_bounded_secret_file(config).decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ManifestError("browser gateway configuration is invalid") from error
    expected = {
        "redirect_url": web_origin + "/oidc/callback", "proxy_prefix": "/oidc",
        "email_domains": ["*"], "cookie_name": "__Host-openepm_session",
        "cookie_secure": True, "cookie_httponly": True,
        "cookie_samesite": "lax", "cookie_expire": "8h",
        "cookie_refresh": "5m",
        "api_routes": ["^/api/", "^/favicon[.]ico$"],
        "session_store_type": "redis",
        "redis_connection_url": "redis://browser-session-store:6379/0",
        "reverse_proxy": True, "skip_provider_button": True,
        "silence_ping_logging": True,
    }
    cookie = _browser_secret(stable.pop("cookie_secret", None))
    redis = _browser_secret(stable.pop("redis_password", None))
    if stable != expected or cookie == redis:
        raise ManifestError("browser gateway configuration is invalid")
    try:
        alpha_text = _bounded_secret_file(alpha).decode("utf-8")
    except UnicodeError as error:
        raise ManifestError("browser gateway alpha configuration is invalid") from error
    if alpha_text != _browser_alpha_contract(issuer, web_origin):
        raise ManifestError("browser gateway alpha configuration is invalid")
    try:
        rows = [shlex.split(line, comments=False, posix=True)
                for line in _bounded_secret_file(store).decode("utf-8").splitlines()
                if line]
    except (UnicodeError, ValueError) as error:
        raise ManifestError("browser session-store configuration is invalid") from error
    expected_rows = [
        ["bind", "0.0.0.0"], ["protected-mode", "yes"], ["port", "6379"],
        ["save", ""], ["appendonly", "no"], ["maxmemory", "128mb"],
        ["maxmemory-policy", "noeviction"], ["requirepass", redis],
        ["rename-command", "FLUSHALL", ""],
        ["rename-command", "FLUSHDB", ""],
    ]
    if rows != expected_rows:
        raise ManifestError("browser session-store configuration is invalid")


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestError(f"cannot read JSON {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise ManifestError(f"{path.name} must contain a JSON object")
    return value


def _relative_file(root: Path, item: dict, label: str) -> Path:
    if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
        raise ManifestError(f"{label} must contain only path and sha256")
    relative = item["path"]
    if not isinstance(relative, str) or not relative:
        raise ManifestError(f"{label}.path must be non-empty")
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or ".." in parsed.parts:
        raise ManifestError(f"{label}.path must stay inside the release bundle")
    expected = item["sha256"]
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        raise ManifestError(f"{label}.sha256 is invalid")
    path = root.joinpath(*parsed.parts)
    if (not path.is_file() or path.is_symlink()
            or any(parent.is_symlink() for parent in path.parents
                   if parent != root.parent)
            or not path.resolve().is_relative_to(root.resolve())):
        raise ManifestError(f"{label} artifact is missing or symbolic: {relative}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ManifestError(f"{label} checksum mismatch: {relative}")
    return path


def _sdk(root: Path, value: object, source_commit: str,
         trusted_public_key: Path) -> dict:
    required = {"package", "source", "signing", "artifacts", "publicKey"}
    if not isinstance(value, dict) or set(value) != required:
        raise ManifestError("signed SDK release fields are invalid")
    artifacts = value["artifacts"]
    labels = {"wheel", "manifest", "signature", "checksums"}
    if not isinstance(artifacts, dict) or set(artifacts) != labels:
        raise ManifestError("signed SDK artifact inventory is invalid")
    paths = {name: _relative_file(root, artifacts[name], f"sdk.{name}")
             for name in labels}
    public_key = _relative_file(root, value["publicKey"], "sdk.publicKey")
    if (not trusted_public_key.is_file() or trusted_public_key.is_symlink()
            or public_key.read_bytes() != trusted_public_key.read_bytes()):
        raise ManifestError("bundled SDK key differs from signing trust policy")
    directory = paths["manifest"].parent
    if any(path.parent != directory for path in paths.values()):
        raise ManifestError("signed SDK artifacts must share one directory")
    if (paths["manifest"].name != SDK_MANIFEST
            or paths["signature"].name != SDK_SIGNATURE
            or paths["checksums"].name != SDK_CHECKSUMS):
        raise ManifestError("signed SDK artifact names are invalid")
    try:
        manifest = verify_sdk_release(directory, public_key=public_key)
    except (OSError, ValueError) as error:
        raise ManifestError(f"signed SDK release verification failed: {error}") from error
    if (manifest.get("source", {}).get("declaredCommit") != source_commit
            or manifest.get("package") != value["package"]
            or manifest.get("source") != value["source"]
            or manifest.get("signing") != value["signing"]
            or manifest.get("package", {}).get("filename") != paths["wheel"].name):
        raise ManifestError("signed SDK identity differs from release manifest")
    return value


def _verify_detached_signature(payload: Path, signature: Path,
                               public_key: Path, label: str) -> None:
    for path, kind in ((payload, "payload"), (signature, "signature"),
                       (public_key, "trusted public key")):
        if not path.is_file() or path.is_symlink():
            raise ManifestError(f"{label} {kind} is missing or symbolic")
    try:
        subprocess.run([
            "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
            "-inkey", str(public_key), "-in", str(payload),
            "-sigfile", str(signature),
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
           timeout=30)
    except (OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as error:
        raise ManifestError(f"{label} signature verification failed") from error


def _environment(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise ManifestError(f"invalid or repeated environment key: {key}")
        values[key] = value
    return values


def validate(manifest_path: Path, environment_path: Path, host_arch: str, *,
             trusted_root_public_key: Path | None = None,
             trust_policy: Path | None = None,
             trust_policy_signature: Path | None = None,
             minimum_trust_policy_sequence: int | None = None,
             manifest_signature: Path | None = None,
             verification_time: datetime | None = None) -> dict:
    root = manifest_path.resolve().parent
    value = _load_json(manifest_path)
    if value.get("format") == "openepm-release-manifest-v3":
        if (trusted_root_public_key is None or trust_policy is None
                or trust_policy_signature is None
                or minimum_trust_policy_sequence is None
                or manifest_signature is None):
            raise ManifestError(
                "v3 verification requires an external offline root and signed trust policy")
        now = verification_time or datetime.now(timezone.utc).replace(microsecond=0)
        try:
            policy = verify_trust_policy(trust_policy,
                signature_path=trust_policy_signature,
                root_public_key=trusted_root_public_key, now=now,
                minimum_sequence=minimum_trust_policy_sequence)
            release_keys = eligible_keys(trust_policy, policy,
                                         purpose="release", now=now)
        except TrustPolicyError as error:
            raise ManifestError(f"signing trust policy verification failed: {error}") from error
        verified_release_keys = []
        for key_id, public_key in release_keys:
            try:
                _verify_detached_signature(manifest_path, manifest_signature,
                                           public_key, "release manifest")
            except ManifestError:
                continue
            verified_release_keys.append(key_id)
        if len(verified_release_keys) != 1:
            raise ManifestError(
                "release manifest signature must match exactly one eligible signing key")
        sdk_signing = value.get("sdk", {}).get("signing", {}) \
            if isinstance(value.get("sdk"), dict) else {}
        sdk_key_id = sdk_signing.get("keyId") \
            if isinstance(sdk_signing, dict) else None
        if not isinstance(sdk_key_id, str):
            raise ManifestError("signed SDK key identity is missing")
        try:
            sdk_public_key = select_key(trust_policy, policy,
                key_id=sdk_key_id, purpose="sdk", now=now)
        except TrustPolicyError as error:
            raise ManifestError(f"signed SDK key is not trusted: {error}") from error
        return _validate_v3(root, value, environment_path, host_arch,
                            sdk_public_key)
    raise ManifestError("unsupported release manifest format; rebuild the retired release topology")


def _validate_v3(root: Path, value: dict, environment_path: Path,
                 host_arch: str, trusted_sdk_public_key: Path) -> dict:
    required = {"format", "status", "release", "sourceCommit",
        "schemaMigration", "architectures", "images", "sdk", "source",
        "sourceBinding", "sourceSbom", "resolvedReleasePolicy",
        "sourceCompliance", "artifacts", "qualificationSummary"}
    if set(value) != required or value.get("status") != "final-qualified":
        raise ManifestError("release manifest fields do not match the final-release contract")
    source_commit = value["sourceCommit"]
    if not isinstance(source_commit, str) or not COMMIT.fullmatch(source_commit):
        raise ManifestError("sourceCommit must be a full Git commit identity")
    if (not isinstance(value["schemaMigration"], str)
            or not MIGRATION.fullmatch(value["schemaMigration"])):
        raise ManifestError("schemaMigration must be the exact final migration filename")
    architectures = value["architectures"]
    if (not isinstance(architectures, list) or not architectures
            or len(architectures) != len(set(architectures))
            or host_arch not in architectures
            or not set(architectures).issubset({"linux/amd64", "linux/arm64"})):
        raise ManifestError(f"release is not qualified for host architecture {host_arch}")
    images = value["images"]
    if not isinstance(images, dict) or set(images) != set(COMPONENTS):
        raise ManifestError("final release must bind the complete runtime image inventory")
    environment = _environment(environment_path)
    for component in COMPONENTS:
        image = images[component]
        if (not isinstance(image, dict)
                or set(image) != {"reference", "digests"}
                or not isinstance(image["digests"], dict)
                or set(image["digests"]) != set(architectures)):
            raise ManifestError(f"invalid image record: {component}")
        digest = image["digests"].get(host_arch)
        if not isinstance(digest, str) or not re.fullmatch(
                r"sha256:[a-f0-9]{64}", digest):
            raise ManifestError(f"invalid image digest: {component}")
        if environment.get(ENV_KEYS[component]) != f"{image['reference']}@{digest}":
            raise ManifestError(f"environment image differs from manifest: {component}")
    for name in ("source", "sourceBinding", "sourceSbom",
                 "resolvedReleasePolicy", "sourceCompliance"):
        _relative_file(root, value[name], name)
    artifacts = value["artifacts"]
    required_artifacts = {"configuration", "inventory", "sbom", "licenses",
                          "checksums", "signature", "provenance"}
    if not isinstance(artifacts, dict) or set(artifacts) != required_artifacts:
        raise ManifestError("final release artifact inventory is invalid")
    for name in required_artifacts:
        _relative_file(root, artifacts[name], f"artifacts.{name}")
    inventory_path = _relative_file(root, artifacts["inventory"],
                                    "artifacts.inventory")
    try:
        from scripts.openepm_release_inventory import resolve
        resolve(inventory_path)
    except (ImportError, ValueError) as error:
        raise ManifestError("release inventory contract is invalid") from error
    sdk = _sdk(root, value["sdk"], source_commit, trusted_sdk_public_key)
    qualification_path = _relative_file(
        root, value["qualificationSummary"], "qualificationSummary")
    qualification = _load_json(qualification_path)
    if (qualification.get("format") != "openepm-exact-artifact-qualification-v1"
            or qualification.get("status") != "passed"
            or qualification.get("release") != value["release"]
            or qualification.get("sourceCommit") != source_commit
            or qualification.get("schemaMigration") != value["schemaMigration"]
            or qualification.get("architectures") != architectures
            or qualification.get("images") != images
            or qualification.get("sdk") != sdk
            or qualification.get("artifacts") != artifacts):
        raise ManifestError("qualification summary does not bind the exact release artifacts")
    validate_execution_evidence(qualification.get("executionEvidence"),
        architectures=architectures, source_commit=source_commit,
        schema_migration=value["schemaMigration"], images=images,
        configuration_profile_sha256=artifacts["configuration"]["sha256"],
        artifact_loader=lambda record, label: _relative_file(root, record, label),
        json_loader=lambda path, _label: _load_json(path),
        error_type=ManifestError)
    policy = _load_json(_relative_file(
        root, value["resolvedReleasePolicy"], "resolvedReleasePolicy"))
    try:
        packet_path = root / "owner-decision-packet.json"
        validate_policy(policy, packet_path if packet_path.is_file() else None,
                        artifact_root=root)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ManifestError("resolved release policy is incomplete")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser-gateway", action="store_true")
    parser.add_argument("--issuer")
    parser.add_argument("--web-origin")
    parser.add_argument("--browser-config", type=Path, default=BROWSER_CONFIG)
    parser.add_argument("--browser-alpha-config", type=Path, default=BROWSER_ALPHA)
    parser.add_argument("--browser-session-store-config", type=Path,
                        default=BROWSER_STORE)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--environment", type=Path)
    parser.add_argument("--host-architecture", choices=("linux/amd64", "linux/arm64"))
    parser.add_argument("--trusted-root-public-key", type=Path)
    parser.add_argument("--trust-policy", type=Path)
    parser.add_argument("--trust-policy-signature", type=Path)
    parser.add_argument("--minimum-trust-policy-sequence", type=int)
    parser.add_argument("--manifest-signature", type=Path)
    args = parser.parse_args()
    if args.browser_gateway:
        if (args.manifest is not None or args.environment is not None
                or args.host_architecture is not None or not args.issuer
                or not args.web_origin):
            parser.error("browser gateway validation arguments are invalid")
        try:
            validate_browser_gateway(args.issuer, args.web_origin,
                config=args.browser_config, alpha=args.browser_alpha_config,
                store=args.browser_session_store_config)
        except ManifestError as error:
            parser.error(str(error))
        print("browser_gateway_config=verified")
        return 0
    if (args.manifest is None or args.environment is None
            or args.host_architecture is None or args.issuer is not None
            or args.web_origin is not None):
        parser.error("release manifest validation arguments are incomplete")
    try:
        value = validate(args.manifest, args.environment, args.host_architecture,
            trusted_root_public_key=args.trusted_root_public_key,
            trust_policy=args.trust_policy,
            trust_policy_signature=args.trust_policy_signature,
            minimum_trust_policy_sequence=args.minimum_trust_policy_sequence,
            manifest_signature=args.manifest_signature,
        )
    except ManifestError as error:
        parser.error(str(error))
    print(f"release_manifest=verified release={value['release']} source={value['sourceCommit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
