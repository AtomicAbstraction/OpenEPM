#!/usr/bin/env python3
"""Bundle-side, fail-closed clean-Linux qualification phase harness."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

IMPLEMENTED = {"host-attestation", "bundle-integrity", "epmctl-doctor",
    "epmctl-install", "database-version-read", "storage-retirement",
    "native-architecture-proof", "service-restart", "populated-backup",
    "authenticated-mcp", "authenticated-browser", "runsc-headless-python",
    "runsc-python-build-publication", "independent-host-restore"}
COMPONENTS = {"application", "database", "operations", "builder",
    "identity", "proxy", "browser_gateway", "browser_session_store", "telemetry_collector"}
SHA256 = re.compile(r"^[a-f0-9]{64}$")
DIGEST = re.compile(r"^(?:[^@\s]+@)?sha256:[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
SCHEMA = re.compile(r"^[0-9]{4}_[A-Za-z0-9_]+\.sql$")


class PhaseError(ValueError):
    pass


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def emit(phase: str, **value: object) -> None:
    print(json.dumps({"phase": phase, "status": "passed", **value}, sort_keys=True))


def command(argv: list[str], *, environment: dict[str, str] | None = None) -> str:
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, check=False, env=environment)
    if result.returncode:
        raise PhaseError(f"command failed ({result.returncode}): {argv[0]}")
    return result.stdout.strip()


def epmctl_environment(context: dict, root: Path,
                       records: dict[Path, str]) -> dict[str, str]:
    environment = dict(os.environ)
    for field, variable in (
            ("offlineRootPublicKey", "EPM_SIGNING_OFFLINE_ROOT_FILE"),
            ("signingTrustPolicy", "EPM_SIGNING_TRUST_POLICY_FILE"),
            ("signingTrustPolicySignature",
             "EPM_SIGNING_TRUST_POLICY_SIGNATURE_FILE"),
            ("releaseBootstrapVerifier", "EPM_RELEASE_BOOTSTRAP_VERIFIER")):
        path = child(root, context.get(field), field)
        if records.get(path) != sha(path):
            raise PhaseError(f"{field} must be bundle-manifest bound")
        environment[variable] = str(path)
    minimum = context.get("minimumTrustPolicySequence")
    if type(minimum) is not int or minimum < 1:
        raise PhaseError("minimumTrustPolicySequence must be a positive integer")
    environment["EPM_MINIMUM_TRUST_POLICY_SEQUENCE"] = str(minimum)
    return environment


def bounded_directory(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise PhaseError(f"context field {label} must be a nonempty string")
    candidate = Path(value)
    if not candidate.is_absolute() or candidate.is_symlink():
        raise PhaseError(f"{label} must be an absolute, non-symbolic directory")
    path = candidate.resolve()
    if not path.is_dir():
        raise PhaseError(f"{label} directory is unavailable")
    return path


def text_field(value: dict, name: str) -> str:
    result = value.get(name)
    if not isinstance(result, str) or not result:
        raise PhaseError(f"context field {name} must be a nonempty string")
    return result


def child(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise PhaseError(f"{label} path must be a nonempty string")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts:
        raise PhaseError(f"unsafe {label} path")
    candidate = root / parsed.as_posix()
    if candidate.is_symlink():
        raise PhaseError(f"symbolic {label} path")
    resolved = candidate.resolve()
    if root not in resolved.parents or not resolved.is_file():
        raise PhaseError(f"missing {label}")
    return resolved


def load(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PhaseError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise PhaseError(f"{label} must be an object")
    return value


def authenticated_mcp_evidence(context: dict, root: Path,
                               records: dict[Path, str]) -> dict:
    endpoint = text_field(context, "mcpEndpoint")
    try:
        parsed_endpoint = urllib.parse.urlsplit(endpoint)
        port = parsed_endpoint.port
    except ValueError as error:
        raise PhaseError("mcpEndpoint is invalid") from error
    if (parsed_endpoint.scheme != "https" or not parsed_endpoint.hostname
            or parsed_endpoint.username is not None
            or parsed_endpoint.password is not None
            or parsed_endpoint.fragment or port == 0):
        raise PhaseError("mcpEndpoint must be credential-free HTTPS")
    request_path = child(root, context.get("mcpRequest"), "MCP request")
    if records.get(request_path) != sha(request_path):
        raise PhaseError("MCP request must be bundle-manifest bound")
    request_body = request_path.read_bytes()
    if not request_body or len(request_body) > 1024 * 1024:
        raise PhaseError("MCP request is empty or oversized")
    request_value = load(request_path, "MCP request")
    if request_value.get("jsonrpc") != "2.0" or "id" not in request_value:
        raise PhaseError("MCP request is not JSON-RPC 2.0")
    token_path = Path(text_field(context, "mcpTokenFile"))
    if not token_path.is_absolute() or token_path.is_symlink() or not token_path.is_file():
        raise PhaseError("MCP token file must be absolute, regular and non-symbolic")
    if stat.S_IMODE(token_path.stat().st_mode) & 0o077:
        raise PhaseError("MCP token file permissions are too broad")
    token = token_path.read_text(encoding="utf-8").strip()
    if not token or len(token) > 16384 or any(character.isspace() for character in token):
        raise PhaseError("MCP bearer token is invalid")

    def invoke(headers: dict[str, str]):
        request = urllib.request.Request(endpoint, data=request_body, headers={
            "Content-Type": "application/json", "Accept": "application/json", **headers},
            method="POST")
        return urllib.request.urlopen(request, timeout=30)

    try:
        with invoke({}) as response:
            response.read(1)
        raise PhaseError("unsigned MCP request was not denied")
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        if code not in (401, 403):
            raise PhaseError(f"unsigned MCP request returned unexpected HTTP {error.code}") from error
    try:
        with invoke({"Authorization": "Bearer " + token}) as response:
            if response.status != 200:
                raise PhaseError(f"authenticated MCP returned HTTP {response.status}")
            raw = response.read(1024 * 1024 + 1)
    except urllib.error.URLError as error:
        raise PhaseError("authenticated MCP request failed") from error
    if len(raw) > 1024 * 1024:
        raise PhaseError("authenticated MCP response is oversized")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PhaseError("authenticated MCP response is invalid JSON") from error
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0" \
            or value.get("id") != request_value["id"] \
            or not isinstance(value.get("result"), dict) or "error" in value:
        raise PhaseError("authenticated MCP response is not a successful matching result")
    return {"verified": True, "unsignedDenied": True,
            "responseSha256": hashlib.sha256(raw).hexdigest()}


def authenticated_mcp(context: dict, root: Path, records: dict[Path, str]) -> None:
    emit("authenticated-mcp", **authenticated_mcp_evidence(context, root, records))


def https_origin(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise PhaseError(f"{label} must be HTTPS")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise PhaseError(f"{label} is invalid") from error
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None \
            or parsed.password is not None or parsed.fragment or port == 0:
        raise PhaseError(f"{label} must be credential-free HTTPS")
    return f"https://{parsed.hostname}" + (f":{port}" if port else "")


def authenticated_browser(context: dict, root: Path,
                          records: dict[Path, str]) -> None:
    executable = child(root, context.get("browserProbeExecutable"),
                       "browser probe executable")
    configuration = child(root, context.get("browserProbeConfig"),
                          "browser probe configuration")
    if records.get(executable) != sha(executable) \
            or records.get(configuration) != sha(configuration):
        raise PhaseError("browser probe executable and config must be bundle-manifest bound")
    if not executable.stat().st_mode & stat.S_IXUSR:
        raise PhaseError("browser probe executable is not executable")
    config = load(configuration, "browser probe configuration")
    if set(config) != {"format", "webOrigin", "oidcIssuer", "expectedTitle",
                       "expectedMarker"} \
            or config.get("format") != "openepm-browser-probe-v1" \
            or not isinstance(config.get("expectedTitle"), str) \
            or not config["expectedTitle"] \
            or not isinstance(config.get("expectedMarker"), str) \
            or not config["expectedMarker"]:
        raise PhaseError("browser probe configuration is invalid")
    web_origin = https_origin(config["webOrigin"], "browser web origin")
    https_origin(config["oidcIssuer"], "browser OIDC issuer")
    issuer = config["oidcIssuer"].rstrip("/")
    secrets_directory = Path(text_field(
        context, "browserIdentitySecretsDirectory"))
    if not secrets_directory.is_absolute() or secrets_directory.is_symlink() \
            or not secrets_directory.is_dir():
        raise PhaseError("browser identity secrets directory is invalid")
    try:
        completed = subprocess.run([str(executable), "--config", str(configuration),
            "--identity-secrets-directory", str(secrets_directory)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            check=False, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PhaseError("browser probe could not execute") from error
    if completed.returncode != 0:
        raise PhaseError(f"browser probe failed with exit {completed.returncode}")
    raw = completed.stdout.strip()
    if len(raw.encode()) > 65536:
        raise PhaseError("browser probe output is oversized")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise PhaseError("browser probe emitted invalid JSON") from error
    expected = {"format", "engine", "browser", "browserVersion", "headless",
                "unauthenticated", "authenticated",
                "runOwnedInitialAdministrator", "qualificationCleanupRequired",
                "secretArtifactsWritten"}
    if not isinstance(value, dict) or set(value) != expected \
            or value.get("format") != "openepm-browser-probe-result-v1" \
            or value.get("engine") != "Playwright" \
            or value.get("browser") != "Google Chrome" \
            or not isinstance(value.get("browserVersion"), str) \
            or not value["browserVersion"] \
            or value.get("headless") is not True \
            or value.get("runOwnedInitialAdministrator") is not True \
            or value.get("qualificationCleanupRequired") is not True \
            or value.get("secretArtifactsWritten") is not False:
        raise PhaseError("browser probe identity or secret handling is invalid")
    unauth = value.get("unauthenticated")
    denied = isinstance(unauth, dict) and unauth.get("status") in (401, 403)
    redirected = False
    if isinstance(unauth, dict) and isinstance(unauth.get("redirectUrl"), str):
        try:
            https_origin(unauth["redirectUrl"], "unauthenticated redirect")
            redirect = unauth["redirectUrl"].split("#", 1)[0]
            redirected = redirect == issuer or redirect.startswith(issuer + "/")
        except PhaseError:
            redirected = False
    if not denied and not redirected:
        raise PhaseError("unauthenticated browser access was not denied or redirected to OIDC")
    authenticated = value.get("authenticated")
    if not isinstance(authenticated, dict) or set(authenticated) != {
            "pageUrl", "pageTitle", "markerObserved", "presentationBundleLoaded",
            "applicationsStatus", "applicationCount", "workspaceCreated",
            "applicationCreated", "metadataMemberCount", "authorizedWrite",
            "exactReadback", "readbackAmount", "sameContext",
            "consoleErrorCount", "nativeLogin", "firstPasswordReplacement",
            "opaqueSessionCookie", "browserTokenStorage"}:
        raise PhaseError("authenticated browser workflow evidence is incomplete")
    if https_origin(authenticated["pageUrl"], "authenticated page URL") != web_origin \
            or authenticated["pageTitle"] != config["expectedTitle"] \
            or authenticated["markerObserved"] != config["expectedMarker"] \
            or authenticated["presentationBundleLoaded"] is not True \
            or authenticated["applicationsStatus"] != 200 \
            or not isinstance(authenticated["applicationCount"], int) \
            or isinstance(authenticated["applicationCount"], bool) \
            or authenticated["applicationCount"] < 0 \
            or authenticated["workspaceCreated"] is not True \
            or authenticated["applicationCreated"] is not True \
            or authenticated["metadataMemberCount"] != 8 \
            or authenticated["authorizedWrite"] is not True \
            or authenticated["exactReadback"] is not True \
            or authenticated["readbackAmount"] != "17.25000000" \
            or authenticated["sameContext"] is not True \
            or authenticated["consoleErrorCount"] != 0 \
            or authenticated["nativeLogin"] is not True \
            or authenticated["firstPasswordReplacement"] is not True \
            or authenticated["opaqueSessionCookie"] is not True \
            or authenticated["browserTokenStorage"] is not False:
        raise PhaseError("authenticated rendered browser workflow did not pass")
    emit("authenticated-browser", verified=True, engine="Playwright",
        browser="Google Chrome", headless=True, unauthenticatedProtected=True,
        browserVersion=value["browserVersion"],
        sameContext=True, presentationBundleLoaded=True,
        nativeLogin=True, firstPasswordReplacement=True,
        opaqueSessionCookie=True, browserTokenStorage=False,
        runOwnedInitialAdministrator=True, qualificationCleanupRequired=True,
        workspaceCreated=True, applicationCreated=True,
        metadataMemberCount=8, authorizedWrite=True, exactReadback=True,
        readbackAmount="17.25000000",
        applicationCount=authenticated["applicationCount"],
        debuggerClaimed=False, persistenceClaimed=False,
        outputSha256=hashlib.sha256(raw.encode()).hexdigest())


def validate_images(context: dict) -> dict[str, str]:
    images = context.get("images")
    if not isinstance(images, dict) or set(images) != COMPONENTS:
        raise PhaseError("context must bind the complete runtime image inventory")
    if any(not isinstance(item, str) or not DIGEST.fullmatch(item)
           for item in images.values()):
        raise PhaseError("component image identities must be sha256 digests")
    return images


def scan_proxy_retirement(image: str, maximum_bytes: int) -> dict:
    if not isinstance(maximum_bytes, int) or isinstance(maximum_bytes, bool) \
            or not 1024 <= maximum_bytes <= 1024 * 1024 * 1024:
        raise PhaseError("proxyRetirementMaximumBytes is invalid")
    try:
        inspected = json.loads(command(["docker", "image", "inspect", image]))
    except json.JSONDecodeError as error:
        raise PhaseError("proxy image inspection is invalid JSON") from error
    if not isinstance(inspected, list) or len(inspected) != 1 \
            or not isinstance(inspected[0], dict):
        raise PhaseError("proxy image inspection is invalid")
    info = inspected[0]
    config = info.get("Config")
    rootfs = info.get("RootFS")
    if (info.get("Os") != "linux" or not isinstance(config, dict)
            or config.get("User") != "65532:65532"
            or config.get("Entrypoint") != ["/usr/local/bin/traefik"]
            or not isinstance(rootfs, dict)
            or not isinstance(rootfs.get("Layers"), list)
            or len(rootfs["Layers"]) != 2):
        raise PhaseError("proxy scratch runtime identity is invalid")
    # Inspect the immutable image layers, not ``docker export``. Export adds
    # runtime-generated files such as /.dockerenv, /etc/hosts and /dev/console
    # and may expand a 44 MiB scratch image beyond the configured bound. Those
    # files are not shipped by the image and made the old release check both
    # inaccurate and host-dependent.
    with tempfile.TemporaryDirectory(prefix="openepm-proxy-retirement-") as directory:
        archive = Path(directory) / "image.tar"
        saved = subprocess.run(["docker", "image", "save", "--output", str(archive),
            image], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=120)
        if saved.returncode != 0 or not archive.is_file() \
                or archive.stat().st_size > maximum_bytes:
            raise PhaseError("proxy image save failed or exceeded bound")
        allowed = {"etc/ssl/certs/ca-certificates.crt", "usr/local/bin/traefik"}
        files: dict[str, bytes] = {}
        try:
            with tarfile.open(archive, "r:*") as image_archive:
                manifest_member = image_archive.getmember("manifest.json")
                manifest_file = image_archive.extractfile(manifest_member)
                if manifest_file is None or manifest_member.size > 1024 * 1024:
                    raise PhaseError("proxy image manifest is unreadable")
                manifest = json.loads(manifest_file.read().decode("utf-8"))
                if not isinstance(manifest, list) or len(manifest) != 1 \
                        or not isinstance(manifest[0], dict):
                    raise PhaseError("proxy image manifest is invalid")
                layers = manifest[0].get("Layers")
                if not isinstance(layers, list) or len(layers) != 2 \
                        or any(not isinstance(layer, str) \
                               or not re.fullmatch(
                                   r"(?:blobs/sha256/[a-f0-9]{64}|"
                                   r"[a-f0-9]{64}/layer\.tar)", layer)
                               for layer in layers):
                    raise PhaseError("proxy image layer manifest is invalid")
                for layer in layers:
                    layer_member = image_archive.getmember(layer)
                    layer_file = image_archive.extractfile(layer_member)
                    if layer_file is None or layer_member.size > maximum_bytes:
                        raise PhaseError("proxy image layer is unreadable or oversized")
                    with tarfile.open(fileobj=layer_file, mode="r:*") as layer_archive:
                        for member in layer_archive:
                            name = member.name.removeprefix("./").rstrip("/")
                            if member.isdir():
                                continue
                            if not member.isfile() or name not in allowed or name in files:
                                raise PhaseError(
                                    "proxy scratch filesystem has an unexpected entry")
                            extracted = layer_archive.extractfile(member)
                            if extracted is None:
                                raise PhaseError("proxy filesystem member is unreadable")
                            data = extracted.read(maximum_bytes + 1)
                            if (
                                len(data) > maximum_bytes
                                or sum(len(value) for value in files.values()) + len(data)
                                > maximum_bytes
                                or (b"sql" + b"ite") in data.lower()
                                or ("sql" + "ite") in name.lower()
                            ):
                                raise PhaseError(
                                    "proxy filesystem contains a retired marker or exceeds bound")
                            files[name] = data
        except (KeyError, json.JSONDecodeError, UnicodeError,
                tarfile.TarError, OSError) as error:
            raise PhaseError("proxy image archive is invalid") from error
        if set(files) != allowed \
                or not files["usr/local/bin/traefik"].startswith(b"\x7fELF"):
            raise PhaseError("proxy scratch filesystem contract is incomplete")
        return {"files": len(files),
            "binarySha256": hashlib.sha256(files["usr/local/bin/traefik"]).hexdigest(),
            "certificateSha256": hashlib.sha256(
                files["etc/ssl/certs/ca-certificates.crt"]).hexdigest()}


def runsc_headless_python(context: dict, root: Path,
                          records: dict[Path, str]) -> None:
    images = validate_images(context)
    profile_path = child(root, context.get("headlessRunscProfile"),
                         "headless runsc profile")
    if records.get(profile_path) != sha(profile_path):
        raise PhaseError("headless runsc profile must be bundle-manifest bound")
    profile = load(profile_path, "headless runsc profile")
    if set(profile) != {"format", "image"} \
            or profile.get("format") != "openepm-headless-runsc-profile-v1" \
            or profile.get("image") != images["builder"]:
        raise PhaseError("headless runsc profile is invalid or not the builder image")
    probe = """import json,os,socket,stat,tempfile
root_read_only=bool(os.statvfs('/').f_flag & os.ST_RDONLY)
network_blocked=False
try:
 socket.create_connection(('1.1.1.1',53),timeout=0.2).close()
except OSError:
 network_blocked=True
with tempfile.NamedTemporaryFile(dir='/tmp') as f:
 f.write(b'ok');f.flush();tmp_writable=True
print(json.dumps({'uid':os.getuid(),'rootReadOnly':root_read_only,
 'networkBlocked':network_blocked,'tmpWritable':tmp_writable},sort_keys=True))
"""
    base = ["docker", "run", "--rm", "--runtime", "runsc", "--network", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "64", "--memory", "256m", "--cpus", "0.5",
        "--user", "65534:65534", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--entrypoint", "python", profile["image"], "-I", "-c"]
    try:
        positive = subprocess.run(base + [probe], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PhaseError("runsc headless probe could not execute") from error
    if positive.returncode != 0:
        raise PhaseError(f"runsc headless probe failed with exit {positive.returncode}")
    try:
        observed = json.loads(positive.stdout)
    except json.JSONDecodeError as error:
        raise PhaseError("runsc headless probe emitted invalid JSON") from error
    if not isinstance(observed, dict) or set(observed) != {
            "uid", "rootReadOnly", "networkBlocked", "tmpWritable"} \
            or not isinstance(observed["uid"], int) or observed["uid"] == 0 \
            or observed["rootReadOnly"] is not True \
            or observed["networkBlocked"] is not True \
            or observed["tmpWritable"] is not True:
        raise PhaseError("runsc headless isolation observations are incomplete")
    try:
        negative = subprocess.run(base + ["import sys;sys.exit(23)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PhaseError("runsc negative probe could not execute") from error
    if negative.returncode != 23:
        raise PhaseError("runsc negative probe did not preserve failure status")
    emit("runsc-headless-python", verified=True, runtime="runsc",
        image=profile["image"], uid=observed["uid"], rootReadOnly=True,
        networkBlocked=True, tmpWritable=True, negativeExitCode=23,
        positiveOutputSha256=hashlib.sha256(positive.stdout.encode()).hexdigest())


def runsc_python_build_publication(context: dict, root: Path,
                                   records: dict[Path, str]) -> None:
    """Run the bundle-bound public P25 probe; never synthesize product evidence."""
    images = validate_images(context)
    executable = child(root, context.get("pythonBuildProbeExecutable"),
                       "Python build/publication probe executable")
    configuration = child(root, context.get("pythonBuildProbeConfig"),
                          "Python build/publication probe configuration")
    qualification_source = child(root, "python-publication-program.py",
                                 "Python publication qualification source")
    if records.get(executable) != sha(executable) \
            or records.get(configuration) != sha(configuration) \
            or records.get(qualification_source) != sha(qualification_source):
        raise PhaseError("Python build/publication probe must be bundle-manifest bound")
    if not executable.stat().st_mode & stat.S_IXUSR:
        raise PhaseError("Python build/publication probe is not executable")
    config = load(configuration, "Python build/publication probe configuration")
    expected_config = {"format", "builderImage", "mcpEndpoint", "workspaceId",
        "applicationId", "programId", "environmentId",
        "environmentVersion", "delegationId",
        "executionIssuer", "executionSubjectId",
        "requestPrefix", "expectedSourceDigest", "expectedResult",
        "resultFunction", "resultArguments", "resultPath", "timeoutSeconds"}
    if set(config) != expected_config \
            or config.get("format") != "openepm-python-build-publication-probe-v3" \
            or config.get("builderImage") != images["builder"] \
            or config.get("mcpEndpoint") != context.get("mcpEndpoint") \
            or config.get("expectedSourceDigest") != sha(qualification_source) \
            or not isinstance(config.get("expectedResult"), str) \
            or not config["expectedResult"]:
        raise PhaseError("Python build/publication probe configuration is invalid")
    token_path = Path(text_field(context, "pythonBuildTokenFile"))
    if not token_path.is_absolute() or token_path.is_symlink() \
            or not token_path.is_file() \
            or stat.S_IMODE(token_path.stat().st_mode) & 0o077:
        raise PhaseError("Python build token must be protected, regular and non-symbolic")
    token = token_path.read_text(encoding="utf-8").strip()
    if not token or len(token) > 16384 or any(character.isspace() for character in token):
        raise PhaseError("Python build token is invalid")
    started_at = int(time.time())
    try:
        completed = subprocess.run([str(executable), "--config", str(configuration),
            "--token-file", str(token_path), "--source-file",
            str(qualification_source)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            check=False, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PhaseError("Python build/publication probe could not execute") from error
    if completed.returncode != 0:
        raise PhaseError(f"Python build/publication probe failed with exit {completed.returncode}")
    raw = completed.stdout.strip()
    if len(raw.encode()) > 65536 or token in raw:
        raise PhaseError("Python build/publication probe output is oversized or leaked its token")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise PhaseError("Python build/publication probe emitted invalid JSON") from error
    expected = {"format", "configuredBuilderImage", "buildId", "workflowId",
        "buildAttempts", "buildClaimGeneration", "buildReplaySame",
        "capabilityActionCount",
        "capabilityGenerationBound",
        "sourceExecutionCount", "sealedRunWithoutRebuild",
        "artifactSha256", "planSha256", "result", "receiptSha256",
        "lineageSha256", "denialZeroEffect", "denialRevisionBefore",
        "denialRevisionAfter", "databaseCredentialsPresent",
        "trustedCorePresent", "dockerSocketPresent", "sourceMounted",
        "publicSdkOnly", "publicMcpHttps"}
    digests = ("artifactSha256", "planSha256", "receiptSha256",
               "lineageSha256", "denialRevisionBefore", "denialRevisionAfter")
    if not isinstance(value, dict) or set(value) != expected \
            or value.get("format") != "openepm-python-build-publication-result-v3" \
            or value.get("configuredBuilderImage") != images["builder"] \
            or value.get("publicSdkOnly") is not True \
            or value.get("publicMcpHttps") is not True \
            or not isinstance(value.get("buildId"), str) \
            or not re.fullmatch(r"[a-f0-9]{32}", value["buildId"]) \
            or not isinstance(value.get("workflowId"), str) \
            or not re.fullmatch(r"[a-f0-9]{32}", value["workflowId"]) \
            or value.get("buildAttempts") != 1 \
            or value.get("buildClaimGeneration") != 1 \
            or value.get("buildReplaySame") is not True \
            or value.get("capabilityActionCount") != 2 \
            or value.get("capabilityGenerationBound") is not True \
            or value.get("sourceExecutionCount") != 1 \
            or value.get("sealedRunWithoutRebuild") is not True \
            or value.get("result") != config["expectedResult"] \
            or value.get("denialZeroEffect") is not True \
            or value.get("denialRevisionBefore") != value.get("denialRevisionAfter") \
            or any(value.get(field) is not False for field in
                   ("databaseCredentialsPresent", "trustedCorePresent",
                    "dockerSocketPresent", "sourceMounted")) \
            or any(not isinstance(value.get(field), str)
                   or not SHA256.fullmatch(value[field]) for field in digests):
        raise PhaseError("Python build/launcher/broker/seal/publication evidence is incomplete")
    journal_unit = text_field(context, "sandboxLauncherJournalUnit")
    if journal_unit != "openepm-sandbox-launcher.service":
        raise PhaseError("sandbox launcher journal unit is invalid")
    journal_result = subprocess.run(["journalctl", "--unit", journal_unit,
        "--since", "@" + str(started_at), "--output", "cat", "--no-pager"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, check=False, timeout=30)
    if journal_result.returncode != 0 \
            or len(journal_result.stdout.encode()) > 1024 * 1024:
        raise PhaseError("sandbox launcher journal is unavailable or oversized")
    events = []
    for line in journal_result.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("event") == \
                "sandbox-build-collected" and event.get("buildId") == value["buildId"]:
            events.append(event)
    if len(events) != 1:
        raise PhaseError("exact sandbox launcher runtime event is absent")
    event = events[0]
    event_fields = {"format", "event", "buildId", "claimGeneration",
        "containerId", "runtime", "image", "environmentId",
        "environmentVersion", "rootReadOnly", "capabilitiesDropped",
        "noNewPrivileges", "pidsLimit", "cpuLimit", "memoryMiB", "network"}
    if set(event) != event_fields \
            or event.get("format") != "openepm-sandbox-launcher-event-v1" \
            or event.get("claimGeneration") != value["buildClaimGeneration"] \
            or not isinstance(event.get("containerId"), str) \
            or not re.fullmatch(r"[a-f0-9]{12,64}", event["containerId"]) \
            or event.get("runtime") != "runsc" \
            or not isinstance(event.get("image"), str) \
            or not event["image"].endswith("@" + images["builder"]) \
            or event.get("environmentId") != config["environmentId"] \
            or event.get("environmentVersion") != config["environmentVersion"] \
            or event.get("rootReadOnly") is not True \
            or event.get("capabilitiesDropped") is not True \
            or event.get("noNewPrivileges") is not True \
            or event.get("pidsLimit") != 128 \
            or event.get("cpuLimit") != 1 \
            or event.get("memoryMiB") != 512 \
            or not isinstance(event.get("network"), str) or not event["network"]:
        raise PhaseError("sandbox launcher runtime event is invalid")
    emit("runsc-python-build-publication", verified=True,
        runtime="runsc", builderImage=images["builder"],
        profileImage=event["image"], rootReadOnly=True,
        capabilitiesDropped=True, noNewPrivileges=True, pidsLimit=128,
        cpuLimit=1, memoryMiB=512, journalUnit=journal_unit,
        launcherEventSha256=hashlib.sha256(json.dumps(event, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest(), **{
        key: item for key, item in value.items()
        if key not in {"format", "configuredBuilderImage"}},
        outputSha256=hashlib.sha256(raw.encode()).hexdigest())


def validate_bundle(root: Path, context: dict) -> tuple[Path, dict, dict[Path, str]]:
    manifest = child(root, context.get("bundleManifest"), "bundle manifest")
    value = load(manifest, "bundle manifest")
    if value.get("format") != "openepm-clean-linux-bundle-manifest-v2":
        raise PhaseError("invalid bundle manifest format")
    if not isinstance(value.get("sourceCommit"), str) or not COMMIT.fullmatch(value["sourceCommit"]):
        raise PhaseError("invalid bundle source commit")
    if not isinstance(value.get("sourceTreeSha256"), str) or not SHA256.fullmatch(value["sourceTreeSha256"]):
        raise PhaseError("invalid bundle source-tree digest")
    if not isinstance(value.get("schemaMigration"), str) or not SCHEMA.fullmatch(value["schemaMigration"]):
        raise PhaseError("invalid bundle schema migration")
    items = value.get("files")
    if not isinstance(items, list) or not items:
        raise PhaseError("bundle manifest files must be a nonempty array")
    records: dict[Path, str] = {}
    names: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise PhaseError("invalid bundle file record")
        name, expected = item["path"], item["sha256"]
        if not isinstance(name, str) or name in names:
            raise PhaseError("bundle file paths must be unique strings")
        if not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise PhaseError("invalid bundle file digest")
        names.add(name)
        path = child(root, name, "bundle file")
        if sha(path) != expected:
            raise PhaseError("bundle file digest mismatch")
        records[path] = expected
    return manifest, value, records


def native_architecture() -> str:
    result = {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}.get(platform.machine())
    if result is None:
        raise PhaseError(f"unsupported native architecture: {platform.machine()}")
    return result


def host_identity(path: Path = Path("/etc/machine-id")) -> str:
    try:
        value = path.read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeError) as error:
        raise PhaseError("stable host identity is unavailable") from error
    if not re.fullmatch(r"[0-9a-f]{32}", value) or value == "0" * 32:
        raise PhaseError("stable host identity is invalid")
    return hashlib.sha256(("openepm-clean-host-v1:" + value).encode()).hexdigest()


def verified_source_attestation(context: dict, root: Path,
                                records: dict[Path, str]) -> dict:
    module_path = child(root, context.get("sourceAttestationModule"),
                        "source attestation module")
    if records.get(module_path) != sha(module_path):
        raise PhaseError("source attestation module must be bundle-manifest bound")
    attestation_path = Path(text_field(context, "sourceBackupAttestation"))
    if (not attestation_path.is_absolute() or attestation_path.is_symlink()
            or not attestation_path.is_file()
            or not 1 <= attestation_path.stat().st_size <= 65536):
        raise PhaseError("transferred source backup attestation is unavailable")
    maximum = context.get("backupMaximumBytes")
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
        raise PhaseError("backupMaximumBytes must be a positive integer")
    spec = importlib.util.spec_from_file_location(
        "openepm_bound_source_attestation", module_path)
    if spec is None or spec.loader is None:
        raise PhaseError("source attestation verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return module.verify(load(attestation_path, "source backup attestation"),
            backup_root=bounded_directory(context.get("backupExportRoot"),
                                           "backupExportRoot"),
            key_file=Path(text_field(context, "sourceAttestationKeyFile")),
            maximum_bytes=maximum)
    except Exception as error:
        raise PhaseError("source backup attestation verification failed") from error


def independent_host_restore(context: dict, root: Path,
                             records: dict[Path, str]) -> None:
    source = verified_source_attestation(context, root, records)
    target_identity = host_identity()
    if source["sourceHostIdentity"] == target_identity:
        raise PhaseError("restore target is not independent from source host")
    epmctl = child(root, context.get("epmctl"), "epmctl")
    verifier = child(root, context.get("restoredPopulatedVerifier"),
                     "restored populated verifier")
    if records.get(verifier) != sha(verifier):
        raise PhaseError("restored populated verifier must be bundle-manifest bound")
    target = text_field(context, "restoreTargetProject")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", target):
        raise PhaseError("restore target project is invalid")
    environment = epmctl_environment(context, root, records)
    environment["EPM_RESTORE_TARGET_PROJECT"] = target
    output = command([str(epmctl), "restore", source["bundle"]],
                     environment=environment)
    result = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    if (result.get("restore") != "verified" or result.get("bundle") != source["bundle"]
            or result.get("target_project") != target
            or not result.get("source_project") or result["source_project"] == target):
        raise PhaseError("epmctl did not verify a distinct fresh restore target")
    try:
        restored = json.loads(command([str(verifier), "--target-project", target],
            environment=environment))
    except json.JSONDecodeError as error:
        raise PhaseError("restored population verifier emitted invalid JSON") from error
    after = restored.get("signature") if isinstance(restored, dict) else None
    before = source["preBackupPopulatedSignature"]
    if (not isinstance(restored, dict) or restored.get("status") != "passed"
            or restored.get("populated") is not True or after != before):
        raise PhaseError("restored populated signature differs from source")
    activation_output = command(
        [str(epmctl), "activate-restored", source["bundle"]],
        environment=environment)
    activation = dict(line.split("=", 1)
        for line in activation_output.splitlines() if "=" in line)
    if (activation.get("activation") != "verified"
            or activation.get("bundle") != source["bundle"]
            or activation.get("target_project") != target
            or activation.get("prior_project") != result["source_project"]):
        raise PhaseError("epmctl did not activate the exact verified restore target")
    emit("independent-host-restore", restore={"populated": True,
        "independentHost": True, "encryptedTransfer": True,
        "activationVerified": True, "bundle": source["bundle"],
        "targetProject": target, "priorProject": result["source_project"],
        "sourceHostIdentity": source["sourceHostIdentity"],
        "targetHostIdentity": target_identity,
        "beforeSignature": before, "afterSignature": after})


def execute(phase: str, context_path: Path) -> None:
    if phase not in IMPLEMENTED:
        raise PhaseError(f"phase is not implemented and cannot pass: {phase}")
    context_path = context_path.resolve()
    context = load(context_path, "phase context")
    root = Path(text_field(context, "bundleRoot"))
    if not root.is_absolute():
        if root != Path("."):
            raise PhaseError("relative bundleRoot must be the bundle directory")
        root = context_path.parent / root
    if root.is_symlink() or not root.is_dir():
        raise PhaseError("bundleRoot must be a real, non-symbolic directory")
    root = root.resolve()
    manifest, bundle, records = validate_bundle(root, context)
    harness = Path(__file__).resolve()
    if records.get(context_path) != sha(context_path) or records.get(harness) != sha(harness):
        raise PhaseError("context and phase harness must be bundle-manifest bound")

    if phase == "bundle-integrity":
        release = child(root, context.get("releaseManifest"), "release manifest")
        emit(phase, bundle={"releaseManifestSha256": sha(release),
            "bundleManifestSha256": sha(manifest), "sourceCommit": bundle["sourceCommit"],
            "schemaMigration": bundle["schemaMigration"],
            "sourceTreeSha256": bundle["sourceTreeSha256"]})
        return
    if phase == "authenticated-mcp":
        authenticated_mcp(context, root, records)
        return
    if phase == "authenticated-browser":
        authenticated_browser(context, root, records)
        return
    if phase == "runsc-headless-python":
        runsc_headless_python(context, root, records)
        return
    if phase == "runsc-python-build-publication":
        runsc_python_build_publication(context, root, records)
        return
    if phase == "independent-host-restore":
        independent_host_restore(context, root, records)
        return
    if phase == "host-attestation":
        os_release = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip('"')
        runtimes = json.loads(command(["docker", "info", "--format", "{{json .Runtimes}}"] ))
        if not isinstance(runtimes, dict):
            raise PhaseError("Docker runtime inventory is invalid")
        runsc = command(["runsc", "--version"]).splitlines()
        if not runsc:
            raise PhaseError("runsc version is absent")
        emit(phase, host={"osId": os_release.get("ID"), "osVersion": os_release.get("VERSION_ID"),
            "architecture": native_architecture(), "cleanHost": context.get("cleanHost") is True,
            "runscVersion": runsc[0], "dockerRunscRegistered": "runsc" in runtimes,
            "developmentMacPathsPresent": any(Path(item).exists() for item in ("/Users", "/Applications/Xcode.app")),
            "hostIdentity": host_identity()})
        return
    if phase in {"epmctl-doctor", "epmctl-install"}:
        command([str(child(root, context.get("epmctl"), "epmctl")),
                 phase.removeprefix("epmctl-")],
                environment=epmctl_environment(context, root, records))
        emit(phase, verified=True)
        return
    if phase == "service-restart":
        epmctl = child(root, context.get("epmctl"), "epmctl")
        environment = epmctl_environment(context, root, records)
        for action in ("stop", "up", "status"):
            command([str(epmctl), action], environment=environment)
        readback = authenticated_mcp_evidence(context, root, records)
        emit(phase, verified=True, authenticatedWorkflowClaimed=True,
            unsignedDenied=readback["unsignedDenied"],
            responseSha256=readback["responseSha256"])
        return
    if phase == "populated-backup":
        if "sourceBackupAttestation" in context:
            source = verified_source_attestation(context, root, records)
            emit(phase, backup={"bundle": source["bundle"],
                "sourceHostIdentity": source["sourceHostIdentity"],
                "preBackupPopulatedSignature": source["preBackupPopulatedSignature"],
                "manifestSha256": source["manifestSha256"],
                "encryptedArtifactSha256": source["encryptedArtifactSha256"],
                "encryptedPayloadCount": source["encryptedPayloadCount"],
                "totalBytes": source["totalBytes"]})
            return
        epmctl = child(root, context.get("epmctl"), "epmctl")
        verifier = child(root, context.get("populatedVerifier"),
                         "populated verifier")
        if records.get(verifier) != sha(verifier):
            raise PhaseError("populated verifier must be bundle-manifest bound")
        try:
            population = json.loads(command([str(verifier)]))
        except json.JSONDecodeError as error:
            raise PhaseError("populated verifier did not emit JSON") from error
        if not isinstance(population, dict) or population.get("status") != "passed" \
                or population.get("populated") is not True \
                or not isinstance(population.get("signature"), str) \
                or not SHA256.fullmatch(population["signature"]):
            raise PhaseError("pre-backup populated signature is invalid")
        export_root = bounded_directory(context.get("backupExportRoot"),
                                        "backupExportRoot")
        before = {item.name for item in export_root.iterdir()
                  if item.is_dir() and not item.is_symlink()}
        output = command([str(epmctl), "backup"],
                         environment=epmctl_environment(context, root, records))
        bundle_names = [line.removeprefix("bundle=") for line in output.splitlines()
                        if line.startswith("bundle=")]
        if len(bundle_names) != 1 or not re.fullmatch(
                r"openepm-base-[0-9]{8}T[0-9]{6}Z-[0-9]+", bundle_names[0]):
            raise PhaseError("epmctl backup did not report one valid bundle")
        bundle_name = bundle_names[0]
        after = {item.name for item in export_root.iterdir()
                 if item.is_dir() and not item.is_symlink()}
        if after - before != {bundle_name}:
            raise PhaseError("backup did not create exactly one new bundle")
        backup = export_root / bundle_name
        if backup.is_symlink() or not backup.is_dir():
            raise PhaseError("reported backup bundle is not a regular directory")
        backup_manifest = load(backup / "manifest.json", "backup manifest")
        payloads = backup_manifest.get("payloads")
        maximum = context.get("backupMaximumBytes")
        if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum <= 0:
            raise PhaseError("backupMaximumBytes must be a positive integer")
        if not isinstance(payloads, list) or not payloads:
            raise PhaseError("backup manifest has no encrypted payloads")
        artifact_records = []
        total = 0
        for item in payloads:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) \
                    or not item["name"].endswith(".enc") \
                    or not isinstance(item.get("cipherSha256"), str) \
                    or not SHA256.fullmatch(item["cipherSha256"]):
                raise PhaseError("backup payload record is invalid")
            payload = child(backup, item["name"], "encrypted backup payload")
            size = payload.stat().st_size
            if size <= 0 or size > maximum or sha(payload) != item["cipherSha256"]:
                raise PhaseError("encrypted backup payload is empty, oversized or mismatched")
            total += size
            if total > maximum:
                raise PhaseError("encrypted backup artifact exceeds bounded size")
            artifact_records.append({"name": item["name"],
                "sha256": item["cipherSha256"], "sizeBytes": size})
        artifact_sha = hashlib.sha256(json.dumps(artifact_records, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        emit(phase, backup={"bundle": bundle_name,
            "sourceHostIdentity": host_identity(),
            "preBackupPopulatedSignature": population["signature"],
            "manifestSha256": sha(backup / "manifest.json"),
            "encryptedArtifactSha256": artifact_sha,
            "encryptedPayloadCount": len(artifact_records), "totalBytes": total})
        return

    images = validate_images(context)
    if phase == "native-architecture-proof":
        architecture = native_architecture()
        for name, digest in images.items():
            raw = json.loads(command(["docker", "image", "inspect", digest]))
            if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], dict):
                raise PhaseError(f"invalid image inspection: {name}")
            if "linux/" + str(raw[0].get("Architecture")) != architecture:
                raise PhaseError(f"image is not native architecture: {name}")
        emit(phase, native={"architecture": architecture,
            "sourceTreeSha256": bundle["sourceTreeSha256"], "imageDigests": images})
        return
    if phase == "storage-retirement":
        for name, digest in images.items():
            if name == "proxy":
                continue
            if name == "builder":
                command(["docker", "run", "--rm", "--read-only", "--network", "none",
                    "--entrypoint", "python", digest,
                    "/usr/local/bin/openepm-sandbox-runtime-check", "--probe-current-runtime", "/"])
                continue
            command(["docker", "run", "--rm", "--read-only", "--network", "none",
                "--entrypoint", "/usr/local/bin/openepm-runtime-check", digest]
                + (["--require-published-skill"] if name in {"application", "operations"} else []))
        proxy = scan_proxy_retirement(images["proxy"],
            context.get("proxyRetirementMaximumBytes"))
        emit(phase, storageRetirement={"scannedImages": sorted(images),
            "prohibitedMatches": 0, "scannerExitCode": 0,
            "proxyScratchFiles": proxy["files"],
            "proxyBinarySha256": proxy["binarySha256"],
            "proxyCertificateSha256": proxy["certificateSha256"]})
        return
    if phase == "database-version-read":
        container = text_field(context, "databaseContainer")
        user = text_field(context, "databaseUser")
        database = text_field(context, "databaseName")
        base = ["docker", "exec", container, "psql", "-U", user, "-d", database]
        postgresql = command(base + ["--version"])
        extension = command(base + ["-Atqc", "SELECT extversion FROM pg_extension WHERE extname='pg_duckdb'"])
        if not extension:
            raise PhaseError("pg_duckdb is not installed")
        emit(phase, databaseVersions={"postgresql": postgresql,
            "pgDuckdb": "pg_duckdb " + extension, "readFromRunningDatabase": True})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True)
    parser.add_argument("--context", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        execute(arguments.phase, arguments.context)
    except (OSError, json.JSONDecodeError, PhaseError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
