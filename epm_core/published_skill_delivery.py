"""Immutable Open EPM skill publication and consent-only MCP bootstrap.

The server publishes bytes.  It never writes a client's filesystem and never
treats reading instructions as business authorization.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from threading import Lock
from typing import Literal

from mcp.server.elicitation import (
    AcceptedElicitation, CancelledElicitation, DeclinedElicitation,
    ElicitationResult,
)
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.resolve import Elicit
from pydantic import BaseModel


SKILL_NAME = "multidimensional-cube-harness"
SKILL_TITLE = "Multidimensional Cube Harness"
SKILL_SHA256 = "822c998f1762fbd306750af43a542a701fc0d3ef3cb6bcd1ac9053df086123ef"
SKILL_URI = f"skill://openepm/{SKILL_NAME}"
MANIFEST_URI = f"skill://openepm/{SKILL_NAME}/manifest"
CHUNK_SIZE = 16_384
MAX_BYTES = 1_000_000
COMPATIBILITY = {
    "target": "Open EPM PostgreSQL V2",
    "mcpProtocolMinimum": "2025-11-25",
    "modernProtocol": "2026-07-28",
    "clientRequirement": "resources or read_openepm_published_skill tool",
}
_CONTEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_ACKNOWLEDGED_STATES = frozenset({
    "install_requested", "review_requested", "reviewed", "not_now",
    "declined", "cancelled", "installed", "verified",
})
_MAX_CONTEXTS = 4096
_offer_states: OrderedDict[tuple[str, str], str] = OrderedDict()
_offer_lock = Lock()
_snapshot_lock = Lock()
_snapshot: PublishedSkill | None = None


class SkillDeliveryError(RuntimeError):
    pass


class SkillInstallChoice(BaseModel):
    choice: Literal["install", "review", "not_now"]


@dataclass(frozen=True)
class SkillOfferBypass:
    reason: Literal["acknowledged", "unsupported"]


SkillInstallOutcome = ElicitationResult[SkillInstallChoice]


@dataclass(frozen=True)
class PublishedSkill:
    content: str
    content_bytes: bytes
    digest: str
    size: int
    chunks: tuple[str, ...]

    def manifest(self) -> dict:
        return {
            "format": "openepm-published-skill-v1",
            "name": SKILL_NAME,
            "title": SKILL_TITLE,
            "uri": SKILL_URI,
            "manifestUri": MANIFEST_URI,
            "mimeType": "text/markdown; charset=utf-8",
            "digest": self.digest,
            "digestAlgorithm": "sha256",
            "sizeBytes": self.size,
            "chunkCharacters": CHUNK_SIZE,
            "chunkCount": len(self.chunks),
            "compatibility": COMPATIBILITY,
            "localInstallPerformed": False,
            "runtimeActivationPerformed": False,
        }


def canonical_skill_path(root: Path | None = None) -> Path:
    base = root if root is not None else Path(__file__).resolve().parents[1]
    return base / "docs" / "skills" / SKILL_NAME / "SKILL.md"


def load_published_skill(root: Path | None = None) -> PublishedSkill:
    path = canonical_skill_path(root)
    try:
        content_bytes = path.read_bytes()
    except OSError as error:
        raise SkillDeliveryError("OPEN_EPM_PUBLISHED_SKILL_UNAVAILABLE") from error
    if not content_bytes or len(content_bytes) > MAX_BYTES:
        raise SkillDeliveryError("OPEN_EPM_PUBLISHED_SKILL_SIZE_INVALID")
    try:
        content = content_bytes.decode("utf-8")
    except UnicodeError as error:
        raise SkillDeliveryError("OPEN_EPM_PUBLISHED_SKILL_ENCODING_INVALID") from error
    expected = "---\nname: " + SKILL_NAME + "\n"
    if not content.startswith(expected) or "\x00" in content:
        raise SkillDeliveryError("OPEN_EPM_PUBLISHED_SKILL_CONTRACT_INVALID")
    # Globally published instructions must never bind to an author's machine or
    # private issue tracker.  This is deliberately narrow: it checks deployed
    # payload risks, not harmless discussion of privacy or authorization.
    forbidden = ("/Users/", "file://", "github.com/users/AtomicAbstraction/projects/")
    if any(value in content for value in forbidden):
        raise SkillDeliveryError("OPEN_EPM_PUBLISHED_SKILL_PRIVATE_VALUE")
    chunks = tuple(content[index:index + CHUNK_SIZE]
                   for index in range(0, len(content), CHUNK_SIZE))
    return PublishedSkill(
        content=content,
        content_bytes=content_bytes,
        digest="sha256:" + hashlib.sha256(content_bytes).hexdigest(),
        size=len(content_bytes),
        chunks=chunks,
    )


def published_skill_snapshot() -> PublishedSkill:
    """Return the process-lifetime release payload, rejecting an unsealed build."""
    global _snapshot
    with _snapshot_lock:
        if _snapshot is None:
            candidate = load_published_skill()
            if candidate.digest != "sha256:" + SKILL_SHA256:
                raise SkillDeliveryError("OPEN_EPM_PUBLISHED_SKILL_RELEASE_MISMATCH")
            _snapshot = candidate
        return _snapshot


def bootstrap_instructions(base: str) -> str:
    skill = published_skill_snapshot()
    manifest = skill.manifest()
    return (base.rstrip() + "\n\n" +
        f"Open EPM makes the current {SKILL_TITLE} available as "
        f"{SKILL_URI} ({manifest['digest']}, {manifest['sizeBytes']} bytes). "
        "On the first eligible interaction, tell the user it is available and "
        "offer Install, Review, or Not now. Say delivered only after the complete "
        "bytes were returned and verified. The server cannot install client files. "
        "Use the resource or read_openepm_published_skill fallback; unrelated "
        "authorized operations remain available after decline or unsupported elicitation.")


def register_skill_resources(server) -> None:
    skill = published_skill_snapshot()

    @server.resource(
        SKILL_URI, name=SKILL_NAME, title=SKILL_TITLE,
        description="Complete current Open EPM multidimensional harness skill.",
        mime_type="text/markdown; charset=utf-8",
        meta={"digest": skill.digest,
              "sizeBytes": skill.size},
    )
    def published_skill_content() -> str:
        return skill.content

    @server.resource(
        MANIFEST_URI, name=SKILL_NAME + "-manifest",
        title=SKILL_TITLE + " manifest",
        description="Current digest, size, compatibility and chunk metadata.",
        mime_type="application/json",
    )
    def published_skill_manifest() -> dict:
        return skill.manifest()


def read_published_skill(part: str, chunk_index: int | None = None) -> dict:
    skill = published_skill_snapshot()
    manifest = skill.manifest()
    if part == "manifest":
        if chunk_index is not None:
            raise ValueError("OPEN_EPM_SKILL_CHUNK_NOT_ALLOWED_FOR_MANIFEST")
        return {"manifest": manifest}
    if part == "content":
        if chunk_index is not None:
            raise ValueError("OPEN_EPM_SKILL_CHUNK_NOT_ALLOWED_FOR_CONTENT")
        return {"manifest": manifest, "content": skill.content,
                "complete": True}
    if part != "chunk" or type(chunk_index) is not int:
        raise ValueError("OPEN_EPM_SKILL_READ_REQUEST_INVALID")
    if not 0 <= chunk_index < len(skill.chunks):
        raise ValueError("OPEN_EPM_SKILL_CHUNK_OUT_OF_RANGE")
    return {"manifest": manifest, "chunkIndex": chunk_index,
            "content": skill.chunks[chunk_index], "complete": False,
            "documentComplete": False,
            "finalChunk": chunk_index == len(skill.chunks) - 1}


def _headers(ctx: Context) -> dict[str, str]:
    try:
        source = ctx.headers or {}
    except (AttributeError, ValueError):
        source = {}
    return {str(key).lower(): str(value) for key, value in source.items()}


def _client_context(headers: dict[str, str]) -> str | None:
    value = headers.get("x-openepm-client-installation-context", "")
    return value if _CONTEXT.fullmatch(value) else None


def _offer_context(ctx: Context) -> str | None:
    explicit = _client_context(_headers(ctx))
    if explicit is not None:
        return "client:" + explicit
    # Connection-local identity is not a machine fingerprint and is never
    # persisted. It prevents repeated prompts during one legacy MCP session;
    # a new stateless connection must acknowledge by version/digest headers.
    try:
        session = ctx.session
    except (AttributeError, ValueError):
        return None
    if session is None:
        return None
    # The SDK constructs a request-scoped ServerSession wrapper, while its
    # Connection is stable for the underlying stdio/SSE/HTTP session.
    connection = getattr(session, "_connection", session)
    return "session:" + str(id(connection))


def _acknowledged(ctx: Context, skill: PublishedSkill) -> bool:
    headers = _headers(ctx)
    digest = headers.get("x-openepm-skill-digest")
    state = headers.get("x-openepm-skill-state")
    if digest == skill.digest \
            and state in _ACKNOWLEDGED_STATES:
        return True
    context = _offer_context(ctx)
    if context is None:
        return False
    key = (context, skill.digest)
    with _offer_lock:
        return key in _offer_states


def _supports_form_elicitation(ctx: Context) -> bool:
    try:
        capabilities = ctx.client_capabilities
        elicitation = capabilities.elicitation if capabilities is not None else None
        return elicitation is not None and (
            getattr(elicitation, "form", None) is not None
            or getattr(elicitation, "url", None) is None)
    except (AttributeError, ValueError):
        return False


def resolve_skill_install_offer(
        ctx: Context) -> Elicit[SkillInstallChoice] | SkillOfferBypass:
    skill = published_skill_snapshot()
    if _acknowledged(ctx, skill):
        return SkillOfferBypass(reason="acknowledged")
    if not _supports_form_elicitation(ctx):
        return SkillOfferBypass(reason="unsupported")
    message = (
        f"Open EPM makes the current {SKILL_TITLE} available "
        f"({skill.digest}, {skill.size} bytes) from this authenticated server. "
        "It guides multidimensional discovery, migration and verification. "
        "Choose install to retrieve and verify it for this client, review to "
        f"inspect {MANIFEST_URI} and {SKILL_URI}, or not_now to continue without "
        "a local write. The server will not install files or activate runtimes."
    )
    return Elicit(message, SkillInstallChoice)


def record_skill_install_outcome(ctx: Context, outcome: SkillInstallOutcome) -> None:
    context = _offer_context(ctx)
    if context is None:
        return
    skill = published_skill_snapshot()
    if isinstance(outcome, AcceptedElicitation):
        if not isinstance(outcome.data, SkillInstallChoice):
            return
        state = {"install": "install_requested",
                 "review": "review_requested",
                 "not_now": "not_now"}[outcome.data.choice]
    elif isinstance(outcome, DeclinedElicitation):
        state = "declined"
    elif isinstance(outcome, CancelledElicitation):
        state = "cancelled"
    else:
        return
    key = (context, skill.digest)
    with _offer_lock:
        _offer_states[key] = state
        _offer_states.move_to_end(key)
        while len(_offer_states) > _MAX_CONTEXTS:
            _offer_states.popitem(last=False)


def reset_offer_state_for_tests() -> None:
    with _offer_lock:
        _offer_states.clear()


def offer_state_for_tests(ctx: Context) -> str | None:
    context = _offer_context(ctx)
    if context is None:
        return None
    skill = published_skill_snapshot()
    with _offer_lock:
        return _offer_states.get((context, skill.digest))
