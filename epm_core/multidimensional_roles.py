"""Domain-neutral dimension-role contract for one programmable cube.

Roles describe authoring ergonomics and validation shape.  They never enable
planning, consolidation, currency or another business engine.
"""

from __future__ import annotations


REQUIRED_PROGRAMMABLE_ROLES = frozenset(
    {"Account", "Entity", "Year", "Period", "View", "Value"}
)
REPEATABLE_PROGRAMMABLE_ROLE = "Custom"
PROGRAMMABLE_ROLES = REQUIRED_PROGRAMMABLE_ROLES | {
    REPEATABLE_PROGRAMMABLE_ROLE
}

# Existing databases and admitted jobs may contain these roles.  They remain
# accepted during the compatibility window but are not part of the fresh
# single-application blueprint and confer no product capability.
LEGACY_COMPATIBILITY_ROLES = frozenset(
    {"Scenario", "ICP", "Currency", "DataType", "Movement"}
)
ACCEPTED_MODEL_ROLES = PROGRAMMABLE_ROLES | LEGACY_COMPATIBILITY_ROLES


def validate_model_role(role: object, *, allow_legacy: bool = True) -> str | None:
    if role is None:
        return None
    allowed = ACCEPTED_MODEL_ROLES if allow_legacy else PROGRAMMABLE_ROLES
    if not isinstance(role, str) or role not in allowed:
        raise ValueError("MODEL_ROLE_INVALID")
    return role


def validate_programmable_blueprint(roles: list[object]) -> dict[str, object]:
    """Validate role cardinality without interpreting business semantics."""
    if not isinstance(roles, list):
        raise ValueError("PROGRAMMABLE_BLUEPRINT_ROLES_INVALID")
    normalized = [validate_model_role(role, allow_legacy=False) for role in roles]
    if any(role is None for role in normalized):
        raise ValueError("PROGRAMMABLE_BLUEPRINT_ROLE_REQUIRED")
    counts = {role: normalized.count(role) for role in PROGRAMMABLE_ROLES}
    missing = sorted(role for role in REQUIRED_PROGRAMMABLE_ROLES if counts[role] == 0)
    duplicates = sorted(role for role in REQUIRED_PROGRAMMABLE_ROLES if counts[role] > 1)
    if missing:
        raise ValueError("PROGRAMMABLE_BLUEPRINT_REQUIRED_ROLES_MISSING:" + ",".join(missing))
    if duplicates:
        raise ValueError("PROGRAMMABLE_BLUEPRINT_ROLE_AMBIGUOUS:" + ",".join(duplicates))
    return {
        "requiredRoles": sorted(REQUIRED_PROGRAMMABLE_ROLES),
        "customDimensionCount": counts[REPEATABLE_PROGRAMMABLE_ROLE],
    }
