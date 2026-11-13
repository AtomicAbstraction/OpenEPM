"""Domain-neutral dimension-role contract for one programmable cube.

Roles describe authoring ergonomics and validation shape.  They never enable
planning, consolidation, currency or another business engine.
"""

from __future__ import annotations


PROGRAMMABLE_BLUEPRINT_VERSION = 2

# Canonical source for fresh-application discovery and creation. The immutable
# SQL descriptor in migration 0282 is verified against this complete contract
# before creation, so a mixed software/schema release fails without effects.
_DIMENSION_DEFAULTS = (
    ("Account", "Account", "Accounts, measures, KPIs and goals.",
     "Application-defined financial or statistical accounts, measures, key performance indicators and goals. "
     "Their calculations and aggregation behavior are defined explicitly by the application's rules."),
    ("Entity", "Entity", "Business objects and organizational units.",
     "The business objects or organizational units modeled by this application. Hierarchies describe their "
     "relationships; aggregation, consolidation and other behavior must be defined explicitly."),
    ("Year", "Year", "Year-level time classification.",
     "The application's year-level time classification. Members and calendar relationships are defined by "
     "the application; no particular fiscal calendar is assumed."),
    ("Period", "Period", "Periods in the application's timeline.",
     "Periods within the application's timeline or calendar. Their order, duration and relationship to years "
     "are defined by the application."),
    ("View", "View", "Interpretation or presentation of values.",
     "The application's interpretation or presentation of values. Any period, cumulative or other behavior "
     "is defined explicitly by its rules rather than inferred from a member name."),
    ("Value", "Value", "Application-defined value categories or layers.",
     "Value categories or layers defined by the application. Their meaning and transformations are expressed "
     "by the model and its rules; no currency or accounting behavior is activated automatically."),
    ("Scenario", "Scenario", "Application-defined alternatives and assumptions.",
     "Alternatives chosen by the application, such as Actual, Budget, Forecast or Simulation. These are "
     "examples rather than required members; the dimension does not create experimental applications."),
    ("DataType", "Data Type", "Application-defined information classification.",
     "A classification chosen by the application, such as numeric, text, commentary, source or input category. "
     "Members do not coerce stored values or replace the platform's numeric, text and supporting-detail validation."),
)
REQUIRED_PROGRAMMABLE_ROLES = frozenset(row[0] for row in _DIMENSION_DEFAULTS)
REPEATABLE_PROGRAMMABLE_ROLE = "Custom"
PROGRAMMABLE_ROLES = REQUIRED_PROGRAMMABLE_ROLES | {
    REPEATABLE_PROGRAMMABLE_ROLE
}

# Existing databases and admitted jobs may contain these roles.  They remain
# accepted during the compatibility window but are not part of the fresh
# single-application blueprint and confer no product capability.
LEGACY_COMPATIBILITY_ROLES = frozenset(
    {"ICP", "Currency", "Movement"}
)
ACCEPTED_MODEL_ROLES = PROGRAMMABLE_ROLES | LEGACY_COMPATIBILITY_ROLES


def programmable_dimension_blueprint() -> tuple[dict[str, str], ...]:
    """Return detached editable metadata defaults without business members."""
    return tuple({
        "dimensionId": role,
        "name": name,
        "modelRole": role,
        "semanticRole": "Core entity" if role == "Entity" else "Context",
        "density": "Sparse",
        "shortDescription": short,
        "detailedDescription": detailed,
    } for role, name, short, detailed in _DIMENSION_DEFAULTS)


def programmable_application_blueprint() -> dict[str, object]:
    return {"version": PROGRAMMABLE_BLUEPRINT_VERSION,
            "dimensions": list(programmable_dimension_blueprint())}


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
