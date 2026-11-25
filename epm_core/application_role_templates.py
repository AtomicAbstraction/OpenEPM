"""Shipped role proposals and the local choices retained across explicit adoption."""

from __future__ import annotations

from .application_authorization_actions import ACTION_SCOPE_KINDS

STARTER_TEMPLATES = {
    "data-reader": (1, "Data Reader", ("application.enter", "metadata.browse", "facts.read")),
    "contributor": (
        1,
        "Contributor",
        ("application.enter", "metadata.browse", "facts.read", "facts.write"),
    ),
    "access-reviewer": (1, "Access Reviewer", ("application.enter", "access.review")),
}


def published_templates():
    return [
        {"templateId": key, "version": version, "name": name, "actions": sorted(actions)}
        for key, (version, name, actions) in sorted(STARTER_TEMPLATES.items())
    ]


def adopt(item, prior):
    latest = STARTER_TEMPLATES.get(item["templateId"])
    if latest is None or item["templateVersion"] != latest[0]:
        raise ValueError("APPLICATION_ROLE_TEMPLATE_VERSION_UNAVAILABLE")
    version, upstream_name, upstream_actions = latest
    if not upstream_actions or any(
        a not in ACTION_SCOPE_KINDS or a.startswith("delegate.") for a in upstream_actions
    ):
        raise ValueError("APPLICATION_ROLE_TEMPLATE_INVALID")
    origin = (prior or {}).get("templateOrigin")
    if prior and (not origin or origin["templateId"] != item["templateId"]):
        raise ValueError("APPLICATION_ROLE_TEMPLATE_ROLE_ID_IN_USE")
    if origin and (
        origin["version"] > version
        or (
            origin["version"] == version
            and (
                origin["upstreamName"] != upstream_name
                or origin["upstreamActions"] != sorted(upstream_actions)
            )
        )
    ):
        raise ValueError("APPLICATION_ROLE_TEMPLATE_CONTENT_CONFLICT")
    metadata = {
        "templateId": item["templateId"],
        "version": version,
        "upstreamName": upstream_name,
        "upstreamActions": sorted(upstream_actions),
        "nameOverridden": bool(origin and origin["nameOverridden"]),
        "addedActions": list(origin["addedActions"] if origin else []),
        "removedActions": list(origin["removedActions"] if origin else []),
    }
    actions = sorted(
        (set(upstream_actions) | set(metadata["addedActions"])) - set(metadata["removedActions"])
    )
    if (
        not actions
        or len(actions) > 256
        or any(action not in ACTION_SCOPE_KINDS for action in actions)
    ):
        raise ValueError("APPLICATION_ROLE_TEMPLATE_ACTIONS_UNAVAILABLE")
    return {
        "roleId": item["roleId"],
        "name": prior["name"] if metadata["nameOverridden"] else upstream_name,
        "actions": actions,
        "templateOrigin": metadata,
    }


def retain_customizations(prior, proposed):
    origin = prior.get("templateOrigin") if prior else None
    if not origin:
        return None
    added = set(proposed["actions"]) - set(prior["actions"])
    removed = set(prior["actions"]) - set(proposed["actions"])
    # Keep the local decision even if a later upstream release temporarily
    # happens to make the same one. A subsequent local edit replaces it.
    return {
        **origin,
        "nameOverridden": (
            proposed["name"] != origin["upstreamName"]
            if proposed["name"] != prior["name"]
            else origin["nameOverridden"]
        ),
        "addedActions": sorted((set(origin["addedActions"]) | added) - removed),
        "removedActions": sorted((set(origin["removedActions"]) | removed) - added),
    }
