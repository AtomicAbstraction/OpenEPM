"""Planning-duty discovery for a verified application caller."""


def group_workflow_role_unbound(db, scope, identity, access):
    """Whether an active policy precludes all new planning writes for this caller.

    This is a coarse admission check for requests without coordinates. Publication
    separately evaluates the active policy, exact cell and same-assignment rights.
    The access decision supplies the current intersection of signed and live groups.
    """
    if access.authorization_model != 'group_assignments':
        return False
    row = db.execute("""SELECT epm.caller_planning_duty_unbound(%s,%s::text[]) AS unbound
        WHERE (current_setting('epm.workspace_id',true),current_setting('epm.application_id',true))=(%s,%s)""",
        (identity.issuer, list(access.groups), scope.workspace_id, scope.application_id)).fetchone()
    return row is None or row['unbound']
