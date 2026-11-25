"""Named hierarchy identity and membership over the existing graph engine.

This module has no independent transaction or publication path. Metadata store
mutations provide current authority, revision lock, exact replay and receipt.
"""
from __future__ import annotations

from psycopg import sql
from psycopg.types.json import Jsonb

from .postgres_access import AccessDenied
from .postgres_dimensional_scope import (
    metadata_dimension_visible, metadata_page_token, metadata_reference_read_sql,
    reject_mixed_metadata_reads, require_metadata_page_token,
)
from .postgres_processing_limits import configure_statement_timeout

PREFIX = "metadata.hierarchy."
MUTATIONS = {
    PREFIX + "create": {"dimensionId", "hierarchyId", "name", "membershipMode", "isDefault"},
    PREFIX + "rename": {"dimensionId", "hierarchyId", "name"},
    PREFIX + "members.set": {"dimensionId", "hierarchyId", "members"},
    PREFIX + "default.set": {"dimensionId", "hierarchyId"},
    PREFIX + "status.set": {"dimensionId", "hierarchyId", "status"},
}
READS = frozenset((PREFIX + "list", PREFIX + "read", PREFIX + "members.list"))


def identifier(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 200
            or value != value.strip() or any(ord(c) < 32 for c in value)):
        raise ValueError("HIERARCHY_ID_INVALID")
    return value


def catalog():
    descriptions = {
        "dimensionId": "active stable dimension ID", "hierarchyId": "stable named hierarchy ID",
        "name": "display name", "membershipMode": "explicit or all_active",
        "isDefault": "explicit boolean; first hierarchy must be the default",
        "members": "1–500 unique {memberId,status} explicit node memberships; omitted nodes unchanged",
        "status": "Active or Inactive",
    }
    result = {name: {"mode": "atomic_write", "permission": "admin",
        "arguments": {**{key: descriptions[key] for key in sorted(fields)},
            "expectedMetadataRevision": "current nonnegative metadata revision"},
        "result": "atomic receipt with operationId, committedRevision and changedCount", "previewRequired": False,
        "idempotencyRequired": True, "workClass": "short"}
        for name, fields in MUTATIONS.items()}
    for name in READS:
        fields = {"dimensionId": descriptions["dimensionId"]}
        if name != PREFIX + "list":
            fields["hierarchyId"] = descriptions["hierarchyId"]
        result[name] = {"mode": "read", "permission": "read", "arguments": fields,
            "optionalArguments": ({"limit": "1–500", "afterId": "prior stable row ID",
                "expectedMetadataRevision": "required on continuation",
                "expectedPageToken": "prior nextPageToken when returned"}
                if name != PREFIX + "read" else {}),
            "result": "named hierarchy metadata or bounded node membership page with current revision",
            "previewRequired": False, "idempotencyRequired": False, "workClass": "short"}
    return result


def compile_mutation(function, args):
    if (function not in MUTATIONS or type(args) is not dict
            or set(args) != MUTATIONS[function] | {"expectedMetadataRevision"}):
        raise ValueError("HIERARCHY_MUTATION_ARGUMENTS_INVALID")
    payload = {key: value for key, value in args.items() if key != "expectedMetadataRevision"}
    identifier(payload["dimensionId"]); identifier(payload["hierarchyId"])
    if "name" in payload:
        identifier(payload["name"])
    if function.endswith("create"):
        if (payload["membershipMode"] not in ("explicit", "all_active")
                or type(payload["isDefault"]) is not bool):
            raise ValueError("HIERARCHY_DEFINITION_INVALID")
    if function.endswith("status.set") and payload["status"] not in ("Active", "Inactive"):
        raise ValueError("HIERARCHY_STATUS_INVALID")
    if function.endswith("members.set"):
        members = payload["members"]
        if type(members) is not list or not 1 <= len(members) <= 500:
            raise ValueError("HIERARCHY_MEMBERS_INVALID")
        seen = set()
        for member in members:
            if type(member) is not dict or set(member) != {"memberId", "status"}:
                raise ValueError("HIERARCHY_MEMBERS_INVALID")
            identifier(member["memberId"])
            if member["memberId"] in seen or member["status"] not in ("Active", "Inactive"):
                raise ValueError("HIERARCHY_MEMBERS_INVALID")
            seen.add(member["memberId"])
        payload["members"] = sorted(members, key=lambda item: item["memberId"])
    return function.removeprefix("metadata."), payload


def resolve_hierarchy(db, scope, dimension, hierarchy_id=None, *, create_default=False,
                      allow_alias=False, active=True):
    return resolve_hierarchy_reference(db, scope, dimension, hierarchy_id,
        create_default=create_default, allow_alias=allow_alias, active=active)[0]


def resolve_hierarchy_reference(db, scope, dimension, hierarchy_id=None, *, create_default=False,
                                allow_alias=False, active=True):
    """Resolve through the same rules, retaining whether default lookup was used."""
    identifier(dimension)
    if hierarchy_id is not None:
        identifier(hierarchy_id)
    keys = (scope.workspace_id, scope.application_id, dimension)
    row = db.execute("""SELECT hierarchy_id,name,status,membership_mode,is_default
        FROM epm.hierarchy_definition WHERE workspace_id=%s AND application_id=%s
        AND dimension_id=%s AND ((%s::text IS NULL AND is_default) OR hierarchy_id=%s)""",
        (*keys, hierarchy_id, hierarchy_id)).fetchone()
    if row is None and allow_alias and hierarchy_id in ("primary", dimension):
        return resolve_hierarchy_reference(db, scope, dimension, None, active=active)
    if row is None and hierarchy_id is None and create_default:
        row = db.execute("""INSERT INTO epm.hierarchy_definition
            (workspace_id,application_id,dimension_id,hierarchy_id,name,membership_mode,is_default)
            VALUES (%s,%s,%s,'primary','Primary','all_active',true)
            RETURNING hierarchy_id,name,status,membership_mode,is_default""", keys).fetchone()
    if row is None or (active and row["status"] != "Active"):
        raise ValueError("HIERARCHY_UNAVAILABLE")
    return dict(row), hierarchy_id is None


def graph_members(db, scope, dimension, hierarchy):
    return [row["member_id"] for row in db.execute("""SELECT m.member_id FROM epm.member m
        WHERE m.workspace_id=%s AND m.application_id=%s AND m.dimension_id=%s AND m.status='Active'
          AND (%s='all_active' OR EXISTS(SELECT 1 FROM epm.hierarchy_member n
            WHERE n.workspace_id=m.workspace_id AND n.application_id=m.application_id
              AND n.dimension_id=m.dimension_id AND n.member_id=m.member_id
              AND n.hierarchy_id=%s AND n.status='Active'))
        ORDER BY m.member_id LIMIT 5001""", (scope.workspace_id, scope.application_id,
            dimension, hierarchy["membership_mode"], hierarchy["hierarchy_id"])).fetchall()]


def insert_relationship(db, scope, *, dimension_id, hierarchy_id, relationship_id,
                        parent_member_id, child_member_id, name=None,
                        short_description='', detailed_description='', status='Active'):
    """Insert a validated placement within the caller's metadata transaction."""
    db.execute('''INSERT INTO epm.relationship
        (workspace_id, application_id, relationship_id, dimension_id,
         parent_member_id, child_member_id, name, short_description,
         detailed_description, hierarchy_id, status)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
        (scope.workspace_id, scope.application_id, relationship_id, dimension_id,
         parent_member_id, child_member_id, relationship_id if name is None else name,
         short_description, detailed_description, hierarchy_id, status))


def apply_mutation(db, scope, kind, payload):
    keys = (scope.workspace_id, scope.application_id, payload["dimensionId"])
    dimension = db.execute("""SELECT 1 FROM epm.dimension WHERE workspace_id=%s
        AND application_id=%s AND dimension_id=%s AND status='Active'""", keys).fetchone()
    if not dimension:
        raise ValueError("ACTIVE_DIMENSION_REQUIRED")
    identity = (*keys, payload["hierarchyId"])
    if kind == "hierarchy.create":
        current = db.execute("""SELECT hierarchy_id FROM epm.hierarchy_definition
            WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s AND is_default""", keys).fetchone()
        if (current is None) != payload["isDefault"]:
            raise ValueError("HIERARCHY_DEFAULT_REQUIRES_EXPLICIT_SWITCH" if current else "HIERARCHY_DEFAULT_REQUIRED")
        db.execute("""INSERT INTO epm.hierarchy_definition(workspace_id,application_id,dimension_id,
            hierarchy_id,name,membership_mode,is_default) VALUES (%s,%s,%s,%s,%s,%s,%s)""",
            (*identity, payload["name"], payload["membershipMode"], payload["isDefault"]))
        return
    hierarchy = resolve_hierarchy(db, scope, payload["dimensionId"], payload["hierarchyId"], active=False)
    if kind == "hierarchy.rename":
        if hierarchy["name"] == payload["name"]:
            raise ValueError("HIERARCHY_NAME_UNCHANGED")
        db.execute("""UPDATE epm.hierarchy_definition SET name=%s,updated_at=transaction_timestamp()
            WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s AND hierarchy_id=%s""",
            (payload["name"], *identity))
    elif kind == "hierarchy.default.set":
        if hierarchy["status"] != "Active":
            raise ValueError("ACTIVE_HIERARCHY_REQUIRED")
        if hierarchy["is_default"]:
            raise ValueError("HIERARCHY_DEFAULT_UNCHANGED")
        db.execute("""UPDATE epm.hierarchy_definition SET is_default=false,updated_at=transaction_timestamp()
            WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s AND is_default""", keys)
        db.execute("""UPDATE epm.hierarchy_definition SET is_default=true,updated_at=transaction_timestamp()
            WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s AND hierarchy_id=%s""", identity)
    elif kind == "hierarchy.status.set":
        if hierarchy["is_default"] and payload["status"] != "Active":
            raise ValueError("DEFAULT_HIERARCHY_REQUIRED")
        if hierarchy["status"] == payload["status"]:
            raise ValueError("HIERARCHY_STATUS_UNCHANGED")
        db.execute("""UPDATE epm.hierarchy_definition SET status=%s,updated_at=transaction_timestamp()
            WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s AND hierarchy_id=%s""",
            (payload["status"], *identity))
    elif kind == "hierarchy.members.set":
        if hierarchy["status"] != "Active" or hierarchy["membership_mode"] != "explicit":
            raise ValueError("EXPLICIT_ACTIVE_HIERARCHY_REQUIRED")
        rows = payload["members"]
        invalid = db.execute("""SELECT 1 FROM jsonb_to_recordset(%s::jsonb) i("memberId" text,status text)
            LEFT JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s
              AND m.dimension_id=%s AND m.member_id=i."memberId"
            WHERE m.member_id IS NULL OR (i.status='Active' AND m.status<>'Active') LIMIT 1""",
            (Jsonb(rows), *keys)).fetchone()
        if invalid:
            raise ValueError("HIERARCHY_MEMBER_UNAVAILABLE")
        inactive = [row["memberId"] for row in rows if row["status"] == "Inactive"]
        if inactive and db.execute("""SELECT 1 FROM epm.relationship WHERE workspace_id=%s
            AND application_id=%s AND dimension_id=%s AND hierarchy_id=%s AND status='Active'
            AND (parent_member_id=ANY(%s::text[]) OR child_member_id=ANY(%s::text[])) LIMIT 1""",
            (*identity, inactive, inactive)).fetchone():
            raise ValueError("HIERARCHY_MEMBER_HAS_ACTIVE_RELATIONSHIPS")
        db.execute("""INSERT INTO epm.hierarchy_member(workspace_id,application_id,dimension_id,hierarchy_id,member_id,status)
            SELECT %s,%s,%s,%s,i."memberId",i.status FROM jsonb_to_recordset(%s::jsonb) i("memberId" text,status text)
            ON CONFLICT(workspace_id,application_id,dimension_id,hierarchy_id,member_id)
            DO UPDATE SET status=EXCLUDED.status""", (*identity, Jsonb(rows)))
    else:
        raise ValueError("HIERARCHY_MUTATION_UNSUPPORTED")


def read(db, scope, function, args, revision, *, authority, identity, cursor_secret):
    required = {"dimensionId"} | ({"hierarchyId"} if function != PREFIX + "list" else set())
    optional = {"limit", "afterId", "expectedMetadataRevision", "expectedPageToken"} if function != PREFIX + "read" else set()
    if type(args) is not dict or not required <= set(args) or set(args) - required - optional:
        raise ValueError("HIERARCHY_READ_ARGUMENTS_INVALID")
    dimension = identifier(args["dimensionId"])
    limit, after = args.get("limit", 100), args.get("afterId")
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("HIERARCHY_PAGE_INVALID")
    expected = args.get("expectedMetadataRevision")
    if after is not None:
        identifier(after)
        if expected is None:
            raise ValueError("METADATA_PAGE_REVISION_REQUIRED")
    if expected is not None and (type(expected) is not int or expected != revision):
        raise ValueError("STALE_METADATA_REVISION")
    if not metadata_dimension_visible(db, scope, authority, dimension):
        raise ValueError("HIERARCHY_UNAVAILABLE")
    keys = (scope.workspace_id, scope.application_id, dimension)
    is_membership = function == PREFIX + "members.list"
    hierarchy_id = None
    if is_membership:
        hierarchy = resolve_hierarchy(db, scope, dimension, args["hierarchyId"], active=False)
        hierarchy_id = hierarchy["hierarchy_id"]
    context = [function, *keys, identity.issuer, identity.subject_id, hierarchy_id,
               limit, revision, authority.scope_digest]
    require_metadata_page_token(authority, cursor_secret, context, after, args.get("expectedPageToken"))
    configure_statement_timeout(db, 30_000)
    if is_membership:
        if hierarchy["membership_mode"] == "explicit":
            population = sql.SQL('''FROM epm.hierarchy_member h JOIN epm.member m
                USING (workspace_id,application_id,dimension_id,member_id)
                WHERE m.workspace_id=%s AND m.application_id=%s
                  AND m.dimension_id=%s AND h.hierarchy_id=%s''')
            status = sql.SQL('h.status')
            parameters = (*keys, hierarchy_id)
        else:
            population = sql.SQL('''FROM epm.member m
                WHERE m.workspace_id=%s AND m.application_id=%s
                  AND m.dimension_id=%s AND m.status='Active' ''')
            status = sql.SQL('m.status')
            parameters = keys
        visible = metadata_reference_read_sql(authority, 'm', dimension)
        if reject_mixed_metadata_reads(authority) and db.execute(
            sql.SQL('SELECT EXISTS(SELECT 1 {} AND NOT {}) AS denied').format(population, visible),
            parameters).fetchone()['denied']:
            raise AccessDenied('METADATA_DIRECTORY_SCOPE_UNAVAILABLE')
        rows = db.execute(sql.SQL('''SELECT m.member_id AS "memberId", {status} {population}
            AND {visible} AND (%s::text IS NULL OR m.member_id>%s)
            ORDER BY m.member_id LIMIT %s''').format(status=status, population=population, visible=visible),
            (*parameters, after, after, limit + 1)).fetchall()
        id_key = "memberId"
    else:
        hierarchy_id = identifier(args["hierarchyId"]) if function.endswith(".read") else None
        rows = db.execute("""SELECT h.hierarchy_id AS "hierarchyId",h.name,h.status,
            h.membership_mode AS "membershipMode",h.is_default AS "isDefault",
            s.state_token AS "stateToken",s.metadata_revision AS "builtMetadataRevision",
            coalesce(s.metadata_revision=%s,false) AS current
            FROM epm.hierarchy_definition h LEFT JOIN epm.hierarchy_state s
              USING(workspace_id,application_id,dimension_id,hierarchy_id)
            WHERE h.workspace_id=%s AND h.application_id=%s AND h.dimension_id=%s
            AND (%s::text IS NULL OR h.hierarchy_id=%s)
            AND (%s::text IS NULL OR h.hierarchy_id>%s) ORDER BY h.hierarchy_id LIMIT %s""",
            (revision, *keys, hierarchy_id, hierarchy_id, after, after, limit + 1)).fetchall()
        id_key = "hierarchyId"
        if function.endswith(".read"):
            if not rows:
                raise ValueError("HIERARCHY_UNAVAILABLE")
            return {**dict(rows[0]), "dimensionId": dimension, "metadataRevision": revision}
    more = len(rows) > limit
    page = [dict(row) for row in rows[:limit]]
    result = {"dimensionId": dimension, **({"hierarchyId": hierarchy_id} if is_membership else {}),
        "metadataRevision": revision, "rows": page,
        "hasMore": more, "nextAfterId": page[-1][id_key] if more else None}
    if authority.policy is not None:
        result["nextPageToken"] = metadata_page_token(
            cursor_secret, context, result["nextAfterId"]) if more else None
    return result


def hierarchy_references(node):
    from .member_list_contract import iter_member_list_nodes
    if not isinstance(node, dict):
        return set()
    return {item['hierarchyId'] for item in iter_member_list_nodes(node) if 'hierarchyId' in item}


def load_hierarchy_graphs(db, scope, dimension, requested_ids):
    """Load only requested graphs, retaining isolated nodes and stable edge IDs."""
    if len(requested_ids) > 128:
        raise ValueError("HIERARCHY_RESOLUTION_BUDGET")
    result = {}; canonical = {}; total = 0
    for requested in sorted(requested_ids):
        hierarchy = resolve_hierarchy(db, scope, dimension, requested, allow_alias=True)
        identity = hierarchy["hierarchy_id"]
        if identity not in canonical:
            members = graph_members(db, scope, dimension, hierarchy)
            relationships = [dict(row) for row in db.execute("""SELECT
                relationship_id AS "relationshipId",parent_member_id AS "parentMemberId",
                child_member_id AS "childMemberId" FROM epm.relationship
                WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
                AND hierarchy_id=%s AND status='Active' ORDER BY relationship_id LIMIT 10001""",
                (scope.workspace_id, scope.application_id, dimension, identity)).fetchall()]
            total += len(members) + len(relationships)
            if len(members) > 5000 or len(relationships) > 10000 or total > 100000:
                raise ValueError("HIERARCHY_RESOLUTION_BUDGET")
            canonical[identity] = {"hierarchyId": identity, "members": members,
                                   "relationships": relationships}
        result[requested] = canonical[identity]
    return result


def read_program_contract(function):
    """Public wire projection of the existing named-hierarchy readers."""
    if function not in READS:
        return None
    from .metadata_read_contract import read_contract, read_example, obj, METADATA_PAGE_TOKEN_SCHEMA
    identifier_schema = {'type': 'string', 'minLength': 1, 'maxLength': 200}
    revision = {'type': 'integer', 'minimum': 0}
    fields = {'dimensionId': identifier_schema}
    if function != PREFIX + 'list':
        fields['hierarchyId'] = identifier_schema
    required = list(fields)
    row = obj({'hierarchyId': identifier_schema, 'name': identifier_schema,
        'status': {'enum': ['Active', 'Inactive']},
        'membershipMode': {'enum': ['explicit', 'all_active']},
        'isDefault': {'type': 'boolean'}, 'stateToken': {'type': ['string', 'null']},
        'builtMetadataRevision': {'anyOf': [revision, {'type': 'null'}]},
        'current': {'type': 'boolean'}})
    base = {'dimensionId': identifier_schema, 'metadataRevision': revision}
    if function == PREFIX + 'read':
        result = obj({**row['properties'], **base})
    else:
        fields.update({'limit': {'type': 'integer', 'minimum': 1, 'maximum': 500},
            'afterId': {'anyOf': [identifier_schema, {'type': 'null'}]},
            'expectedPageToken': METADATA_PAGE_TOKEN_SCHEMA,
            'expectedMetadataRevision': {'anyOf': [revision, {'type': 'null'}]}})
        if function == PREFIX + 'members.list':
            row = obj({'memberId': identifier_schema,
                'status': {'enum': ['Active', 'Inactive']}})
            base['hierarchyId'] = identifier_schema
        result_fields = {**base, 'rows': {'type': 'array', 'maxItems': 500, 'items': row},
            'hasMore': {'type': 'boolean'},
            'nextAfterId': {'anyOf': [identifier_schema, {'type': 'null'}]}}
        result = obj({**result_fields, 'nextPageToken': {'anyOf': [METADATA_PAGE_TOKEN_SCHEMA,
                     {'type': 'null'}]}}, list(result_fields))
    arguments = obj(fields, required)
    if function != PREFIX + 'read':
        arguments['allOf'] = [{'if': {'required': ['afterId'],
            'properties': {'afterId': {'type': 'string'}}},
            'then': {'required': ['expectedMetadataRevision'],
                     'properties': {'expectedMetadataRevision': revision}}},
            {'if': {'required': ['expectedPageToken']},
             'then': {'required': ['afterId', 'expectedMetadataRevision'],
                      'properties': {'afterId': {'type': 'string'},
                                     'expectedMetadataRevision': revision}}}]
    example = {'dimensionId': 'custom-axis'}
    if function != PREFIX + 'list':
        example['hierarchyId'] = 'primary'
    return read_contract(function, arguments, result, owner='postgres_hierarchies.read',
        examples=[read_example(function, example, name='Read the selected named hierarchy',
            binding='Use a current dimension ID and, where required, the hierarchyId returned by its authorized hierarchy list.')],
        semantic_rules=[
            'Native identifiers exclude control characters and leading/trailing whitespace. Current metadata authority and revision checks remain native.',
            'The core rechecks current application access before returning a result. On METADATA_DIRECTORY_READ_AUTHORIZATION_STALE, restart the read under current access.',
            'The selected dimension and member identities require current dimensional READ. Filter mode pages only visible memberships. Strict mode refuses a mixed member population.',
            'When a page returns nextPageToken, the continuation must carry it as expectedPageToken with the original limit. Restart from the first page if the token is stale.',
            'A continuation pins the prior metadata revision. A null build state means the named hierarchy has no current built state, not an empty member set.',
            'Explicit membership and all_active membership remain distinct; inactive definitions may be inspected by these current metadata readers.'])


def write_program_contract(function):
    if function not in MUTATIONS:
        return None
    from .metadata_read_contract import metadata_mutation_receipt_schema, obj, read_contract, read_example

    identifier_schema = {'type': 'string', 'minLength': 1, 'maxLength': 200,
        'description': 'Use a nonempty value without leading or trailing whitespace or control characters.'}
    status = {'enum': ['Active', 'Inactive']}
    revision = {'type': 'integer', 'minimum': 0}
    properties = {'dimensionId': identifier_schema, 'hierarchyId': identifier_schema,
        'name': identifier_schema, 'membershipMode': {'enum': ['explicit', 'all_active']},
        'isDefault': {'type': 'boolean'}, 'status': status,
        'members': {'type': 'array', 'minItems': 1, 'maxItems': 500, 'uniqueItems': True,
            'items': obj({'memberId': identifier_schema, 'status': status})}}
    suffix = function.removeprefix(PREFIX)
    caption, values, rule = {
        'create': ('Create a named hierarchy',
            {'name': 'Alternate hierarchy', 'membershipMode': 'explicit', 'isDefault': False},
            'The first hierarchy in a dimension must be the default. For a dimension with a default, create an alternate and switch separately.'),
        'rename': ('Rename a named hierarchy', {'name': 'Alternate rollup'},
            'Select the exact existing hierarchy ID. Renaming leaves its ID and membership intact.'),
        'members.set': ('Set explicit hierarchy membership', {'members': [
            {'memberId': 'member-a', 'status': 'Active'}, {'memberId': 'member-b', 'status': 'Active'}]},
            'Use distinct member IDs in an active explicit hierarchy. The fixed core checks member availability and active relationships.'),
        'default.set': ('Switch to an active default hierarchy', {},
            'Set an active alternate as the default. The fixed core switches the old and new default together.'),
        'status.set': ('Deactivate a hierarchy outside the default',
            {'hierarchyId': 'route-primary', 'status': 'Inactive'},
            'Switch the default first if the hierarchy being deactivated is currently the default.'),
    }[suffix]
    example = {'dimensionId': 'custom-axis', 'hierarchyId': 'route-explicit',
        'expectedMetadataRevision': 1, **values}
    binding = ('Use authorized IDs and the current metadataRevision. Confirm the exact write before '
               'requesting operation admission. ' + rule)
    arguments = {field: properties[field] for field in sorted(MUTATIONS[function])}
    arguments['expectedMetadataRevision'] = revision
    contract = read_contract(function, obj(arguments), metadata_mutation_receipt_schema(),
        owner='PostgresMetadataStore.hierarchy_mutation',
        examples=[read_example(function, example, name=caption, binding=binding)],
        semantic_rules=[rule, 'Use the authorized hierarchy read to inspect current membership, status and build state.'])
    contract['programContract']['recovery'] = (
        'On an uncertain outcome, read the original operation receipt or replay the exact admitted request. '
        'After a definite stale refusal, refresh the hierarchy and revision, review the change and obtain new admission.')
    return contract
