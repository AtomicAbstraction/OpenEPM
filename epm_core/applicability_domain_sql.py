"""Set-oriented PostgreSQL lowering for a resolved applicability domain."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ApplicabilityDomainSql:
    joins: str
    join_parameters: tuple[object, ...]
    aliases: dict[tuple[str, str], str]
    value_parameters: dict[tuple[str, str], tuple[object, ...]]
    target_members_sql: str
    target_parameters: tuple[object, ...]
    required_predicate: str
    missing_error_predicate: str
    lineage_sql: str
    lineage_parameters: tuple[object, ...]


def _json_overlay(bindings: list[dict], row_alias: str) -> tuple[str, list[str]]:
    if not bindings:
        return "'{}'::jsonb", []
    arguments = []
    parameters = []
    for item in bindings:
        arguments.extend(("%s::text", f"{row_alias}.values->>%s::text"))
        parameters.extend((item["dimensionId"], item["columnId"]))
    return "jsonb_build_object(" + ",".join(arguments) + ")", parameters


def compile_applicability_domain_sql(domain: dict, *,
                                     source_alias: str = "c") -> ApplicabilityDomainSql:
    """Lower a canonical domain into joins over one source-coordinate alias.

    The caller supplies a domain already verified by
    ``resolve_applicability_domain``. Values still become SQL parameters;
    authored identifiers never become SQL identifiers or executable text.
    """
    row_alias = "applicability_row"
    definition_alias = "applicability_definition"
    parameters: list[object] = [domain["relationId"],
        domain["relationStateToken"], domain["relationDigest"],
        domain["relationId"]]
    source_members,source_parameters=_json_overlay(
        domain["anchorMemberColumns"],row_alias)
    # The anchor is complete across all active dimensions.  Resolve it as an
    # exact coordinate key instead of comparing every relation row with every
    # present cube coordinate.  PostgreSQL can therefore use the coordinate
    # series-key index even for large sparse relations.
    parameters.extend((*source_parameters,*source_parameters))
    joins = [f'''JOIN epm.applicability_relation_definition {definition_alias}
        ON {definition_alias}.workspace_id={source_alias}.workspace_id
       AND {definition_alias}.application_id={source_alias}.application_id
       AND {definition_alias}.relation_id=%s
       AND {definition_alias}.state_token=%s
       AND {definition_alias}.definition_digest=%s
       AND {definition_alias}.status='Active' ''',
        f'''JOIN epm.applicability_relation_row {row_alias}
        ON {row_alias}.workspace_id={source_alias}.workspace_id
       AND {row_alias}.application_id={source_alias}.application_id
       AND {row_alias}.relation_id=%s
       AND {source_alias}.series_key=epm.coordinate_series_key({source_members})
       AND {source_alias}.members={source_members}''']
    target_overlay, target_parameters = _json_overlay(
        domain["targetMemberColumns"], row_alias)
    target_sql = (f"{source_alias}.members" if not domain["targetMemberColumns"]
                  else f"({source_alias}.members||{target_overlay})")
    aliases: dict[tuple[str, str], str] = {}
    value_parameters: dict[tuple[str, str], tuple[object, ...]] = {}
    required = []
    missing = []
    for ordinal, operand in enumerate(domain["operands"]):
        coordinate_alias = f"relation_operand_coordinate_{ordinal}"
        value_alias = f"relation_operand_value_{ordinal}"
        overlay, overlay_parameters = _json_overlay(
            operand["memberColumns"], row_alias)
        # The exact coordinate lookup uses the same overlay in both the
        # indexed series-key predicate and the full-members equality. Keep
        # both parameter groups in SQL occurrence order.
        parameters.extend((*overlay_parameters,*overlay_parameters))
        joins.append(f'''LEFT JOIN LATERAL (
          SELECT operand_coordinate.workspace_id,
                 operand_coordinate.application_id,
                 operand_coordinate.coordinate_id,
                 operand_coordinate.members
          FROM epm.coordinate operand_coordinate
          WHERE operand_coordinate.workspace_id={source_alias}.workspace_id
            AND operand_coordinate.application_id={source_alias}.application_id
            AND operand_coordinate.series_key=epm.coordinate_series_key(
              {source_alias}.members||{overlay})
            AND operand_coordinate.members=({source_alias}.members||{overlay})
          LIMIT 1) {coordinate_alias} ON true''')
        joins.append(f'''LEFT JOIN LATERAL (
          SELECT operand_value.coordinate_id,operand_value.amount,
                 operand_value.change_id
          FROM epm.numeric_cell_current operand_value
          WHERE operand_value.workspace_id={coordinate_alias}.workspace_id
            AND operand_value.application_id={coordinate_alias}.application_id
            AND operand_value.coordinate_id={coordinate_alias}.coordinate_id
            AND operand_value.present
          LIMIT 1) {value_alias} ON true''')
        aliases[("relation_operand", operand["operandId"])] = value_alias
        unavailable = f"{value_alias}.coordinate_id IS NULL"
        (missing if operand["missing"] == "error" else required).append(
            unavailable if operand["missing"] == "error"
            else f"{value_alias}.coordinate_id IS NOT NULL")
    for item in domain["values"]:
        raw = f"{row_alias}.values->>%s::text"
        expression = ({"Amount": f"({raw})::numeric",
                       "Ratio": f"({raw})::numeric",
                       "Boolean": f"({raw})::boolean",
                       "String": raw}[item["type"]])
        aliases[("relation_value", item["valueId"])] = expression
        value_parameters[("relation_value", item["valueId"])] = (
            item["columnId"],)
    operand_lineage=[]
    lineage_parameters: list[object]=[
        domain["relationId"],domain["relationDigest"]]
    for ordinal,operand in enumerate(domain["operands"]):
        operand_lineage.append(f'''jsonb_build_object(
          'operandId',%s::text,
          'members',relation_operand_coordinate_{ordinal}.members,
          'amount',relation_operand_value_{ordinal}.amount::text,
          'changeId',relation_operand_value_{ordinal}.change_id)''')
        lineage_parameters.append(operand["operandId"])
    operands_sql=("jsonb_build_array("+",".join(operand_lineage)+")"
        if operand_lineage else "'[]'::jsonb")
    return ApplicabilityDomainSql(
        joins="\n".join(joins), join_parameters=tuple(parameters),
        aliases=aliases, value_parameters=value_parameters,
        target_members_sql=target_sql,
        target_parameters=tuple(target_parameters),
        required_predicate=" AND ".join(required) if required else "TRUE",
        missing_error_predicate=" OR ".join(missing) if missing else "FALSE",
        lineage_sql=("jsonb_build_object('relationId',%s::text,'rowId',"
                     f"{row_alias}.row_id,'relationDigest',%s::text,"
                     f"'operands',{operands_sql})"),
        lineage_parameters=tuple(lineage_parameters))
