"""Pure fail-closed review guard for a schema-143 to schema-163 artifact build.

This module never constructs or activates a baseline.  It validates evidence
produced by independently isolated constructor and parity runs before a human
reviewer may consider creating an activation manifest.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any


_DIGEST=re.compile(r"[0-9a-f]{64}")
_PRESERVATION_DOMAINS={
    "workspaceApplications","metadataDefinitions","hierarchies",
    "numericFacts","textFacts","supportingDetail","genericFacts",
    "operationReceipts","jobs","calculationLineage","pythonArtifacts",
    "planningArtifacts","consolidationArtifacts","transferArtifacts",
}
_RESET_DOMAINS={"metadata","numericFacts","textFacts","supportingDetail",
    "genericFacts","operationReceipts","jobs","pythonPrograms",
    "pythonBuilds","pythonWorkflows","queryResults","forecastDefinitions",
    "planningPolicies","consolidationGenerations","transferArtifacts"}
_ROLLBACK_POINTS={"after-artifact","after-fingerprint","after-audit"}


def _fail(code:str)->None:
    raise ValueError(code)


def _digest(value:Any)->str:
    return hashlib.sha256(json.dumps(value,separators=(",",":"),
        sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def object_category_digests(objects:list[list[str]]|list[tuple[str,str]])->dict[str,str]:
    """Return deterministic per-category digests for human-readable parity."""
    if not isinstance(objects,list):_fail("BASELINE_CONSTRUCTOR_OBJECTS_INVALID")
    grouped:dict[str,list[str]]={}
    previous=None
    for row in objects:
        if (not isinstance(row,(list,tuple)) or len(row)!=2
                or not all(isinstance(value,str) for value in row)):
            _fail("BASELINE_CONSTRUCTOR_OBJECTS_INVALID")
        item=(row[0],row[1])
        if previous is not None and item<previous:
            _fail("BASELINE_CONSTRUCTOR_OBJECT_ORDER_INVALID")
        previous=item;grouped.setdefault(row[0],[]).append(row[1])
    return {kind:_digest(values) for kind,values in sorted(grouped.items())}


def validate_constructor_evidence(evidence:dict[str,Any])->dict[str,Any]:
    """Validate an independently produced, non-activating constructor packet."""
    required={"format","activationAuthorized","sourceVersion","targetVersion",
      "canonicalMigrations","reference","materialized","rollbackProbes",
      "populatedUpgrade","resetProbe","independentBuilds"}
    if not isinstance(evidence,dict) or set(evidence)!=required:
        _fail("BASELINE_CONSTRUCTOR_EVIDENCE_SHAPE_INVALID")
    if (evidence["format"]!="openepm-schema143-to-163-constructor-evidence-v1"
            or evidence["activationAuthorized"] is not False
            or evidence["sourceVersion"]!=143 or evidence["targetVersion"]!=163):
        _fail("BASELINE_CONSTRUCTOR_BOUNDARY_INVALID")

    canonical=evidence["canonicalMigrations"]
    if (not isinstance(canonical,list) or len(canonical)!=163
            or any(not isinstance(row,dict) for row in canonical)
            or [row.get("version") for row in canonical]!=list(range(1,164))
            or any(set(row)!={"version","sha256"}
              or not _DIGEST.fullmatch(str(row["sha256"])) for row in canonical)):
        _fail("BASELINE_CONSTRUCTOR_CANONICAL_CHAIN_INVALID")

    reference=evidence["reference"];materialized=evidence["materialized"]
    capture_fields={"schemaFingerprint","schemaObjects","objectListDigest",
      "migrationRows","postgresProfile","extensionProfile"}
    if (not isinstance(reference,dict) or set(reference)!=capture_fields
            or not isinstance(materialized,dict) or set(materialized)!=capture_fields):
        _fail("BASELINE_CONSTRUCTOR_CAPTURE_SHAPE_INVALID")
    expected_rows=[[row["version"],row["sha256"]] for row in canonical]
    for capture in (reference,materialized):
        if (capture["migrationRows"]!=expected_rows
                or not _DIGEST.fullmatch(str(capture["schemaFingerprint"]))
                or not _DIGEST.fullmatch(str(capture["objectListDigest"]))
                or not all(isinstance(capture[name],str) and capture[name]
                  for name in ("postgresProfile","extensionProfile"))):
            _fail("BASELINE_CONSTRUCTOR_CAPTURE_INVALID")
        if capture["objectListDigest"]!=_digest(capture["schemaObjects"]):
            _fail("BASELINE_CONSTRUCTOR_OBJECT_DIGEST_MISMATCH")
    reference_categories=object_category_digests(reference["schemaObjects"])
    materialized_categories=object_category_digests(materialized["schemaObjects"])
    if (reference["postgresProfile"]!=materialized["postgresProfile"]
            or reference["extensionProfile"]!=materialized["extensionProfile"]):
        _fail("BASELINE_CONSTRUCTOR_PROFILE_MISMATCH")
    if (reference["schemaFingerprint"]!=materialized["schemaFingerprint"]
            or reference["schemaObjects"]!=materialized["schemaObjects"]
            or reference_categories!=materialized_categories):
        _fail("BASELINE_CONSTRUCTOR_SCHEMA_PARITY_MISMATCH")

    probes=evidence["rollbackProbes"]
    if (not isinstance(probes,list) or len(probes)!=len(_ROLLBACK_POINTS)
            or any(not isinstance(row,dict) for row in probes)
            or {row.get("failurePoint") for row in probes}!=_ROLLBACK_POINTS):
        _fail("BASELINE_CONSTRUCTOR_ROLLBACK_PROBES_INCOMPLETE")
    for row in probes:
        if (set(row)!={"failurePoint","pristineAfterFailure","migrationRows",
                       "epmSchemas","baselineAuditRows"}
                or row["pristineAfterFailure"] is not True
                or row["migrationRows"]!=[] or row["epmSchemas"]!=[]
                or row["baselineAuditRows"]!=[]):
            _fail("BASELINE_CONSTRUCTOR_ROLLBACK_LEAK")

    populated=evidence["populatedUpgrade"]
    if (not isinstance(populated,dict) or set(populated)!={"sourceVersion",
          "appliedVersions","migrationRows","beforeDigests","afterDigests"}
            or populated["sourceVersion"]!=143
            or populated["appliedVersions"]!=list(range(144,164))
            or populated["migrationRows"]!=expected_rows):
        _fail("BASELINE_CONSTRUCTOR_POPULATED_UPGRADE_INVALID")
    before=populated["beforeDigests"];after=populated["afterDigests"]
    if (not isinstance(before,dict) or set(before)!=_PRESERVATION_DOMAINS
            or not isinstance(after,dict) or set(after)!=_PRESERVATION_DOMAINS
            or before!=after or any(not _DIGEST.fullmatch(str(value))
                                    for value in before.values())):
        _fail("BASELINE_CONSTRUCTOR_POPULATED_PRESERVATION_FAILED")

    reset=evidence["resetProbe"]
    if (not isinstance(reset,dict) or set(reset)!={"preparedOnly","appliedThroughOwnerWorkflow",
          "schemaFingerprintBefore","schemaFingerprintAfter","postResetLeakCounts",
          "migrationRows"} or reset["preparedOnly"] is not False
            or reset["appliedThroughOwnerWorkflow"] is not True
            or reset["schemaFingerprintBefore"]!=materialized["schemaFingerprint"]
            or reset["schemaFingerprintAfter"]!=materialized["schemaFingerprint"]
            or reset["migrationRows"]!=expected_rows
            or not isinstance(reset["postResetLeakCounts"],dict)
            or set(reset["postResetLeakCounts"])!=_RESET_DOMAINS
            or any(type(value) is not int or value!=0
                   for value in reset["postResetLeakCounts"].values())):
        _fail("BASELINE_CONSTRUCTOR_RESET_BEHAVIOR_FAILED")

    builds=evidence["independentBuilds"]
    if (not isinstance(builds,list) or len(builds)<2
            or any(not isinstance(row,dict)
              or set(row)!={"buildId","inputSnapshotSha256","artifactSha256",
                             "statementCount"}
              or not isinstance(row["buildId"],str) or not row["buildId"]
              or not _DIGEST.fullmatch(str(row["inputSnapshotSha256"]))
              or not _DIGEST.fullmatch(str(row["artifactSha256"]))
              or type(row["statementCount"]) is not int or row["statementCount"]<=0
              for row in builds)
            or len({row["buildId"] for row in builds})!=len(builds)
            or len({(row["inputSnapshotSha256"],row["artifactSha256"],
                     row["statementCount"])
                    for row in builds})!=1):
        _fail("BASELINE_CONSTRUCTOR_OUTPUT_NONDETERMINISTIC")
    return {"validated":True,"activationAuthorized":False,
      "schemaFingerprint":materialized["schemaFingerprint"],
      "objectCategoryDigests":materialized_categories,
      "artifactSha256":builds[0]["artifactSha256"],
      "statementCount":builds[0]["statementCount"]}
