"""Deterministic, non-activating schema-163 semantic reference construction.

This module does not repair or apply the historical migration ledger.  It
derives reviewable schema statements for 0144-0163 from byte-pinned canonical
sources and can apply them to an honestly recorded canonical schema-143
database.  The resulting database is an independent semantic reference only.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .postgres_fresh_baseline import database_profile, schema_fingerprint_objects


FORMAT = "openepm-schema163-semantic-reference-v1"
BASE_VERSION = 143
TARGET_VERSION = 163

_EXPECTED_SHA256 = {
    144: "489471456d3185d119e6a9f34c2b6479aa03ee02273997c91a1a4d70eef681c7",
    145: "641a6fdbe2b5e15b1295e3e6d8de6d4dbb5ff3614b308b70a62982c5ac1efbfd",
    146: "1632cfb995245acf84a1abc60a8d4f9c25fd8fa80379af6a08ec5a4460c105fd",
    147: "ced2c1a659ce105f3ffa6743c2970c0d8a4fd1bfb3fc47f181df3dbcd4bc5cd6",
    148: "a8fcb23ce0f72bd0c4d28a153a1fcc6cbba10dafcd4d448f89a847e23b177cae",
    149: "4411378aaa321dcfd3d7440ed30829433d85155f80d7219a969df6a959ba7ad3",
    150: "fa7b4c28a289217600cb7afcbdd12153d9a589cc7293cc09fbe935b8e66f1cbb",
    151: "d8ba1a5d373005b926132072bb41269412daa1f14d046a883df854a30eddb50e",
    152: "b65727e22c3c24df70a4326df45e8df3d489b251979677e9d0cc45235ee0c269",
    153: "36775e3c9f8a49d870b7f4b773a4660e6e2d9ef8169e50ce242d07acfd58bbe9",
    154: "c2d5ded288eab3c026d64c9087e481c74df7e71c31371f6e155ff7872c651b22",
    155: "3bd3961e130492606a4267a08a37adf1b54987747ce7069f32ec881708b67b06",
    156: "cf2499364a79e82538d0f0ba4e3debfd02208ae7e9c7067442cdafadb2220f29",
    157: "eb32d5f5c195dfb5af8b466ef1642d47de80b8110bc710cf984df6ffedc4c384",
    158: "ec63278026c0d49755b657d0602943895f369f35da8a153cbf59eb072a3395b2",
    159: "bf967966f15cb4cf7414831343b8cfca0a2827f3f5506fcc2cb6af72436496ad",
    160: "3b324ce3cfe21b4f39c8ff897222d95c6774ee8092de7bf82cb50b0a539d7d69",
    161: "63ecb21d39babc7f8b21a2ecf40bd7e6fb3a0eb578d06f2a882d6c4a67018815",
    162: "3c767fd467a8660af99ef23f6bc9a7f9a1d1542dd4204604ce9d1061a54e7f0f",
    163: "c35402bd55c16406b9014d442de0a74f57c86647e2276dc480e4dd8f4308c4d6",
}

_REPLACEMENTS = {
    148: (("DO $$\nBEGIN\n  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=147) THEN\n    RAISE EXCEPTION 'MIGRATION_0148_PREDECESSOR_0147_REQUIRED';\n  END IF;\nEND $$;\n",
           "", "construction-order-replaces-ledger-predecessor-guard"),),
    149: (("DO $$BEGIN\n IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=148) THEN\n  RAISE EXCEPTION 'MIGRATION_0149_PREDECESSOR_0148_REQUIRED';\n END IF;\nEND$$;\n",
           "", "construction-order-replaces-ledger-predecessor-guard"),),
    151: (
        ("DO $$ BEGIN\n  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=150) THEN\n    RAISE EXCEPTION 'MIGRATION_0151_REQUIRES_0150';\n  END IF;\nEND $$;\n",
         "", "construction-order-replaces-ledger-predecessor-guard"),
        ("$pattern$'source_batch_row','source_batch_chunk',$pattern$",
         "$pattern$'source_batch_row',\n        'source_batch_chunk',$pattern$",
         "match-postgresql-deparsed-reset-table-layout"),
        ("$pattern$'source_import_execution','source_batch_row','source_batch_chunk',$pattern$",
         "$pattern$'source_import_execution','source_batch_row',\n        'source_batch_chunk',$pattern$",
         "preserve-postgresql-deparsed-reset-table-layout"),
        ("IF EXISTS (SELECT 1 FROM epm.source_batch WHERE workspace_id=p_workspace_id",
         "IF EXISTS (SELECT 1 FROM epm.source_batch\n        WHERE workspace_id=p_workspace_id",
         "match-postgresql-deparsed-reset-guard-layout"),
    ),
    153: (("DO $$BEGIN\n IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=152) THEN\n  RAISE EXCEPTION 'MIGRATION_0153_PREDECESSOR_0152_REQUIRED';\n END IF;\nEND$$;\n",
           "", "construction-order-replaces-ledger-predecessor-guard"),),
    154: (("DO $$BEGIN\n IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=153) THEN\n  RAISE EXCEPTION 'MIGRATION_0154_PREDECESSOR_0153_REQUIRED';\n END IF;\nEND$$;\n",
           "", "construction-order-replaces-ledger-predecessor-guard"),),
    156: (
        ("old text:='status IN (''Accepted'',''Reading'',''Prepared'')';",
         "old text:='status IN(''Accepted'',''Reading'',''Prepared'')';",
         "match-postgresql-deparsed-status-expression"),
        ("new text:='status IN (''Accepted'',''Reading'',''Prepared'',''Publishing'')';",
         "new text:='status IN(''Accepted'',''Reading'',''Prepared'',''Publishing'')';",
         "preserve-postgresql-deparsed-status-expression"),
    ),
    157: (("coordinate_id text NOT NULL", "coordinate_id bigint NOT NULL",
           "match-coordinate-primary-key-type"),),
    159: (("DO $$BEGIN\n IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=158) THEN\n  RAISE EXCEPTION 'MIGRATION_0159_PREDECESSOR_0158_REQUIRED';\n END IF;\nEND$$;\n",
           "", "construction-order-replaces-ledger-predecessor-guard"),),
    160: (("DO $$BEGIN\n IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=159) THEN\n  RAISE EXCEPTION 'MIGRATION_0160_PREDECESSOR_0159_REQUIRED';\n END IF;\nEND$$;\n",
           "", "construction-order-replaces-ledger-predecessor-guard"),),
    161: (("DO $$BEGIN\n IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=160) THEN\n  RAISE EXCEPTION 'MIGRATION_0161_PREDECESSOR_0160_REQUIRED';\n END IF;\nEND$$;\n",
           "", "construction-order-replaces-ledger-predecessor-guard"),),
    162: (
        ("DO $$BEGIN\n IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=161) THEN\n  RAISE EXCEPTION 'MIGRATION_0162_PREDECESSOR_0161_REQUIRED';\n END IF;\nEND$$;\n",
         "", "construction-order-replaces-ledger-predecessor-guard"),
        ("IF receipt IS NOT NULL AND CASE\n"
         "   WHEN jsonb_typeof(receipt->'sourceLookupLineage')='array'\n"
         "    THEN jsonb_array_length(receipt->'sourceLookupLineage')=1\n"
         "   ELSE false END THEN",
         "IF receipt IS NOT NULL AND (CASE\n"
         "   WHEN jsonb_typeof(receipt->'sourceLookupLineage')='array'\n"
         "    THEN jsonb_array_length(receipt->'sourceLookupLineage')=1\n"
         "   ELSE false END) THEN",
         "parenthesize-plpgsql-boolean-case-expression"),
        ("OR CASE WHEN jsonb_typeof(receipt->'rows')='array'\n"
         "      THEN jsonb_array_length(receipt->'rows') IS DISTINCT FROM 4 ELSE true END",
         "OR (CASE WHEN jsonb_typeof(receipt->'rows')='array'\n"
         "      THEN jsonb_array_length(receipt->'rows') IS DISTINCT FROM 4 ELSE true END)",
         "parenthesize-plpgsql-boolean-case-expression"),
        ("OR CASE WHEN jsonb_typeof(receipt->'rows')='array' THEN\n"
         "      (SELECT count(DISTINCT x->>'role') FROM jsonb_array_elements(receipt->'rows') x\n"
         "       WHERE x->>'role' IN ('Opening','Creation','Release','Closing'))<>4\n"
         "      ELSE true END",
         "OR (CASE WHEN jsonb_typeof(receipt->'rows')='array' THEN\n"
         "      (SELECT count(DISTINCT x->>'role') FROM jsonb_array_elements(receipt->'rows') x\n"
         "       WHERE x->>'role' IN ('Opening','Creation','Release','Closing'))<>4\n"
         "      ELSE true END)",
         "parenthesize-plpgsql-boolean-case-expression"),
    ),
    163: (("DO $$BEGIN\n IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=162) THEN\n  RAISE EXCEPTION 'MIGRATION_0163_PREDECESSOR_0162_REQUIRED';\n END IF;\nEND$$;\n",
           "", "construction-order-replaces-ledger-predecessor-guard"),),
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _migration_files(directory: Path, first: int, last: int) -> list[tuple[int, Path]]:
    found: dict[int, Path] = {}
    for path in sorted(directory.glob("*.sql")):
        try:
            version = int(path.name[:4])
        except ValueError:
            continue
        if first <= version <= last:
            if version in found:
                raise ValueError("SEMANTIC_REFERENCE_DUPLICATE_MIGRATION")
            found[version] = path
    if sorted(found) != list(range(first, last + 1)):
        raise ValueError("SEMANTIC_REFERENCE_MIGRATION_CHAIN_INCOMPLETE")
    return sorted(found.items())


def canonical_migration_rows(directory: Path, last: int) -> list[tuple[int, str]]:
    """Return the exact source checksums a recorded canonical base must have."""
    return [(version, _sha(path.read_bytes())) for version, path in
            _migration_files(directory, 1, last)]


def derive_statement(version: int, source: bytes) -> tuple[str, list[dict[str, str]]]:
    if version in _EXPECTED_SHA256 and _sha(source) != _EXPECTED_SHA256[version]:
        raise ValueError(f"SEMANTIC_REFERENCE_{version:04d}_SOURCE_DRIFT")
    text = source.decode("utf-8")
    changes = []
    for old, new, reason in _REPLACEMENTS.get(version, ()):
        if text.count(old) != 1 or (new and new in text):
            raise ValueError(f"SEMANTIC_REFERENCE_{version:04d}_TRANSFORM_SHAPE_INVALID")
        text = text.replace(old, new, 1)
        changes.append({"reason": reason, "oldSha256": _sha(old.encode()),
                        "newSha256": _sha(new.encode())})
    return text, changes


def derive_historical_execution_statement(version: int, source: bytes
                                          ) -> tuple[str, list[dict[str, str]]]:
    """Apply only byte-pinned fixes needed by ordinary ledger execution.

    Semantic-reference construction omits predecessor-ledger guards because it
    deliberately builds outside the migration ledger.  The ordinary runner
    must retain those guards, while reusing the same reviewed syntax, type and
    PostgreSQL-deparse compatibility corrections.
    """
    if version in _EXPECTED_SHA256 and _sha(source) != _EXPECTED_SHA256[version]:
        raise ValueError(f"HISTORICAL_EXECUTION_{version:04d}_SOURCE_DRIFT")
    text = source.decode("utf-8")
    changes = []
    for old, new, reason in _REPLACEMENTS.get(version, ()):
        if reason == "construction-order-replaces-ledger-predecessor-guard":
            continue
        if text.count(old) != 1 or (new and new in text):
            raise ValueError(
                f"HISTORICAL_EXECUTION_{version:04d}_TRANSFORM_SHAPE_INVALID")
        text = text.replace(old, new, 1)
        changes.append({"reason": reason, "oldSha256": _sha(old.encode()),
                        "newSha256": _sha(new.encode())})
    return text, changes


def build_artifact(directory: Path) -> dict[str, Any]:
    migrations = []
    statements = []
    for version, path in _migration_files(directory, BASE_VERSION + 1,
                                           TARGET_VERSION):
        source = path.read_bytes()
        statement, changes = derive_statement(version, source)
        migrations.append({"version": version, "filename": path.name,
                           "sourceSha256": _sha(source),
                           "statementSha256": _sha(statement.encode()),
                           "transformations": changes})
        statements.append(statement)
    body = {"format": FORMAT, "baseVersion": BASE_VERSION,
            "targetVersion": TARGET_VERSION,
            "activationAuthorized": False,
            "migrationLedgerMutationAuthorized": False,
            "migrations": migrations, "statements": statements}
    body["artifactDigest"] = _sha(json.dumps(
        body, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("ascii"))
    return body


def apply_artifact(db: Any, artifact: dict[str, Any],
                   source_directory: Path, *,
                   _failure_after_version: int | None = None) -> dict[str, Any]:
    expected = build_artifact(source_directory)
    if artifact != expected:
        raise ValueError("SEMANTIC_REFERENCE_ARTIFACT_DRIFT")
    if (artifact.get("format") != FORMAT
            or artifact.get("baseVersion") != BASE_VERSION
            or artifact.get("targetVersion") != TARGET_VERSION
            or artifact.get("activationAuthorized") is not False
            or artifact.get("migrationLedgerMutationAuthorized") is not False
            or len(artifact.get("migrations", [])) != 20
            or len(artifact.get("statements", [])) != 20):
        raise ValueError("SEMANTIC_REFERENCE_ARTIFACT_INVALID")
    if (_failure_after_version is not None
            and _failure_after_version not in range(BASE_VERSION + 1,
                                                    TARGET_VERSION + 1)):
        raise ValueError("SEMANTIC_REFERENCE_FAILURE_POINT_INVALID")
    with db.transaction():
        db.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        rows = db.execute("SELECT version,checksum FROM epm.schema_migration "
                          "ORDER BY version").fetchall()
        expected_base=canonical_migration_rows(source_directory,BASE_VERSION)
        if list(rows)!=expected_base:
            raise ValueError("SEMANTIC_REFERENCE_BASE_NOT_CANONICAL_143")
        before = list(rows)
        for migration, statement in zip(artifact["migrations"],
                                        artifact["statements"]):
            db.execute(statement, prepare=False)
            if migration["version"] == _failure_after_version:
                raise RuntimeError("INJECTED_SEMANTIC_REFERENCE_FAILURE")
        after = db.execute("SELECT version,checksum FROM epm.schema_migration "
                           "ORDER BY version").fetchall()
        if list(after) != before:
            raise ValueError("SEMANTIC_REFERENCE_MIGRATION_LEDGER_CHANGED")
        objects = schema_fingerprint_objects(db)
        encoded = json.dumps(objects, separators=(",", ":")).encode()
        fingerprint_source = "\n".join(
            f"{kind}:{value}" for kind, value in objects).encode()
        postgres_profile, extension_profile = database_profile(db)
        canonical_rows_encoded = json.dumps(
            before, separators=(",", ":")).encode()
        return {"format": FORMAT, "status": "semantic-reference-constructed",
                "activationAuthorized": False,
                "migrationLedgerMaximum": BASE_VERSION,
                "canonicalBaseRows": before,
                "canonicalBaseRowsDigest": _sha(canonical_rows_encoded),
                "artifactDigest": artifact["artifactDigest"],
                "schemaFingerprint": _sha(fingerprint_source),
                "objectCount": len(objects),
                "objectListDigest": _sha(encoded),
                "schemaObjects": objects,
                "postgresProfile": postgres_profile,
                "extensionProfile": extension_profile}
