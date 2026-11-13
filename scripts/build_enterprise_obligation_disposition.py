#!/usr/bin/env python3
"""Build the exhaustive disposition of superseded package registers."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "enterprise-obligation-disposition.json"

P_WORK = {
    "P00": ["W0", "W10"], "P01": ["W0"], "P02": ["W2", "W10"],
    "P03": ["W9"], "P04": ["W7"], "P05": ["W3", "W4"],
    "P06": ["W5", "W7"], "P07": ["W5", "W6", "W7"],
    "P08": ["W2", "W6"], "P09": ["W2", "W5"],
    "P10": ["W2", "W6"], "P11": ["W5", "W9"],
    "P12": ["W5", "W7"], "P13": ["W2", "W5", "W6"],
    "P14": ["W4", "W5"], "P15": ["W0", "W10"],
    "P16": ["W0", "W10"], "P17": ["W0", "W10"],
    "P18": ["W2", "W5"], "P19": ["W10"], "P20": ["W5"],
    "P21": ["W9"], "P22": ["W10"], "P23": ["W3", "W7", "W10"],
    "P24": ["W2", "W8", "W10"], "P25": ["W8"],
    "P26": ["W8", "W9"], "P27": ["W3", "W7", "W10"],
    "P28": ["W0"],
}
V_WORK = {
    **{f"V{number:02d}": ["W2", "W5"] for number in range(15)},
    "V15": ["W5"], "V16": ["W0", "W10"], "V17": ["W7", "W10"],
    "V18": ["W9"], "V19": ["W5", "W10"],
}
H_TITLES = {
    "H00": "Reconciliation", "H01": "Component inventory",
    "H02": "Keycloak production profile", "H02a": "MCP OIDC integration",
    "H03": "Principal contracts", "H04": "Group administration",
    "H05": "Completed identity migration", "H06": "Metadata schema",
    "H07": "Attribute Catalog", "H08": "Security String",
    "H09": "Group authorization", "H10": "Metadata Manager",
    "H11": "Universal enforcement", "H12": "Performance and reliability",
    "H13": "Guarded activation", "H14": "Retirement", "H15": "Owner UAT",
}
H_WORK = {
    "H00": ["W0"], "H01": ["W0", "W10"], "H02": ["W3", "W4"],
    "H02a": ["W3", "W4", "W8"], "H03": ["W4"], "H04": ["W4"],
    "H05": ["W4", "W10"], "H06": ["W5", "W7"], "H07": ["W5"],
    "H08": ["W4", "W5"], "H09": ["W4"], "H10": ["W5"],
    "H11": ["W2", "W4"], "H12": ["W6", "W9"],
    "H13": ["W3", "W7", "W10"], "H14": ["W10"], "H15": ["W5", "W10"],
}
B_TITLES = {
    "B00": "Inventory and contracts", "B01": "Browser session gateway",
    "B02": "Global client lifecycle", "B03": "Transport and retry policy",
    "B04": "Cache and release policy", "B05": "Navigation and unsaved work",
    "B06": "Enterprise security baseline", "B07": "Reliability and observability",
    "B08": "Whole-application qualification",
}
B_WORK = {
    "B00": ["W0", "W2"], "B01": ["W3", "W4"], "B02": ["W5"],
    "B03": ["W2", "W5"], "B04": ["W5", "W10"], "B05": ["W5"],
    "B06": ["W4", "W5"], "B07": ["W5", "W9"], "B08": ["W5", "W10"],
}


def _row(source: str, obligation_id: str, work: list[str], *, title: str = "") -> dict:
    if obligation_id == "P03":
        disposition = "deferred"
        rationale = "Production analytical acceleration remains disabled pending measured benefit."
    elif obligation_id in {"P15", "P16", "P17"}:
        disposition = "retired"
        rationale = "Fixed financial-product completion is outside the generic first release; reusable exactness and governance controls remain in the replacement work packages."
    elif obligation_id in {"P19", "P28", "H05"}:
        disposition = "historical"
        rationale = "The bounded activity is preserved as history and is not a discoverable current product or release gate."
    else:
        disposition = "replaced"
        rationale = "The enterprise remediation work packages replace this package's status authority while retaining applicable requirements and evidence."
    return {"source": source, "obligationId": obligation_id, "title": title,
            "disposition": disposition, "replacementWorkPackages": work,
            "verificationAuthority": "docs/enterprise-readiness-acceptance-register.json",
            "rationale": rationale}


def build() -> dict:
    # The superseded P/V registers were removed. Their complete stable ID sets
    # live here only to map each former obligation to its current W owner.
    p_ids = list(P_WORK)
    v_ids = list(V_WORK)
    rows = ([_row("P", item, P_WORK[item]) for item in p_ids]
        + [_row("V", item, V_WORK[item]) for item in v_ids]
        + [_row("H", item, H_WORK[item], title=title)
           for item, title in H_TITLES.items()]
        + [_row("B", item, B_WORK[item], title=title)
           for item, title in B_TITLES.items()])
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    counts = {name: sum(row["disposition"] == name for row in rows)
              for name in ("retained", "replaced", "retired", "deferred", "historical")}
    return {"format": "openepm-enterprise-obligation-disposition-v1",
            "asOf": "2026-11-05", "authority": "PROJECT_INPUTS.md input 702",
            "allowedDispositions": ["retained", "replaced", "retired", "deferred", "historical"],
            "sourceCounts": {"P": len(p_ids), "V": len(v_ids),
                             "H": len(H_TITLES), "B": len(B_TITLES)},
            "dispositionCounts": counts,
            "obligationDigest": hashlib.sha256(canonical).hexdigest(),
            "obligations": rows}


def main() -> None:
    OUTPUT.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
