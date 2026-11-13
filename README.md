# Open EPM

Open EPM is a self-hosted, MCP-first programmable multidimensional application platform under active remediation. Every application uses the same generic metadata, fact, calculation, workflow and task primitives. Planning, forecasting, simulation, operational analysis and consolidation are compositions of those primitives; they are not application types or privileged fixed-core products. External MCP clients and the SDK submit bounded versioned programs, fixed Python/PostgreSQL code authorizes and executes them, and the browser provides governed human workflows and inspection.

## Current status

**The refined local application is under implementation and qualification; the enterprise release remains incomplete.** The current work adds eight mandatory dimensions, readable Python authoring with automatic validation, private Test and exact activation, shared administrator decisions, and an embedded editor. Follow [the refinement plan](docs/product-refinement-implementation-plan-2026-11-08.md) for current implementation evidence and the remaining local deployment, development purge and replacement-sample work. The broader release gates remain tracked in `docs/enterprise-readiness-acceptance-register.json`.

Historical qualification reports preserve their exact package milestones but do not establish readiness of current source or artifacts. Jupyter and its release obligations are retired; isolated headless Python builds remain. Native amd64/arm64 clean-host releases and the sustained 300-session mixed workload remain deferred external-release gates under the owner's laptop-first priority. Physical 500-GB-per-application testing is also deferred and must not be reported as passed.

## PostgreSQL V2 (development)

See [deployment guidance](deploy/postgres/README.md) and [the MCP contract](docs/postgres-v2-mcp.md). The Compose stack and PostgreSQL tests must use isolated, disposable applications and databases. The sole executable schema is under `schema/postgres/`; the migration runner is `scripts/apply_postgres_migrations.py`. Run `python3 scripts/check_storage_retirement.py` as a release gate. The old research, discovery, PDF ingestion, catalogue export and report website have also been removed.
The [synthetic planning example](examples/planning_group_bulk_program.json) illustrates a current V2 application-language program without business data or old instance IDs.

Use the [documentation authority map](docs/ACTIVE_DOCUMENTATION.md) before treating a root-level design file or historical qualification as current behavior.
Use `python3 scripts/check_enterprise_readiness.py` for the fail-closed current
enterprise/UAT-readiness check. Exit `1` means the register is valid but
incomplete, exit `2` means invalid, and only exit `0` permits a readiness claim.

The older [MCP guide](MCP.md), [data-transfer guide](DATA_TRANSFER.md), [processing guide](APPLICATION_PROCESSING.md), and [financial coverage contract](HFM_COVERAGE_CONTRACT.md) retain historical requirements and gap context; use the V2 MCP contract and deployment guide for executable behavior.

## Development boundary

Run tests against disposable, isolated applications. Business metadata and data changes to a shared application must originate from an authorized MCP client or browser workflow and pass through the application language and fixed Python validation. Do not use direct database scripts or temporary Codex-driven clients to operate shared applications.
