# Open EPM

**[Visit openepm.dev](https://openepm.dev)** — product overview, documentation, and access to the hosted development pilot.

Open EPM is a self-hosted, programmable multidimensional application platform for planning, forecasting, simulation, operational analysis, workflow, and consolidation compositions. External MCP clients and the browser use the same fixed Python/PostgreSQL authorization, validation, sequencing, persistence, and publication boundaries.

This repository contains the application source associated with `app.openepm.dev`. The separate `openepm.dev` landing and documentation website source is deliberately not included.

## Source availability

The current branch is a source-available development snapshot for ARM64 systems. It can build the same application and PostgreSQL images used by the laptop deployment, but it is not yet a signed, production-qualified release. Native AMD64, clean-host release qualification, sustained-capacity qualification, and downloadable release assets remain pending.

See [INSTALL.md](INSTALL.md) for the exact supported source-build boundary and prerequisites. Do not point a development installation at an existing or shared Open EPM database.

## Repository layout

- `epm_core/` — fixed application, authorization, validation, and persistence core
- `openepm/` — public Python SDK
- `schema/postgres/` — forward-only PostgreSQL schema
- `web-ui/` — browser client
- `deploy/postgres/` — ARM64 development Compose deployment
- `deploy/release/` — fail-closed release contracts and operational tooling
- `scripts/` — build, migration, validation, and qualification tooling

## Community

- Use Issues for reproducible bugs, feature proposals, and repository documentation improvements.
- Use Discussions for questions and ideas.
- Submit code changes through pull requests. The project owner makes the final merge decision.
- Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Open EPM is licensed under the [MIT License](LICENSE). Third-party components retain their own licenses and notices.
