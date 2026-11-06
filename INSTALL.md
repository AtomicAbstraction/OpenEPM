# Install from source

## Supported source-build boundary

This development snapshot supports source builds on an ARM64 host with Docker Engine or Docker Desktop and Docker Compose v2. The current development Compose file explicitly targets `linux/arm64`. Native AMD64 installation is not yet qualified.

The deployment requires an existing OpenID Connect provider. Keycloak is the reference identity provider. You must supply the exact issuer, JWKS URL, audiences, and verified subject of the first platform operator. Open EPM does not accept an authored email address as a substitute for the provider's immutable subject identifier.

This is not yet a one-command production installer. Use a new, disposable deployment and database until a signed release is published.

## Prerequisites

- ARM64 Linux or Apple Silicon macOS
- Docker Engine or Docker Desktop with Docker Compose v2
- At least 8 GB of memory available to Docker for a development build
- HTTPS origins for the browser and MCP endpoints
- A configured OIDC client with `openepm-web` and `openepm-mcp` audiences, or equivalent values reflected in your environment

## Configure

Clone the repository and create a private environment file:

```sh
git clone https://github.com/AtomicAbstraction/OpenEPM.git
cd OpenEPM
cp deploy/postgres/.env.example deploy/postgres/.env
chmod 600 deploy/postgres/.env
```

Fill every required value in `deploy/postgres/.env`. Generate independent random values for every database role password. Set `EPM_PG_PREVIEW_SECRET_HEX` to 64 lowercase hexadecimal characters. Never reuse examples, commit the `.env` file, or expose it in issue reports.

The public origins must be absolute HTTPS origins without a path, for example:

```text
EPM_PUBLIC_WEB_ORIGIN=https://app.example.com
EPM_PUBLIC_MCP_ORIGIN=https://mcp.example.com
```

## Build and initialize a new database

From the repository root:

```sh
docker compose --env-file deploy/postgres/.env -f deploy/postgres/compose.yaml build
docker compose --env-file deploy/postgres/.env -f deploy/postgres/compose.yaml up -d db
docker compose --env-file deploy/postgres/.env -f deploy/postgres/compose.yaml --profile setup run --rm migrate
docker compose --env-file deploy/postgres/.env -f deploy/postgres/compose.yaml --profile setup run --rm bootstrap-roles
docker compose --env-file deploy/postgres/.env -f deploy/postgres/compose.yaml --profile setup run --rm bootstrap-operator
docker compose --env-file deploy/postgres/.env -f deploy/postgres/compose.yaml --profile v2 --profile workspace up -d
```

Inspect service state without printing the environment file:

```sh
docker compose --env-file deploy/postgres/.env -f deploy/postgres/compose.yaml ps
```

The development listeners bind to loopback ports defined in the Compose file. Place an authenticated HTTPS reverse proxy in front of them; do not expose the raw loopback services directly to the public internet.

## Stop and clean up

Stop while retaining the development database:

```sh
docker compose --env-file deploy/postgres/.env -f deploy/postgres/compose.yaml --profile v2 --profile workspace down
```

Deleting volumes permanently destroys the installation's database and is intentionally not included as a routine command. Use a disposable project and an explicit, reviewed lifecycle decision if permanent removal is required.

## Current limitations

- ARM64 is the only current source-build target.
- The source snapshot is not a signed release and has no production support declaration.
- Clean Linux, native AMD64, sustained 300-session/ten-notebook capacity, and physical 500-GB qualification are not complete.
- Managed notebooks and the full release topology have additional host and isolation requirements documented under `deploy/release/` and `deploy/notebook/`.
- The hosted `app.openepm.dev` pilot is not a shared test target for source installations.
