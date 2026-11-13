ARG SOURCE_COMMIT=""
ARG SOURCE_TREE=""
FROM node:24.14.0-alpine3.23@sha256:7fddd9ddeae8196abf4a3ef2de34e11f7b1a722119f91f28ddf1e99dcafdf114 AS ui-build

WORKDIR /build/openepm-ui
COPY web-ui/package.json web-ui/package-lock.json ./
RUN npm ci
COPY web-ui/index.html web-ui/tsconfig.json web-ui/tsconfig.app.json web-ui/tsconfig.node.json web-ui/vite.config.ts ./
COPY web-ui/src/ ./src/
COPY web-ui/build/ ./build/
RUN npm run format:check && npm run check && npm test && npm run build

FROM python:3.14-slim@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8 AS app-build

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/openepm

COPY requirements-postgres.lock ./
RUN python -m pip install --no-cache-dir --root-user-action=ignore \
        --require-hashes --only-binary=:all: -r requirements-postgres.lock \
    && groupadd --system --gid 10001 openepm \
    && useradd --uid 10001 --gid 10001 --no-create-home \
        --shell /usr/sbin/nologin openepm

# Package the fixed core as one reviewed source unit.  Prefix-only copies
# previously omitted required non-postgres helpers (for example aggregate IR
# and forecast-window modules) even though their callers shipped.
COPY epm_core/ ./epm_core/
COPY openepm/ ./openepm/
COPY platform_postgres*.py ./
COPY docs/skills/multidimensional-cube-harness/SKILL.md ./docs/skills/multidimensional-cube-harness/SKILL.md
COPY --from=ui-build /build/openepm-ui/dist/ ./web/app/
COPY scripts/operator_import_path.py scripts/apply_postgres_migrations.py scripts/initialize_postgres_release.py scripts/initialize_schema163_public_parity.py scripts/bootstrap_postgres_operator.py scripts/bootstrap_postgres_service_roles.py scripts/bootstrap_postgres_python_coordinator.py scripts/check_postgres_mcp_health.py scripts/check_postgres_worker_health.py scripts/serve_openepm_postgres_worker.py scripts/serve_openepm_python_build_broker.py scripts/serve_openepm_sandbox_launcher.py ./scripts/
COPY schema/postgres/ ./schema/postgres/
# A pristine installation cannot replay the defective immutable 0144-0163
# historical text chain. Ship the independently reviewed schema-163 baseline
# with the ordinary image so its migrate service can take the qualified
# forward-only path without a private qualification overlay.
COPY schema/postgres/ /qualification/migrations/
COPY tests/evidence/schema163-fresh-baseline-artifact-2026-10-29.json /qualification/artifact.json

COPY scripts/retire_runtime_packages.sh scripts/prune_python_runtime.py scripts/check_openepm_runtime_independence.py /usr/local/libexec/openepm/
COPY scripts/check_runtime_retirement.sh /usr/local/bin/openepm-runtime-check
RUN chmod 0555 /usr/local/bin/openepm-runtime-check \
    && touch /etc/openepm-image-build \
    && bash /usr/local/libexec/openepm/retire_runtime_packages.sh app \
    && python /usr/local/libexec/openepm/prune_python_runtime.py \
    && python /usr/local/libexec/openepm/check_openepm_runtime_independence.py --root /srv/openepm \
    && rm -rf /usr/local/libexec/openepm /etc/openepm-image-build \
    && bash /usr/local/bin/openepm-runtime-check --require-published-skill

# Flatten the clean filesystem: deleted engines must not survive in lower layers.
FROM scratch
ARG SOURCE_COMMIT
ARG SOURCE_TREE
COPY --from=app-build / /
LABEL org.openepm.qualification="schema163-public-parity" \
      org.openepm.source.commit="${SOURCE_COMMIT}" \
      org.openepm.source.tree="${SOURCE_TREE}"
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    EPM_SOURCE_COMMIT=${SOURCE_COMMIT} EPM_SOURCE_TREE=${SOURCE_TREE}
WORKDIR /srv/openepm
USER 10001:10001
CMD ["python", "-m", "platform_postgres_router_mcp_http"]
