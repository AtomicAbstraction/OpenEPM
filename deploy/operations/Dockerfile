ARG SOURCE_COMMIT=""
ARG SOURCE_TREE=""
FROM python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f AS python-build
WORKDIR /srv/openepm
COPY requirements-postgres.lock ./
RUN python -m pip install --no-cache-dir --root-user-action=ignore \
      --require-hashes --only-binary=:all: -r requirements-postgres.lock
COPY epm_core/ ./epm_core/
COPY openepm/ ./openepm/
COPY docs/skills/multidimensional-cube-harness/SKILL.md ./docs/skills/multidimensional-cube-harness/SKILL.md
COPY scripts/openepm_release_operations.py \
  scripts/validate_release_manifest.py \
  scripts/openepm_signing_trust_policy.py \
  scripts/openepm_release_policy_contract.py \
  scripts/openepm_release_inventory.py \
  scripts/build_openepm_sdk_release.py \
  scripts/build_openepm_sdk_wheel.py \
  scripts/openepm_control_bootstrap.py \
  scripts/openepm_keycloak_bootstrap.py \
  scripts/operator_import_path.py \
  scripts/apply_postgres_migrations.py scripts/bootstrap_postgres_operator.py \
  scripts/bootstrap_postgres_service_roles.py \
  scripts/bootstrap_postgres_python_coordinator.py ./scripts/
COPY schema/postgres/ ./schema/postgres/
COPY scripts/retire_runtime_packages.sh scripts/prune_python_runtime.py /usr/local/libexec/openepm/
RUN touch /etc/openepm-image-build \
 && bash /usr/local/libexec/openepm/retire_runtime_packages.sh app \
 && python /usr/local/libexec/openepm/prune_python_runtime.py \
 && rm -rf /usr/local/libexec/openepm /etc/openepm-image-build

FROM pgduckdb/pgduckdb@sha256:44c88eb9207971af1d7f9804a37429b1bb36f413cd8d7118c81e1288ddde85d1 AS operations
USER 0:0
COPY scripts/retire_runtime_packages.sh /usr/local/libexec/openepm/retire_runtime_packages.sh
COPY scripts/check_runtime_retirement.sh /usr/local/bin/openepm-runtime-check
RUN touch /etc/openepm-image-build \
 && bash /usr/local/libexec/openepm/retire_runtime_packages.sh db \
 && rm -rf /usr/local/libexec/openepm /etc/openepm-image-build
COPY --from=python-build /usr/local/ /usr/local/
COPY --from=python-build /srv/openepm/ /srv/openepm/
COPY deploy/operations/openepm-release-backup \
  deploy/operations/openepm-release-restore \
  deploy/operations/openepm-release-restore-verify \
  deploy/operations/openepm-release-upgrade-preflight \
  deploy/operations/openepm-control-bootstrap /usr/local/bin/
COPY deploy/operations/openepm-keycloak-bootstrap /usr/local/bin/
RUN chmod 0555 /usr/local/bin/openepm-release-* /usr/local/bin/openepm-control-bootstrap /usr/local/bin/openepm-keycloak-bootstrap /usr/local/bin/openepm-runtime-check \
 && ldconfig \
 && PYTHONPATH=/srv/openepm bash /usr/local/bin/openepm-runtime-check --require-published-skill \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin openepm

FROM scratch
ARG SOURCE_COMMIT
ARG SOURCE_TREE
COPY --from=operations / /
LABEL org.openepm.source.commit="${SOURCE_COMMIT}" \
      org.openepm.source.tree="${SOURCE_TREE}"
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/18/bin \
    LANG=C.UTF-8 PYTHONPATH=/srv/openepm PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/openepm
USER 10001:10001
ENTRYPOINT ["/usr/bin/env"]
