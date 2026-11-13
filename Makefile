PYTHON ?= python3
PYTEST ?= $(PYTHON) -m pytest
RUFF ?= ruff
MYPY ?= mypy
PIP_AUDIT ?= pip-audit

.PHONY: focused unit integration lint type web security qualify readiness

# Fast, deterministic gate for the release/recovery contract.
focused:
	$(PYTHON) -m unittest -v \
		tests/test_deployment_secrets.py \
		tests/test_release_operations.py \
		tests/test_identity_release_contract.py \
		tests/test_epmctl_release.py

# Unit tests only.  PostgreSQL fixtures are explicitly opt-in.
unit:
	PYTHONPYCACHEPREFIX=/tmp/openepm-python-cache \
		$(PYTHON) -m tests.run_enterprise_source_suite

# Requires a disposable PostgreSQL target. Empty selection is impossible: the
# named modules contain the migration/idempotency, transaction-budget and core
# numeric/text exactness integration contracts.
integration:
	@test "$(EPM_TEST_POSTGRES_DISPOSABLE)" = "1" || \
		(echo "EPM_TEST_POSTGRES_DISPOSABLE=1 is required" >&2; exit 2)
	@test -n "$(EPM_TEST_POSTGRES_DSN)" || \
		(echo "EPM_TEST_POSTGRES_DSN is required" >&2; exit 2)
	PYTHONPATH=$(CURDIR)/tests:$(CURDIR) \
	PYTHONPYCACHEPREFIX=/tmp/openepm-python-cache $(PYTHON) -m unittest \
		tests.test_postgres_connection \
		tests.test_mcp_execution \
		tests.test_enterprise_postgres_inventory
	PYTHONPATH=$(CURDIR)/tests:$(CURDIR) \
	PYTHONPYCACHEPREFIX=/tmp/openepm-python-cache \
		$(PYTHON) tests/run_enterprise_postgres_suite.py
	PYTHONPYCACHEPREFIX=/tmp/openepm-python-cache \
		$(PYTHON) scripts/verify_enterprise_postgres_cleanup.py

lint:
	$(RUFF) check .

type:
	MYPY_CACHE_DIR=/tmp/openepm-mypy-cache $(MYPY)

web:
	cd web-ui && npm ci && npm run check && npm test && npm run format:check && npm run build && npm run browser:rules

security:
	$(PIP_AUDIT) -r requirements-postgres.lock

# Frozen-artifact, host, browser or load qualification.  Never a merge gate.
qualify:
	$(PYTEST) -q -m qualification

# This command is expected to exit 1 until every enterprise gate has exact
# evidence. Exit 2 means the register itself is invalid.
readiness:
	$(PYTHON) scripts/check_enterprise_readiness.py
