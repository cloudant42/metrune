.PHONY: check test test-integration integration-up integration-down web-build compose-check

TEST_PG_CONTAINER := metrune-test-postgres
TEST_PG_PORT := 55432
TEST_DATABASE_URL := postgres://metrune:metrune-test@localhost:$(TEST_PG_PORT)/metrune_test
TEST_CH_CONTAINER := metrune-test-clickhouse
TEST_CH_PORT := 58123
TEST_CLICKHOUSE_URL := http://localhost:$(TEST_CH_PORT)

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	cd web && npm run typecheck && npm run build
	docker compose config --quiet
	bash scripts/check-production-compose.sh

test:
	cargo test --workspace

# The HTTP tests need a real Postgres because every authorization rule in the
# API is a SQL predicate, and a real ClickHouse because the analytics scoping
# lives in query WHERE clauses. Without these variables the tests report that
# they were skipped, so a plain `make test` stays useful without Docker.
test-integration: integration-up
	METRUNE_TEST_DATABASE_URL=$(TEST_DATABASE_URL) \
	METRUNE_TEST_CLICKHOUSE_URL=$(TEST_CLICKHOUSE_URL) \
		cargo test --workspace
	$(MAKE) integration-down

integration-up:
	@docker rm -f $(TEST_PG_CONTAINER) $(TEST_CH_CONTAINER) >/dev/null 2>&1 || true
	docker run -d --name $(TEST_PG_CONTAINER) \
		-e POSTGRES_USER=metrune \
		-e POSTGRES_PASSWORD=metrune-test \
		-e POSTGRES_DB=metrune_test \
		-p $(TEST_PG_PORT):5432 \
		postgres:17-alpine -c max_connections=500 >/dev/null
	docker run -d --name $(TEST_CH_CONTAINER) \
		-e CLICKHOUSE_SKIP_USER_SETUP=1 \
		--ulimit nofile=262144:262144 \
		-p $(TEST_CH_PORT):8123 \
		clickhouse/clickhouse-server:24.8-alpine >/dev/null
	@printf 'waiting for postgres'
	@for i in $$(seq 1 60); do \
		if docker exec $(TEST_PG_CONTAINER) pg_isready -U metrune -d metrune_test >/dev/null 2>&1; then \
			echo ' ready'; break; \
		fi; \
		printf '.'; sleep 1; \
		if [ $$i -eq 60 ]; then echo ' timed out'; exit 1; fi; \
	done
	@printf 'waiting for clickhouse'
	@for i in $$(seq 1 60); do \
		if curl -fsS '$(TEST_CLICKHOUSE_URL)/ping' >/dev/null 2>&1; then \
			echo ' ready'; break; \
		fi; \
		printf '.'; sleep 1; \
		if [ $$i -eq 60 ]; then echo ' timed out'; exit 1; fi; \
	done

integration-down:
	@docker rm -f $(TEST_PG_CONTAINER) $(TEST_CH_CONTAINER) >/dev/null 2>&1 || true

web-build:
	cd web && npm run build

compose-check:
	docker compose config --quiet
	bash scripts/check-production-compose.sh
