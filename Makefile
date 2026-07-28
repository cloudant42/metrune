.PHONY: check test web-build compose-check

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	cd web && npm run typecheck && npm run build
	docker compose config --quiet
	bash scripts/check-production-compose.sh

test:
	cargo test --workspace

web-build:
	cd web && npm run build

compose-check:
	docker compose config --quiet
	bash scripts/check-production-compose.sh
