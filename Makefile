.PHONY: build build-prod launch halt restart dev test test-watch test-coverage test-e2e typecheck clean status help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build server + client (dev)
	@./bin/build

build-prod: ## Build server + client (production, with SRI)
	@./bin/build production

launch: ## Start the server (builds first if needed)
	@./bin/launch

halt: ## Stop the server
	@./bin/halt

restart: halt launch ## Restart the server

dev: ## Start dev mode (watchers + auto-reload)
	@./bin/dev

test: ## Run tests
	@./bin/test run

test-watch: ## Run tests in watch mode
	@./bin/test watch

test-coverage: ## Run tests with coverage
	@./bin/test coverage

test-e2e: ## Run E2E tests (server must be on port 3001)
	@./bin/test e2e

typecheck: ## Type-check server + client
	@./bin/typecheck

clean: ## Remove build artifacts
	@./bin/clean

status: ## Show server/build/db/redis status
	@./bin/status
