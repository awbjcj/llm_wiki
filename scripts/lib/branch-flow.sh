# Shared helpers for scripts/sync-main-to-dev.sh and scripts/release.sh.
# shellcheck shell=bash

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

require_clean_tree() {
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        echo "Working tree has uncommitted changes; commit or stash them first." >&2
        exit 1
    fi
}

# Same gates as the `quality` job in .github/workflows/ci.yml.
run_quality_gates() {
    log "Installing dependencies"
    npm ci --no-audit --no-fund --loglevel=error
    npm --prefix mcp-server ci --no-audit --no-fund --loglevel=error
    log "Typecheck";  npm run --silent typecheck
    log "Unit tests"; npm run --silent test:mocks
    log "MCP tests";  npm run --silent mcp:test
    log "Web sign-in tests"; python3 -m unittest discover -s docker/tests
}

# Rebuild the browser-served image from the current checkout and restart it.
rebuild_deployment() {
    log "Building Docker image"
    docker compose build
    log "Restarting container"
    docker compose up -d
    local id status=starting
    id=$(docker compose ps -q llm-wiki)
    for _ in $(seq 1 60); do
        status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id")
        [ "$status" = healthy ] && break
        [ "$status" = unhealthy ] && break
        sleep 5
    done
    if [ "$status" != healthy ]; then
        echo "Container is $status; check: docker compose logs llm-wiki" >&2
        exit 1
    fi
    log "Container healthy"
}
