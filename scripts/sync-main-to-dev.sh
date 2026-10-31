#!/usr/bin/env bash
# Merge release-branch fixes from `main` into `dev`, run the quality gates,
# push `dev`, and rebuild + restart the Docker deployment from `dev`.
#
# Usage: scripts/sync-main-to-dev.sh [--no-test] [--no-push] [--no-rebuild]
set -euo pipefail

run_tests=1 push=1 rebuild=1
for arg in "$@"; do
    case "$arg" in
        --no-test) run_tests=0 ;;
        --no-push) push=0 ;;
        --no-rebuild) rebuild=0 ;;
        -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

cd "$(git rev-parse --show-toplevel)"
source scripts/lib/branch-flow.sh

require_clean_tree
log "Fetching origin"
git fetch --quiet origin main dev

git switch --quiet dev
git merge --quiet --ff-only origin/dev

if git merge-base --is-ancestor origin/main HEAD; then
    log "dev already contains main"
else
    log "Merging origin/main into dev"
    if ! git merge --no-edit -m "chore(sync): merge main into dev" origin/main; then
        echo >&2
        echo "Merge conflict. Resolve, 'git commit', then re-run this script." >&2
        exit 1
    fi
fi

[ "$run_tests" = 1 ] && run_quality_gates

if [ "$push" = 1 ] && [ -n "$(git rev-list origin/dev..HEAD)" ]; then
    log "Pushing dev"
    git push origin dev
fi

[ "$rebuild" = 1 ] && rebuild_deployment
log "dev is at $(git rev-parse --short HEAD)"
