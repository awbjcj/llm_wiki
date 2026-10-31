#!/usr/bin/env bash
# Release `dev` to `main`: sync main into dev first, gate, merge dev into main,
# optionally tag (vX.Y.Z tags trigger .github/workflows/build.yml), push, and
# return to `dev`. The push to main triggers sync-main-to-dev.yml.
#
# Usage: scripts/release.sh [--tag vX.Y.Z] [--no-test]
set -euo pipefail

tag="" run_tests=1
while [ $# -gt 0 ]; do
    case "$1" in
        --tag) tag="${2:?--tag needs a value}"; shift ;;
        --no-test) run_tests=0 ;;
        -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

cd "$(git rev-parse --show-toplevel)"
source scripts/lib/branch-flow.sh

if [ -n "$tag" ] && git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    echo "tag $tag already exists" >&2; exit 1
fi

sync_args=(--no-rebuild)
[ "$run_tests" = 0 ] && sync_args+=(--no-test)
scripts/sync-main-to-dev.sh "${sync_args[@]}"

log "Merging dev into main"
git switch --quiet main
git merge --quiet --ff-only origin/main
git merge --no-ff --no-edit -m "release: merge dev into main${tag:+ ($tag)}" dev

if [ -n "$tag" ]; then
    git tag -a "$tag" -m "LLM Wiki $tag"
    git push --atomic origin main "$tag"
else
    git push origin main
fi

# Bring dev level with main right away (fast-forward) so CI's auto-sync is a no-op.
git switch --quiet dev
git merge --quiet --ff-only main
git push origin dev
log "Released $(git rev-parse --short main)${tag:+ as $tag}; back on dev"
