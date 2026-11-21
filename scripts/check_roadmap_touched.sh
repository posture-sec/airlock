#!/bin/sh
# Roadmap gate (task 1.9): every pull request that changes files must change ROADMAP.md too.
#
# Two checks, both stated in AGENTS.md section 1:
#   1. if the diff touches any file, it must touch ROADMAP.md;
#   2. the `Last updated` line must actually have moved, because a PR that ticks nothing and
#      rewrites nothing leaves the document claiming a state it no longer describes.
#
# Usage: scripts/check_roadmap_touched.sh <refs/heads/name|refs/remotes/name>
# In a workflow the base ref is refs/remotes/origin/$GITHUB_BASE_REF. A branch with no commits ahead of its
# base passes: there is no change to describe.

set -eu

base="${1:-}"
if [ -z "$base" ] && [ -n "${GITHUB_BASE_REF:-}" ]; then
    base="refs/remotes/origin/${GITHUB_BASE_REF}"
fi
if [ -z "$base" ]; then
    echo "check_roadmap_touched: no base ref; pass one or set GITHUB_BASE_REF" >&2
    exit 1
fi

case "$base" in
    refs/heads/?*|refs/remotes/?*) ;;
    *) echo "check_roadmap_touched: invalid base ref '$base'; expected refs/heads/<name> or refs/remotes/<name>" >&2; exit 1 ;;
esac

if ! git rev-parse --verify --quiet --end-of-options "${base}^{commit}" >/dev/null; then
    echo "check_roadmap_touched: ${base} is not a commit here; fetch the base branch" >&2
    exit 1
fi

merge_base=$(git merge-base "${base}" HEAD) || {
    echo "check_roadmap_touched: cannot find a merge base with ${base}" >&2
    exit 1
}

changed=$(git diff --name-only "${merge_base}" HEAD)
if [ -z "$changed" ]; then
    echo "check_roadmap_touched: nothing changed, so there is nothing to record"
    exit 0
fi

if ! printf '%s\n' "$changed" | grep -qx 'ROADMAP.md'; then
    echo "check_roadmap_touched: this change touches files but not ROADMAP.md."
    echo "AGENTS.md section 1: a task is not finished until ROADMAP.md is current."
    exit 1
fi

before=$(git show "${merge_base}:ROADMAP.md" | sed -n 's/^Last updated: //p' | head -n 1)
after=$(sed -n 's/^Last updated: //p' ROADMAP.md | head -n 1)
if [ -z "$after" ]; then
    echo "check_roadmap_touched: ROADMAP.md has no 'Last updated:' line to check" >&2
    exit 1
fi
if [ "$before" = "$after" ]; then
    echo "check_roadmap_touched: ROADMAP.md changed but its 'Last updated' line did not."
    echo "It still reads: Last updated: ${after}"
    exit 1
fi

echo "check_roadmap_touched: ROADMAP.md updated, ${before} -> ${after}"
exit 0
