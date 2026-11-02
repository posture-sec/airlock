#!/bin/sh
# Publish the Wave issue batch (task 1.14) from docs/wave/issues/.
#
# Dry run by default: it prints the title, the label list and the resolved body length for each
# file, and changes nothing. `--apply` is the only mode that calls gh, and it refuses to start if
# the repository has no `Stellar Wave` label yet, because on an unapproved repository Drips strips
# that label silently and the issue would look published while scoring nothing.
#
# Issues are created in filename order so that the `#N` references inside a blocking banner resolve
# against the numbers that already exist. `{{issue:slug}}` becomes that number; `{{issue:self}}`
# becomes the issue's own number, which is only knowable after creation, so it is patched with
# `gh issue edit` immediately afterwards.
#
# Usage:
#   sh scripts/create_wave_issues.sh                 # dry run against posture-sec/airlock
#   sh scripts/create_wave_issues.sh --apply [--repo owner/name]
#
# AGENTS.md section 4: no network during a scan. This is not a scan; it is a maintenance script and
# it only ever talks to GitHub when given --apply.

set -eu

repo="posture-sec/airlock"
apply=0
dir="docs/wave/issues"

for arg in "$@"; do
    case "$arg" in
        --apply) apply=1 ;;
        --repo) want_repo=1 ;;
        --repo=*) repo="${arg#--repo=}" ;;
        --dir) want_dir=1 ;;
        --dir=*) dir="${arg#--dir=}" ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *)
            if [ "${want_repo:-0}" -eq 1 ]; then
                repo="$arg"
                want_repo=0
                continue
            fi
            if [ "${want_dir:-0}" -eq 1 ]; then
                dir="$arg"
                want_dir=0
                continue
            fi
            echo "create_wave_issues: unknown argument $arg" >&2
            exit 2
            ;;
    esac
done

if [ "${want_repo:-0}" -eq 1 ]; then
    echo "create_wave_issues: --repo needs a value; use --repo owner/name" >&2
    exit 2
fi
if [ "${want_dir:-0}" -eq 1 ]; then
    echo "create_wave_issues: --dir needs a value" >&2
    exit 2
fi

if [ ! -d "$dir" ]; then
    echo "create_wave_issues: no issue directory at $dir" >&2
    exit 2
fi

if [ "$apply" -eq 1 ] && ! command -v gh >/dev/null 2>&1; then
    echo "create_wave_issues: --apply needs the gh CLI on PATH" >&2
    exit 2
fi

# Front matter is three fields and a body, written by hand in a fixed shape. Parsing it with a
# here-doc reader rather than a YAML library is a deliberate choice: there is no YAML parser in the
# runtime dependencies and this script is not allowed to acquire one.
read_field() {
    key="$1"
    file="$2"
    sed -n "s/^${key}: //p" "$file" | head -n 1 | sed 's/[[:space:]]*$//'
}

body_from() {
    # Everything after the closing front-matter delimiter. Counting the delimiters rather than
    # setting a flag on the first one matters: the file opens with `---`, so a flag test starts
    # the body at the `slug:` line and publishes the front matter as part of the description.
    awk '/^---$/ { fence++; next } fence >= 2' "$1"
}

if [ "$apply" -eq 1 ]; then
    if ! gh api "repos/${repo}/labels/Stellar%20Wave" --silent >/dev/null 2>&1; then
        echo "create_wave_issues: ${repo} has no 'Stellar Wave' label." >&2
        echo "On a repository Drips has not approved, that label is removed automatically and the" >&2
        echo "issues score nothing. Follow docs/wave/settings.md: apply first, then publish." >&2
        exit 1
    fi
fi

echo "target repository: ${repo}"
echo "mode: $([ "$apply" -eq 1 ] && echo 'apply' || echo 'dry run')"
echo

count=0
numbers=""
for file in "$dir"/*.md; do
    [ -e "$file" ] || continue
    title=$(read_field title "$file")
    labels=$(read_field labels "$file")
    roadmap=$(read_field roadmap "$file")
    slug=$(basename "$file" .md | sed 's/^[0-9]*-//')

    if [ -z "$title" ] || [ -z "$labels" ]; then
        echo "create_wave_issues: $file has no title or labels in its front matter" >&2
        exit 2
    fi

    body=$(body_from "$file")
    # Resolve {{issue:slug}} against issues created earlier in this run.
    for pair in $numbers; do
        key=${pair%%=*}
        num=${pair##*=}
        body=$(printf '%s' "$body" | sed "s|{{issue:${key}}}|${num}|g")
    done

    if [ "$apply" -eq 0 ]; then
        unresolved=$(printf '%s' "$body" | grep -c '{{issue:' || true)
        printf '%s\n' "  ${slug}"
        printf '%s\n' "    title   ${title}"
        printf '%s\n' "    labels  ${labels}"
        printf '%s\n' "    roadmap ${roadmap}"
        printf '%s\n' "    body    $(printf '%s' "$body" | wc -l) lines, ${unresolved} unresolved issue reference(s)"
        count=$((count + 1))
        continue
    fi

    # The self reference has to survive creation, so it is masked and put back after.
    printf '%s' "$body" | sed 's|{{issue:self}}|__SELF__|g' >"/tmp/airlock-wave-body.${slug}.md"
    url=$(gh issue create --repo "$repo" --title "$title" \
        --label "$(printf '%s' "$labels" | sed 's/, /,/g')" \
        --body-file "/tmp/airlock-wave-body.${slug}.md")
    num=${url##*/}
    if grep -q '__SELF__' "/tmp/airlock-wave-body.${slug}.md"; then
        sed -i "s|__SELF__|${num}|g" "/tmp/airlock-wave-body.${slug}.md"
        gh issue edit "$num" --repo "$repo" --body-file "/tmp/airlock-wave-body.${slug}.md"
    fi
    rm -f "/tmp/airlock-wave-body.${slug}.md"
    numbers="${numbers} ${slug}=${num}"
    echo "  created #${num}  ${title}"
    count=$((count + 1))
done

echo
if [ "$apply" -eq 0 ]; then
    echo "dry run: ${count} issue(s) staged, nothing created. Re-run with --apply."
else
    echo "created ${count} issue(s) in ${repo}."
    echo "Next, per docs/wave/settings.md: record the points total against the per-repo cap, and"
    echo "tick the Wave row in ROADMAP.md in the pull request that reports the result."
fi
