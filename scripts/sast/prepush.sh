#!/usr/bin/env bash
#
# CFML SAST pre-push hook.
#
# Deliberately bash-3.2 compatible: macOS still ships bash 3.2 as /bin/bash,
# so readarray/mapfile and associative arrays are unavailable here.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# The installer writes the scanner to CFSAST/; a source checkout keeps it in
# scripts/. Accept either, so the hook works in both layouts.
scanner=""
for candidate in "CFSAST/cfml_sast_simple.py" "scripts/cfml_sast_simple.py"; do
    if [ -f "$candidate" ]; then
        scanner="$candidate"
        break
    fi
done

if [ -z "$scanner" ]; then
    echo "CFML SAST: scanner not found (looked in CFSAST/ and scripts/)" >&2
    echo "CFML SAST: run 'python3 install.py' from the repository root" >&2
    exit 1
fi

python_cmd=""
for candidate in python3 python py; do
    if command -v "$candidate" >/dev/null 2>&1; then
        python_cmd="$candidate"
        break
    fi
done

if [ -z "$python_cmd" ]; then
    echo "CFML SAST: Python 3.8+ not found in PATH" >&2
    exit 1
fi

# Choose the commit to diff against.
base=""
upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
if [ -n "$upstream" ]; then
    base="$(git merge-base HEAD "$upstream" 2>/dev/null || true)"
fi
if [ -z "$base" ]; then
    # No upstream yet (first push of a branch): fall back to the parent commit.
    # --verify --quiet is required here; a bare `git rev-parse HEAD~1` echoes
    # the unresolved argument to stdout *and* exits non-zero, so a `||`
    # fallback would concatenate both results.
    base="$(git rev-parse --verify --quiet 'HEAD~1' || true)"
fi
if [ -z "$base" ]; then
    # HEAD is the root commit: diff against the empty tree.
    base="$(git hash-object -t tree /dev/null)"
fi

# NUL-delimited so paths containing spaces or newlines survive intact.
cfml_files=()
while IFS= read -r -d '' file; do
    lower="$(printf '%s' "$file" | tr '[:upper:]' '[:lower:]')"
    case "$lower" in
        *.cfm|*.cfc|*.cfml|*.cfinclude)
            if [ -f "$file" ]; then
                cfml_files+=("$file")
            fi
            ;;
    esac
done < <(git diff --name-only -z "$base" HEAD)

if [ ${#cfml_files[@]} -eq 0 ]; then
    echo "CFML SAST: no changed CFML files"
    exit 0
fi

echo "CFML SAST: scanning ${#cfml_files[@]} changed CFML file(s)..."

# Apply a baseline when the project has one, so the hook reports only new
# findings rather than the whole backlog.
baseline_args=()
if [ -f ".sast-baseline.json" ]; then
    baseline_args=(--baseline ".sast-baseline.json")
fi

# ${arr+"${arr[@]}"} is the bash-3.2-safe way to expand a possibly-empty array
# under `set -u`.
exec "$python_cmd" "$scanner" \
    --files "${cfml_files[@]}" \
    ${baseline_args+"${baseline_args[@]}"} \
    --fail-on-high
