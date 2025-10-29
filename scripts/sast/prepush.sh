#!/bin/bash
set -euo pipefail  # Strict error handling

# Get the base commit for comparison
upstream_branch="$(git rev-parse --abbrev-ref --symbolic-full-name @{u} 2>/dev/null || echo "")"
if [ -n "$upstream_branch" ]; then
    BASE="$(git merge-base HEAD "$upstream_branch" 2>/dev/null || echo "HEAD~1")"
else
    BASE="HEAD~1"
fi

# Get changed files (quoted to handle spaces in filenames)
readarray -t changed_files < <(git diff --name-only "$BASE" HEAD 2>/dev/null || git diff --cached --name-only)

if [ ${#changed_files[@]} -eq 0 ]; then
    echo "No changed files detected"
    exit 0
fi

# Filter for CFML files only
cfml_files=()
for file in "${changed_files[@]}"; do
    if [[ "$file" =~ \.(cfm|cfc|cfml|cfinclude)$ ]] && [ -f "$file" ]; then
        cfml_files+=("$file")
    fi
done

if [ ${#cfml_files[@]} -eq 0 ]; then
    echo "No CFML files changed"
    exit 0
fi

echo "Scanning ${#cfml_files[@]} changed CFML files..."

# Run SAST scanner on changed files (properly quoted)
if command -v python3 >/dev/null 2>&1; then
    python3 "scripts/cfml_sast_simple.py" --files "${cfml_files[@]}" --fail-on-high
elif command -v python >/dev/null 2>&1; then
    python "scripts/cfml_sast_simple.py" --files "${cfml_files[@]}" --fail-on-high
else
    echo "Error: Python not found. Please install Python 3.6+" >&2
    exit 1
fi