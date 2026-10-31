#!/usr/bin/env bash
# Identity check of deploy/: fails when a vendor, person or account name, an e-mail
# address, a source repository URL or a host home path appears in a file or a file name.
#   SCRUB_PATTERNS='<ERE>|<ERE>' bash deploy/s6/test/scrub.sh
# SCRUB_PATTERNS (required): identity patterns separated by '|', kept outside the repository.
# SCRUB_ROOT (optional): directory to scan instead of the tracked files of deploy/
# (tracked = in the index: run it after `git add` to cover new files).
# Exit codes: 0 clean, 1 match found (matches printed), 2 usage error.
set -euo pipefail

readonly email_pattern='[[:alnum:]._%+-]+@[[:alnum:].-]+\.[a-z]{2,}'
readonly source_url_pattern='https?://[^ ]*(gitlab|git\.)[^ ]*'
readonly home_path_pattern='/home/[a-z]'

# Splits SCRUB_PATTERNS on '|' and drops empty items, so that "", "|" or "||" are refused
# instead of producing an empty alternative that would match every line.
identity_patterns=()
IFS='|' read -r -a raw_patterns <<< "${SCRUB_PATTERNS:-}"
for raw_pattern in "${raw_patterns[@]}"; do
    if [[ -n "${raw_pattern}" ]]; then
        identity_patterns+=("${raw_pattern}")
    fi
done
if (( ${#identity_patterns[@]} == 0 )); then
    echo "SCRUB_PATTERNS is required (identity patterns separated by '|')" >&2
    exit 2
fi

combined_pattern="$(IFS='|'; printf '%s' "${identity_patterns[*]}")"
combined_pattern="${combined_pattern}|${email_pattern}|${source_url_pattern}|${home_path_pattern}"

match_found=0

if [[ -n "${SCRUB_ROOT:-}" ]]; then
    if [[ ! -d "${SCRUB_ROOT}" ]]; then
        echo "SCRUB_ROOT ${SCRUB_ROOT} is not a directory" >&2
        exit 2
    fi
    if grep -rnIiE -- "${combined_pattern}" "${SCRUB_ROOT}"; then
        match_found=1
    fi
    if find "${SCRUB_ROOT}" -mindepth 1 -printf '%P\n' | grep -iE -- "${combined_pattern}" | sed 's/^/file name: /'; then
        match_found=1
    fi
else
    repository_root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
    cd "${repository_root}"
    if git grep -nIiE -e "${combined_pattern}" -- deploy; then
        match_found=1
    fi
    if git ls-files deploy | grep -iE -- "${combined_pattern}" | sed 's/^/file name: /'; then
        match_found=1
    fi
fi

if (( match_found == 1 )); then
    echo "identity patterns found, see the lines above" >&2
    exit 1
fi
echo "no identity pattern found"
