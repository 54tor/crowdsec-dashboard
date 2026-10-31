#!/usr/bin/env bash
# Tests of scrub.sh, the identity check of deploy/. No docker.
#   SCRUB_PATTERNS='<pattern>|<pattern>' bash deploy/s6/test/scrub.test.sh
# SCRUB_PATTERNS holds the real identity patterns and is provided from outside the
# repository; only scrub_passes_on_deploy uses it, the other cases inject a dummy value.
set -euo pipefail

test_directory="$(cd "$(dirname "$0")" && pwd)"
scrub_script="${test_directory}/scrub.sh"
operator_patterns="${SCRUB_PATTERNS:-}"
unset SCRUB_PATTERNS SCRUB_ROOT

scratch_directory="$(mktemp -d -t csdash-scrub-test.XXXXXX)"

# The directory is removed only when its value is the one mktemp produced, so an empty
# or altered variable can never turn the cleanup into a removal of something else.
remove_scratch_directory() {
    case "${scratch_directory}" in
        */csdash-scrub-test.??????) rm -rf -- "${scratch_directory}" ;;
        *) printf 'refusing to remove unexpected directory %s\n' "${scratch_directory}" >&2 ;;
    esac
}
trap remove_scratch_directory EXIT

failed_test_count=0

report_failure() {
    printf 'FAIL %s: %s\n' "$1" "$2"
    failed_test_count=$((failed_test_count + 1))
}

report_success() {
    printf 'ok   %s\n' "$1"
}

# Runs scrub.sh with the given environment assignments; stdout and stderr go to
# ${scratch_directory}/output, the exit code is printed.
run_scrub() {
    local exit_code=0
    env "$@" bash "${scrub_script}" > "${scratch_directory}/output" 2>&1 || exit_code=$?
    printf '%s\n' "${exit_code}"
}

scrub_refuses_empty_patterns() {
    local test_name="scrub_refuses_empty_patterns"
    local refused_case exit_code
    for refused_case in absent empty separators; do
        case "${refused_case}" in
            absent) exit_code="$(run_scrub SCRUB_ROOT="${scratch_directory}")" ;;
            empty) exit_code="$(run_scrub SCRUB_ROOT="${scratch_directory}" SCRUB_PATTERNS=)" ;;
            separators) exit_code="$(run_scrub SCRUB_ROOT="${scratch_directory}" 'SCRUB_PATTERNS=||')" ;;
        esac
        if [[ "${exit_code}" != 2 ]]; then
            report_failure "${test_name}" "${refused_case} patterns must exit 2, got ${exit_code}"
            return
        fi
        if ! grep -q 'SCRUB_PATTERNS is required' "${scratch_directory}/output"; then
            report_failure "${test_name}" "${refused_case} patterns must print 'SCRUB_PATTERNS is required'"
            return
        fi
    done
    report_success "${test_name}"
}

scrub_detects_injected_pattern() {
    local test_name="scrub_detects_injected_pattern"
    local probe_root="${scratch_directory}/injected"
    local exit_code
    mkdir -p "${probe_root}"
    printf 'image label: scrub-probe-value\n' > "${probe_root}/content.txt"
    : > "${probe_root}/scrub-probe-value.txt"
    exit_code="$(run_scrub SCRUB_ROOT="${probe_root}" SCRUB_PATTERNS=scrub-probe-value)"
    if [[ "${exit_code}" != 1 ]]; then
        report_failure "${test_name}" "injected pattern must exit 1, got ${exit_code}"
        return
    fi
    if ! grep -q 'content.txt' "${scratch_directory}/output"; then
        report_failure "${test_name}" "the file containing the pattern is not reported"
        return
    fi
    if ! grep -q 'scrub-probe-value.txt' "${scratch_directory}/output"; then
        report_failure "${test_name}" "the file named after the pattern is not reported"
        return
    fi
    report_success "${test_name}"
}

# The address and the URL are assembled from variables so that this file itself never
# contains a literal that the built-in e-mail and source-URL patterns would match.
scrub_detects_email_and_source_url() {
    local test_name="scrub_detects_email_and_source_url"
    local mail_root="${scratch_directory}/mail" url_root="${scratch_directory}/url"
    local local_part=alice mail_domain=example.com url_scheme=https
    local exit_code
    mkdir -p "${mail_root}" "${url_root}"
    printf 'maintainer: %s@%s\n' "${local_part}" "${mail_domain}" > "${mail_root}/labels.txt"
    printf 'source: %s://git.example.com/x\n' "${url_scheme}" > "${url_root}/labels.txt"
    exit_code="$(run_scrub SCRUB_ROOT="${mail_root}" SCRUB_PATTERNS=scrub-probe-value)"
    if [[ "${exit_code}" != 1 ]]; then
        report_failure "${test_name}" "e-mail address must exit 1, got ${exit_code}"
        return
    fi
    exit_code="$(run_scrub SCRUB_ROOT="${url_root}" SCRUB_PATTERNS=scrub-probe-value)"
    if [[ "${exit_code}" != 1 ]]; then
        report_failure "${test_name}" "source URL must exit 1, got ${exit_code}"
        return
    fi
    report_success "${test_name}"
}

scrub_passes_on_deploy() {
    local test_name="scrub_passes_on_deploy"
    local exit_code
    if [[ -z "${operator_patterns}" ]]; then
        report_failure "${test_name}" "SCRUB_PATTERNS must be provided by the environment"
        return
    fi
    exit_code="$(run_scrub SCRUB_PATTERNS="${operator_patterns}")"
    if [[ "${exit_code}" != 0 ]]; then
        report_failure "${test_name}" "deploy/ must be clean, got exit ${exit_code} (see scrub.sh output)"
        return
    fi
    report_success "${test_name}"
}

scrub_refuses_empty_patterns
scrub_detects_injected_pattern
scrub_detects_email_and_source_url
scrub_passes_on_deploy

if (( failed_test_count > 0 )); then
    printf '%s test(s) failed\n' "${failed_test_count}"
    exit 1
fi
printf 'all scrub tests passed\n'
