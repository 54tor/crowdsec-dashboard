#!/usr/bin/env bash
# Host-side tests of 25-secrets-key. No docker: the script runs with `bash <script>` and the
# chown to docker-user is skipped because the tests do not run as root.
#   bash deploy/s6/test/secrets-key.test.sh
set -euo pipefail

test_directory="$(cd "$(dirname "$0")" && pwd)"
secrets_key_script="${test_directory}/../rootfs/etc/cont-init.d/25-secrets-key"
key_material="c2VjcmV0LWtleS1tYXRlcmlhbC1mb3ItdGVzdHMtb25seQ=="
other_key_material="b3RoZXIta2V5LW1hdGVyaWFsLWZvci10ZXN0cy1vbmx5Cg=="

scratch_directory="$(mktemp -d -t csdash-secrets-test.XXXXXX)"
remove_scratch_directory() {
    case "${scratch_directory}" in
        */csdash-secrets-test.??????) rm -rf -- "${scratch_directory}" ;;
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

new_case_directory() {
    mktemp -d "${scratch_directory}/case.XXXXXX"
}

write_source() {
    printf '%s' "$2" > "$1"
    chmod 0600 "$1"
}

run_script() {
    local case_directory="$1"
    shift
    env SECRETS_KEY_DIR="${case_directory}/out" "$@" bash "${secrets_key_script}"
}

key_copy_is_0400_in_0700_dir() {
    local test_name="key_copy_is_0400_in_0700_dir"
    local case_directory
    case_directory="$(new_case_directory)"
    write_source "${case_directory}/source" "${key_material}"
    run_script "${case_directory}" SECRETS_KEY_SOURCE="${case_directory}/source" > /dev/null 2>&1 \
        || { report_failure "${test_name}" "script failed"; return; }
    if [[ "$(cat "${case_directory}/out/key")" != "${key_material}" ]]; then
        report_failure "${test_name}" "copy differs from the source"
        return
    fi
    if [[ "$(stat -c '%a' "${case_directory}/out")" != 700 || "$(stat -c '%a' "${case_directory}/out/key")" != 400 ]]; then
        report_failure "${test_name}" "modes are $(stat -c '%a' "${case_directory}/out") and $(stat -c '%a' "${case_directory}/out/key")"
        return
    fi
    report_success "${test_name}"
}

missing_source_fails_without_content() {
    local test_name="missing_source_fails_without_content"
    local case_directory missing_exit_code=0 empty_exit_code=0 combined_output
    case_directory="$(new_case_directory)"
    combined_output="$(run_script "${case_directory}" SECRETS_KEY_SOURCE="${case_directory}/absent" 2>&1)" || missing_exit_code=$?
    : > "${case_directory}/empty"
    combined_output+="$(run_script "${case_directory}" SECRETS_KEY_SOURCE="${case_directory}/empty" 2>&1)" || empty_exit_code=$?
    if [[ "${missing_exit_code}" != 1 || "${empty_exit_code}" != 1 ]]; then
        report_failure "${test_name}" "expected exit 1 twice, got ${missing_exit_code} and ${empty_exit_code}"
        return
    fi
    if [[ -z "${combined_output}" ]]; then
        report_failure "${test_name}" "no message was printed"
        return
    fi
    report_success "${test_name}"
}

copy_never_echoes_key() {
    local test_name="copy_never_echoes_key"
    local case_directory captured_output
    case_directory="$(new_case_directory)"
    write_source "${case_directory}/source" "${key_material}"
    write_source "${case_directory}/retired" "${other_key_material}"
    captured_output="$(run_script "${case_directory}" SECRETS_KEY_SOURCE="${case_directory}/source" \
        SECRETS_RETIRED_KEY_FILES="${case_directory}/retired" 2>&1)"
    if [[ "${captured_output}" == *"${key_material}"* || "${captured_output}" == *"${other_key_material}"* ]]; then
        report_failure "${test_name}" "output contains key material"
        return
    fi
    report_success "${test_name}"
}

rerun_replaces_previous_copy() {
    local test_name="rerun_replaces_previous_copy"
    local case_directory
    case_directory="$(new_case_directory)"
    write_source "${case_directory}/source" "${key_material}"
    run_script "${case_directory}" SECRETS_KEY_SOURCE="${case_directory}/source" > /dev/null 2>&1
    write_source "${case_directory}/source" "${other_key_material}"
    run_script "${case_directory}" SECRETS_KEY_SOURCE="${case_directory}/source" > /dev/null 2>&1 \
        || { report_failure "${test_name}" "second run failed"; return; }
    if [[ "$(cat "${case_directory}/out/key")" != "${other_key_material}" ]]; then
        report_failure "${test_name}" "second run kept the old value"
        return
    fi
    if [[ "$(stat -c '%a' "${case_directory}/out")" != 700 || "$(stat -c '%a' "${case_directory}/out/key")" != 400 ]]; then
        report_failure "${test_name}" "modes changed after the second run"
        return
    fi
    report_success "${test_name}"
}

TestRetiredKeysAreCopiedWithSameModeAndOwner() {
    local test_name="TestRetiredKeysAreCopiedWithSameModeAndOwner"
    local case_directory
    case_directory="$(new_case_directory)"
    write_source "${case_directory}/source" "${key_material}"
    write_source "${case_directory}/retired-a" "retired-one"
    write_source "${case_directory}/retired-b" "retired-two"
    run_script "${case_directory}" SECRETS_KEY_SOURCE="${case_directory}/source" \
        SECRETS_RETIRED_KEY_FILES="${case_directory}/retired-a,${case_directory}/retired-b" > /dev/null 2>&1 \
        || { report_failure "${test_name}" "script failed"; return; }
    local retired_index
    for retired_index in 1 2; do
        local copied_path="${case_directory}/out/retired-${retired_index}"
        if [[ "$(stat -c '%a %U' "${copied_path}")" != "400 $(id -un)" ]]; then
            report_failure "${test_name}" "retired-${retired_index} is $(stat -c '%a %U' "${copied_path}")"
            return
        fi
    done
    if [[ "$(cat "${case_directory}/out/retired-1")" != retired-one || "$(cat "${case_directory}/out/retired-2")" != retired-two ]]; then
        report_failure "${test_name}" "retired contents differ"
        return
    fi
    report_success "${test_name}"
}

TestMissingRetiredKeyFailsLoudly() {
    local test_name="TestMissingRetiredKeyFailsLoudly"
    local case_directory exit_code=0 captured_output
    case_directory="$(new_case_directory)"
    write_source "${case_directory}/source" "${key_material}"
    captured_output="$(run_script "${case_directory}" SECRETS_KEY_SOURCE="${case_directory}/source" \
        SECRETS_RETIRED_KEY_FILES="${case_directory}/absent-retired" 2>&1)" || exit_code=$?
    if [[ "${exit_code}" != 1 || "${captured_output}" != *absent-retired* ]]; then
        report_failure "${test_name}" "expected exit 1 naming the path, got ${exit_code}: ${captured_output}"
        return
    fi
    report_success "${test_name}"
}

key_copy_is_0400_in_0700_dir
missing_source_fails_without_content
copy_never_echoes_key
rerun_replaces_previous_copy
TestRetiredKeysAreCopiedWithSameModeAndOwner
TestMissingRetiredKeyFailsLoudly

if (( failed_test_count > 0 )); then
    printf '%s test(s) failed\n' "${failed_test_count}"
    exit 1
fi
printf 'all secrets-key tests passed\n'
