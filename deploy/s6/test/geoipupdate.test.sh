#!/usr/bin/env bash
# Host-side tests of 30-geoipupdate, geoipupdate-once and the cron service. No docker: every
# script is run with `bash <script>`, and fake geoipupdate, supercronic, run_as_docker_user,
# id and chown are put first in PATH. The fakes write what they receive into the case
# directory so that each test can assert on argv, environment and side effects.
#   bash deploy/s6/test/geoipupdate.test.sh
# shellcheck disable=SC2016  # fake bodies are written single-quoted on purpose: they expand when the fake runs
set -euo pipefail

test_directory="$(cd "$(dirname "$0")" && pwd)"
geoipupdate_init_script="${test_directory}/../rootfs/etc/cont-init.d/30-geoipupdate"
geoipupdate_once_script="${test_directory}/../rootfs/usr/local/bin/geoipupdate-once"
cron_service_script="${test_directory}/../overlays/alpine/etc/services.d/cron/run"

# Valid-looking but fake MaxMind values; the key is long and unusual so that a substring
# search for it cannot match anything else by accident.
fake_account_id="123456"
fake_license_key="FakeLicenseKey_0123456789abcdefXYZ"
expected_cron_command="root /usr/local/bin/run_as_docker_user /usr/local/bin/geoipupdate-once"

scratch_directory="$(mktemp -d -t csdash-geoip-test.XXXXXX)"
remove_scratch_directory() {
    case "${scratch_directory}" in
        */csdash-geoip-test.??????) rm -rf -- "${scratch_directory}" ;;
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

# Every fake appends "<name> <argv>" and its full environment to $FAKE_RECORD_DIR, so a
# test can grep all of them at once for the license key.
write_fake() {
    local fake_directory="$1" fake_name="$2" fake_body="$3"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'printf "%%s %%s\\n" "%s" "$*" >> "${FAKE_RECORD_DIR}/%s.argv"\n' "${fake_name}" "${fake_name}"
        printf 'env >> "${FAKE_RECORD_DIR}/%s.env"\n' "${fake_name}"
        printf '%s\n' "${fake_body}"
    } > "${fake_directory}/${fake_name}"
    chmod 0755 "${fake_directory}/${fake_name}"
}

# Wraps a real command: the wrapper records its argv and environment, then runs the real
# binary, so the scripts keep working while every external call is observed.
write_recording_wrapper() {
    local fake_directory="$1" command_name="$2"
    local real_command_path
    real_command_path="$(command -v "${command_name}")"
    write_fake "${fake_directory}" "${command_name}" "exec \"${real_command_path}\" \"\$@\""
}

new_case_directory() {
    local case_directory
    case_directory="$(mktemp -d "${scratch_directory}/case.XXXXXX")"
    mkdir -p "${case_directory}/secrets" "${case_directory}/cron.d" "${case_directory}/geoip" \
        "${case_directory}/records" "${case_directory}/fakes"
    local wrapped_command
    for wrapped_command in chmod chown mkdir rm cat mv install; do
        write_recording_wrapper "${case_directory}/fakes" "${wrapped_command}"
    done
    printf '%s\n' "${case_directory}"
}

write_credentials() {
    local case_directory="$1" account_id_content="$2" license_key_content="$3"
    printf '%s' "${account_id_content}" > "${case_directory}/secrets/maxmind-account-id"
    printf '%s' "${license_key_content}" > "${case_directory}/secrets/maxmind-license-key"
}

# Runs 30-geoipupdate with the case directories; stdout and stderr go to the case
# directory, the exit code is printed.
run_geoipupdate_init() {
    local case_directory="$1"
    shift
    local exit_code=0
    env PATH="${case_directory}/fakes:${PATH}" FAKE_RECORD_DIR="${case_directory}/records" \
        GEOIPUPDATE_SECRETS_DIR="${case_directory}/secrets" \
        GEOIPUPDATE_CONF_DIR="${case_directory}/conf" \
        CRON_DIR="${case_directory}/cron.d" \
        GEOIP_DIR="${case_directory}/geoip" \
        "$@" bash "${geoipupdate_init_script}" \
        > "${case_directory}/stdout" 2> "${case_directory}/stderr" || exit_code=$?
    printf '%s\n' "${exit_code}"
}

cron_entry_line() {
    cat "$1/cron.d/geoipupdate"
}

output_contains() {
    local case_directory="$1" needle="$2"
    grep -qF -- "${needle}" "${case_directory}/stdout" "${case_directory}/stderr"
}

records_contain() {
    local case_directory="$1" needle="$2"
    grep -rqF -- "${needle}" "${case_directory}/records"
}

credentials_missing_creates_no_cron_entry() {
    local test_name="credentials_missing_creates_no_cron_entry"
    local case_directory exit_code
    case_directory="$(new_case_directory)"
    printf '17 3 */1 * * %s\n' "${expected_cron_command}" > "${case_directory}/cron.d/geoipupdate"
    exit_code="$(run_geoipupdate_init "${case_directory}")"
    if [[ "${exit_code}" != 0 ]]; then
        report_failure "${test_name}" "expected exit 0, got ${exit_code}"
        return
    fi
    if [[ -e "${case_directory}/cron.d/geoipupdate" ]]; then
        report_failure "${test_name}" "the previous cron entry was not removed"
        return
    fi
    if [[ -e "${case_directory}/conf/GeoIP.conf" ]]; then
        report_failure "${test_name}" "GeoIP.conf exists without credentials"
        return
    fi
    if [[ ! -s "${case_directory}/stdout" && ! -s "${case_directory}/stderr" ]]; then
        report_failure "${test_name}" "no warning was printed"
        return
    fi
    report_success "${test_name}"
}

empty_license_file_creates_no_cron_entry() {
    local test_name="empty_license_file_creates_no_cron_entry"
    local case_directory exit_code
    case_directory="$(new_case_directory)"
    write_credentials "${case_directory}" "${fake_account_id}" ""
    exit_code="$(run_geoipupdate_init "${case_directory}")"
    if [[ "${exit_code}" != 0 || -e "${case_directory}/cron.d/geoipupdate" || -e "${case_directory}/conf/GeoIP.conf" ]]; then
        report_failure "${test_name}" "expected exit 0 and no entry, got ${exit_code}"
        return
    fi
    report_success "${test_name}"
}

invalid_credentials_never_fail_the_init() {
    local test_name="invalid_credentials_never_fail_the_init"
    local invalid_case account_id_content license_key_content case_directory exit_code
    for invalid_case in non_numeric_id key_with_newline key_with_space key_with_symbol; do
        account_id_content="${fake_account_id}"
        license_key_content="${fake_license_key}"
        case "${invalid_case}" in
            non_numeric_id) account_id_content="12ab34" ;;
            key_with_newline) license_key_content="${fake_license_key}"$'\n'"SecondLine" ;;
            key_with_space) license_key_content="${fake_license_key} SecondWord" ;;
            key_with_symbol) license_key_content="${fake_license_key};" ;;
        esac
        case_directory="$(new_case_directory)"
        write_credentials "${case_directory}" "${account_id_content}" "${license_key_content}"
        exit_code="$(run_geoipupdate_init "${case_directory}")"
        if [[ "${exit_code}" != 0 ]]; then
            report_failure "${test_name}" "${invalid_case}: expected exit 0, got ${exit_code}"
            return
        fi
        if [[ -e "${case_directory}/cron.d/geoipupdate" || -e "${case_directory}/conf/GeoIP.conf" ]]; then
            report_failure "${test_name}" "${invalid_case}: an entry or a GeoIP.conf was written"
            return
        fi
        if output_contains "${case_directory}" "${fake_license_key}" || output_contains "${case_directory}" "12ab34"; then
            report_failure "${test_name}" "${invalid_case}: the output contains secret content"
            return
        fi
    done
    report_success "${test_name}"
}

cron_entry_runs_as_docker_user_with_validated_schedule() {
    local test_name="cron_entry_runs_as_docker_user_with_validated_schedule"
    local case_directory exit_code expected_line
    case_directory="$(new_case_directory)"
    write_credentials "${case_directory}" "${fake_account_id}" "${fake_license_key}"
    exit_code="$(run_geoipupdate_init "${case_directory}")"
    if [[ "${exit_code}" != 0 ]]; then
        report_failure "${test_name}" "expected exit 0, got ${exit_code}"
        return
    fi
    expected_line="17 3 */1 * * ${expected_cron_command}"
    if [[ "$(cron_entry_line "${case_directory}")" != "${expected_line}" ]]; then
        report_failure "${test_name}" "entry is '$(cron_entry_line "${case_directory}")'"
        return
    fi
    if [[ "$(stat -c '%a' "${case_directory}/cron.d/geoipupdate")" != 644 ]]; then
        report_failure "${test_name}" "entry mode is $(stat -c '%a' "${case_directory}/cron.d/geoipupdate")"
        return
    fi
    report_success "${test_name}"
}

frequency_is_validated_before_use() {
    local test_name="frequency_is_validated_before_use"
    local default_schedule="17 3 */1 * *"
    local -A expected_schedule_by_frequency=(
        ["1"]="17 */1 * * *"
        ["6"]="17 */6 * * *"
        ["12"]="17 */12 * * *"
        ["24"]="${default_schedule}"
        ["48"]="17 3 */2 * *"
        ["168"]="17 3 */7 * *"
        ["5"]="${default_schedule}"
        ["36"]="${default_schedule}"
        ["abc"]="${default_schedule}"
        ["0"]="${default_schedule}"
        ["06"]="${default_schedule}"
        ["999"]="${default_schedule}"
        ["1; rm"]="${default_schedule}"
        ["-24"]="${default_schedule}"
    )
    local frequency_value case_directory exit_code expected_line
    for frequency_value in "${!expected_schedule_by_frequency[@]}"; do
        case_directory="$(new_case_directory)"
        write_credentials "${case_directory}" "${fake_account_id}" "${fake_license_key}"
        exit_code="$(run_geoipupdate_init "${case_directory}" GEOIPUPDATE_FREQUENCY_HOURS="${frequency_value}")"
        expected_line="${expected_schedule_by_frequency[${frequency_value}]} ${expected_cron_command}"
        if [[ "${exit_code}" != 0 ]]; then
            report_failure "${test_name}" "frequency '${frequency_value}': exit ${exit_code}"
            return
        fi
        if [[ "$(cron_entry_line "${case_directory}")" != "${expected_line}" ]]; then
            report_failure "${test_name}" "frequency '${frequency_value}': entry is '$(cron_entry_line "${case_directory}")'"
            return
        fi
    done
    report_success "${test_name}"
}

conf_is_mode_0600() {
    local test_name="conf_is_mode_0600"
    local case_directory exit_code expected_conf
    case_directory="$(new_case_directory)"
    write_credentials "${case_directory}" "${fake_account_id}" "${fake_license_key}"$'\n'
    exit_code="$(run_geoipupdate_init "${case_directory}")"
    if [[ "${exit_code}" != 0 ]]; then
        report_failure "${test_name}" "expected exit 0, got ${exit_code}"
        return
    fi
    if [[ "$(stat -c '%a' "${case_directory}/conf")" != 700 || "$(stat -c '%a' "${case_directory}/conf/GeoIP.conf")" != 600 ]]; then
        report_failure "${test_name}" "modes are $(stat -c '%a' "${case_directory}/conf") and $(stat -c '%a' "${case_directory}/conf/GeoIP.conf")"
        return
    fi
    expected_conf="$(printf 'AccountID %s\nLicenseKey %s\nEditionIDs GeoLite2-Country' "${fake_account_id}" "${fake_license_key}")"
    if [[ "$(cat "${case_directory}/conf/GeoIP.conf")" != "${expected_conf}" ]]; then
        report_failure "${test_name}" "GeoIP.conf content differs from the expected three lines"
        return
    fi
    report_success "${test_name}"
}

argv_env_and_logs_never_contain_license_key() {
    local test_name="argv_env_and_logs_never_contain_license_key"
    local case_directory exit_code
    case_directory="$(new_case_directory)"
    write_fake "${case_directory}/fakes" id 'if [[ "${1:-}" == "-u" ]]; then echo 0; else exec /usr/bin/id "$@"; fi'
    write_fake "${case_directory}/fakes" chown 'exit 0'
    write_credentials "${case_directory}" "${fake_account_id}" "${fake_license_key}"
    exit_code="$(run_geoipupdate_init "${case_directory}")"
    if [[ "${exit_code}" != 0 || ! -e "${case_directory}/conf/GeoIP.conf" ]]; then
        report_failure "${test_name}" "init did not write GeoIP.conf (exit ${exit_code})"
        return
    fi
    if ! records_contain "${case_directory}" "chown"; then
        report_failure "${test_name}" "no external call was recorded, the check would be vacuous"
        return
    fi
    if records_contain "${case_directory}" "${fake_license_key}"; then
        report_failure "${test_name}" "the key appears in the argv or environment of an external command"
        return
    fi
    if output_contains "${case_directory}" "${fake_license_key}"; then
        report_failure "${test_name}" "the key appears in the init output"
        return
    fi
    report_success "${test_name}"
}

geoip_dir_is_chowned_on_every_start() {
    local test_name="geoip_dir_is_chowned_on_every_start"
    local case_directory exit_code
    case_directory="$(new_case_directory)"
    write_fake "${case_directory}/fakes" chown 'exit 0'
    write_credentials "${case_directory}" "${fake_account_id}" "${fake_license_key}"
    exit_code="$(run_geoipupdate_init "${case_directory}")"
    if [[ "${exit_code}" != 0 ]]; then
        report_failure "${test_name}" "non-root run: expected exit 0, got ${exit_code}"
        return
    fi
    if [[ -e "${case_directory}/records/chown.argv" ]]; then
        report_failure "${test_name}" "non-root run attempted a chown"
        return
    fi
    write_fake "${case_directory}/fakes" id 'if [[ "${1:-}" == "-u" ]]; then echo 0; else exec /usr/bin/id "$@"; fi'
    exit_code="$(run_geoipupdate_init "${case_directory}")"
    if [[ "${exit_code}" != 0 ]]; then
        report_failure "${test_name}" "simulated root run: expected exit 0, got ${exit_code}"
        return
    fi
    if ! grep -qxF "chown -R docker-user:docker-user ${case_directory}/geoip" "${case_directory}/records/chown.argv"; then
        report_failure "${test_name}" "geoip directory not chowned: $(cat "${case_directory}/records/chown.argv")"
        return
    fi
    if ! grep -qxF "chown docker-user:docker-user ${case_directory}/conf ${case_directory}/conf/GeoIP.conf" "${case_directory}/records/chown.argv"; then
        report_failure "${test_name}" "GeoIP.conf not handed to docker-user: $(cat "${case_directory}/records/chown.argv")"
        return
    fi
    report_success "${test_name}"
}

# Runs the cron service with fakes. The fake supercronic copies the crontab it receives
# to records/crontab and exits; the fake run_as_docker_user only records its argv.
run_cron_service() {
    local case_directory="$1"
    local exit_code=0
    write_fake "${case_directory}/fakes" supercronic 'cp "$1" "${FAKE_RECORD_DIR}/crontab"'
    write_fake "${case_directory}/fakes" run_as_docker_user 'exit 0'
    env PATH="${case_directory}/fakes:${PATH}" FAKE_RECORD_DIR="${case_directory}/records" \
        SUPERCRONIC_BIN="${case_directory}/fakes/supercronic" \
        CRON_WORK_DIR="${case_directory}/supercronic" \
        CRON_DIR="${case_directory}/cron.d" \
        GEOIP_DIR="${case_directory}/geoip" \
        bash "${cron_service_script}" > "${case_directory}/stdout" 2> "${case_directory}/stderr" || exit_code=$?
    printf '%s\n' "${exit_code}"
}

# The initial fetch runs in the background, so absence can only be checked after a delay
# and presence is polled for at most 5 s.
wait_for_file() {
    local expected_path="$1" remaining_polls="$2"
    while (( remaining_polls > 0 )); do
        [[ -e "${expected_path}" ]] && return 0
        sleep 0.1
        remaining_polls=$((remaining_polls - 1))
    done
    return 1
}

initial_fetch_runs_only_when_database_missing() {
    local test_name="initial_fetch_runs_only_when_database_missing"
    local case_directory exit_code
    case_directory="$(new_case_directory)"
    printf '17 3 */1 * * %s\n' "${expected_cron_command}" > "${case_directory}/cron.d/geoipupdate"
    exit_code="$(run_cron_service "${case_directory}")"
    if [[ "${exit_code}" != 0 ]]; then
        report_failure "${test_name}" "cron service exited ${exit_code}"
        return
    fi
    if ! wait_for_file "${case_directory}/records/run_as_docker_user.argv" 50; then
        report_failure "${test_name}" "no initial fetch within 5 s while the database is missing"
        return
    fi
    if [[ "$(cat "${case_directory}/records/run_as_docker_user.argv")" != "run_as_docker_user /usr/local/bin/geoipupdate-once" ]]; then
        report_failure "${test_name}" "initial fetch argv is '$(cat "${case_directory}/records/run_as_docker_user.argv")'"
        return
    fi

    case_directory="$(new_case_directory)"
    printf '17 3 */1 * * %s\n' "${expected_cron_command}" > "${case_directory}/cron.d/geoipupdate"
    : > "${case_directory}/geoip/GeoLite2-Country.mmdb"
    run_cron_service "${case_directory}" > /dev/null
    if wait_for_file "${case_directory}/records/run_as_docker_user.argv" 10; then
        report_failure "${test_name}" "initial fetch ran although the database exists"
        return
    fi

    case_directory="$(new_case_directory)"
    run_cron_service "${case_directory}" > /dev/null
    if wait_for_file "${case_directory}/records/run_as_docker_user.argv" 10; then
        report_failure "${test_name}" "initial fetch ran without a geoipupdate cron entry"
        return
    fi
    report_success "${test_name}"
}

cron_service_strips_root_field() {
    local test_name="cron_service_strips_root_field"
    local case_directory exit_code
    case_directory="$(new_case_directory)"
    : > "${case_directory}/geoip/GeoLite2-Country.mmdb"
    {
        printf '17 */6 * * * %s\n' "${expected_cron_command}"
        printf '@daily root /usr/local/bin/other-job\n'
        printf '# comment line\n'
    } > "${case_directory}/cron.d/geoipupdate"
    exit_code="$(run_cron_service "${case_directory}")"
    if [[ "${exit_code}" != 0 || ! -e "${case_directory}/records/crontab" ]]; then
        report_failure "${test_name}" "fake supercronic did not receive a crontab (exit ${exit_code})"
        return
    fi
    if ! grep -qxF "17 */6 * * * /usr/local/bin/run_as_docker_user /usr/local/bin/geoipupdate-once" "${case_directory}/records/crontab"; then
        report_failure "${test_name}" "five-field entry kept its user field: $(cat "${case_directory}/records/crontab")"
        return
    fi
    if ! grep -qxF "@daily /usr/local/bin/other-job" "${case_directory}/records/crontab"; then
        report_failure "${test_name}" "@ entry kept its user field: $(cat "${case_directory}/records/crontab")"
        return
    fi
    if grep -qw root "${case_directory}/records/crontab"; then
        report_failure "${test_name}" "the generated crontab still contains a root field"
        return
    fi
    report_success "${test_name}"
}

geoipupdate_once_returns_binary_status_without_secrets() {
    local test_name="geoipupdate_once_returns_binary_status_without_secrets"
    local case_directory exit_code=0
    case_directory="$(new_case_directory)"
    mkdir -p "${case_directory}/conf"
    printf 'AccountID %s\nLicenseKey %s\nEditionIDs GeoLite2-Country\n' "${fake_account_id}" "${fake_license_key}" \
        > "${case_directory}/conf/GeoIP.conf"
    write_fake "${case_directory}/fakes" geoipupdate 'echo "fake download failure" >&2; exit 3'
    env PATH="${case_directory}/fakes:${PATH}" FAKE_RECORD_DIR="${case_directory}/records" \
        GEOIPUPDATE_CONF_DIR="${case_directory}/conf" GEOIP_DIR="${case_directory}/geoip" \
        bash "${geoipupdate_once_script}" > "${case_directory}/stdout" 2> "${case_directory}/stderr" || exit_code=$?
    if [[ "${exit_code}" != 3 ]]; then
        report_failure "${test_name}" "expected the binary status 3, got ${exit_code}"
        return
    fi
    if [[ "$(cat "${case_directory}/records/geoipupdate.argv")" != "geoipupdate -f ${case_directory}/conf/GeoIP.conf -d ${case_directory}/geoip" ]]; then
        report_failure "${test_name}" "geoipupdate argv is '$(cat "${case_directory}/records/geoipupdate.argv")'"
        return
    fi
    if records_contain "${case_directory}" "${fake_license_key}" || output_contains "${case_directory}" "${fake_license_key}"; then
        report_failure "${test_name}" "the key appears in the argv, environment or output"
        return
    fi
    report_success "${test_name}"
}

credentials_missing_creates_no_cron_entry
empty_license_file_creates_no_cron_entry
invalid_credentials_never_fail_the_init
cron_entry_runs_as_docker_user_with_validated_schedule
frequency_is_validated_before_use
conf_is_mode_0600
argv_env_and_logs_never_contain_license_key
geoip_dir_is_chowned_on_every_start
initial_fetch_runs_only_when_database_missing
cron_service_strips_root_field
geoipupdate_once_returns_binary_status_without_secrets

if (( failed_test_count > 0 )); then
    printf '%s test(s) failed\n' "${failed_test_count}"
    exit 1
fi
printf 'all geoipupdate tests passed\n'
