#!/usr/bin/env bash
# Host-side tests of the copied cont-init scripts. No docker: each script is run with
# `bash <script>` because its `#!/command/with-contenv` shebang only exists in the image.
#   bash deploy/s6/test/init.test.sh
set -euo pipefail

test_directory="$(cd "$(dirname "$0")" && pwd)"
cont_init_directory="${test_directory}/../rootfs/etc/cont-init.d"
wait_network_script="${cont_init_directory}/05-wait-network"

failed_test_count=0

report_failure() {
    printf 'FAIL %s: %s\n' "$1" "$2"
    failed_test_count=$((failed_test_count + 1))
}

report_success() {
    printf 'ok   %s\n' "$1"
}

# EPOCHREALTIME (microseconds) avoids the whole-second rounding of `date +%s`, which
# would make the 1 s bound of the disabled case flaky.
current_milliseconds() {
    local seconds_with_fraction="${EPOCHREALTIME/[.,]/}"
    printf '%s\n' "$(( seconds_with_fraction / 1000 ))"
}

# Runs the wait-network script with the given environment assignments and prints
# "<exit code> <elapsed milliseconds>". 127.0.0.1:1 is a closed local port: every probe
# is refused at once, so only the timeout logic can end the loop.
run_wait_network() {
    local start_milliseconds
    local exit_code=0
    start_milliseconds="$(current_milliseconds)"
    env WAIT_FOR_NETWORK_HOST=127.0.0.1 WAIT_FOR_NETWORK_PORT=1 "$@" \
        bash "${wait_network_script}" > /dev/null 2>&1 || exit_code=$?
    printf '%s %s\n' "${exit_code}" "$(( $(current_milliseconds) - start_milliseconds ))"
}

wait_network_is_bounded() {
    local test_name="wait_network_is_bounded"
    local lenient_exit_code lenient_elapsed strict_exit_code strict_elapsed
    read -r lenient_exit_code lenient_elapsed < <(run_wait_network WAIT_FOR_NETWORK_TIMEOUT=2)
    if [[ "${lenient_exit_code}" != 0 ]]; then
        report_failure "${test_name}" "non-strict timeout must exit 0, got ${lenient_exit_code}"
        return
    fi
    if (( lenient_elapsed >= 8000 )); then
        report_failure "${test_name}" "non-strict timeout took ${lenient_elapsed}ms, limit is 8000ms"
        return
    fi
    read -r strict_exit_code strict_elapsed < <(run_wait_network WAIT_FOR_NETWORK_TIMEOUT=2 WAIT_FOR_NETWORK_STRICT=1)
    if [[ "${strict_exit_code}" != 1 ]]; then
        report_failure "${test_name}" "strict timeout must exit 1, got ${strict_exit_code}"
        return
    fi
    if (( strict_elapsed >= 8000 )); then
        report_failure "${test_name}" "strict timeout took ${strict_elapsed}ms, limit is 8000ms"
        return
    fi
    report_success "${test_name}"
}

wait_network_disabled_exits_immediately() {
    local test_name="wait_network_disabled_exits_immediately"
    local disabled_exit_code disabled_elapsed
    read -r disabled_exit_code disabled_elapsed < <(run_wait_network WAIT_FOR_NETWORK=false WAIT_FOR_NETWORK_TIMEOUT=30)
    if [[ "${disabled_exit_code}" != 0 ]]; then
        report_failure "${test_name}" "disabled wait must exit 0, got ${disabled_exit_code}"
        return
    fi
    if (( disabled_elapsed >= 1000 )); then
        report_failure "${test_name}" "disabled wait took ${disabled_elapsed}ms, limit is 1000ms"
        return
    fi
    report_success "${test_name}"
}

wait_network_is_bounded
wait_network_disabled_exits_immediately

if (( failed_test_count > 0 )); then
    printf '%s test(s) failed\n' "${failed_test_count}"
    exit 1
fi
printf 'all init tests passed\n'
