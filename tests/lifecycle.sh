#!/bin/sh
# FreeBSD integration test: isolated PID/log/config files, no blocklist helper.
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d /tmp/horwall-test.XXXXXXXX)
groups=
cleanup()
{
    trap - EXIT INT TERM HUP
    for group in $groups; do
        kill -CONT -- "-$group" 2>/dev/null || :
        kill -TERM -- "-$group" 2>/dev/null || :
    done
    sleep 1
    for group in $groups; do
        kill -KILL -- "-$group" 2>/dev/null || :
    done
    rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP
# Check default/empty semantics without starting a process or sending reports.
helper_default=$(grep '^: .*horwall_helper' rc.d/horwall)
(
    unset horwall_helper
    eval "$helper_default"
    [ "$horwall_helper" = /usr/local/libexec/horwall/horwall-blocklist ]
    horwall_helper=
    eval "$helper_default"
    [ -z "$horwall_helper" ]
    horwall_helper=/custom/helper
    eval "$helper_default"
    [ "$horwall_helper" = /custom/helper ]
)
echo 'PASS: helper default preserves empty and custom values'
# Do not read live rc.conf/rc.conf.d; otherwise use the actual rc.d code.
awk '!/^load_rc_config /' rc.d/horwall > "$tmp/rc"
install -m 555 horwalld "$tmp/horwalld-real"
# Fail closed before starting the real watcher if rc.d ever restores a helper.
# This guard prevents regressions from contacting the live blocklistd socket.
printf '%s\n' '#!/bin/sh' \
    '[ "$#" -eq 4 ] && [ -z "$3" ] || exit 65' \
    'echo "TEST: empty helper verified"' \
    'exec "$(dirname "$0")/horwalld-real" "$@"' > "$tmp/horwalld"
chmod 555 "$tmp/horwalld"
install -m 555 horwall.awk "$tmp/horwall.awk"
cp patterns.example "$tmp/patterns"
: > "$tmp/access.log"
mkdir "$tmp/work"
export TMPDIR="$tmp/work"
test_user=${HORWALL_TEST_USER:-$(id -un)}
test_uid=$(id -u "$test_user")
# Let an unprivileged watcher traverse the fixture and create its private FIFO.
chmod 755 "$tmp"
chmod 644 "$tmp/patterns" "$tmp/access.log"
if [ "$test_uid" != "$(id -u)" ]; then
    chown "$test_user" "$tmp/work"
fi
export horwall_enable=YES
if [ "$test_user" = www ]; then
    # Exercise the actual rc.d default rather than overriding it.
    unset horwall_user
else
    export horwall_user="$test_user"
fi
export horwall_logfile="$tmp/access.log" horwall_pattern_file="$tmp/patterns"
export horwall_awk="$tmp/horwall.awk" horwall_wrapper="$tmp/horwalld"
export horwall_helper="$tmp/nonexistent-helper" horwall_output="$tmp/output"
export pidfile="$tmp/service.pid"
rc() { /bin/sh "$tmp/rc" "$1"; }
if rc start; then
    echo 'FAIL: start accepted a missing blocklist helper' >&2
    exit 1
fi
[ ! -e "$pidfile" ]
echo 'PASS: missing helper prevents startup'
# Explicit empty helper enables observation-only mode for the remaining tests.
export horwall_helper=
remember() {
    group=$(awk '{print $1}' "$pidfile")
    groups="$groups $group"
}
assert_gone() {
    if pgrep -g "$1" >/dev/null; then
        echo "FAIL: processes remain in group $1" >&2
        exit 1
    fi
}
assert_pipeline() {
    wrapper_pid=$(pgrep -P "$group")
    [ "$(ps -o uid= -p "$wrapper_pid" | tr -d ' ')" = "$test_uid" ]
    for child_pid in $(pgrep -P "$wrapper_pid"); do
        [ "$(ps -o uid= -p "$child_pid" | tr -d ' ')" = "$test_uid" ]
    done
    [ "$(pgrep -P "$wrapper_pid" | wc -l | tr -d ' ')" -eq 2 ]
    pgrep -P "$wrapper_pid" -x tail >/dev/null
    pgrep -P "$wrapper_pid" -x awk >/dev/null
    # FreeBSD tail may also run a Capsicum system.fileargs helper.
}
rc start
remember
assert_pipeline
if rc start; then
    echo 'FAIL: duplicate start accepted' >&2
    exit 1
fi
assert_pipeline
echo 'PASS: start and duplicate prevention'
for iteration in 1 2 3; do
    old=$group
    rc restart
    remember
    assert_gone "$old"
    assert_pipeline
done
echo 'PASS: three restarts leave one pipeline'
rc stop
assert_gone "$group"
[ ! -e "$pidfile" ]
[ -z "$(ls -A "$tmp/work")" ]
rc stop
echo 'PASS: stop reaps children and removes FIFO; repeated stop is safe'

# A matching request must still be observed with an empty helper. End tail to
# deliver EOF and flush AWK output without relying on stdio buffering delays.
printf '%s\n' 'example.test 192.0.2.1 - - [19/Sep/2026:19:00:00 +0200] "GET /evil.php HTTP/1.1" 200 0 "-" "test"' > "$tmp/access.log"
: > "$tmp/output"
rc start
remember
assert_pipeline
grep -Fqx 'TEST: empty helper verified' "$tmp/output"
kill -TERM "$(pgrep -P "$wrapper_pid" -x tail)"
sleep 3
assert_gone "$group"
grep -Fqx "$(printf '192.0.2.1\t19/Sep/2026:19:00:00 +0200\t\\.php')" "$tmp/output"
: > "$tmp/access.log"
echo 'PASS: observation-only mode processes matches without a blocklist helper'

# A suspended wrapper cannot handle TERM: restart must fail, retaining the PID.
rc start
remember
wrapper_pid=$(pgrep -P "$group")
kill -STOP "$wrapper_pid"
if rc restart; then
    echo 'FAIL: restart succeeded despite blocked shutdown' >&2
    exit 1
fi
[ "$(awk '{print $1}' "$pidfile")" = "$group" ]
kill -CONT "$wrapper_pid"
sleep 3
assert_gone "$group"
echo 'PASS: stop timeout retains PID and prevents replacement instance'

for program in tail awk; do
    rc start
    remember
    wrapper_pid=$(pgrep -P "$group")
    child=$(pgrep -P "$wrapper_pid" -x "$program")
    kill -TERM "$child"
    sleep 3
    assert_gone "$group"
    [ -z "$(ls -A "$tmp/work")" ]
    echo "PASS: $program failure cleans up the other child"
done
