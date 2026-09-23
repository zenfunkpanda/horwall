#!/bin/sh
# Staged FreeBSD install: never writes to the live prefix.
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d /tmp/horwall-install-test.XXXXXXXX)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/src/rc.d" "$tmp/stage"
cp Makefile horwall-blocklist.c horwall-pf-helper horwalld horwall.awk \
    patterns.example blocklistd.conf.example "$tmp/src/"
cp rc.d/horwall "$tmp/src/rc.d/"
make -C "$tmp/src" DESTDIR="$tmp/stage" install >/dev/null
active="$tmp/stage/usr/local/etc/horwall.patterns"
example="$tmp/stage/usr/local/etc/horwall.patterns.example"
cmp "$active" "$tmp/src/patterns.example"
printf '%s\n' '^/local-only$' > "$active"
printf '%s\n' '^/new-example$' >> "$tmp/src/patterns.example"
make -C "$tmp/src" DESTDIR="$tmp/stage" install >/dev/null
grep -Fqx '^/local-only$' "$active"
[ "$(wc -l < "$active" | tr -d ' ')" -eq 1 ]
grep -Fqx '^/new-example$' "$example"
echo 'PASS: install preserves active patterns and updates the example'
cmp "$tmp/src/rc.d/horwall" "$tmp/stage/usr/local/etc/rc.d/horwall"
echo 'PASS: default rc.d paths are unchanged'

check_paths() {
    rc="$tmp/stage$1/horwall"
    etc=$2 libexec=$3
    sh -n "$rc"
    grep -Fqx ": \${horwall_pattern_file:=\"$etc/horwall.patterns\"}" "$rc"
    for setting in 'awk horwall.awk' 'helper horwall-blocklist' 'wrapper horwalld'; do
        set -- $setting
        operator=':='
        [ "$1" != helper ] || operator='='
        grep -Fqx ": \${horwall_$1$operator\"$libexec/$2\"}" "$rc"
        [ -x "$tmp/stage$libexec/$2" ]
    done
    [ -r "$tmp/stage$etc/horwall.patterns" ]
    if grep -F "$tmp/stage" "$rc"; then
        echo 'FAIL: DESTDIR leaked into runtime paths' >&2
        exit 1
    fi
}
make -C "$tmp/src" DESTDIR="$tmp/stage" PREFIX=/opt/horwall install >/dev/null
check_paths /opt/horwall/etc/rc.d /opt/horwall/etc /opt/horwall/libexec/horwall
echo 'PASS: custom PREFIX sets runtime paths'

make -C "$tmp/src" DESTDIR="$tmp/stage" PREFIX=/opt/horwall \
    RC_DIR=/custom/rc.d ETCDIR=/custom/etc LIBEXECDIR=/custom/libexec install >/dev/null
check_paths /custom/rc.d /custom/etc /custom/libexec
echo 'PASS: directory overrides set runtime paths independently of DESTDIR'
