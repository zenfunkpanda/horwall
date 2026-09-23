#!/bin/sh
# Offline only: never invokes the blocklist helper.
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
printf '%s\n' '\.php' '\.git' '^/wp-' '!^/notaprendi\.php$' > "$tmp/patterns"
check() {
    name=$1 target=$2 referer=$3 agent=$4 ip=$5 expected=$6
    printf 'example.test %s - - [19/Sep/2026:19:00:00 +0200] "GET %s HTTP/1.1" 200 0 "%s" "%s"\n' \
        "$ip" "$target" "$referer" "$agent" > "$tmp/input"
    awk -v PATTERN_FILE="$tmp/patterns" -v BLOCKLIST_HELPER= -f horwall.awk "$tmp/input" > "$tmp/output"
    count=$(wc -l < "$tmp/output" | tr -d ' ')
    if [ "$count" != "$expected" ]; then
        echo "FAIL: $name ($count instead of $expected)" >&2
        exit 1
    fi
    echo "PASS: $name"
}
check 'exact exclusion' /notaprendi.php - test 192.0.2.1 0
check 'query ignored' '/notaprendi.php?x=login' - test 192.0.2.1 0
check 'IPv6 exclusion' /notaprendi.php - test 2001:db8::1 0
check 'PHP still detected' /evil.php - test 192.0.2.1 1
check 'IPv6 detection' /evil.php - test 2001:db8::1 1
check 'Referer cannot exempt' /evil.php /notaprendi.php test 192.0.2.1 1
check 'User-Agent cannot exempt' /.git/config - /notaprendi.php 192.0.2.1 1
check 'query cannot exempt' '/evil.php?next=/notaprendi.php' - test 192.0.2.1 1
check 'suffix not exempt' /notaprendi.php/evil - test 192.0.2.1 1
check 'prefix not exempt' /other/notaprendi.php - test 192.0.2.1 1
check 'Referer cannot trigger' /normal /evil.php test 192.0.2.1 0
check 'User-Agent cannot trigger' /normal - evil.php 192.0.2.1 0
check 'query cannot trigger' '/normal?next=/evil.php' - test 192.0.2.1 0
check 'literal dot' /notaprendiXphp - evil.php 192.0.2.1 0
check 'malformed request cannot trigger' '/evil.php BAD' - test 192.0.2.1 0
check 'anchored wp pattern' /wp-admin - test 192.0.2.1 1
printf '%s\n' '\.php' '!' > "$tmp/patterns"
if awk -v PATTERN_FILE="$tmp/patterns" -v BLOCKLIST_HELPER= -f horwall.awk /dev/null > "$tmp/output" 2> "$tmp/error"; then
    echo 'FAIL: empty exclusion accepted' >&2
    exit 1
fi
echo 'PASS: empty exclusion rejected'
