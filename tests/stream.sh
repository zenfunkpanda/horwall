#!/bin/sh
# Offline only: uses a fake helper and the real helper in dry-run mode (-n).
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
printf '%s\n' '\.php' '\.env' > "$tmp/patterns"
line() {
    printf 'example.test %s - - [19/Sep/2026:19:00:0%s +0200] "GET %s HTTP/1.1" 404 0 "-" "test"\n' "$1" "$2" "$3"
}
{
    line 192.0.2.1 1 /a.php
    line 192.0.2.1 2 /.env
    line 192.0.2.2 3 /normal
    line 2001:db8::1 4 /b.php
    line 192.0.2.3 5 /c.php
} > "$tmp/log"

# The fake helper records its arguments and the reports it receives.
cat > "$tmp/fake" <<EOF
#!/bin/sh
echo "\$*" >> "$tmp/invocations"
cat >> "$tmp/reports"
EOF
chmod 555 "$tmp/fake"
awk -v PATTERN_FILE="$tmp/patterns" -v BLOCKLIST_HELPER="$tmp/fake" \
    -f horwall.awk "$tmp/log" > "$tmp/output"
[ "$(cat "$tmp/invocations")" = '-s' ]
echo 'PASS: one helper process in stream mode for all reports'
printf '%s\t%s\t%s\n' \
    192.0.2.1 '19/Sep/2026:19:00:01 +0200' '\.php' \
    192.0.2.1 '19/Sep/2026:19:00:02 +0200' '\.env' \
    2001:db8::1 '19/Sep/2026:19:00:04 +0200' '\.php' \
    192.0.2.3 '19/Sep/2026:19:00:05 +0200' '\.php' > "$tmp/expected"
cmp "$tmp/expected" "$tmp/reports"
cmp "$tmp/expected" "$tmp/output"
echo 'PASS: every match is printed and streamed to the helper'

if [ -x ./horwall-blocklist ]; then
    ./horwall-blocklist -s -n < "$tmp/expected" > "$tmp/dry"
    [ "$(wc -l < "$tmp/dry" | tr -d ' ')" -eq 3 ]
    grep -Fqx 'report 192.0.2.1 "horwall 19/Sep/2026:19:00:01 +0200 \.php"' "$tmp/dry"
    echo 'PASS: repeated address reported once within the window'
    ./horwall-blocklist -s -n -w 0 < "$tmp/expected" > "$tmp/dry"
    [ "$(wc -l < "$tmp/dry" | tr -d ' ')" -eq 4 ]
    echo 'PASS: -w 0 disables deduplication'
    printf 'bogus\tx\ty\n192.0.2.9\tt\tr\n' |
        ./horwall-blocklist -s -n > "$tmp/dry" 2> "$tmp/err"
    grep -Fq 'invalid ip address: bogus' "$tmp/err"
    grep -Fq 'report 192.0.2.9' "$tmp/dry"
    echo 'PASS: invalid lines are skipped without stopping the stream'
else
    echo 'SKIP: build horwall-blocklist to test dry-run deduplication'
fi
