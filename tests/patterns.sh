#!/bin/sh
# Offline only: checks patterns.example against real-world paths.
# Never invokes the blocklist helper.
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
fail=0
check() {
    expected=$1 target=$2
    printf 'example.test 192.0.2.1 - - [19/Sep/2026:19:00:00 +0200] "GET %s HTTP/1.1" 404 0 "-" "test"\n' \
        "$target" > "$tmp/input"
    awk -v PATTERN_FILE=patterns.example -v BLOCKLIST_HELPER= -f horwall.awk "$tmp/input" > "$tmp/output"
    count=$(wc -l < "$tmp/output" | tr -d ' ')
    if [ "$count" != "$expected" ]; then
        echo "FAIL: $target (expected $expected, got $count)" >&2
        fail=1
    fi
}

# Legitimate paths: substrings of broad words must not match.
for p in / /robots.txt /favicon.ico /sitemap.xml /ads.txt \
    /.well-known/acme-challenge/token /.well-known/security.txt \
    /assets/paper-bg.jpg /asset-manifest.json /en/tags/dnssec/ \
    /en/tags/audiocassette/index.xml /tags/ispconfig/ \
    /posts/2020-04-13-ispconfig-socket.io/ \
    /sysadmin/montare-le-partizioni-allavvio-login-di-gnome2/ \
    /blog/musica/funk-1/ /kratos-demo/assets/camera-ingresso.svg \
    /posts/environment-variables/ /tags/git/ /tags/env/; do
    check 0 "$p"
done

# Scanner paths seen in production logs.
for p in /wp-login.php /wp-admin/ /blog/wp-json/ /blog/wp-includes/js/json2.js \
    /wordpress/ /wp /xmlrpc.php /index.php7 /shell.phtml /index.jsp \
    /login.action /cgi-bin/authLogin.cgi /phpinfo /administrator/ \
    /.env /.env.production /app/.env /config.env /.git/config /.gitignore \
    /.svn/wc.db /.aws/credentials /.AWS_/credentials /.ssh/id_rsa \
    /.docker/config.json /.kube/config /.cursor/mcp.json \
    /.claude/settings.json /.config/gcloud/application_default_credentials.json \
    /.vault-token /.pgpass /.my.cnf /.boto /.amplifyrc /../etc/passwd \
    /config.json /next.config.js /sftp-config.json /config/default.json \
    /api/config /v1/config /kube/config /credentials.json /api/v1/credentials \
    /k8s/secrets.yaml /terraform.tfstate /terraform.tfstate.backup \
    /docker-compose.yml /src/environments/environment.prod.ts \
    /storage/logs/laravel.log /backup.zip /backup.tar.gz /dump.sql \
    /db.sql.gz /index.bak /login /login/ /admin/login /auth/login \
    /login.html /mcp /api/mcp /sse /graphql /api/graphql \
    /actuator/env /server-status /xleet.php; do
    check 1 "$p"
done

# /ads.txt is explicitly excluded, but only that exact path.
check 0 /ads.txt
check 0 '/ads.txt?x=/.env'
check 1 /ads.txt/../.env
check 1 /wp-content/ads.txt
check 1 /ads.txt.php

[ "$fail" -eq 0 ] || exit 1
echo 'PASS: patterns.example matches scanners and spares legitimate paths'
