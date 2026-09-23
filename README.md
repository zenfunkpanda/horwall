# horwall

`horwall` is a lightweight awk logfile watcher and blocklistd signaler for FreeBSD.
It matches suspicious requests and reports offending IP addresses to
[`blocklistd`](https://man.freebsd.org/blocklistd) through a minimal C helper.

The name comes from **hor**, the Dutch word for *insect screen* (Italian: *zanzariera*).

## Status: alpha

Version: `0.1.0`

Operational in my FreeBSD setup.

## Design and log format

The goal is to observe logs in real time, identify suspicious requests, extract
source IP addresses, and let `blocklistd` manage blocking and expiration.
The core is a FreeBSD `rc.d` service: filtering stays in `awk`, while a minimal
C helper handles `libblocklist` integration.

The current service follows one nginx access log in the custom `awstats` format:

```nginx
log_format awstats '$host $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
```

The filter expects the client IP in the second field and the timestamp in square
brackets. It matches only well-formed request paths, without query strings;
malformed requests are ignored. The pipeline is `tail -F` → `awk` → optional
C helper → `blocklistd`.

## Features

- Follows log rotation safely with `tail -F`
- Supports one regular expression per line in a pattern file
- Uses `libblocklist` to notify `blocklistd`
- Includes an `rc.d` service and sample configuration

## Requirements

- FreeBSD
- nginx access logs
- `awk`, `tail`, and an active `blocklistd`
- A compiler and `libblocklist` for building the helper

## Build and install

```sh
make
make install
```

Copy or adapt `blocklistd.conf.example` for the local `blocklistd` configuration.
**Review the patterns before enabling bans:** broad rules such as `login`,
`graphql`, and `\.php` can match legitimate requests. Remove or narrow rules
for your site; the example exclusion is commented out.

The default `PREFIX` is `/usr/local`. For a different location, use
`make PREFIX=/your/prefix install`. The installed rc.d script uses the selected
`ETCDIR` and `LIBEXECDIR`; `RC_DIR` controls where that script is installed.
`DESTDIR` is only a staging root and is not included in runtime paths.
Adapt the configuration commands below to your chosen paths. With a custom
`RC_DIR`, ensure FreeBSD discovers the script through `local_startup` in
`rc.conf`, or invoke it by its full path.

With the default prefix, installation provides:

- `/usr/local/etc/rc.d/horwall`
- `/usr/local/libexec/horwall/horwalld`
- `/usr/local/libexec/horwall/horwall.awk`
- `/usr/local/libexec/horwall/horwall-blocklist`
- `/usr/local/libexec/horwall/horwall-pf-helper`
- `/usr/local/etc/horwall.patterns`
- `/usr/local/etc/horwall.patterns.example`
- `/usr/local/share/examples/horwall/blocklistd.conf.example`

**Note:** `make install` updates the example but creates the active pattern file
only if it does not exist. Existing local patterns are preserved.

### blocklistd configuration

`blocklistd` must be running and configured to accept notifications from the
helper's local socket. The helper reports `BLOCKLIST_ABUSIVE_BEHAVIOR` through
a fixed loopback UDP socket (`127.0.0.1:53137` or `[::1]:53137`).
The recommended Horwall policy is one report followed by a 5-minute block (`1/5m`):

```conf
[local]
127.0.0.1:53137    dgram   udp     www     horwall     1       5m
[::1]:53137        dgram   udp6    www     horwall     1       5m
```

These rules assume the helper runs as `www` (the default). The user column
in both entries must match `horwall_user`.

### PF: block the source IP on all inbound services

Add this anchor to `/etc/pf.conf` before public-service pass rules:

```pf
anchor "horwall/*"
```

Configure blocklistd to use the installed control helper (preserve any other
local flags, replacing an existing `-C` option if present):

```sh
sysrc blocklistd_flags="-r -v -C /usr/local/libexec/horwall/horwall-pf-helper"
pfctl -nf /etc/pf.conf
# Only proceed if validation succeeded:
service blocklistd restart
pfctl -f /etc/pf.conf
```

`horwall-pf-helper` maintains `horwall/53137` with the rule
`block drop in quick from <port53137> to any`, without protocol/port limits.
Other services are delegated to the standard FreeBSD helper. Expiration remains
managed by blocklistd; source states are killed when adding an IP.

Horwall blocks the logged IP even if it is a shared proxy/CDN address.

Then enable and start the service:

```sh
sysrc horwall_enable=YES
```

```sh
service horwall start
```

### Service settings and control

The main settings in `/etc/rc.conf` are:

| Variable | Default |
| --- | --- |
| `horwall_enable` | `NO` |
| `horwall_user` | `www` |
| `horwall_logfile` | `/var/log/nginx/access.log` |
| `horwall_pattern_file` | `/usr/local/etc/horwall.patterns` |
| `horwall_awk` | `/usr/local/libexec/horwall/horwall.awk` |
| `horwall_helper` | `/usr/local/libexec/horwall/horwall-blocklist` |
| `horwall_wrapper` | `/usr/local/libexec/horwall/horwalld` |
| `horwall_output` | `/var/log/horwall.log` |

### Permissions

Start and stop the service as root. The watcher, `tail`, `awk`, and notification
helper run as `www` by default; the `daemon` supervisor remains root and manages
the PID file and `horwall_output`. Do not grant `www` write access to these files.
`blocklistd` and its PF control helper remain privileged. The notification
helper needs no elevated privileges: it binds an unprivileged UDP port.

The configured user needs read access to the nginx log (including after rotation),
patterns, and AWK filter, traversal access to their parent directories, execute
access to the wrapper/helper, and write access to the blocklistd socket and a
temporary directory (normally `/tmp`). Keep installed code and patterns owned
by root and not writable by the service user.

For stronger isolation from web applications, a dedicated account can be used
instead: grant it the access above and set the same username in `horwall_user`
and both blocklistd rules. Sharing `www` also lets other processes with that UID
interfere with Horwall and submit authorized notifications.

### Output and lifecycle

`horwall_output` receives the process's stdout and stderr. Startup fails if a
configured `horwall_helper` is missing or not executable. Set
`horwall_helper=""` explicitly for observation-only mode (no bans). Service controls:

```sh
service horwall start
service horwall stop
service horwall restart
service horwall status
```

The `horwalld` wrapper manages `tail` and `awk`, cleaning up both on shutdown
or unexpected exit. A stop timeout prevents restart from launching a duplicate
instance. There is no automatic restart after an unexpected exit.
Startup may process the last ten log lines (`tail -F`).

## Manual use

```sh
awk -v PATTERN_FILE=patterns.example -f horwall.awk /var/log/nginx/access.log
```

The filter reads one regex per line, ignoring blank lines and comments beginning
with `#` (optionally preceded by whitespace). For each matching, non-excluded
request, it prints the first matching rule as:

```text
IP<TAB>timestamp<TAB>matched_rule
```

Manual use only prints matches unless `BLOCKLIST_HELPER` is set. To enable live
notifications (which may trigger bans):

```sh
awk -v PATTERN_FILE=patterns.example \
    -v BLOCKLIST_HELPER=/usr/local/libexec/horwall/horwall-blocklist \
    -f horwall.awk /var/log/nginx/access.log
```

Output can be redirected to a log file or forwarded to syslog; the installed
service already captures it in `horwall_output`.

### Pattern exclusions

Positive regexes and lines starting with `!` (exclusions) both match only the
request path, without the query string, in the nginx `awstats` format documented
above. Anchor patterns to the path, for example `^/wp-`. Exclusions take
precedence regardless of their position in the file. For example:

```text
!^/allowed\.php$
\.php
```

This exempts exactly `/allowed.php`, including requests with query strings,
without allowing Referer or User-Agent to exempt other paths. Referer,
User-Agent, host, and query string cannot trigger positive rules either. Paths
are not URL-decoded or normalized. An excluded request never triggers a
notification. A bare `!` is rejected.
To match a literal leading exclamation mark in a positive regex, use `[!]`.
Changes require restarting Horwall to reload the patterns.

Run offline regression tests (no blocklist notifications):

```sh
sh tests/exclusions.sh
# FreeBSD only: isolated service lifecycle tests, no live configuration/helper
sh tests/lifecycle.sh
# As root: also test the default www account, without live notifications
HORWALL_TEST_USER=www sh tests/lifecycle.sh
# FreeBSD only: staged install test, no live configuration/helper
sh tests/install.sh
```
