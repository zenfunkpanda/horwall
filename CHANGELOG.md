# Changelog

## Unreleased

### Changed

- `patterns.example` rewritten: rules are anchored to path segments and
  grouped by category. Bare words matched inside legitimate paths:
  `sse` matched `/assets/` and `/tags/dnssec/`, `config` matched
  `/tags/ispconfig/`, `login` matched blog slugs. Checked on one week of
  production logs: false positives went from 60 to 0, and 65 more scanner
  paths are matched (dotfiles such as `.claude`, `.svn`, `.ssh`, `.pgpass`,
  Terraform state, SQL dumps and backups, `actuator`, `secrets.yaml`).
- New offline test `tests/patterns.sh`.

## 0.1.2

### Fixed

- Reports were lost during bursts of matches, in every previous version.
  Starting one helper per match closed the `blocklistd` connection right
  after each send, and FreeBSD discards unread datagrams of a closed
  connected sender unless the receiver's queue is empty. With 0.1.0 this
  showed up as `socket/bind: Address already in use`; 0.1.1 removed the error
  but reports were still silently dropped (11/20 delivered in a back-to-back
  test).
- Under load, the 8 KB default send buffer of the libblocklist socket filled
  up; `sendmsg` failed with `ENOBUFS` and libblocklist reconnected, silently
  discarding all queued reports (74/200 delivered).
- `horwall_output` is now flushed after every match.

### Changed

- `horwall-blocklist -s`: new stream mode. awk starts one helper and streams
  matches through a pipe; the helper keeps one `blocklistd` connection and one
  bound socket per address family, and enlarges the socket send buffer to
  1 MiB. Measured: 200/200 and 1000/1000 distinct addresses delivered.
- Repeated reports for the same address within 60 seconds are suppressed
  (`-w seconds`, `0` disables). This also avoids a `fork` per match.
- `horwall-blocklist -n`: dry run, prints reports instead of sending them.
- New offline test `tests/stream.sh`.

## 0.1.1

**Note:** the `SO_REUSEPORT` change below hides the bind error but does not
prevent lost reports; upgrade to 0.1.2.

### Fixed

- `horwall-blocklist`: set `SO_REUSEPORT` on the notification socket, so a new
  notification can bind loopback port `53137` while `blocklistd` still holds
  the socket passed by the previous one (avoids `EADDRINUSE`).
- `horwall-blocklist`: always set `sin_len`/`sin6_len` on the reported address.
  Previously it was left at 0 and libblocklist logged
  `correcting socket len 0 to 16` on every notification.

### Documentation

- Document the fixed source port and `SO_REUSEPORT` in the permissions section
  and in `blocklistd.conf.example`.
- Add this changelog.

## 0.1.0

- Initial public release: `awk` filter for nginx `awstats` logs, `horwalld`
  wrapper, `rc.d` service, `libblocklist` notification helper, PF control
  helper for whole-source-IP bans, example patterns with `!` exclusions,
  offline and FreeBSD integration tests.
