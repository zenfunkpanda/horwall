# Changelog

## 0.1.1

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
