#!/usr/bin/awk -f
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Giampaolo Bozzali zenfunkpanda <giampaolo@zenfunk.it>
# horwall.awk
#
# Simple filter for nginx access.log in awstats format.
# Matches are printed to stdout; with BLOCKLIST_HELPER set they are also
# streamed to "BLOCKLIST_HELPER -s" as IP<TAB>timestamp<TAB>rule lines.
# Reads one regex per line from PATTERN_FILE (!regex excludes request paths).
# Positive regexes match the request path (without query string). Prints:
#   IP<TAB>timestamp<TAB>matched_rule
#
# Usage:
#   awk -v PATTERN_FILE=patterns.txt -f horwall.awk /var/log/nginx/access.log

function shellquote(s,   t) {
    t = s
    gsub(/'/, "'\"'\"'", t)
    return "'" t "'"
}

# One long-lived helper in stream mode receives every report through a pipe.
# A helper per report would close its blocklistd connection immediately, and
# FreeBSD may then discard reports that blocklistd has not read yet.
# If the helper dies, the next write kills awk with SIGPIPE and horwalld exits.
function notify_blocklist(ip, ts, rule) {
    if (BLOCKLIST_HELPER == "") {
        return
    }

    if (helper_cmd == "") {
        helper_cmd = "exec " shellquote(BLOCKLIST_HELPER) " -s"
    }
    print ip "\t" ts "\t" rule | helper_cmd
    fflush(helper_cmd)
}

BEGIN {
    if (PATTERN_FILE == "") {
        PATTERN_FILE = "patterns.txt"
    }

    n_patterns = 0
    n_exclusions = 0
    while ((getline pat < PATTERN_FILE) > 0) {
        gsub(/\r$/, "", pat)
        if (pat ~ /^[[:space:]]*$/) {
            continue
        }
        if (pat ~ /^[[:space:]]*#/) {
            continue
        }

        if (substr(pat, 1, 1) == "!") {
            if (length(pat) == 1) {
                print "horwall: empty exclusion in " PATTERN_FILE > "/dev/stderr"
                exit 1
            }
            exclusions[++n_exclusions] = substr(pat, 2)
            continue
        }
        n_patterns++
        patterns[n_patterns] = pat
    }
    close(PATTERN_FILE)

    if (n_patterns == 0) {
        print "horwall: no patterns loaded from " PATTERN_FILE > "/dev/stderr"
        exit 1
    }
}

{
    line = $0
    n = split(line, f, " ")

    if (n >= 2 && f[2] != "" && match(line, /\[[^\]]+\]/)) {
        ip = f[2]
        ts = substr(line, RSTART + 1, RLENGTH - 2)

        # The request is the first quoted field after the timestamp in awstats.
        # Only a well-formed request path can trigger a notification.
        rest = substr(line, RSTART + RLENGTH)
        if (!match(rest, /^ "[^" ]+ \/[^" ]* HTTP\/[0-9.]+"/)) {
            next
        }
        request = substr(rest, 1, RLENGTH)
        split(request, parts, " ")
        path = parts[2]
        sub(/\?.*$/, "", path)
        excluded = 0
        for (i = 1; i <= n_exclusions; i++) {
            if (path ~ exclusions[i]) {
                excluded = 1
                break
            }
        }
        if (excluded) {
            next
        }

        for (i = 1; i <= n_patterns; i++) {
            if (path ~ patterns[i]) {
                print ip "\t" ts "\t" patterns[i]
                # Keep horwall_output current; awk buffers stdout otherwise.
                fflush("/dev/stdout")
                notify_blocklist(ip, ts, patterns[i])
                break
            }
        }
    }
}
