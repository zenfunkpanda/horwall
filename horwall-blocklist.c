/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 Giampaolo Bozzali zenfunkpanda <giampaolo@zenfunk.it> */

/*
 * Report abusive IP addresses to blocklistd.
 *
 *   horwall-blocklist [-n] ip [timestamp] [rule]
 *   horwall-blocklist -s [-n] [-w seconds]
 *
 * Stream mode (-s) reads "ip<TAB>timestamp<TAB>rule" lines from stdin and
 * keeps one blocklistd connection and one bound socket per address family
 * open for its whole lifetime.  This matters on FreeBSD: when a connected
 * PF_LOCAL datagram sender closes before the receiver has read its messages,
 * the kernel discards them unless the receiver's queue is empty
 * (unp_disconnect() in sys/kern/uipc_usrreq.c).  A short-lived helper per
 * notification therefore loses reports silently during bursts.
 *
 * Pending reports of a connected sender are charged to the sender's send
 * buffer (net.local.dgram.maxdgram, 8 KB: about 40 reports).  When it is
 * full, sendmsg() fails with ENOBUFS and libblocklist silently reconnects,
 * discarding every report still queued.  Stream mode therefore enlarges the
 * send buffer of the libblocklist socket, and suppresses repeated reports
 * for the same address within a window (-w, default 60 seconds).
 *
 * -n is a dry run: nothing is bound or sent; reports are printed to stdout.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <blocklist.h>

#define HORWALL_BLOCKLIST_PORT 53137
#define DEDUP_SLOTS 1024
#define SEND_ATTEMPTS 3
#define BL_SNDBUF (1024 * 1024)
#define BL_SNDBUF_MIN (64 * 1024)

/* Exported by libblocklist but declared only in its internal bl.h. */
int bl_getfd(struct blocklist *);

#ifndef HORWALL_VERSION
#define HORWALL_VERSION "unknown"
#endif

struct report_addr {
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } u;
    socklen_t len;
};

struct dedup_slot {
    struct report_addr addr;
    time_t when;
    bool used;
};

static bool dry_run;
static struct blocklist *bl;
static int sock4 = -1;
static int sock6 = -1;
static struct dedup_slot dedup[DEDUP_SLOTS];

static void
usage(void)
{
    fprintf(stderr,
        "usage: horwall-blocklist [-n] ip [timestamp] [rule]\n"
        "       horwall-blocklist -s [-n] [-w seconds]\n"
        "       horwall-blocklist -V\n");
    exit(64);
}

static int
make_local_socket(int family)
{
    int s;
    int reuseport = 1;

    s = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s == -1)
        return -1;
    /* Lets a manual one-shot report coexist with the running service. */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &reuseport,
        sizeof(reuseport)) == -1) {
        close(s);
        return -1;
    }

    if (family == AF_INET) {
        struct sockaddr_in sin;

        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_len = sizeof(sin);
        sin.sin_port = htons(HORWALL_BLOCKLIST_PORT);
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
            close(s);
            return -1;
        }
        return s;
    }

    if (family == AF_INET6) {
        struct sockaddr_in6 sin6;

        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_len = sizeof(sin6);
        sin6.sin6_port = htons(HORWALL_BLOCKLIST_PORT);
        sin6.sin6_addr = in6addr_loopback;
        if (bind(s, (struct sockaddr *)&sin6, sizeof(sin6)) == -1) {
            close(s);
            return -1;
        }
        return s;
    }

    close(s);
    errno = EAFNOSUPPORT;
    return -1;
}

static bool
parse_addr(const char *ip, struct report_addr *ra)
{
    memset(ra, 0, sizeof(*ra));
    if (inet_pton(AF_INET, ip, &ra->u.sin.sin_addr) == 1) {
        ra->u.sin.sin_family = AF_INET;
        ra->u.sin.sin_len = sizeof(ra->u.sin);
        ra->len = sizeof(ra->u.sin);
        return true;
    }
    if (inet_pton(AF_INET6, ip, &ra->u.sin6.sin6_addr) == 1) {
        ra->u.sin6.sin6_family = AF_INET6;
        ra->u.sin6.sin6_len = sizeof(ra->u.sin6);
        ra->len = sizeof(ra->u.sin6);
        return true;
    }
    return false;
}

/* Returns the bound socket for the family, creating it on first use. */
static int
local_socket(int family)
{
    int *sp = (family == AF_INET) ? &sock4 : &sock6;

    if (*sp == -1)
        *sp = make_local_socket(family);
    return *sp;
}

/*
 * Make room for a backlog of reports on the libblocklist socket.  libblocklist
 * recreates the socket after a failure, so this is checked after every send.
 */
static void
tune_bl_socket(void)
{
    static bool warned;
    socklen_t optlen;
    int fd, size;

    if (bl == NULL || (fd = bl_getfd(bl)) == -1)
        return;
    optlen = sizeof(size);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, &optlen) == 0 &&
        size >= BL_SNDBUF_MIN)
        return;
    for (size = BL_SNDBUF; size >= BL_SNDBUF_MIN; size /= 2) {
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size,
            sizeof(size)) == 0)
            return;
    }
    if (!warned) {
        warn("cannot enlarge blocklistd socket send buffer");
        warned = true;
    }
}

static void
format_msg(char *msg, size_t size, const char *ts, const char *rule)
{
    if (ts != NULL && rule != NULL)
        snprintf(msg, size, "horwall %s %s", ts, rule);
    else if (ts != NULL)
        snprintf(msg, size, "horwall %s", ts);
    else
        snprintf(msg, size, "horwall");
}

/* Returns 0 on success, -1 with a warning already printed on failure. */
static int
report(const char *ip, const struct report_addr *ra, const char *ts,
    const char *rule)
{
    char msg[256];
    int fd;

    format_msg(msg, sizeof(msg), ts, rule);
    if (dry_run) {
        printf("report %s \"%s\"\n", ip, msg);
        fflush(stdout);
        return 0;
    }

    fd = local_socket(ra->u.ss.ss_family);
    if (fd == -1) {
        warn("socket/bind");
        return -1;
    }
    if (bl == NULL && (bl = blocklist_open()) == NULL) {
        warn("blocklist_open");
        return -1;
    }
    tune_bl_socket();
    if (blocklist_sa_r(bl, BLOCKLIST_ABUSIVE_BEHAVIOR, fd,
        (const struct sockaddr *)&ra->u.ss, ra->len, msg) == -1) {
        warn("blocklist_sa_r %s", ip);
        tune_bl_socket();
        return -1;
    }
    tune_bl_socket();
    return 0;
}

static time_t
now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

static bool
same_addr(const struct report_addr *a, const struct report_addr *b)
{
    if (a->u.ss.ss_family != b->u.ss.ss_family)
        return false;
    if (a->u.ss.ss_family == AF_INET)
        return a->u.sin.sin_addr.s_addr == b->u.sin.sin_addr.s_addr;
    return memcmp(&a->u.sin6.sin6_addr, &b->u.sin6.sin6_addr,
        sizeof(a->u.sin6.sin6_addr)) == 0;
}

/* True if the address was already reported within the window. */
static bool
recently_reported(const struct report_addr *ra, time_t t, long window)
{
    size_t i;

    for (i = 0; i < DEDUP_SLOTS; i++) {
        if (dedup[i].used && t - dedup[i].when < window &&
            same_addr(&dedup[i].addr, ra))
            return true;
    }
    return false;
}

static void
remember(const struct report_addr *ra, time_t t)
{
    size_t i, victim = 0;

    for (i = 0; i < DEDUP_SLOTS; i++) {
        if (!dedup[i].used || same_addr(&dedup[i].addr, ra)) {
            victim = i;
            break;
        }
        if (dedup[i].when < dedup[victim].when)
            victim = i;
    }
    dedup[victim].addr = *ra;
    dedup[victim].when = t;
    dedup[victim].used = true;
}

static int
stream(long window)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;

    while ((len = getline(&line, &cap, stdin)) != -1) {
        struct report_addr ra;
        char *ip, *ts, *rule, *tab;
        time_t t;
        int attempt;

        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';
        if (len == 0)
            continue;

        ip = line;
        ts = rule = NULL;
        if ((tab = strchr(ip, '\t')) != NULL) {
            *tab = '\0';
            ts = tab + 1;
            if ((tab = strchr(ts, '\t')) != NULL) {
                *tab = '\0';
                rule = tab + 1;
            }
        }
        if (!parse_addr(ip, &ra)) {
            warnx("invalid ip address: %s", ip);
            continue;
        }

        t = now();
        if (window > 0 && recently_reported(&ra, t, window))
            continue;

        for (attempt = 1; attempt <= SEND_ATTEMPTS; attempt++) {
            if (report(ip, &ra, ts, rule) == 0) {
                remember(&ra, t);
                break;
            }
            if (attempt < SEND_ATTEMPTS)
                usleep(200000 * attempt);
        }
        if (attempt > SEND_ATTEMPTS)
            warnx("giving up on %s", ip);
    }
    free(line);
    if (ferror(stdin))
        err(1, "stdin");

    /*
     * Closing the connection discards reports that blocklistd has not read
     * yet; give it a moment to drain the queue first.
     */
    if (bl != NULL) {
        sleep(1);
        blocklist_close(bl);
    }
    return 0;
}

int
main(int argc, char **argv)
{
    struct report_addr ra;
    bool stream_mode = false;
    long window = 60;
    char *end;
    int ch;

    if (argc == 2 && strcmp(argv[1], "--version") == 0)
        argv[1] = "-V";

    while ((ch = getopt(argc, argv, "nsVw:")) != -1) {
        switch (ch) {
        case 'n':
            dry_run = true;
            break;
        case 's':
            stream_mode = true;
            break;
        case 'V':
            printf("horwall-blocklist %s\n", HORWALL_VERSION);
            return 0;
        case 'w':
            errno = 0;
            window = strtol(optarg, &end, 10);
            if (errno != 0 || *end != '\0' || end == optarg || window < 0)
                errx(64, "invalid window: %s", optarg);
            break;
        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;

    if (stream_mode) {
        if (argc != 0)
            usage();
        return stream(window);
    }

    if (argc < 1 || argc > 3)
        usage();
    if (!parse_addr(argv[0], &ra))
        errx(64, "invalid ip address: %s", argv[0]);
    if (report(argv[0], &ra, argc >= 2 ? argv[1] : NULL,
        argc >= 3 ? argv[2] : NULL) == -1)
        return 1;
    if (bl != NULL)
        blocklist_close(bl);
    return 0;
}
