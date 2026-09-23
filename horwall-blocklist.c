/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 Giampaolo Bozzali zenfunkpanda <giampaolo@zenfunk.it> */

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <blocklist.h>

#define HORWALL_BLOCKLIST_PORT 53137

#ifndef HORWALL_VERSION
#define HORWALL_VERSION "unknown"
#endif

static int
make_local_socket(int family)
{
    int s;

    s = socket(family, SOCK_DGRAM, 0);
    if (s == -1)
        return -1;

    if (family == AF_INET) {
        struct sockaddr_in sin;

        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_len = sizeof(sin);
        sin.sin_port = htons(HORWALL_BLOCKLIST_PORT);
        (void)inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);
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
        (void)inet_pton(AF_INET6, "::1", &sin6.sin6_addr);
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

int
main(int argc, char **argv)
{
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } addr;
    const char *ip;
    char msg[256];
    int fd;
    int ret;

    if (argc == 2 && (strcmp(argv[1], "--version") == 0 ||
        strcmp(argv[1], "-V") == 0)) {
        printf("%s %s\n", argv[0], HORWALL_VERSION);
        return 0;
    }

    if (argc < 2)
        errx(64, "usage: %s ip [timestamp] [rule]", argv[0]);

    ip = argv[1];
    memset(&addr, 0, sizeof(addr));

    if (inet_pton(AF_INET, ip, &addr.sin.sin_addr) == 1) {
        addr.sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
        addr.sin.sin_len = sizeof(addr.sin);
#endif
        fd = make_local_socket(AF_INET);
    } else if (inet_pton(AF_INET6, ip, &addr.sin6.sin6_addr) == 1) {
        addr.sin6.sin6_family = AF_INET6;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
        addr.sin6.sin6_len = sizeof(addr.sin6);
#endif
        fd = make_local_socket(AF_INET6);
    } else {
        errx(64, "invalid ip address: %s", ip);
    }

    if (fd == -1)
        err(1, "socket/bind");

    if (argc >= 4)
        snprintf(msg, sizeof(msg), "horwall %s %s", argv[2], argv[3]);
    else if (argc == 3)
        snprintf(msg, sizeof(msg), "horwall %s", argv[2]);
    else
        snprintf(msg, sizeof(msg), "horwall");

    ret = blocklist_sa(BLOCKLIST_ABUSIVE_BEHAVIOR, fd,
        (struct sockaddr *)&addr,
        (addr.sin.sin_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
        msg);

    close(fd);

    if (ret == -1)
        err(1, "blocklist_sa");

    return 0;
}
