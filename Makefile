PROG=horwall-blocklist
SRCS=horwall-blocklist.c
VERSION?=0.1.0

PREFIX?=/usr/local
LIBEXECDIR?=${PREFIX}/libexec/horwall
RC_DIR?=${PREFIX}/etc/rc.d
ETCDIR?=${PREFIX}/etc
EXAMPLESDIR?=${PREFIX}/share/examples/horwall

AWK_SRC=horwall.awk
RC_SRC=rc.d/horwall
PF_HELPER_SRC=horwall-pf-helper
WRAPPER_SRC=horwalld
PATTERNS_SRC=patterns.example
BLOCKLISTD_CONF_SRC=blocklistd.conf.example

CC?=cc
CFLAGS?=-O2 -pipe
CPPFLAGS+=-I/usr/include
CPPFLAGS+=-DHORWALL_VERSION=\"${VERSION}\"
LDLIBS+=-lblocklist

all: ${PROG}

${PROG}: ${SRCS}
	${CC} ${CFLAGS} ${CPPFLAGS} -o ${.TARGET} ${.ALLSRC} ${LDLIBS}

install: all
	install -d ${DESTDIR}${LIBEXECDIR}
	install -d ${DESTDIR}${RC_DIR}
	install -d ${DESTDIR}${ETCDIR}
	install -d ${DESTDIR}${EXAMPLESDIR}
	install -m 555 ${PROG} ${DESTDIR}${LIBEXECDIR}/${PROG}
	install -m 555 ${PF_HELPER_SRC} ${DESTDIR}${LIBEXECDIR}/${PF_HELPER_SRC}
	install -m 555 ${WRAPPER_SRC} ${DESTDIR}${LIBEXECDIR}/${WRAPPER_SRC}
	install -m 555 ${AWK_SRC} ${DESTDIR}${LIBEXECDIR}/${AWK_SRC}
	@set -eu; rc=$$(mktemp); trap 'rm -f "$$rc"' EXIT HUP INT TERM; \
		sed -e 's|/usr/local/etc/horwall.patterns|${ETCDIR}/horwall.patterns|g' \
		    -e 's|/usr/local/libexec/horwall/|${LIBEXECDIR}/|g' \
		    ${RC_SRC} > "$$rc"; \
		install -m 555 "$$rc" ${DESTDIR}${RC_DIR}/horwall
	install -m 444 ${PATTERNS_SRC} ${DESTDIR}${ETCDIR}/horwall.patterns.example
	@if [ ! -e "${DESTDIR}${ETCDIR}/horwall.patterns" ]; then \
		install -m 444 ${PATTERNS_SRC} "${DESTDIR}${ETCDIR}/horwall.patterns"; \
	fi
	install -m 444 ${BLOCKLISTD_CONF_SRC} ${DESTDIR}${EXAMPLESDIR}/blocklistd.conf.example

clean:
	rm -f ${PROG}

help:
	@echo "Targets:"
	@echo "  make          build ${PROG}"
	@echo "  make install  install helpers, horwalld, awk, rc.d and examples"
	@echo "  make clean    remove build artifacts"

.PHONY: all install clean help
