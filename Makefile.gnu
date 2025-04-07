LOCALBASE?=	/usr/

PROG=		filter-auth
MAN=		filter-auth.8
BINDIR=		${LOCALBASE}/libexec/opensmtpd/
MANDIR=		${LOCALBASE}/share/man/man8

SRCS+=		main.c ltok.c unpack_dns.c

ifdef HAVE_ED25519
CFLAGS+=	-DHAVE_ED25519
endif
ifdef LIBCRYPTOPC
CRYPT_CFLAGS!=	pkg-config --cflags ${LIBCRYPTOPC}
CRYPT_LDFLAGS_L!=pkg-config --libs-only-L ${LIBCRYPTOPC}
CRYPT_LDFLAGS_libdir!=pkg-config --variable libdir ${LIBCRYPTOPC}
CRYPT_LDFLAGS=	${CRYPT_LDFLAGS_L}
CRYPT_LDFLAGS+=	-Wl,-rpath,${CRYPT_LDFLAGS_libdir}
CRYPT_LDADD!=	pkg-config --libs-only-l ${LIBCRYPTOPC}
else
CRYPT_CFLAGS=
CRYPT_LDFLAGS=
CRYPT_LDADD=	-lcrypto
endif

CFLAGS+=	-I${LOCALBASE}/include
CFLAGS+=	-Wall -I${.CURDIR}
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare
CFLAGS+=	${CRYPT_CFLAGS}
CFLAGS+=	-I${CURDIR} -I${CURDIR}/openbsd-compat/

LDFLAGS+=	-L${LOCALBASE}/lib
LDFLAGS+=	${CRYPT_LDFLAGS}
LDADD+=		${CRYPT_LDADD} -lopensmtpd -levent

INSTALL?=	install

NEED_RECALLOCARRAY?=	1
NEED_STRTONUM?=		1
NEED_PLEDGE?=		1
NEED_INET_NET_PTON?=	1
NEED_FGETLN?=		1
NEED_LIBASR?=		1

MANFORMAT?=		mangz

BINOWN?=	root
BINGRP?=	root
BINPERM?=	755
MANOWN?=	root
MANGRP?=	root
MANPERM?=	644

ifeq (${MANFORMAT}, mangz)
TARGET_MAN=		${MAN}.gz
CLEANFILES+=		${TARGET_MAN}
${TARGET_MAN}: ${MAN}
	mandoc -Tman ${MAN} | gzip > $@
else
TARGET_MAN=		${MAN}
endif

ifeq (${NEED_RECALLOCARRAY}, 1)
SRCS+=		${CURDIR}/openbsd-compat/recallocarray.c
CFLAGS+=	-DNEED_RECALLOCARRAY=1

recallocarray.o: ${CURDIR}/openbsd-compat/recallocarray.c
	${CC} ${CFLAGS} -c -o recallocarray.o ${CURDIR}/openbsd-compat/recallocarray.c
endif
ifeq (${NEED_STRTONUM}, 1)
SRCS+=		${CURDIR}/openbsd-compat/strtonum.c
CFLAGS+=	-DNEED_STRTONUM=1

strtonum.o: ${CURDIR}/openbsd-compat/strtonum.c
	${CC} ${CFLAGS} -c -o strtonum.o ${CURDIR}/openbsd-compat/strtonum.c
endif
ifeq (${NEED_PLEDGE}, 1)
CFLAGS+=	-DNEED_PLEDGE=1
endif
ifeq (${NEED_INET_NET_PTON}, 1)
SRCS+=		${CURDIR}/openbsd-compat/inet_net_pton.c
CFLAGS+=	-DNEED_INET_NET_PTON=1

inet_net_pton.o: ${CURDIR}/openbsd-compat/inet_net_pton.c
	${CC} ${CFLAGS} -c -o inet_net_pton.o ${CURDIR}/openbsd-compat/inet_net_pton.c
endif
ifeq (${NEED_FGETLN}, 1)
SRCS+=		${CURDIR}/openbsd-compat/fgetln.c
CFLAGS+=	-DNEED_FGETLN=1

fgetln.o: ${CURDIR}/openbsd-compat/fgetln.c
	${CC} ${CFLAGS} -c -o fgetln.o ${CURDIR}/openbsd-compat/fgetln.c
endif
ifeq (${NEED_LIBASR}, 1)
SRCS+=		${CURDIR}/openbsd-compat/event_asr_run.c
SRCS+=		${CURDIR}/openbsd-compat/libasr/asr.c
SRCS+=		${CURDIR}/openbsd-compat/libasr/asr_utils.c
SRCS+=		${CURDIR}/openbsd-compat/libasr/res_search_async.c
SRCS+=		${CURDIR}/openbsd-compat/libasr/res_send_async.c
CFLAGS+=	-I${CURDIR}/openbsd-compat/libasr -DNEED_LIBASR=1

event_asr_run.o: ${CURDIR}/openbsd-compat/event_asr_run.c
	${CC} ${CFLAGS} -c -o event_asr_run.o ${CURDIR}/openbsd-compat/event_asr_run.c
asr.o: ${CURDIR}/openbsd-compat/libasr/asr.c
	${CC} ${CFLAGS} -c -o asr.o ${CURDIR}/openbsd-compat/libasr/asr.c
asr_utils.o: ${CURDIR}/openbsd-compat/libasr/asr_utils.c
	${CC} ${CFLAGS} -c -o asr_utils.o ${CURDIR}/openbsd-compat/libasr/asr_utils.c
res_search_async.o: ${CURDIR}/openbsd-compat/libasr/res_search_async.c
	${CC} ${CFLAGS} -c -o res_search_async.o ${CURDIR}/openbsd-compat/libasr/res_search_async.c
res_send_async.o: ${CURDIR}/openbsd-compat/libasr/res_send_async.c
	${CC} ${CFLAGS} -c -o res_send_async.o ${CURDIR}/openbsd-compat/libasr/res_send_async.c
endif

${SRCS:.c=.d}:%.d:%.c
	 ${CC} ${CFLAGS} -MM $< >$@
CLEANFILES+=	${SRCS:.c=.d}

OBJS=		${notdir ${SRCS:.c=.o}}
CLEANFILES+=	${OBJS}

${PROG}: ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

.DEFAULT_GOAL=		all
.PHONY: all
all: ${PROG} ${TARGET_MAN}
CLEANFILES+=	${PROG}

.PHONY: clean
clean:
	rm -f ${CLEANFILES}

.PHONY: install
install: ${PROG}
	${INSTALL} -D -o ${BINOWN} -g ${BINGRP} -m ${BINPERM} ${PROG} ${DESTDIR}${BINDIR}/${PROG}
	${INSTALL} -D -o ${MANOWN} -g ${MANGRP} -m ${MANPERM} ${TARGET_MAN} ${DESTDIR}${MANDIR}/${TARGET_MAN}
