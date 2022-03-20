LOCALBASE?=	/usr/local/
PROG=	filter-dkimverify
MAN=	filter-dkimverify.8
BINDIR=	${LOCALBASE}/libexec/smtpd/
MANDIR=	${LOCALBASE}/man/man

SRCS+=	main.c mheader.c unpack_dns.c

CFLAGS+=-I${LOCALBASE}/include
CFLAGS+=-Wall -I${.CURDIR}
CFLAGS+=-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations
CFLAGS+=-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare
LDFLAGS+=-L${LOCALBASE}/lib
LDADD+=	-lcrypto -lopensmtpd -levent
DPADD=	${LIBCRYPTO} ${LIBEVENT}

bindir:
	${INSTALL} -d ${DESTDIR}${BINDIR}

.include <bsd.prog.mk>
