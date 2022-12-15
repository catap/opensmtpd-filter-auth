LOCALBASE?=	/usr/local/

PROG=		filter-dkimverify
MAN=		filter-dkimverify.8
BINDIR=		${LOCALBASE}/libexec/smtpd/
MANDIR=		${LOCALBASE}/man/man

SRCS+=		main.c ltok.c unpack_dns.c

CRYPT_CFLAGS=
CRYPT_LDFLAGS=
CRYPT_LDADD=	-lcrypto

CFLAGS+=	-I${LOCALBASE}/include -I${.CURDIR}/openbsd-compat 
CFLAGS+=	-Wall -I${.CURDIR}
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare
CFLAGS+=	${CRYPT_CFLAGS}

LDFLAGS+=	-L${LOCALBASE}/lib
LDFLAGS+=	${CRYPT_LDFLAGS}
LDADD+=		${CRYPT_LDADD} -lopensmtpd -levent
DPADD=		${LIBCRYPTO}

bindir:
	${INSTALL} -d ${DESTDIR}${BINDIR}

.include <bsd.prog.mk>
