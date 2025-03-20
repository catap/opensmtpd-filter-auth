/*
 * Copyright (c) 2024 Kirill A. Korinsky <kirill@korins.ky>
 * Copyright (c) 2022 Martijn van Duren <martijn@openbsd.org>
 * Copyright (c) 2019 Martijn van Duren <martijn@openbsd.org>
 * Copyright (c) 2017 Gilles Chehade <gilles@poolp.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <arpa/nameser.h>

#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <limits.h>
#include <netdb.h>
#include <opensmtpd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <asr.h>

#include "unpack_dns.h"
#include "ltok.h"

/*
 * Use RFC8601 (Authentication-Results) codes instead of RFC6376 codes,
 * since they're more expressive with additional NONE and SOFTFAIL for
 * RFC7208 (Sender Policy Framework (SPF)).
 */
enum ar_state {
	AR_UNKNOWN,
	AR_NONE,
	AR_PASS,
	AR_FAIL,
	AR_SOFTFAIL,
	AR_POLICY,
	AR_NEUTRAL,
	AR_TEMPERROR,
	AR_PERMERROR
};

struct ar_signature {
	struct header *header;
	enum ar_state state;
	const char *state_reason;
	int dkim;
	int seal;
	int v;
	const char *a;
	size_t asz;
	int ak;
	int sephash;
	const EVP_MD *ah;
	char *b;
	size_t bsz;
	const char *bheader;
	size_t bheadersz;
#define HEADER_B_MAX_LEN        8
	char bheaderclean[HEADER_B_MAX_LEN + 1];
	/* Make sure padding bits for base64 decoding fit */
	char bh[EVP_MAX_MD_SIZE + (3 - (EVP_MAX_MD_SIZE % 3))];
	size_t bhsz;
	EVP_MD_CTX *bhctx;
	int c;
	enum ar_state cv;
#define CANON_HEADER_SIMPLE	0
#define CANON_HEADER_RELAXED	1
#define CANON_HEADER		1
#define CANON_BODY_SIMPLE	0
#define CANON_BODY_RELAXED	1 << 1
#define CANON_BODY		1 << 1
#define CANON_DONE		1 << 2
	char d[HOST_NAME_MAX + 1];
	char **h;
	int arc_i;
	const char *i;
	size_t isz;
	ssize_t l;
	int q;
	char s[HOST_NAME_MAX + 1];
	time_t t;	/* Signature t=/timestamp */
#define KT_Y			1
#define KT_S			1 << 1
	int kt;		/* Key t=/Flags */
	time_t x;
	int z;
	struct event_asr *query;
	EVP_PKEY *p;
	/* RFC 6376 doesn't care about CNAME, use simalr with SPF limit */
#define AR_LOOKUP_LOOKUP_LIMIT 11
	int nqueries;
};

/*
 * RFC 5321 doesn't limit record size, enforce some resanable limit
 */
#define SPF_RECORD_MAX 4096

struct spf_query {
	struct spf_record *spf;
	struct event_asr *eva;
	int type;
	enum ar_state q;
	int include;
	int exists;
	char *domain;
	char *txt;
	int pos;
};

struct spf_record {
	struct osmtpd_ctx *ctx;
	enum ar_state state;
	const char *state_reason;
	char *sender_local;
	char *sender_domain;
	int nqueries;
	int running;
	int done;
/* RFC 7208 Section 4.6.4 limits to 10 DNS lookup,
 * and one is reserved for the first query.
 * To prevent of infinity loop I count each CNAME
 * as dedicated lookup, same as A and AAAA.
 * So, I use 41 as the limit. */
#define SPF_DNS_LOOKUP_LIMIT 41
	struct spf_query queries[SPF_DNS_LOOKUP_LIMIT];
};

struct header {
	struct message *msg;
	uint8_t readdone;
	uint8_t parsed;
	char *buf;
	size_t buflen;
	struct ar_signature *sig;
};

#define AUTHENTICATION_RESULTS_LINELEN 78
#define MIN(a, b) ((a) < (b) ? (a) : (b))


/* RFC 8617 Section 4.2.1 */
#define ARC_MIN_I 1
#define ARC_MAX_I 50

struct message {
	struct osmtpd_ctx *ctx;
	FILE *origf;
	int parsing_headers;
	size_t body_whitelines;
	int has_body;
	struct header *header;
	size_t nheaders;
	int readdone;
	int nqueries;
	struct ar_signature *last_arc_seal;
	struct ar_signature *last_arc_sign;
	struct ar_signature **arc_seals;
	struct ar_signature **arc_signs;
};

struct session {
	struct osmtpd_ctx *ctx;
	enum ar_state iprev;
	struct spf_record *spf_helo;
	struct spf_record *spf_mailfrom;
	struct sockaddr_storage src;
	char *identity;
	char *rdns;
};

void usage(void);
void auth_conf(const char *, const char *);
void auth_connect(struct osmtpd_ctx *, const char *, enum osmtpd_status, struct sockaddr_storage *, struct sockaddr_storage *);
void spf_identity(struct osmtpd_ctx *, const char *);
void spf_mailfrom(struct osmtpd_ctx *, const char *);
void auth_dataline(struct osmtpd_ctx *, const char *);
void *spf_record_new(struct osmtpd_ctx *, const char *);
void spf_record_free(struct spf_record *);
void *auth_session_new(struct osmtpd_ctx *);
void auth_session_free(struct osmtpd_ctx *, void *);
void *auth_message_new(struct osmtpd_ctx *);
void auth_message_free(struct osmtpd_ctx *, void *);
void ar_header_add(struct osmtpd_ctx *, const char *);
void ar_signature_parse(struct header *, int, int);
void ar_signature_parse_v(struct ar_signature *, const char *, const char *);
void ar_signature_parse_a(struct ar_signature *, const char *, const char *);
void ar_signature_parse_b(struct ar_signature *, const char *, const char *);
void ar_signature_parse_bh(struct ar_signature *, const char *, const char *);
void ar_signature_parse_c(struct ar_signature *, const char *, const char *);
void arc_signature_parse_cv(struct ar_signature *, const char *, const char *);
void ar_signature_parse_d(struct ar_signature *, const char *, const char *);
void ar_signature_parse_h(struct ar_signature *, const char *, const char *);
void dkim_signature_parse_i(struct ar_signature *, const char *, const char *);
void arc_signature_parse_i(struct ar_signature *, const char *, const char *);
void ar_signature_parse_l(struct ar_signature *, const char *, const char *);
void ar_signature_parse_q(struct ar_signature *, const char *, const char *);
void ar_signature_parse_s(struct ar_signature *, const char *, const char *);
void ar_signature_parse_t(struct ar_signature *, const char *, const char *);
void ar_signature_parse_x(struct ar_signature *, const char *, const char *);
void ar_signature_parse_z(struct ar_signature *, const char *, const char *);
void ar_lookup_record(struct ar_signature *sig, const char *);
void ar_signature_verify(struct ar_signature *);
void ar_signature_header(EVP_MD_CTX *, struct ar_signature *, struct header *);
void ar_signature_state(struct ar_signature *, enum ar_state, const char *);
const char *ar_state2str(enum ar_state);
void ar_header_cat(struct osmtpd_ctx *, const char *);
void ar_body_parse(struct message *, const char *);
void ar_body_verify(struct ar_signature *);
void ar_rr_resolve(struct asr_result *, void *);
char *spf_evaluate_domain(struct spf_record *, const char *);
void spf_lookup_record(struct spf_record *, const char *, int,
    enum ar_state, int, int);
void spf_done(struct spf_record *, enum ar_state, const char *);
void spf_resolve(struct asr_result *, void *);
void spf_resolve_txt(struct dns_rr *, struct spf_query *);
void spf_resolve_mx(struct dns_rr *, struct spf_query *);
void spf_resolve_a(struct dns_rr *, struct spf_query *);
void spf_resolve_aaaa(struct dns_rr *, struct spf_query *);
void spf_resolve_cname(struct dns_rr *, struct spf_query *);
char* spf_parse_txt(const char *, size_t);
int spf_check_cidr(struct spf_record *, struct in_addr *, int );
int spf_check_cidr6(struct spf_record *, struct in6_addr *, int );
int spf_execute_txt(struct spf_query *);
int spf_ar_cat(const char *, struct spf_record *, char **, size_t *, ssize_t *);
void auth_message_verify(struct message *);
void auth_ar_create(struct osmtpd_ctx *);
int ar_signature_ar_cat(const char *, struct ar_signature *, char **, size_t *, ssize_t *);
ssize_t auth_ar_cat(char **ar, size_t *n, size_t aroff, const char *fmt, ...)
    __attribute__((__format__ (printf, 4, 5)));
int auth_ar_print(struct osmtpd_ctx *, const char *);
int ar_key_text_parse(struct ar_signature *, const char *);


/* RFC8617 Section 5.1.1 */
static char *arc_seal_headers[] = {
	"ARC-Authentication-Results",
	"ARC-Message-Signature",
	"ARC-Seal"
};

char *authservid = NULL;
int arc = 0;
EVP_ENCODE_CTX *ectx = NULL;

int
main(int argc, char *argv[])
{
	int ch;

	OpenSSL_add_all_digests();

	if (pledge("tmppath stdio dns", NULL) == -1)
		osmtpd_err(1, "pledge");

	while ((ch = getopt(argc, argv, "A")) != -1) {
		switch (ch) {
		case 'A':
			arc = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 1)
		osmtpd_errx(1, "invalid authservid count");
	if (argc == 1)
		authservid = argv[0];

	if ((ectx = EVP_ENCODE_CTX_new()) == NULL)
		osmtpd_err(1, "EVP_ENCODE_CTX_new");

	osmtpd_need(OSMTPD_NEED_SRC|OSMTPD_NEED_FCRDNS|OSMTPD_NEED_IDENTITY|OSMTPD_NEED_GREETING);
	osmtpd_register_conf(auth_conf);
	osmtpd_register_filter_dataline(auth_dataline);
	osmtpd_register_report_connect(1, auth_connect);
	osmtpd_register_filter_helo(spf_identity);
	osmtpd_register_filter_ehlo(spf_identity);
	osmtpd_register_filter_mailfrom(spf_mailfrom);
	osmtpd_local_session(auth_session_new, auth_session_free);
	osmtpd_local_message(auth_message_new, auth_message_free);
	osmtpd_run();

	return 0;
}

void
auth_conf(const char *key, const char *value)
{
	const char *end;

	if (key == NULL) {
		if (authservid == NULL)
			osmtpd_errx(1, "Didn't receive admd config option");
		return;
	}
	if (strcmp(key, "admd") == 0 && authservid == NULL) {
		if ((authservid = strdup(value)) == NULL)
			osmtpd_err(1, "%s: malloc", __func__);
		end = osmtpd_ltok_skip_value(authservid, 0);
		if (authservid + strlen(authservid) != end)
			osmtpd_errx(1, "Invalid authservid");
	}
}

void
auth_connect(struct osmtpd_ctx *ctx, const char *rdns, enum osmtpd_status fcrdns,
			 struct sockaddr_storage *src, struct sockaddr_storage *dst)
{
	struct session *ses = ctx->local_session;

	if (fcrdns == OSMTPD_STATUS_OK)
		ses->iprev = AR_PASS;
	else
		ses->iprev = AR_FAIL;

	memcpy(&ses->src, src, sizeof(struct sockaddr_storage));

	if (rdns != NULL) {
		if ((ses->rdns = strdup(rdns)) == NULL)
			osmtpd_err(1, "%s: malloc", __func__);
	}
}

void
spf_identity(struct osmtpd_ctx *ctx, const char *identity)
{
	char from[HOST_NAME_MAX + 12];

	struct session *ses = ctx->local_session;

	if (identity == NULL) {
		osmtpd_filter_proceed(ctx);
		return;
	}

	if ((ses->identity = strdup(identity)) == NULL)
		osmtpd_err(1, "%s: strdup", __func__);

	if (strlen(identity) == 0) {
		osmtpd_filter_proceed(ctx);
		return;
	}

	snprintf(from, sizeof(from), "postmaster@%s", identity);

	if ((ses->spf_helo = spf_record_new(ctx, from)) == NULL)
		osmtpd_filter_proceed(ctx);
}

void
spf_mailfrom(struct osmtpd_ctx *ctx, const char *from)
{
	struct session *ses = ctx->local_session;

	if (from == NULL || !strlen(from)) {
		osmtpd_filter_proceed(ctx);
		return;
	}

	if (ses->spf_mailfrom)
		spf_record_free(ses->spf_mailfrom);

	if ((ses->spf_mailfrom = spf_record_new(ctx, from)) == NULL)
		osmtpd_filter_proceed(ctx);
}

void
auth_dataline(struct osmtpd_ctx *ctx, const char *line)
{
	struct message *msg = ctx->local_message;
	size_t i;

	if (fprintf(msg->origf, "%s\n", line) < 0)
		osmtpd_err(1, "Couldn't write to tempfile");

	if (line[0] == '.') {
		line++;
		if (line[0] == '\0') {
			msg->readdone = 1;
			for (i = 0; i < msg->nheaders; i++) {
				if (msg->header[i].sig == NULL)
					continue;
				ar_body_verify(msg->header[i].sig);
			}
			auth_message_verify(msg);
			return;
		}
	}
	if (msg->parsing_headers) {
		ar_header_add(ctx, line);
		if (line[0] == '\0') {
			msg->parsing_headers = 0;
			for (i = 0; i < msg->nheaders; i++) {
				if (msg->header[i].sig == NULL)
					continue;
				if (msg->header[i].sig->query == NULL)
					ar_signature_verify(
					    msg->header[i].sig);
			}
		}
		return;
	} else {
		ar_body_parse(msg, line);
	}
}

void *
spf_record_new(struct osmtpd_ctx *ctx, const char *from)
{
	int i;
	const char *at;
	struct spf_record *spf;

	if ((spf = malloc(sizeof(*spf))) == NULL)
		osmtpd_err(1, "%s: malloc", __func__);

	spf->ctx = ctx;
	spf->state = AR_NONE;
	spf->state_reason = NULL;
	spf->nqueries = 0;
	spf->running = 0;
	spf->done = 0;

	for (i = 0; i < SPF_DNS_LOOKUP_LIMIT; i++) {
		spf->queries[i].domain = NULL;
		spf->queries[i].txt = NULL;
		spf->queries[i].eva = NULL;
	}

	from = osmtpd_ltok_skip_cfws(from, 1);

	if ((at = osmtpd_ltok_skip_local_part(from, 0)) == NULL)
		goto fail;

	if ((spf->sender_local = strndup(from, at - from)) == NULL)
		osmtpd_err(1, "%s: malloc", __func__);

	if (*at != '@')
		goto fail_local;
	at++;

	if ((from = osmtpd_ltok_skip_domain(at, 0)) == NULL)
		goto fail_local;


	if ((spf->sender_domain = strndup(at, from - at)) == NULL)
		osmtpd_err(1, "%s: malloc", __func__);

	spf_lookup_record(
		spf, spf->sender_domain, T_TXT, AR_PASS, 0, 0);

	return spf;

fail_local:
	free(spf->sender_local);

fail:
	free(spf);
	return NULL;
}

void
spf_record_free(struct spf_record *spf)
{
	int i;

	for (i = 0; i < SPF_DNS_LOOKUP_LIMIT; i++) {
		if (spf->queries[i].domain)
			free(spf->queries[i].domain);
		if (spf->queries[i].txt)
			free(spf->queries[i].txt);
		if (spf->queries[i].eva)
			event_asr_abort(spf->queries[i].eva);
	}

	free(spf->sender_local);
	free(spf->sender_domain);

	free(spf);
}

void *
auth_session_new(struct osmtpd_ctx *ctx)
{
	struct session *ses;

	if ((ses = malloc(sizeof(*ses))) == NULL)
		osmtpd_err(1, "%s: malloc", __func__);

	ses->ctx = ctx;
	ses->iprev = AR_NONE;

	ses->spf_helo = NULL;
	ses->spf_mailfrom = NULL;

	ses->identity = NULL;
	ses->rdns = NULL;

	return ses;
}

void
auth_session_free(struct osmtpd_ctx *ctx, void *data)
{
	struct session *ses = data;

	if (ses->spf_helo)
		spf_record_free(ses->spf_helo);
	if (ses->spf_mailfrom)
		spf_record_free(ses->spf_mailfrom);
	if (ses->identity)
		free(ses->identity);
	if (ses->rdns)
		free(ses->rdns);

	free(ses);
}

void *
auth_message_new(struct osmtpd_ctx *ctx)
{
	struct message *msg;

	if ((msg = malloc(sizeof(*msg))) == NULL)
		osmtpd_err(1, "%s: malloc", __func__);

	if ((msg->origf = tmpfile()) == NULL) {
		osmtpd_warn(NULL, "Can't open tempfile");
		free(msg);
		return NULL;
	}
	msg->ctx = ctx;
	msg->parsing_headers = 1;
	msg->body_whitelines = 0;
	msg->has_body = 0;
	msg->header = NULL;
	msg->nheaders = 0;
	msg->readdone = 0;
	msg->nqueries = 0;
	msg->last_arc_seal = NULL;
	msg->last_arc_sign = NULL;
	if ((msg->arc_seals =
	    calloc(ARC_MAX_I + 1, sizeof(*msg->arc_seals))) == NULL)
		osmtpd_err(1, "%s: malloc", __func__);
	if ((msg->arc_signs =
	    calloc(ARC_MAX_I + 1, sizeof(*msg->arc_signs))) == NULL)
		osmtpd_err(1, "%s: malloc", __func__);

	return msg;
}

void
auth_message_free(struct osmtpd_ctx *ctx, void *data)
{
	struct message *msg = data;
	size_t i, j;

	fclose(msg->origf);
	for (i = 0; i < msg->nheaders; i++) {
		if (msg->header[i].sig != NULL) {
			free(msg->header[i].sig->b);
			EVP_MD_CTX_free(msg->header[i].sig->bhctx);
			if (msg->header[i].sig->h != arc_seal_headers) {
				for (j = 0; msg->header[i].sig->h != NULL &&
					 msg->header[i].sig->h[j] != NULL; j++)
					free(msg->header[i].sig->h[j]);
				free(msg->header[i].sig->h);
			}
			EVP_PKEY_free(msg->header[i].sig->p);
			if (msg->header[i].sig->query)
				event_asr_abort(msg->header[i].sig->query);
		}
		free(msg->header[i].buf);
		free(msg->header[i].sig);
	}
	free(msg->header);
	free(msg->arc_seals);
	free(msg->arc_signs);
	free(msg);
}

void
ar_header_add(struct osmtpd_ctx *ctx, const char *line)
{
	struct message *msg = ctx->local_message;
	const char *start, *end, *verify;
	struct header *headers;
	size_t i;

	if (msg->nheaders > 0 &&
	    msg->header[msg->nheaders - 1].readdone == 0) {
		if (line[0] != ' ' && line[0] != '\t') {
			msg->header[msg->nheaders - 1].readdone = 1;
			start = msg->header[msg->nheaders - 1].buf;
			end = osmtpd_ltok_skip_field_name(start, 0);
			/* In case someone uses an obs-optional */
			if (end != NULL)
				verify = osmtpd_ltok_skip_wsp(end, 1);
			if (end != NULL &&
			    strncasecmp(
			    start, "DKIM-Signature", end - start) == 0 &&
			    verify[0] == ':')
				ar_signature_parse(
				    &msg->header[msg->nheaders - 1], 1, 0);
			else if (end != NULL &&
			    strncasecmp(
			    start, "ARC-Message-Signature", end - start) == 0 &&
			    verify[0] == ':')
				ar_signature_parse(
				    &msg->header[msg->nheaders - 1], 0, 0);
			else if (end != NULL &&
			    strncasecmp(
			    start, "ARC-Seal", end - start) == 0 &&
			    verify[0] == ':')
				ar_signature_parse(
				    &msg->header[msg->nheaders - 1], 0, 1);

			if (line[0] == '\0')
				return;
		} else {
			ar_header_cat(ctx, line);
			return;
		}
	}
	if (msg->nheaders % 10 == 0) {
		if ((headers = recallocarray(msg->header, msg->nheaders,
		    msg->nheaders + 10, sizeof(*msg->header))) == NULL)
			osmtpd_err(1, "%s: malloc", __func__);
		msg->header = headers;
		for (i = 0; i < msg->nheaders; i++) {
			if (msg->header[i].sig == NULL)
				continue;
			msg->header[i].sig->header = &msg->header[i];
		}
	}
	msg->header[msg->nheaders].msg = msg;
	msg->nheaders++;
	ar_header_cat(ctx, line);
}

void
ar_header_cat(struct osmtpd_ctx *ctx, const char *line)
{
	struct message *msg = ctx->local_message;
	struct header *header = &msg->header[msg->nheaders - 1];
	char *buf;

	size_t needed = header->buflen + strlen(line) + 2;

	if (needed > (header->buflen / 1024) + 1) {
		buf = reallocarray(header->buf, (needed / 1024) + 1, 1024);
		if (buf == NULL)
			osmtpd_err(1, "%s: malloc", __func__);
		header->buf = buf;
	}
	header->buflen += snprintf(header->buf + header->buflen,
	    (((needed / 1024) + 1) * 1024) - header->buflen, "%s%s",
	    header->buflen == 0 ? "" : "\r\n", line);
}

void
ar_signature_parse(struct header *header, int dkim, int seal)
{
	struct ar_signature *sig, *last;
	const char *buf, *i, *end;
	char tagname[3];
	char subdomain[HOST_NAME_MAX + 1];
	size_t ilen, dlen;

	/* Format checked by ar_header_add */
	buf = osmtpd_ltok_skip_field_name(header->buf, 0);
	buf = osmtpd_ltok_skip_wsp(buf, 1) + 1;

	if ((header->sig = calloc(1, sizeof(*header->sig))) == NULL)
		osmtpd_err(1, "%s: malloc", __func__);
	sig = header->sig;
	sig->header = header;
	sig->dkim = dkim;
	sig->seal = seal;
	sig->l = -1;
	sig->t = -1;
	sig->x = -1;

	end = osmtpd_ltok_skip_tag_list(buf, 0);
	if (end == NULL || end[0] != '\0') {
		ar_signature_state(sig, AR_PERMERROR, "Invalid tag-list");
		return;
	}

	while (buf[0] != '\0') {
		buf = osmtpd_ltok_skip_fws(buf, 1);
		end = osmtpd_ltok_skip_tag_name(buf, 0);

		/* Unknown tag-name */
		if ((size_t)(end - buf) >= sizeof(tagname))
			tagname[0] = '\0';
		else
			strlcpy(tagname, buf, (end - buf) + 1);
		buf = osmtpd_ltok_skip_fws(end, 1);
		/* '=' */
		buf = osmtpd_ltok_skip_fws(buf + 1, 1);
		end = osmtpd_ltok_skip_tag_value(buf, 1);
		if (dkim && strcmp(tagname, "v") == 0)
			ar_signature_parse_v(sig, buf, end);
		else if (strcmp(tagname, "a") == 0)
			ar_signature_parse_a(sig, buf, end);
		else if (strcmp(tagname, "b") == 0)
			ar_signature_parse_b(sig, buf, end);
		else if (!seal && strcmp(tagname, "bh") == 0)
			ar_signature_parse_bh(sig, buf, end);
		else if (!seal && strcmp(tagname, "c") == 0)
			ar_signature_parse_c(sig, buf, end);
		else if (seal && strcmp(tagname, "cv") == 0)
			arc_signature_parse_cv(sig, buf, end);
		else if (strcmp(tagname, "d") == 0)
			ar_signature_parse_d(sig, buf, end);
		else if (!seal && strcmp(tagname, "h") == 0)
			ar_signature_parse_h(sig, buf, end);
		else if (dkim && strcmp(tagname, "i") == 0)
			dkim_signature_parse_i(sig, buf, end);
		else if (!dkim && strcmp(tagname, "i") == 0)
			arc_signature_parse_i(sig, buf, end);
		else if (!seal && strcmp(tagname, "l") == 0)
			ar_signature_parse_l(sig, buf, end);
		else if (!seal && strcmp(tagname, "q") == 0)
			ar_signature_parse_q(sig, buf, end);
		else if (strcmp(tagname, "s") == 0)
			ar_signature_parse_s(sig, buf, end);
		else if (strcmp(tagname, "t") == 0)
			ar_signature_parse_t(sig, buf, end);
		else if (!seal && strcmp(tagname, "x") == 0)
			ar_signature_parse_x(sig, buf, end);
		else if (!seal && strcmp(tagname, "z") == 0)
			ar_signature_parse_z(sig, buf, end);

		buf = osmtpd_ltok_skip_fws(end, 1);
		if (buf[0] == ';')
			buf++;
		else if (buf[0] != '\0') {
			ar_signature_state(sig, AR_PERMERROR,
			    "Invalid tag-list");
			return;
		}
	}
	if (sig->state != AR_UNKNOWN)
		return;

	if (dkim && sig->v != 1)
		ar_signature_state(sig, AR_PERMERROR, "Missing v tag");
	else if (sig->ah == NULL)
		ar_signature_state(sig, AR_PERMERROR, "Missing a tag");
	else if (sig->b == NULL)
		ar_signature_state(sig, AR_PERMERROR, "Missing b tag");
	else if (!seal && sig->bhsz == 0)
		ar_signature_state(sig, AR_PERMERROR, "Missing bh tag");
	else if (seal && sig->cv == AR_UNKNOWN)
		ar_signature_state(sig, AR_PERMERROR, "Missing cv tag");
	else if (sig->d[0] == '\0')
		ar_signature_state(sig, AR_PERMERROR, "Missing d tag");
	else if (!dkim && sig->arc_i == 0)
		ar_signature_state(sig, AR_PERMERROR, "Missing i tag");
	else if (!seal && sig->h == NULL)
		ar_signature_state(sig, AR_PERMERROR, "Missing h tag");
	else if (sig->s[0] == '\0')
		ar_signature_state(sig, AR_PERMERROR, "Missing s tag");
	if (sig->state != AR_UNKNOWN)
		return;

	if (seal) {
		sig->c = CANON_HEADER_RELAXED;
		sig->h = arc_seal_headers;
	}

	if (sig->i != NULL) {
		i = osmtpd_ltok_skip_local_part(sig->i, 1) + 1;
		ilen = sig->isz - (size_t)(i - sig->i);
		dlen = strlen(sig->d);
		if (ilen < dlen) {
			ar_signature_state(sig, AR_PERMERROR,
			    "i tag not subdomain of d");
			return;
		}
		i += ilen - dlen;
		if ((i[-1] != '.' && i[-1] != '@') ||
		    strncasecmp(i, sig->d, dlen) != 0) {
			ar_signature_state(sig, AR_PERMERROR,
			    "i tag not subdomain of d");
			return;
		}
	}
	if (sig->t != -1 && sig->x != -1 && sig->t > sig->x) {
		ar_signature_state(sig, AR_PERMERROR, "t tag after x tag");
		return;
	}

	if (!dkim) {
		if (seal) {
			last = header->msg->last_arc_seal;
			header->msg->last_arc_seal = sig;
			if (header->msg->arc_seals[sig->arc_i] == NULL)
				header->msg->arc_seals[sig->arc_i] = sig;
		} else {
			last = header->msg->last_arc_sign;
			header->msg->last_arc_sign = sig;
			if (header->msg->arc_signs[sig->arc_i] == NULL)
				header->msg->arc_signs[sig->arc_i] = sig;
		}

		if (last != NULL) {
			if ((last->arc_i - 1) != sig->arc_i) {
				ar_signature_state(
				    last, AR_PERMERROR, "Invalind i-chain");
				return;
			}

			switch (last->cv) {
			case AR_UNKNOWN:
			case AR_FAIL:
				break;
			case AR_PASS:
				if (sig->cv == AR_PASS)
					break;
			default:
				ar_signature_state(
				    last, AR_PERMERROR, "Invalind cv-chain");
				return;
			}
		}
	}

	if ((size_t)snprintf(subdomain, sizeof(subdomain), "%s._domainkey.%s",
	    sig->s, sig->d) >= sizeof(subdomain)) {
		ar_signature_state(sig, AR_PERMERROR,
		    "dns/txt query too long");
		return;
	}

	ar_lookup_record(sig, subdomain);
}

void
ar_lookup_record(struct ar_signature *sig, const char *domain)
{
	struct asr_query *query;

	if (sig->state != AR_UNKNOWN)
		return;

	sig->nqueries++;

	if (sig->query != NULL) {
		event_asr_abort(sig->query);
		sig->query = NULL;
		sig->header->msg->nqueries--;
	}

	if ((query = res_query_async(domain, C_IN, T_TXT, NULL)) == NULL)
		osmtpd_err(1, "res_query_async");

	if ((sig->query = event_asr_run(query, ar_rr_resolve, sig)) == NULL)
		osmtpd_err(1, "res_query_async");

	sig->header->msg->nqueries++;
}

void
ar_signature_parse_v(struct ar_signature *sig, const char *start, const char *end)
{
	if (sig->v != 0) {	/* Duplicate tag */
		ar_signature_state(sig, AR_PERMERROR, "Duplicate v tag");
		return;
	}
	/* Unsupported version */
	if (start[0] != '1' || start + 1 != end)
		ar_signature_state(sig, AR_NEUTRAL, "Unsupported v tag");
	else
		sig->v = 1;
}

void
ar_signature_parse_a(struct ar_signature *sig, const char *start, const char *end)
{
	char ah[sizeof("sha256")];

	if (sig->ah != NULL) {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate a tag");
		return;
	}

	if (osmtpd_ltok_skip_sig_a_tag_alg(start, 0) != end) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid a tag");
		return;
	}
	sig->a = start;
	sig->asz = (size_t)(end - start);
	if (strncmp(start, "rsa-", 4) == 0) {
		start += 4;
		sig->ak = EVP_PKEY_RSA;
		sig->sephash = 0;
#if HAVE_ED25519
	} else if (strncmp(start, "ed25519-", 8) == 0) {
		start += 8;
		sig->ak = EVP_PKEY_ED25519;
		sig->sephash = 1;
#endif
	} else {
		ar_signature_state(sig, AR_NEUTRAL, "Unsuppored a tag k");
		return;
	}
	if ((size_t)(end - start) >= sizeof(ah)) {
		ar_signature_state(sig, AR_NEUTRAL, "Unsuppored a tag h");
		return;
	}
	strlcpy(ah, start, sizeof(ah));
	ah[end - start] = '\0';
	if ((sig->ah = EVP_get_digestbyname(ah)) == NULL) {
		ar_signature_state(sig, AR_NEUTRAL, "Unsuppored a tag h");
		return;
	}
	if ((sig->bhctx = EVP_MD_CTX_new()) == NULL)
		osmtpd_err(1, "EVP_MD_CTX_new");

	if (EVP_DigestInit_ex(sig->bhctx, sig->ah, NULL) <= 0) {
		ar_signature_state(sig, AR_FAIL, "Unsuppored a tag ah");
		return;
	}
}

void
ar_signature_parse_b(struct ar_signature *sig, const char *start, const char *end)
{
	int decodesz;
	size_t i, j;

	if (sig->b != NULL) {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate b tag");
		return;
	}
	sig->bheader = start;
	sig->bheadersz = end - start;
	if ((sig->b = malloc(((sig->bheadersz / 4) + 1) * 3)) == NULL)
		osmtpd_err(1, "%s: malloc", __func__);
	/* EVP_DecodeBlock doesn't handle internal whitespace */
	EVP_DecodeInit(ectx);
	if (EVP_DecodeUpdate(ectx, sig->b, &decodesz, start,
	    (int)(end - start)) == -1) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid b tag");
		return;
	}
	sig->bsz = decodesz;
	if (EVP_DecodeFinal(ectx, sig->b + sig->bsz,
	    &decodesz) == -1) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid b tag");
		return;
	}
	sig->bsz += decodesz;
	for (i = 0, j = 0;
	     i < sig->bheadersz && j < HEADER_B_MAX_LEN; i++) {
		if (isalnum(sig->bheader[i]) || sig->bheader[i] == '/'
		    || sig->bheader[i] == '+' || sig->bheader[i] == '=')
			sig->bheaderclean[j++] = sig->bheader[i];
	}
	sig->bheaderclean[j] = '\0';
}

void
ar_signature_parse_bh(struct ar_signature *sig, const char *start, const char *end)
{
	const char *b64;
	size_t n;
	int decodesz;

	if (sig->bhsz != 0) {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate bh tag");
		return;
	}
	/*
	 * EVP_Decode* expects sig->bh to be large enough,
	 * so count the actual b64 characters.
	 */
	b64 = start;
	n = 0;
	while (1) {
		b64 = osmtpd_ltok_skip_fws(b64, 1);
		if (osmtpd_ltok_skip_alphadigitps(b64, 0) == NULL)
			break;
		n++;
		b64++;
	}
	if (b64[0] == '=') {
		n++;
		b64 = osmtpd_ltok_skip_fws(b64 + 1, 1);
		if (b64[0] == '=') {
			n++;
			b64++;
		}
	}
	/* Invalid tag value */
	if (b64 != end || n % 4 != 0 || (n / 4) * 3 > sizeof(sig->bh)) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid bh tag");
		return;
	}
	/* EVP_DecodeBlock doesn't handle internal whitespace */
	EVP_DecodeInit(ectx);
	if (EVP_DecodeUpdate(ectx, sig->bh, &decodesz, start,
	    (int)(end - start)) == -1) {
		/* Paranoia check */
		ar_signature_state(sig, AR_PERMERROR, "Invalid bh tag");
		return;
	}
	sig->bhsz = decodesz;
	if (EVP_DecodeFinal(ectx, sig->bh + sig->bhsz, &decodesz) == -1) {
		/* Paranoia check */
		ar_signature_state(sig, AR_PERMERROR, "Invalid bh tag");
		return;
	}
	sig->bhsz += decodesz;
}

void
ar_signature_parse_c(struct ar_signature *sig, const char *start, const char *end)
{
	if (sig->c != 0) {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate c tag");
		return;
	}
	if (strncmp(start, "simple", 6) == 0) {
		sig->c = CANON_HEADER_SIMPLE;
		start += 6;
	} else if (strncmp(start, "relaxed", 7) == 0) {
		sig->c = CANON_HEADER_RELAXED;
		start += 7;
	} else {
		ar_signature_state(sig, AR_PERMERROR, "Invalid c tag");
		return;
	}
	if (start[0] == '/') {
		start++;
		if (strncmp(start, "simple", 6) == 0) {
			sig->c |= CANON_BODY_SIMPLE;
			start += 6;
		} else if (strncmp(start, "relaxed", 7) == 0) {
			sig->c |= CANON_BODY_RELAXED;
			start += 7;
		} else {
			ar_signature_state(sig, AR_PERMERROR,
			    "Invalid c tag");
			return;
		}
	}

	if (start != end) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid c tag");
		return;
	}
	sig->c |= CANON_DONE;
}

void
arc_signature_parse_cv(struct ar_signature *sig, const char *start, const char *end)
{
	if (sig->cv != AR_UNKNOWN) {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate cv tag");
		return;
	}

	if (strncmp(start, "pass", 4) == 0) {
		sig->cv = AR_PASS;
	} else if (strncmp(start, "fail", 4) == 0) {
		sig->cv = AR_FAIL;
	} else if (strncmp(start, "none", 4) == 0) {
		sig->cv = AR_NONE;
	} else {
		ar_signature_state(sig, AR_PERMERROR, "Invalid cv tag");
		return;
	}
}

void
ar_signature_parse_d(struct ar_signature *sig, const char *start, const char *end)
{
	if (sig->d[0] != '\0') {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate d tag");
		return;
	}
	if (osmtpd_ltok_skip_sig_d_tag_value(start, 0) != end ||
	    (size_t)(end - start) >= sizeof(sig->d)) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid d tag");
		return;
	}
	strlcpy(sig->d, start, end - start + 1);
}

void
ar_signature_parse_h(struct ar_signature *sig, const char *start, const char *end)
{
	const char *h;
	size_t n = 0;

	if (sig->h != NULL) {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate h tag");
		return;
	}
	if (osmtpd_ltok_skip_sig_h_tag_value(start, 0) < end) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid h tag");
		return;
	}
	h = start;
	while (1) {
		if ((h = osmtpd_ltok_skip_hdr_name(h, 0)) == NULL) {
			ar_signature_state(sig, AR_PERMERROR,
			    "Invalid h tag");
			return;
		}
		n++;
		/* ';' is part of hdr-name */
		if (h > end) {
			h = end;
			break;
		}
		h = osmtpd_ltok_skip_fws(h, 1);
		if (h[0] != ':')
			break;
		h = osmtpd_ltok_skip_fws(h + 1, 1);
	}
	if ((sig->h = calloc(n + 1, sizeof(*sig->h))) == NULL)
		osmtpd_err(1, "%s: malloc", __func__);
	n = 0;
	h = start;
	while (1) {
		h = osmtpd_ltok_skip_hdr_name(start, 0);
		/* ';' is part of hdr-name */
		if (h > end) {
			sig->h[n] = strndup(start, end - start);
			break;
		}
		if ((sig->h[n++] = strndup(start, h - start)) == NULL)
			osmtpd_err(1, "%s: malloc", __func__);
		start = osmtpd_ltok_skip_fws(h, 1);
		if (start[0] != ':')
			break;
		start = osmtpd_ltok_skip_fws(start + 1, 1);
	}
}

void
dkim_signature_parse_i(struct ar_signature *sig, const char *start, const char *end)
{
	if (sig->i != NULL) {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate i tag");
		return;
	}
	if (osmtpd_ltok_skip_sig_i_tag_value(start, 0) != end) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid i tag");
		return;
	}
	sig->i = start;
	sig->isz = (size_t)(end - start);
}

void
arc_signature_parse_i(struct ar_signature *sig, const char *start, const char *end)
{
	char *ep;
	long i;
	if (sig->arc_i != 0) {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate i tag");
		return;
	}
	if (osmtpd_ltok_skip_digit(start, 0) != end) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid i tag");
		return;
	}
	i = strtol(start, &ep, 10);
	if (i < ARC_MIN_I || i > ARC_MAX_I || ep != end) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid i tag");
		return;
	}
	sig->arc_i = (int) i;
}

void
ar_signature_parse_l(struct ar_signature *sig, const char *start, const char *end)
{
	long long l;
	char *lend;

	if (sig->l != -1) {	/* Duplicate tag */
		ar_signature_state(sig, AR_PERMERROR, "Duplicate l tag");
		return;
	}
	errno = 0;
	l = strtoll(start, &lend, 10);
	/* > 76 digits in stroll is an overflow */
	if (osmtpd_ltok_skip_digit(start, 0) == NULL ||
	    lend != end || errno != 0) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid l tag");
		return;
	}
	if (l > SSIZE_MAX) {
		ar_signature_state(sig, AR_PERMERROR, "l tag too large");
		return;
	}
	sig->l = (ssize_t)l;
}

void
ar_signature_parse_q(struct ar_signature *sig, const char *start, const char *end)
{
	const char *qend;

	if (sig->q != 0) {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate q tag");
		return;
	}

	while (1) {
		start = osmtpd_ltok_skip_fws(start, 1);
		qend = osmtpd_ltok_skip_sig_q_tag_method(start, 0);
		if (qend == NULL) {
			ar_signature_state(sig, AR_PERMERROR, "Invalid q tag");
			return;
		}
		if (strncmp(start, "dns/txt", qend - start) == 0)
			sig->q = 1;
		start = osmtpd_ltok_skip_fws(qend, 1);
		if (start[0] != ':')
			break;
	}
	if (start != end) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid q tag");
		return;
	}
	if (sig->q != 1) {
		sig->q = 1;
		ar_signature_state(sig, AR_NEUTRAL, "No useable q found");
		return;
	}
}

void
ar_signature_parse_s(struct ar_signature *sig, const char *start, const char *end)
{
	if (sig->s[0] != '\0') {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate s tag");
		return;
	}
	if (osmtpd_ltok_skip_selector(start, 0) != end) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid s tag");
		return;
	}
	strlcpy(sig->s, start, end - start + 1);
}

void
ar_signature_parse_t(struct ar_signature *sig, const char *start, const char *end)
{
	char *tend;

	if (sig->t != -1) {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate t tag");
		return;
	}
	errno = 0;
	sig->t = strtoll(start, &tend, 10);
	if (osmtpd_ltok_skip_digit(start, 0) == NULL || tend != end ||
	    tend - start > 12 || errno != 0) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid t tag");
		return;
	}
}

void
ar_signature_parse_x(struct ar_signature *sig, const char *start, const char *end)
{
	char *xend;

	if (sig->x != -1) {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate x tag");
		return;
	}
	errno = 0;
	sig->x = strtoll(start, &xend, 10);
	if (osmtpd_ltok_skip_digit(start, 0) == NULL || xend != end ||
	    xend - start > 12 || errno != 0) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid x tag");
		return;
	}
}

void
ar_signature_parse_z(struct ar_signature *sig, const char *start, const char *end)
{
	if (sig->z != 0) {
		ar_signature_state(sig, AR_PERMERROR, "Duplicate z tag");
		return;
	}

	sig->z = 1;
	if (osmtpd_ltok_skip_sig_z_tag_value(start, 0) != end) {
		ar_signature_state(sig, AR_PERMERROR, "Invalid z tag");
		return;
	}
}

void
ar_signature_verify(struct ar_signature *sig)
{
	struct message *msg = sig->header->msg;
	static EVP_MD_CTX *bctx = NULL;
	char digest[EVP_MAX_MD_SIZE];
	unsigned int digestsz;
	const char *end;
	size_t i, header;

	if (sig->state != AR_UNKNOWN)
		return;

	if (sig->cv == AR_FAIL ||
	    (sig->cv == AR_PASS && sig->arc_i == 1) ||
	    (sig->cv == AR_NONE && sig->arc_i > 1)) {
		ar_signature_state(sig, AR_FAIL, "cv tag");
		return;
	}

	if (bctx == NULL) {
		if ((bctx = EVP_MD_CTX_new()) == NULL)
			osmtpd_err(1, "EVP_MD_CTX_new");
	}
	EVP_MD_CTX_reset(bctx);
	if (!sig->sephash) {
		if (EVP_DigestVerifyInit(bctx, NULL, sig->ah, NULL,
			sig->p) != 1) {
			ar_signature_state(sig, AR_FAIL, "ah tag");
			return;
		}
	} else {
		if (EVP_DigestInit_ex(bctx, sig->ah, NULL) != 1) {
			ar_signature_state(sig, AR_FAIL, "ah tag");
			return;
		}
	}

	for (i = 0; i < msg->nheaders; i++)
		msg->header[i].parsed = 0;

	if (sig->h != NULL) {
		for (header = 0; sig->h[header] != NULL; header++) {
			for (i = msg->nheaders; i > 0; ) {
				i--;
				if (msg->header[i].parsed ||
				    strncasecmp(msg->header[i].buf, sig->h[header],
				    strlen(sig->h[header])) != 0 ||
				    msg->header[i].sig == sig)
					continue;
				end = osmtpd_ltok_skip_fws(
				    msg->header[i].buf + strlen(sig->h[header]), 1);
				if (end[0] != ':')
					continue;
				ar_signature_header(bctx, sig, &(msg->header[i]));
				msg->header[i].parsed = 1;
				break;
			}
		}
	}

	ar_signature_header(bctx, sig, sig->header);
	if (!sig->sephash) {
		if (EVP_DigestVerifyFinal(bctx, sig->b, sig->bsz) != 1) {
			ar_signature_state(sig, AR_FAIL, "b mismatch");
			return;
		}
	} else {
		if (EVP_DigestFinal_ex(bctx, digest, &digestsz) == 0)
			osmtpd_err(1, "EVP_DigestFinal_ex");

		if (EVP_DigestVerifyInit(bctx, NULL, NULL, NULL, sig->p) != 1)
			osmtpd_err(1, "EVP_DigestVerifyInit");

		switch (EVP_DigestVerify(bctx, sig->b, sig->bsz, digest,
		    digestsz)) {
		case 1:
			break;
		case 0:
			ar_signature_state(sig, AR_FAIL, "b mismatch");
			return;
		default:
			osmtpd_err(1, "EVP_DigestVerify");
		}
	}

	if (sig->arc_i > 0) {
		if (msg->arc_seals[sig->arc_i] == NULL ||
		    msg->arc_signs[sig->arc_i] == NULL) {
			ar_signature_state(sig, AR_PERMERROR, "missed ARC header");
			return;
		}

		if (msg->arc_seals[sig->arc_i]->state == AR_UNKNOWN ||
		    msg->arc_signs[sig->arc_i]->state == AR_UNKNOWN)
			return;

		if (msg->arc_seals[sig->arc_i]->state !=
		    msg->arc_signs[sig->arc_i]->state) {
			ar_signature_state(
			    msg->arc_signs[sig->arc_i], AR_FAIL, NULL);
			return;
		}
	}
}

/* EVP_DigestVerifyUpdate is a macro, so we can't alias this on a variable */
#define ar_b_digest_update(a, b, c)					\
	(sig->sephash ? EVP_DigestUpdate((a), (b), (c)) :\
	    EVP_DigestVerifyUpdate((a), (b), (c)))

void
ar_signature_header(EVP_MD_CTX *bctx, struct ar_signature *sig,
    struct header *header)
{
	char c;
	const char *ptr = header->buf, *end;
	int inhdrname = 1;
	int canon = sig->c & CANON_HEADER;

	for (ptr = header->buf; ptr[0] != '\0'; ptr++) {
		if (inhdrname) {
			if (canon == CANON_HEADER_RELAXED) {
				ptr = osmtpd_ltok_skip_fws(ptr, 1);
				c = tolower(ptr[0]);
			} else
				c = ptr[0];
			if (c == ':') {
				inhdrname = 0;
				if (canon == CANON_HEADER_RELAXED)
					ptr = osmtpd_ltok_skip_fws(
					    ptr + 1, 1) - 1;
			}
			if (ar_b_digest_update(bctx, &c, 1) == 0)
				osmtpd_errx(1, "ar_b_digest_update");
			continue;
		}
		end = osmtpd_ltok_skip_fws(ptr, 1);
		if (end == ptr) {
			if (sig->header == header && ptr == sig->bheader) {
				ptr = osmtpd_ltok_skip_tag_value(
				    ptr, 0) - 1;
				continue;
			}
			if (ar_b_digest_update(bctx, ptr, 1) == 0)
				osmtpd_errx(1, "ar_b_digest_update");
		} else {
			if (canon == CANON_HEADER_RELAXED) {
				if (end[0] == '\0')
					continue;
				if (ar_b_digest_update(bctx, " ", 1) == 0)
					osmtpd_errx(1, "ar_b_digest_update");
			} else {
				if (ar_b_digest_update(bctx, ptr,
				    end - ptr) == 0)
					osmtpd_errx(1, "ar_b_digest_update");
			}
			ptr = end - 1;
		}
			
	}
	if (sig->header != header) {
		if (ar_b_digest_update(bctx, "\r\n", 2) == 0)
			osmtpd_errx(1, "ar_b_digest_update");
	}
}

void
ar_signature_state(struct ar_signature *sig, enum ar_state state,
    const char *reason)
{
	if (sig->query != NULL) {
		event_asr_abort(sig->query);
		sig->query = NULL;
		sig->header->msg->nqueries--;
	}
	switch (sig->state) {
	case AR_UNKNOWN:
	case AR_NONE:
		break;
	case AR_FAIL:
		if (state == AR_PERMERROR)
			break;
	case AR_PASS:
	case AR_SOFTFAIL:
		osmtpd_errx(1, "Unexpected transition: %s -> %",
		    ar_state2str(sig->state), ar_state2str(state));
	case AR_POLICY:
		if (state == AR_PASS)
			return;
		break;
	case AR_NEUTRAL:
		if (state == AR_PASS)
			return;
		if (state == AR_TEMPERROR || state == AR_PERMERROR)
			break;
		osmtpd_errx(1, "Unexpected transition: %s -> %",
		    ar_state2str(sig->state), ar_state2str(state));
	case AR_TEMPERROR:
		if (state == AR_PERMERROR)
			break;
		return;
	case AR_PERMERROR:
		return;
	}
	sig->state = state;
	sig->state_reason = reason;
}

const char *
ar_state2str(enum ar_state state)
{
	switch (state)
	{
	case AR_UNKNOWN:
		return "unknown";
	case AR_NONE:
		return "none";
	case AR_PASS:
		return "pass";
	case AR_FAIL:
		return "fail";
	case AR_SOFTFAIL:
		return "softfail";
	case AR_POLICY:
		return "policy";
	case AR_NEUTRAL:
		return "neutral";
	case AR_TEMPERROR:
		return "temperror";
	case AR_PERMERROR:
		return "permerror";
	}
}

void
ar_rr_resolve(struct asr_result *ar, void *arg)
{
	struct ar_signature *sig = arg;
	char key[UINT16_MAX + 1];
	const char *rr_txt;
	size_t keylen, cstrlen;
	struct unpack pack;
	struct dns_header h;
	struct dns_query q;
	struct dns_rr rr;
	char buf[HOST_NAME_MAX + 1];

	sig->query = NULL;
	sig->header->msg->nqueries--;

	if (sig->state != AR_UNKNOWN)
		goto verify;

	if (ar->ar_h_errno == TRY_AGAIN || ar->ar_h_errno == NO_RECOVERY) {
		ar_signature_state(sig, AR_TEMPERROR,
		    hstrerror(ar->ar_h_errno));
		goto verify;
	}
	if (ar->ar_h_errno == HOST_NOT_FOUND) {
		ar_signature_state(sig, AR_PERMERROR,
		    hstrerror(ar->ar_h_errno));
		goto verify;
	}

	unpack_init(&pack, ar->ar_data, ar->ar_datalen);
	if (unpack_header(&pack, &h) != 0 ||
	    unpack_query(&pack, &q) != 0) {
		osmtpd_warn(sig->header->msg->ctx,
		    "Mallformed DKIM DNS response for domain %s: %s",
		    print_dname(q.q_dname, buf, sizeof(buf)),
		    pack.err);
		ar_signature_state(sig, AR_PERMERROR, pack.err);
		goto verify;
	}

	for (; h.ancount > 0; h.ancount--) {
		if (unpack_rr(&pack, &rr) != 0) {
			osmtpd_warn(sig->header->msg->ctx,
			    "Mallformed DKIM DNS record for domain %s: %s",
			    print_dname(q.q_dname, buf, sizeof(buf)),
			    pack.err);
			continue;
		}

		/* If we below limit, follow CNAME*/
		if (rr.rr_type == T_CNAME &&
		    sig->nqueries < AR_LOOKUP_LOOKUP_LIMIT ) {
			print_dname(rr.rr.cname.cname, buf, sizeof(buf));
			ar_lookup_record(sig, buf);
			free(ar->ar_data);
			return;
		}

		if (rr.rr_type != T_TXT) {
			osmtpd_warn(sig->header->msg->ctx,
			    "Unexpected DKIM DNS record: %d for domain %s",
			    rr.rr_type,
			    print_dname(q.q_dname, buf, sizeof(buf)));
			continue;
		}

		keylen = 0;
		rr_txt = rr.rr.other.rdata;
		while (rr.rr.other.rdlen > 0) {
			cstrlen = ((const unsigned char *)rr_txt)[0];
			if (cstrlen >= rr.rr.other.rdlen ||
			    keylen + cstrlen >= sizeof(key))
				break;
			/*
			 * RFC 6376 Section 3.6.2.2
			 * Strings in a TXT RR MUST be concatenated together
			 * before use with no intervening whitespace.
			 */
			strlcpy(key + keylen, rr_txt + 1, cstrlen + 1);
			rr.rr.other.rdlen -= (cstrlen + 1);
			rr_txt += (cstrlen + 1);
			keylen += cstrlen;
		}
		if (rr.rr.other.rdlen > 0)	/* Invalid TXT RDATA */
			continue;

		if (ar_key_text_parse(sig, key))
			break;
	}

	if (h.ancount == 0) {
		ar_signature_state(sig, AR_PERMERROR,
		    "No matching key found");
	} else {
		/* Only verify if all headers have been read */
		if (!sig->header->msg->parsing_headers)
			ar_signature_verify(sig);
	}
 verify:
	free(ar->ar_data);
	auth_message_verify(sig->header->msg);
}

int
ar_key_text_parse(struct ar_signature *sig, const char *key)
{
	char tagname, *hashname;
	const char *end, *tagvend;
	char pkraw[UINT16_MAX] = "", pkimp[UINT16_MAX];
	size_t pkrawlen = 0, pkoff, linelen;
	int h = 0, k = 0, n = 0, p = 0, s = 0, t = 0, first = 1;
	BIO *bio;
#ifdef HAVE_ED25519
	size_t pklen;
	int tmp;
#endif

	key = osmtpd_ltok_skip_fws(key, 1);
	/* Validate syntax early */
	if ((end = osmtpd_ltok_skip_tag_list(key, 0)) == NULL)
		return 0;

	while (key[0] != '\0') {
		key = osmtpd_ltok_skip_fws(key, 1);
		if ((end = osmtpd_ltok_skip_tag_name(key, 0)) == NULL)
			return 0;

		if ((size_t)(end - key) != 1)
			tagname = '\0';
		else
			tagname = key[0];
		key = osmtpd_ltok_skip_fws(end, 1);
		/* '=' */
		if (key[0] != '=')
			return 0;
		key = osmtpd_ltok_skip_fws(key + 1, 1);
		if ((end = osmtpd_ltok_skip_tag_value(key, 0)) == NULL)
			return 0;
		switch (tagname) {
		case 'v':
			/*
			 * RFC 6376 section 3.6.1, v=:
			 * RECOMMENDED...This tag MUST be the first tag in the
			 * record.
			 */
			if (!first ||
			    osmtpd_ltok_skip_key_v_tag_value(key, 0) != end)
				return 0;
			key = end;
			break;
		case 'h':
			if (h != 0)	/* Duplicate tag */
				return 0;
			/* Invalid tag value */
			if (osmtpd_ltok_skip_key_h_tag_value(key, 0) != end)
				return 0;
			while (1) {
				if ((tagvend = osmtpd_ltok_skip_key_h_tag_alg(
				    key, 0)) == NULL)
					break;
				hashname = strndup(key, tagvend - key);
				if (hashname == NULL)
					osmtpd_err(1, "strndup");
				if (EVP_get_digestbyname(hashname) == sig->ah) {
					free(hashname);
					h = 1;
					break;
				}
				free(hashname);
				key = osmtpd_ltok_skip_fws(tagvend, 1);
				if (key[0] != ':')
					break;
				key = osmtpd_ltok_skip_fws(key + 1, 1);
			}
			if (h != 1)
				return 0;
			key = end;
			break;
		case 'k':
			if (k != 0)	/* Duplicate tag */
				return 0;
			k = 1;
			if (strncmp(key, "rsa", end - key) == 0) {
				if (sig->ak != EVP_PKEY_RSA)
					return 0;
#if HAVE_ED25519
			} else if (strncmp(key, "ed25519", end - key) == 0) {
				if (sig->ak != EVP_PKEY_ED25519)
					return 0;
#endif
			} else
				return 0;
			key = end;
			break;
		case 'n':
			if (n != 0)	/* Duplicate tag */
				return 0;
			n = 1;
			/* semicolon is part of safe-char */
			if (osmtpd_ltok_skip_key_n_tag_value(key, 0) < end)
				return 0;
			key = end;
			break;
		case 'p':
			if (p != 0)	/* Duplicate tag */
				return 0;
			p = 1;
			while (1) {
				key = osmtpd_ltok_skip_fws(key, 1);
				if (osmtpd_ltok_skip_alphadigitps(
				    key, 0) == NULL)
					break;
				pkraw[pkrawlen++] = key++[0];
				if (pkrawlen >= sizeof(pkraw))
					return 0;
			}
			if (key[0] == '=') {
				pkraw[pkrawlen++] = '=';
				key = osmtpd_ltok_skip_fws(key + 1, 1);
				if (pkrawlen >= sizeof(pkraw))
					return 0;
				if (key[0] == '=') {
					pkraw[pkrawlen++] = '=';
					key++;
					if (pkrawlen >= sizeof(pkraw))
						return 0;
				}
			}
			/* Invalid tag value */
			if (pkrawlen % 4 != 0 || key != end)
				return 0;
			break;
		case 's':
			if (s != 0)	/* Duplicate tag */
				return 0;
			/* Invalid tag value */
			if (osmtpd_ltok_skip_key_s_tag_value(key, 0) != end)
				return 0;
			while (1) {
				if ((tagvend =
				    osmtpd_ltok_skip_key_s_tag_type(
				    key, 0)) == NULL)
					break;
				if (strncmp(key, "*", tagvend - key) == 0 ||
				    strncmp(key, "email", tagvend - key) == 0) {
					s = 1;
					break;
				}
				key = osmtpd_ltok_skip_fws(tagvend, 1);
				if (key[0] != ':')
					break;
				key = osmtpd_ltok_skip_fws(key + 1, 1);
			}
			if (s != 1)
				return 0;
			key = end;
			break;
		case 't':
			if (t != 0)	/* Duplicate tag */
				return 0;
			t = 1;
			if (osmtpd_ltok_skip_key_t_tag_value(key, 0) != end)
				return 0;
			while (1) {
				tagvend = osmtpd_ltok_skip_key_t_tag_flag(
				    key, 0);
				if (strncmp(key, "y", tagvend - key) == 0)
					sig->kt |= KT_Y;
				else if (strncmp(key, "s", tagvend - key) == 0)
					sig->kt |= KT_S;
				key = osmtpd_ltok_skip_fws(tagvend, 1);
				if (key[0] != ':')
					break;
				key = osmtpd_ltok_skip_fws(key + 1, 1);
			}
			break;
		default:
			key = end;
			break;
		}

		first = 0;
		key = osmtpd_ltok_skip_fws(key, 1);
		if (key[0] == ';')
			key++;
		else if (key[0] != '\0')
			return 0;
	}

	if (!p)					/* Missing tag */
		return 0;
	if (k == 0 && sig->ak != EVP_PKEY_RSA)	/* Default to RSA */
		return 0;

	if (pkraw[0] == '\0') {
		ar_signature_state(sig, AR_PERMERROR, "Key is revoked");
		return 1;
	}

	switch (sig->ak) {
	case EVP_PKEY_RSA:
		pkoff = strlcpy(pkimp, "-----BEGIN PUBLIC KEY-----\n",
		    sizeof(pkimp));
		linelen = 0;
		for (key = pkraw; key[0] != '\0';) {
			if (pkoff + 2 >= sizeof(pkimp))
				return 0;
			pkimp[pkoff++] = key++[0];
			if (++linelen == 64) {
				pkimp[pkoff++] = '\n';
				linelen = 0;
			}
		}
		/* Leverage pkoff check in loop */
		if (linelen != 0)
			pkimp[pkoff++] = '\n';
		/* PEM_read_bio_PUBKEY will catch truncated keys */
		pkoff += strlcpy(pkimp + pkoff, "-----END PUBLIC KEY-----\n",
		    sizeof(pkimp) - pkoff);
		if ((bio = BIO_new_mem_buf(pkimp, pkoff)) == NULL)
			osmtpd_err(1, "BIO_new_mem_buf");
		sig->p = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
		BIO_free(bio);
		break;
#if HAVE_ED25519
	case EVP_PKEY_ED25519:
		if ((pkrawlen / 4) * 3 >= sizeof(pkimp))
			return 0;
		EVP_DecodeInit(ectx);
		if (EVP_DecodeUpdate(ectx, pkimp, &tmp, pkraw, pkrawlen) == -1)
			return 0;
		pklen = tmp;
		if (EVP_DecodeFinal(ectx, pkimp, &tmp) == -1)
			return 0;
		pklen += tmp;
		sig->p = EVP_PKEY_new_raw_public_key(sig->ak, NULL, pkimp,
		    pklen);
		break;
#endif
	}
	if (sig->p == NULL) {
		/*
		 * XXX No clue how to differentiate between invalid key and
		 * temporary failure like *alloc.
		 * Assume invalid key, because it's more likely.
		 */
		return 0;
	}
	return 1;
}

void
ar_body_parse(struct message *msg, const char *line)
{
	struct ar_signature *sig;
	const char *end = line, *hash, *prev;
	size_t hashn, len, i;
	int wsp, ret;

	if (line[0] == '\0') {
		msg->body_whitelines++;
		return;
	}

	while (msg->body_whitelines-- > 0) {
		for (i = 0; i < msg->nheaders; i++) {
			if ((sig = msg->header[i].sig) == NULL ||
			    sig->state != AR_UNKNOWN)
				continue;
			hashn = sig->l == -1 ? 2 : MIN(2, sig->l);
			sig->l -= sig->l == -1 ? 0 : hashn;
			if (EVP_DigestUpdate(sig->bhctx, "\r\n", hashn) == 0)
				osmtpd_errx(1, "EVP_DigestUpdate");
		}
	}
	msg->body_whitelines = 0;
	msg->has_body = 1;

	while (line[0] != '\0') {
		while (1) {
			prev = end;
			if ((end = osmtpd_ltok_skip_wsp(end, 0)) == NULL)
				break;
		}
		end = prev;
		wsp = end != line;
		if (!wsp) {
			while (osmtpd_ltok_skip_wsp(end, 0) == NULL &&
			    end[0] != '\0')
				end++;
		}
		for (i = 0; i < msg->nheaders; i++) {
			sig = msg->header[i].sig;
			if (sig == NULL || sig->state != AR_UNKNOWN)
				continue;
			if (wsp &&
			    (sig->c & CANON_BODY) == CANON_BODY_RELAXED) {
				hash = " ";
				len = end[0] == '\0' ? 0 : 1;
			} else {
				hash = line;
				len = (size_t)(end - line);
			}
			hashn = sig->l == -1 ? len : MIN(len, (size_t)sig->l);
			sig->l -= sig->l == -1 ? 0 : hashn;
			ret = EVP_DigestUpdate(sig->bhctx, hash, hashn);
			if (ret == 0)
				osmtpd_err(1, "EVP_DigestUpdate");
		}
		line = end;
	}
	for (i = 0; i < msg->nheaders; i++) {
		sig = msg->header[i].sig;
		if (sig == NULL || sig->state != AR_UNKNOWN)
			continue;
		hashn = sig->l == -1 ? 2 : MIN(2, sig->l);
		sig->l -= sig->l == -1 ? 0 : hashn;
		ret = EVP_DigestUpdate(sig->bhctx, "\r\n", hashn);
		if (ret == 0)
			osmtpd_err(1, "EVP_DigestUpdate");
	}
}

void
ar_body_verify(struct ar_signature *sig)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digestsz;

	if (sig->state != AR_UNKNOWN)
		return;

	if (sig->seal)
		return;

	if ((sig->c & CANON_BODY) == CANON_BODY_SIMPLE &&
	    !sig->header->msg->has_body) {
		if (EVP_DigestUpdate(sig->bhctx, "\r\n",
		    sig->l == -1 ? 2 : MIN(2, sig->l)) <= 0)
			osmtpd_errx(1, "EVP_DigestUpdate");
	}
	if (sig->l > 0) {
		ar_signature_state(sig, AR_PERMERROR,
		    "l tag larger than body");
		return;
	}

	if (EVP_DigestFinal_ex(sig->bhctx, digest, &digestsz) == 0)
		osmtpd_err(1, "EVP_DigestFinal_ex");

	if (digestsz != sig->bhsz || memcmp(digest, sig->bh, digestsz) != 0)
		ar_signature_state(sig, AR_FAIL, "bh mismatch");
}

char *
spf_evaluate_domain(struct spf_record *spf, const char *domain)
{
	struct session *ses = spf->ctx->local_session;

	char spec[HOST_NAME_MAX + 1];
	char macro[HOST_NAME_MAX + 1], smacro[sizeof(macro)];
	char delimiters[sizeof(".-+,/_=")];
	char *endptr, *tmp;
	const u_char *addr;
	size_t i, mlen;
	long digits;
	int reverse;

	if (domain == NULL || domain[0] == '\0') {
		spf_done(spf, AR_PERMERROR, "Empty domain");
		return NULL;
	}

	for (i = 0;
	     domain[0] != ' ' && domain[0] != '\0' && i < sizeof(spec);
	     domain++) {

		if (domain[0] < 0x21 || domain[0] > 0x7e) {
			spf_done(
			    spf, AR_PERMERROR, "Invalid character in domain-spec");
			return NULL;
		}

		if (domain[0] != '%') {
			spec[i++] = domain[0];
			continue;
		}
		domain++;

		switch (domain[0]) {
		case '%':
			spec[i++] = '%';
			break;
		case '_':
			spec[i++] = ' ';
			break;
		case '-':
			if (i + 3 >= sizeof(spec)) {
				spf_done(
				    spf, AR_PERMERROR, "domain-spec too large");
				return NULL;
			}

			spec[i++] = '%';
			spec[i++] = '2';
			spec[i++] = '0';
			break;
		case '{':
			domain++;
			digits = -1;
			reverse = 0;
			delimiters[0] = '\0';

			switch (domain[0]) {
			case 'S':
			case 's':
				mlen = (size_t) snprintf(macro, sizeof(macro),
				    "%s@%s", spf->sender_local,
				    spf->sender_domain);
				break;
			case '{':
				domain++;
				digits = -1;
				reverse = 0;
				delimiters[0] = '\0';

				switch (domain[0]) {
				case 'S':
				case 's':
					mlen = (size_t) snprintf(macro, sizeof(macro),
					    "%s@%s", spf->sender_local,
					    spf->sender_domain);
					break;
				case 'L':
				case 'l':
					mlen = strlcpy(macro,
					    spf->sender_local, sizeof(macro));
					break;
				case 'O':
				case 'o':
					mlen = strlcpy(macro,
					    spf->sender_domain,
					    sizeof(macro));
					break;
				case 'D':
				case 'd':
					if (spf->nqueries < 1) {
						spf_done(spf, AR_PERMERROR,
						    "no domain for d macro");
						return NULL;
					}
					mlen = strlcpy(macro,
					    spf->queries[spf->nqueries - 1].domain,
					    sizeof(macro));
					break;
				case 'I':
				case 'i':
					if (ses->src.ss_family == AF_INET) {
						addr = (u_char *)(&((struct sockaddr_in *)
						    &(ses->src))->sin_addr);
						mlen = snprintf(macro, sizeof(macro),
						    "%u.%u.%u.%u",
						    (addr[0] & 0xff), (addr[1] & 0xff),
						    (addr[2] & 0xff), (addr[3] & 0xff));
					} else if (ses->src.ss_family == AF_INET6) {
						addr = (u_char *)(&((struct sockaddr_in6 *)
						    &(ses->src))->sin6_addr);
						mlen = snprintf(macro, sizeof(macro),
						    "%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx."
						    "%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx."
						    "%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx."
						    "%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx",
						    (u_char) ((addr[0] >> 4) & 0x0f), (u_char) (addr[0] & 0x0f),
						    (u_char) ((addr[1] >> 4) & 0x0f), (u_char) (addr[1] & 0x0f),
						    (u_char) ((addr[2] >> 4) & 0x0f), (u_char) (addr[2] & 0x0f),
						    (u_char) ((addr[3] >> 4) & 0x0f), (u_char) (addr[3] & 0x0f),
						    (u_char) ((addr[4] >> 4) & 0x0f), (u_char) (addr[4] & 0x0f),
						    (u_char) ((addr[5] >> 4) & 0x0f), (u_char) (addr[5] & 0x0f),
						    (u_char) ((addr[6] >> 4) & 0x0f), (u_char) (addr[6] & 0x0f),
						    (u_char) ((addr[7] >> 4) & 0x0f), (u_char) (addr[7] & 0x0f),
						    (u_char) ((addr[8] >> 4) & 0x0f), (u_char) (addr[8] & 0x0f),
						    (u_char) ((addr[9] >> 4) & 0x0f), (u_char) (addr[9] & 0x0f),
						    (u_char) ((addr[10] >> 4) & 0x0f), (u_char) (addr[10] & 0x0f),
						    (u_char) ((addr[11] >> 4) & 0x0f), (u_char) (addr[11] & 0x0f),
						    (u_char) ((addr[12] >> 4) & 0x0f), (u_char) (addr[12] & 0x0f),
						    (u_char) ((addr[13] >> 4) & 0x0f), (u_char) (addr[13] & 0x0f),
						    (u_char) ((addr[14] >> 4) & 0x0f), (u_char) (addr[14] & 0x0f),
						    (u_char) ((addr[15] >> 4) & 0x0f), (u_char) (addr[15] & 0x0f));
					} else {
						spf_done(spf, AR_PERMERROR,
						    "unsupported type of address");
						return NULL;
					}
					break;
				case 'P':
				case 'p':
					mlen = strlcpy(macro, ses->rdns, sizeof(macro));
					break;
				case 'V':
				case 'v':
					if (ses->src.ss_family == AF_INET)
						mlen = strlcpy(macro, "in-addr",
						    sizeof(macro));
					else if (ses->src.ss_family == AF_INET6)
						mlen = strlcpy(macro, "ip6",
						    sizeof(macro));
					else {
						spf_done(spf, AR_PERMERROR,
						    "unsupported type of address");
						return NULL;
					}
					break;
				case 'H':
				case 'h':
					mlen = strlcpy(macro, ses->identity,
					    sizeof(macro));
					break;
				default:
					spf_done(spf, AR_PERMERROR,
					    "Unexpected macro in domain-spec");
					return NULL;
				}

				if (mlen >= sizeof(macro)) {
					spf_done(spf, AR_PERMERROR,
					    "Macro expansions too large");
					return NULL;
				}

				domain++;
				if (isdigit(domain[0])) {
					digits = strtol(domain, &endptr, 10);
					if (digits < 1) {
						spf_done(spf, AR_PERMERROR,
						    "digits in macro can't be 0");
						return NULL;
					}
					domain = endptr;
				}

				if (domain[0] == 'r') {
					domain++;
					reverse = 1;
				}

				for (; strchr(".-+,/_=", domain[0]) != NULL; domain++) {
					if (strchr(delimiters, domain[0]) == NULL) {
						delimiters[strlen(delimiters) + 1] = '\0';
						delimiters[strlen(delimiters)] = domain[0];
					}
				}

				if (delimiters[0] == '\0') {
					delimiters[0] = '.';
					delimiters[1] = '\0';
				}

				if (domain[0] != '}') {
					spf_done(spf, AR_PERMERROR,
					    "Mallformed macro, expected end");
					return NULL;
				}

				if (reverse) {
					smacro[0] = '\0';
					tmp = macro + strlen(macro) - 1;
					/*
					 * DIGIT rightmost elements after reversal is DIGIT
					 * lefmost elements before reversal
					 */
					while (1) {
						while (tmp > macro &&
						    strchr(delimiters, tmp[0]) == NULL)
							tmp--;
						if (tmp == macro)
							break;
						if (digits == 0)
							break;
						if (digits > 0)
							digits--;

						tmp[0] = '\0';
						if (smacro[0] != '\0')
							strlcat(smacro, ".", sizeof(smacro));
						strlcat(smacro, tmp + 1, sizeof(smacro));
						tmp--;
					}
					if (digits != 0) {
						if (smacro[0] != '\0')
							strlcat(smacro, ".", sizeof(smacro));
						strlcat(smacro, macro, sizeof(smacro));
					}
				} else {
					if (digits != -1) {
						tmp = macro;
						endptr = macro + strlen(macro);
						while (digits > 0) {
							while (tmp < endptr &&
							    strchr(delimiters, tmp[0]) == NULL)
								tmp++;
							if (tmp == endptr)
								break;
							if (digits == 1) {
								tmp[0] = '\0';
								break;
							}
							digits--;
							tmp++;
						}
					}
					strlcpy(smacro, macro, sizeof(smacro));
				}

				spec[i] = '\0';
				i = strlcat(spec, smacro, sizeof(spec));
				if (i >= sizeof(spec)) {
					spf_done(
					    spf, AR_PERMERROR, "domain-spec too large");
					return NULL;
				}
				break;
			case 'P':
			case 'p':
				mlen = strlcpy(macro, ses->rdns, sizeof(macro));
				break;
			case 'V':
			case 'v':
				if (ses->src.ss_family == AF_INET)
					mlen = strlcpy(macro, "in-addr",
					    sizeof(macro));
				else if (ses->src.ss_family == AF_INET6)
					mlen = strlcpy(macro, "ip6",
					    sizeof(macro));
				else {
					spf_done(spf, AR_PERMERROR,
					    "unsupported type of address");
					return NULL;
				}
				break;
			case 'H':
			case 'h':
				mlen = strlcpy(macro, ses->identity,
				    sizeof(macro));
				break;
			default:
				spf_done(spf, AR_PERMERROR,
				    "Mallformed macro, unexpected character after %");
				return NULL;
			}

			if (mlen >= sizeof(macro)) {
				spf_done(spf, AR_PERMERROR,
				    "Macro expansions too large");
				return NULL;
			}

			domain++;
			if (isdigit(domain[0])) {
				digits = strtol(domain, &endptr, 10);
				if (digits < 1) {
					spf_done(spf, AR_PERMERROR,
					    "digits in macro can't be 0");
					return NULL;
				}
				domain = endptr;
			}

			if (domain[0] == 'r') {
				domain++;
				reverse = 1;
			}

			for (; strchr(".-+,/_=", domain[0]) != NULL; domain++) {
				if (strchr(delimiters, domain[0]) == NULL) {
					delimiters[strlen(delimiters) + 1] = '\0';
					delimiters[strlen(delimiters)] = domain[0];
				}
			}

			if (delimiters[0] == '\0') {
				delimiters[0] = '.';
				delimiters[1] = '\0';
			}

			if (domain[0] != '}') {
				spf_done(spf, AR_PERMERROR,
				    "Mallformed macro, expected end");
				return NULL;
			}

			if (reverse) {
				smacro[0] = '\0';
				tmp = macro + strlen(macro) - 1;
				/*
				 * DIGIT rightmost elements after reversal is DIGIT
				 * lefmost elements before reversal
				 */
				while (1) {
					while (tmp > macro &&
					    strchr(delimiters, tmp[0]) == NULL)
						tmp--;
					if (tmp == macro)
						break;
					if (digits == 0)
						break;
					if (digits > 0)
						digits--;

					tmp[0] = '\0';
					if (smacro[0] != '\0')
						strlcat(smacro, ".", sizeof(smacro));
					strlcat(smacro, tmp + 1, sizeof(smacro));
					tmp--;
				}
				if (digits != 0) {
					if (smacro[0] != '\0')
						strlcat(smacro, ".", sizeof(smacro));
					strlcat(smacro, macro, sizeof(smacro));
				}
			} else {
				if (digits != -1) {
					tmp = macro;
					endptr = macro + strlen(macro);
					while (digits > 0) {
						while (tmp < endptr &&
						    strchr(delimiters, tmp[0]) == NULL)
							tmp++;
						if (tmp == endptr)
							break;
						if (digits == 1) {
							tmp[0] = '\0';
							break;
						}
						digits--;
						tmp++;
					}
				}
				strlcpy(smacro, macro, sizeof(smacro));
			}

			spec[i] = '\0';
			i = strlcat(spec, smacro, sizeof(spec));
			if (i >= sizeof(spec)) {
				spf_done(
				    spf, AR_PERMERROR, "domain-spec too large");
				return NULL;
			}
			break;

		default:
			spf_done(spf, AR_PERMERROR,
			    "Mallformed macro, unexpected character after %");
			return NULL;
		}
	}

	if ((tmp = strndup(spec, i)) == NULL)
		osmtpd_err(1, "%s: strndup", __func__);

	return tmp;
}

void
spf_lookup_record(struct spf_record *spf, const char *domain, int type,
    enum ar_state qualifier, int include, int exists)
{
	struct asr_query *aq;
	struct spf_query *query;

	if (spf->done)
		return;

	if (spf->nqueries >= SPF_DNS_LOOKUP_LIMIT) {
		spf_done(spf, AR_PERMERROR, "Too many DNS queries");
		return;
	}

	query = &spf->queries[spf->nqueries];
	query->spf = spf;
	query->type = type;
	query->q = qualifier;
	query->include = include;
	query->exists = exists;
	query->txt = NULL;
	query->eva = NULL;

	if ((query->domain = spf_evaluate_domain(spf, domain)) == NULL)
		return;

	if (domain == NULL || !strlen(domain)) {
		spf_done(spf, AR_PERMERROR, "Empty domain");
		return;
	}

	if ((aq = res_query_async(query->domain, C_IN, type, NULL)) == NULL)
		osmtpd_err(1, "res_query_async");

	if ((query->eva = event_asr_run(aq, spf_resolve, query)) == NULL)
		osmtpd_err(1, "event_asr_run");

	spf->running++;
	spf->nqueries++;
}

void
spf_resolve(struct asr_result *ar, void *arg)
{
	int i;

	struct spf_query *query = arg;
	struct spf_record *spf = query->spf;
	struct unpack pack;
	struct dns_header h;
	struct dns_query q;
	struct dns_rr rr;
	char buf[HOST_NAME_MAX + 1];

	query->eva = NULL;
	query->spf->running--;

	if (ar->ar_h_errno == TRY_AGAIN
	    || ar->ar_h_errno == NO_RECOVERY) {
		spf_done(query->spf, AR_TEMPERROR, hstrerror(ar->ar_h_errno));
		goto end;
	}

	if (ar->ar_h_errno == HOST_NOT_FOUND) {
		if (query->include && !query->exists)
			spf_done(query->spf,
			    AR_PERMERROR, hstrerror(ar->ar_h_errno));
		goto consume;
	}

	unpack_init(&pack, ar->ar_data, ar->ar_datalen);
	if (unpack_header(&pack, &h) != 0 ||
	    unpack_query(&pack, &q) != 0) {
		osmtpd_warn(query->spf->ctx,
		    "Mallformed SPF DNS response for domain %s: %s",
		    print_dname(q.q_dname, buf, sizeof(buf)),
		    pack.err);
		spf_done(query->spf, AR_TEMPERROR, pack.err);
		goto end;
	}

	for (; h.ancount; h.ancount--) {
		if (unpack_rr(&pack, &rr) != 0) {
			osmtpd_warn(query->spf->ctx,
			    "Mallformed SPF DNS record for domain %s: %s",
			    print_dname(q.q_dname, buf, sizeof(buf)),
			    pack.err);
			continue;
		}

		switch (rr.rr_type)
		{
		case T_TXT:
			spf_resolve_txt(&rr, query);
			break;

		case T_MX:
			spf_resolve_mx(&rr, query);
			break;

		case T_A:
			spf_resolve_a(&rr, query);
			break;

		case T_AAAA:
			spf_resolve_aaaa(&rr, query);
			break;

		case T_CNAME:
			spf_resolve_cname(&rr, query);
			break;

		default:
			osmtpd_warn(spf->ctx,
			    "Unexpected SPF DNS record: %d for domain %s",
			    rr.rr_type, query->domain);
			spf_done(query->spf, AR_TEMPERROR, "Unexpected record");
			break;
		}

		if (spf->done)
			goto end;
	}

 consume:
	if (spf->running > 0)
		goto end;

	for (i = spf->nqueries - 1; i >= 0; i--) {
		if (spf->queries[i].txt != NULL) {
			if (spf_execute_txt(&spf->queries[i]) != 0)
				break;
		}
	}

 end:
	free(ar->ar_data);
	if (!spf->done && spf->running == 0)
		spf_done(spf, AR_NONE, NULL);
}

void
spf_resolve_txt(struct dns_rr *rr, struct spf_query *query)
{
	char *txt;
	txt = spf_parse_txt(rr->rr.other.rdata, rr->rr.other.rdlen);
	if (txt == NULL) {
		osmtpd_warn(NULL, "spf_parse_txt");
		return;
	}

	if (strncasecmp("v=spf1 ", txt, 7)) {
		free(txt);
		return;
	}

	if (query->txt != NULL) {
		free(txt);
		spf_done(query->spf, AR_PERMERROR, "Duplicated SPF record");
		return;
	}

	query->txt = txt;
	query->pos = 0;
	spf_execute_txt(query);
}

void
spf_resolve_mx(struct dns_rr *rr, struct spf_query *query)
{
	char buf[HOST_NAME_MAX + 1];

	char *domain = print_dname(rr->rr.mx.exchange, buf, sizeof(buf));

	spf_lookup_record(query->spf, domain, T_A,
	    query->q, query->include, 0);
	spf_lookup_record(query->spf, domain, T_AAAA,
	    query->q, query->include, 0);
}

void
spf_resolve_a(struct dns_rr *rr, struct spf_query *query)
{
	if (query->exists ||
	    spf_check_cidr(query->spf, &rr->rr.in_a.addr, 32) == 0) {
		spf_done(query->spf, query->q, NULL);
	}
}

void
spf_resolve_aaaa(struct dns_rr *rr, struct spf_query *query)
{
	if (spf_check_cidr6(query->spf, &rr->rr.in_aaaa.addr6, 128) == 0) {
		spf_done(query->spf, query->q, NULL);
	}
}

void
spf_resolve_cname(struct dns_rr *rr, struct spf_query *query)
{
	char buf[HOST_NAME_MAX + 1];

	char *domain = print_dname(rr->rr.cname.cname, buf, sizeof(buf));

	spf_lookup_record(query->spf, domain, query->type,
	    query->q, query->include, 0);
}

char *
spf_parse_txt(const char *rdata, size_t rdatalen)
{
	size_t len, dstsz = SPF_RECORD_MAX - 1;
	ssize_t r = 0;
	char *dst, *odst;

	if (rdatalen >= dstsz) {
		errno = EOVERFLOW;
		return NULL;
	}

	odst = dst = malloc(dstsz);
	if (dst == NULL)
		osmtpd_err(1, "%s: malloc", __func__);

	while (rdatalen) {
		len = *(const unsigned char *)rdata;
		if (len >= rdatalen) {
			errno = EINVAL;
			return NULL;
		}

		rdata++;
		rdatalen--;

		if (len == 0)
			continue;

		if (len >= dstsz) {
			errno = EOVERFLOW;
			return NULL;
		}
		memmove(dst, rdata, len);
		dst += len;
		dstsz -= len;

		rdata += len;
		rdatalen -= len;
		r += len;
	}

	odst[r] = '\0';

	return odst;
}

int
spf_check_cidr(struct spf_record *spf, struct in_addr *net, int bits)
{
	struct in_addr *addr;
	struct session *ses = spf->ctx->local_session;

	if (ses->src.ss_family != AF_INET)
		return -1;

	if (bits == 0)
		return 0;

	addr = &(((struct sockaddr_in *)(&ses->src))->sin_addr);

	return ((addr->s_addr ^ net->s_addr) & htonl(0xFFFFFFFFu << (32 - bits)));
}

int
spf_check_cidr6(struct spf_record *spf, struct in6_addr *net, int bits)
{
	int rc;
	uint32_t *a, *n, whole, incomplete;
	struct in6_addr *addr;
	struct session *ses = spf->ctx->local_session;

	if (ses->src.ss_family != AF_INET6)
		return -1;

	if (bits == 0)
		return 0;

	addr = &(((struct sockaddr_in6 *)(&ses->src))->sin6_addr);

	a = addr->__u6_addr.__u6_addr32;
	n = net->__u6_addr.__u6_addr32;

	whole = bits >> 5;
	incomplete = bits & 0x1f;
	if (whole) {
		rc = memcmp(a, n, whole << 2);
		if (rc)
			return rc;
	}
	if (incomplete)
		return (a[whole] ^ n[whole]) & htonl((0xffffffffu) << (32 - incomplete));

	return 0;
}

int
spf_execute_txt(struct spf_query *query)
{
	struct in_addr ina;
	struct in6_addr in6a;
	char *ap = NULL;
	char *in = query->txt + query->pos;
	char *end;
	int bits;

	enum ar_state q = query->q;

	while ((ap = strsep(&in, " ")) != NULL) {
		if (strcasecmp(ap, "v=spf1") == 0)
			continue;

		end = ap + strlen(ap)-1;
		if (*end == '.')
			*end = '\0';

		if (*ap == '+') {
			q = AR_PASS;
			ap++;
		} else if (*ap == '-') {
			q = AR_FAIL;
			ap++;
		} else if (*ap == '~') {
			q = AR_SOFTFAIL;
			ap++;
		} else if (*ap == '?') {
			q = AR_NEUTRAL;
			ap++;
		}

		if (q != AR_PASS && query->include)
			continue;

		if (strncasecmp("all", ap, 3) == 0) {
			spf_done(query->spf, q, NULL);
			return 0;
		}
		if (strncasecmp("ip4:", ap, 4) == 0) {
			if ((bits = inet_net_pton(AF_INET, ap + 4, &ina, sizeof(ina))) == -1)
				continue;

			if (spf_check_cidr(query->spf, &ina, bits) == 0) {
				spf_done(query->spf, q, NULL);
				return 0;
			}
			continue;
		}
		if (strncasecmp("ip6:", ap, 4) == 0) {
			if ((bits = inet_net_pton(AF_INET6, ap + 4, &ina, sizeof(ina))) == -1)
				continue;

			if (spf_check_cidr6(query->spf, &in6a, bits) == 0) {
				spf_done(query->spf, q, NULL);
				return 0;
			}
			continue;
		}
		if (strcasecmp("a", ap) == 0) {
			spf_lookup_record(query->spf, query->domain, T_A,
			    q, query->include, 0);
			spf_lookup_record(query->spf, query->domain, T_AAAA,
			    q, query->include, 0);
			break;
		}
		if (strncasecmp("a:", ap, 2) == 0) {
			spf_lookup_record(query->spf, ap + 2, T_A,
			    q, query->include, 0);
			spf_lookup_record(query->spf, ap + 2, T_AAAA,
			    q, query->include, 0);
			break;
		}
		if (strncasecmp("exists:", ap, 7) == 0) {
			spf_lookup_record(query->spf, ap + 7, T_A,
			    q, query->include, 1);
			break;
		}
		if (strncasecmp("include:", ap, 8) == 0) {
			spf_lookup_record(query->spf, ap + 8, T_TXT, q, 1, 0);
			break;
		}
		if (strncasecmp("redirect=", ap, 9) == 0) {
			if (in != NULL)
				continue;
			spf_lookup_record(query->spf, ap + 9, T_TXT,
			    q, query->include, 0);
			return 0;
		}
		if (strcasecmp("mx", ap) == 0) {
			spf_lookup_record(query->spf, query->domain, T_MX,
			    q, query->include, 0);
			break;
		}
		if (strncasecmp("mx:", ap, 3) == 0) {
			spf_lookup_record(query->spf, ap + 3, T_MX,
			    q, query->include, 0);
			break;
		}
	}

	if (in == NULL)
		return 0;

	query->pos = in - query->txt;

	return query->pos;
}

void
spf_done(struct spf_record *spf, enum ar_state state, const char *reason)
{
	int i;

	if (spf->done)
		return;

	for (i = 0; i < spf->nqueries; i++) {
		if (spf->queries[i].eva) {
			event_asr_abort(spf->queries[i].eva);
			spf->queries[i].eva = NULL;
		}
	}

	spf->nqueries = 0;
	spf->running = 0;
	spf->state = state;
	spf->state_reason = reason;
	spf->done = 1;

	osmtpd_filter_proceed(spf->ctx);
}

int
spf_ar_cat(const char *type, struct spf_record *spf, char **line, size_t *linelen, ssize_t *aroff)
{
	if (spf == NULL) {
		if ((*aroff =
		    auth_ar_cat(line, linelen, *aroff,
		    "; spf=none %s=none", type)
		    ) == -1) {
			return -1;
		}
		return 0;
	}

	if ((*aroff =
	    auth_ar_cat(line, linelen, *aroff,
	    "; spf=%s", ar_state2str(spf->state))
	    ) == -1) {
		return -1;
	}

	if ((*aroff =
	    auth_ar_cat(line, linelen, *aroff,
	    " %s=%s@%s",
	    type,
	    spf->sender_local,
	    spf->sender_domain)
	    ) == -1) {
		return -1;
	}

	if (spf->state_reason != NULL) {
		if ((*aroff =
		    auth_ar_cat(line, linelen, *aroff,
		    " reason=\"%s\"", spf->state_reason)
		    ) == -1) {
			return -1;
		}
	}

	return 0;
}

void
auth_message_verify(struct message *msg)
{
	size_t i;

	if (!msg->readdone || msg->nqueries > 0)
		return;

	for (i = 0; i < msg->nheaders; i++) {
		if (msg->header[i].sig == NULL)
			continue;
		if (msg->header[i].sig->query != NULL)
			return;
		if (msg->header[i].sig->state != AR_UNKNOWN)
			continue;
		ar_signature_state(msg->header[i].sig, AR_PASS, NULL);
	}

	auth_ar_create(msg->ctx);
}

int
ar_signature_ar_cat(const char *type, struct ar_signature *sig, char **line, size_t *linelen, ssize_t *aroff)
{
	if ((*aroff =
	    auth_ar_cat(line, linelen, *aroff,
	    "; %s=%s", type, ar_state2str(sig->state))
	    ) == -1)
		return -1;

	if (sig->state_reason != NULL) {
		if ((*aroff =
		    auth_ar_cat(line, linelen, *aroff,
		    " reason=\"%s\"", sig->state_reason)
		    ) == -1)
			return -1;
	}

	if (sig->s[0] != '\0') {
		if ((*aroff =
		    auth_ar_cat(line, linelen, *aroff,
		    " header.s=%s", sig->s)
		    ) == -1)
			return -1;
	}

	if (sig->d[0] != '\0') {
		if ((*aroff =
		    auth_ar_cat(line, linelen, *aroff,
		    " header.d=%s", sig->d)
		    ) == -1)
			return -1;
	}

	/*
	 * Don't print i-tag for DKIM, since localpart can be a
	 * quoted-string, which can contain FWS and CFWS. But
	 * ARC is different story and it should be printed out.
	 */
	if (sig->arc_i != 0) {
		if ((*aroff =
		    auth_ar_cat(line, linelen, *aroff,
		    " header.i=%d", sig->arc_i)
		    ) == -1)
			return -1;
	}

	if (sig->a != NULL) {
		if ((*aroff =
		    auth_ar_cat(line, linelen, *aroff,
		    " header.a=%.*s", (int)sig->asz, sig->a)
		    ) == -1)
			return -1;
	}

	if (sig->bheaderclean[0] != '\0') {
		if ((*aroff =
		    auth_ar_cat(line, linelen, *aroff,
		    " header.b=%s", sig->bheaderclean)
		    ) == -1)
			return -1;
	}

	return 0;
}

void
auth_ar_create(struct osmtpd_ctx *ctx)
{
	struct ar_signature *sig;
	size_t i;
	ssize_t n, aroff = 0;
	int found = 0;
	char *line = NULL;
	size_t linelen = 0;
	struct session *ses = ctx->local_session;
	struct message *msg = ctx->local_message;

	if (!arc && (aroff = auth_ar_cat(&line, &linelen, aroff,
	    "Authentication-Results: %s", authservid)) == -1)
		osmtpd_err(1, "%s: malloc", __func__);

	if (arc) {
		for (i = ARC_MAX_I; i >= ARC_MIN_I; i--) {
			if (msg->arc_signs[i] != NULL)
				break;
		}
		i += 1;

		if (i <= ARC_MAX_I && (aroff = auth_ar_cat(
		    &line, &linelen, aroff,
		    "ARC-Authentication-Results: i=%zu; %s",
		    i, authservid)) == -1)
			osmtpd_err(1, "%s: malloc", __func__);
	}

	for (i = 0; i < msg->nheaders; i++) {
		sig = msg->header[i].sig;
		if (sig == NULL || !sig->dkim)
			continue;

		found = 1;

		if (ar_signature_ar_cat(
		    "dkim", sig, &line, &linelen, &aroff) != 0)
			osmtpd_err(1, "%s: malloc", __func__);
	}

	if (!found) {
		aroff = auth_ar_cat(&line, &linelen, aroff, "; dkim=none");
		if (aroff == -1)
			osmtpd_err(1, "%s: malloc", __func__);
	}

	found = 0;

	for (i = ARC_MAX_I; i > 0; i--) {
		sig = msg->arc_signs[i];
		if (sig == NULL)
			continue;

		found = 1;

		if (ar_signature_ar_cat(
		    "arc", sig, &line, &linelen, &aroff) != 0)
			osmtpd_err(1, "%s: malloc", __func__);

		break;
	}

	if (!found) {
		aroff = auth_ar_cat(&line, &linelen, aroff, "; arc=none");
		if (aroff == -1)
			osmtpd_err(1, "%s: malloc", __func__);
	}

	if ((aroff = auth_ar_cat(&line, &linelen, aroff,
	    "; iprev=%s", ar_state2str(ses->iprev))) == -1)
		osmtpd_err(1, "%s: malloc", __func__);

	if (spf_ar_cat("smtp.helo", ses->spf_helo,
	    &line, &linelen, &aroff) != 0)
		osmtpd_err(1, "%s: malloc", __func__);

	if (ses->spf_mailfrom != NULL) {
		if (spf_ar_cat("smtp.mailfrom", ses->spf_mailfrom,
		    &line, &linelen, &aroff) != 0)
			osmtpd_err(1, "%s: malloc", __func__);
	} else {
		if (spf_ar_cat("smtp.mailfrom", ses->spf_helo,
		    &line, &linelen, &aroff) != 0)
			osmtpd_err(1, "%s: malloc", __func__);
	}

	if (aroff == -1)
		osmtpd_err(1, "%s: malloc", __func__);

	if (auth_ar_print(msg->ctx, line) != 0)
		osmtpd_warn(msg->ctx, "Invalid AR line: %s", line);

	rewind(msg->origf);
	while ((n = getline(&line, &linelen, msg->origf)) != -1) {
		line[n - 1] = '\0';
		osmtpd_filter_dataline(msg->ctx, "%s", line);
	}
	if (ferror(msg->origf))
		osmtpd_err(1, "%s: ferror", __func__);
	free(line);
	return;
}

int
auth_ar_print(struct osmtpd_ctx *ctx, const char *start)
{
	const char *scan, *checkpoint, *ncheckpoint;
	int arlen = 0, first = 1, arid = 1;

	checkpoint = start;
	ncheckpoint = osmtpd_ltok_skip_hdr_name(start, 0) + 1;
	for (scan = start; scan[0] != '\0'; scan++) {
		if (scan[0] == '\t')
			arlen = (arlen + 8) & ~7;
		else
			arlen++;
		if (arlen >= AUTHENTICATION_RESULTS_LINELEN) {
			arlen = (int)(checkpoint - start);
			if (arlen <= 0) {
				arlen = (int)(ncheckpoint - start);
				checkpoint = ncheckpoint;
			}
			osmtpd_filter_dataline(ctx, "%s%.*s", first ? "" : "\t",
			    arlen, start);
			start = osmtpd_ltok_skip_cfws(checkpoint, 1);
			if (*start == '\0')
				return 0;
			ncheckpoint = start;
			scan = start;
			arlen = 8;
			first = 0;
		}
		if (scan == ncheckpoint) {
			checkpoint = ncheckpoint;
			ncheckpoint = osmtpd_ltok_skip_cfws(ncheckpoint, 1);
			/* ARC-AR starts with i= */
			if (strncmp(ncheckpoint, "i=",
			    sizeof("i=") - 1) == 0) {
				ncheckpoint = osmtpd_ltok_skip_digit(
				    ncheckpoint + sizeof("i=") - 1, 0);
			/* authserv-id */
			} else if (arid) {
				ncheckpoint = osmtpd_ltok_skip_value(
				    ncheckpoint, 0);
				arid = 0;
			/* methodspec */
			} else if (strncmp(ncheckpoint, "arc=",
			    sizeof("arc=") - 1) == 0) {
				ncheckpoint = osmtpd_ltok_skip_keyword(
				    ncheckpoint + sizeof("arc=") - 1, 0);
			} else if (strncmp(ncheckpoint, "dkim=",
			    sizeof("dkim=") - 1) == 0) {
				ncheckpoint = osmtpd_ltok_skip_keyword(
				    ncheckpoint + sizeof("dkim=") - 1, 0);
			} else if (strncmp(ncheckpoint, "iprev=",
			    sizeof("iprev=") - 1) == 0) {
				ncheckpoint = osmtpd_ltok_skip_keyword(
				    ncheckpoint + sizeof("iprev=") - 1, 0);
			} else if (strncmp(ncheckpoint, "spf=",
			    sizeof("spf=") - 1) == 0) {
				ncheckpoint = osmtpd_ltok_skip_keyword(
				    ncheckpoint + sizeof("spf=") - 1, 0);
			/* reasonspec */
			} else if (strncmp(ncheckpoint, "reason=",
			    sizeof("reason=") - 1) == 0) {
				ncheckpoint = osmtpd_ltok_skip_ar_reasonspec(
				    ncheckpoint, 0);
			/* propspec */
			} else {
				ncheckpoint = osmtpd_ltok_skip_ar_propspec(
				    ncheckpoint, 0);
			}

			if (ncheckpoint == NULL)
				return -1;

			if (*ncheckpoint == ';')
				ncheckpoint++;
		}
	}
	osmtpd_filter_dataline(ctx, "%s%s", first ? "" : "\t", start);
	return 0;
}

ssize_t
auth_ar_cat(char **ar, size_t *n, size_t aroff, const char *fmt, ...)
{
	va_list ap;
	char *artmp;
	int size;
	size_t nn;

	va_start(ap, fmt);
	size = vsnprintf(*ar + aroff, *n - aroff, fmt, ap);
	va_end(ap);
	if (size + aroff < *n)
		return (ssize_t)size + aroff;
	nn = (((aroff + size)  / 256) + 1) * 256;
	artmp = realloc(*ar, nn);
	if (artmp == NULL)
		return -1;
	*ar = artmp;
	*n = nn;
	va_start(ap, fmt);
	size = vsnprintf(*ar + aroff, *n - aroff, fmt, ap);
	va_end(ap);
	return (ssize_t)size + aroff;
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: filter-auth [-A] [authserv-id]\n");
	exit(1);
}
