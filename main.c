/*
 * Copyright (c) 2024 Kirill A. Korinsky <kirill@korins.ky>
 * Copyright (c) 2022 Martijn van Duren <martijn@openbsd.org>
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
#include <inttypes.h>
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
 * since they're more expressive.
 */
enum dkim_state {
	DKIM_UNKNOWN,
	DKIM_PASS,
	DKIM_FAIL,
	DKIM_POLICY,
	DKIM_NEUTRAL,
	DKIM_TEMPERROR,
	DKIM_PERMERROR
};

struct dkim_signature {
	struct header *header;
	enum dkim_state state;
	const char *state_reason;
	int v;
	const char *a;
	size_t asz;
	int ak;
	int sephash;
	const EVP_MD *ah;
	char *b;
	size_t bsz;
	const char *bheader;
	/* Make sure padding bits for base64 decoding fit */
	char bh[EVP_MAX_MD_SIZE + (3 - (EVP_MAX_MD_SIZE % 3))];
	size_t bhsz;
	EVP_MD_CTX *bhctx;
	int c;
#define CANON_HEADER_SIMPLE	0
#define CANON_HEADER_RELAXED	1
#define CANON_HEADER		1
#define CANON_BODY_SIMPLE	0
#define CANON_BODY_RELAXED	1 << 1
#define CANON_BODY		1 << 1
#define CANON_DONE		1 << 2
	char d[HOST_NAME_MAX + 1];
	char **h;
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
};

/*
 * Use RFC7601 (Authentication-Results), anyway OpenSMTPD reports only pass or fail
 */
enum iprev_state {
	IPREV_NONE,
	IPREV_PASS,
	IPREV_FAIL
};

/*
 * Base on RFC7208
 */
enum spf_state {
	SPF_NONE,
	SPF_NEUTRAL,
	SPF_PASS,
	SPF_FAIL,
	SPF_SOFTFAIL,
	SPF_TEMPERROR,
	SPF_PERMERROR
};

/*
 * RFC 5321 doesn't limit record size, enforce some resanable limit
 */
#define SPF_RECORD_MAX 4096

struct spf_query {
	struct spf_record *spf;
	struct event_asr *eva;
	enum spf_state q;
	int include;
	int exists;
	char *domain;
	char *txt;
	int pos;
};

struct spf_record {
	void (*cb)(struct osmtpd_ctx *);
	struct osmtpd_ctx *ctx;
	enum spf_state state;
	const char *state_reason;
	char *sender_local;
	char *sender_domain;
	int nqueries;
	int running;
	int done;
/* RFC 7208 Section 4.6.4 limits to 10 DNS lookup,
 * and one is reserved for the first query.*/
#define SPF_DNS_LOOKUP_LIMIT 11
	struct spf_query queries[SPF_DNS_LOOKUP_LIMIT];
};

struct header {
	struct message *msg;
	uint8_t readdone;
	uint8_t parsed;
	char *buf;
	size_t buflen;
	struct dkim_signature *sig;
};

#define AUTHENTICATION_RESULTS_LINELEN 78
#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct message {
	struct osmtpd_ctx *ctx;
	FILE *origf;
	int parsing_headers;
	size_t body_whitelines;
	int has_body;
	struct header *header;
	size_t nheaders;
	int err;
	int readdone;
	struct spf_record *spf_from;
};

struct session {
	struct osmtpd_ctx *ctx;
	enum iprev_state iprev;
	struct spf_record *spf_helo;
	struct spf_record *spf_mailfrom;
	struct sockaddr_storage src;
};

void usage(void);
void auth_warn(struct osmtpd_ctx *, const char*, ...);
void auth_err(struct osmtpd_ctx *, char *);
void auth_errx(struct osmtpd_ctx *, char *);
void auth_conf(const char *, const char *);
void auth_connect(struct osmtpd_ctx *, const char *, enum osmtpd_status, struct sockaddr_storage *, struct sockaddr_storage *);
void spf_identity(struct osmtpd_ctx *, const char *);
void spf_mailfrom(struct osmtpd_ctx *, const char *);
void auth_dataline(struct osmtpd_ctx *, const char *);
void auth_commit(struct osmtpd_ctx *);
void *spf_record_new(struct osmtpd_ctx *, const char *,
	void (*)(struct osmtpd_ctx *));
void spf_record_free(struct spf_record *);
void *auth_session_new(struct osmtpd_ctx *);
void auth_session_free(struct osmtpd_ctx *, void *);
void *auth_message_new(struct osmtpd_ctx *);
void auth_message_free(struct osmtpd_ctx *, void *);
void dkim_header_add(struct osmtpd_ctx *, const char *);
void dkim_signature_parse(struct header *);
void dkim_signature_parse_v(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_a(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_b(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_bh(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_c(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_d(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_h(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_i(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_l(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_q(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_s(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_t(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_x(struct dkim_signature *, const char *, const char *);
void dkim_signature_parse_z(struct dkim_signature *, const char *, const char *);
void dkim_signature_verify(struct dkim_signature *);
void dkim_signature_header(EVP_MD_CTX *, struct dkim_signature *, struct header *);
void dkim_signature_state(struct dkim_signature *, enum dkim_state, const char *);
const char *dkim_state2str(enum dkim_state);
void dkim_header_cat(struct osmtpd_ctx *, const char *);
void dkim_body_parse(struct message *, const char *);
void dkim_body_verify(struct dkim_signature *);
void dkim_rr_resolve(struct asr_result *, void *);
const char *iprev_state2str(enum iprev_state);
void spf_lookup_record(struct spf_record *, const char *, int,
	enum spf_state, int, int);
void spf_done(struct spf_record *, enum spf_state, const char *);
void spf_resolve(struct asr_result *, void *);
void spf_resolve_txt(struct dns_rr *, struct spf_query *);
void spf_resolve_mx(struct dns_rr *, struct spf_query *);
void spf_resolve_a(struct dns_rr *, struct spf_query *);
void spf_resolve_aaaa(struct dns_rr *, struct spf_query *);
char* spf_parse_txt(const char *, size_t);
int spf_check_cidr(struct spf_record *, struct in_addr *, int );
int spf_check_cidr6(struct spf_record *, struct in6_addr *, int );
int spf_execute_txt(struct spf_query *);
const char *spf_state2str(enum spf_state);
int spf_ar_cat(const char *, struct spf_record *, char **, size_t *, ssize_t *);
void auth_message_verify(struct message *);
void auth_ar_create(struct osmtpd_ctx *);
ssize_t auth_ar_cat(char **ar, size_t *n, size_t aroff, const char *fmt, ...)
    __attribute__((__format__ (printf, 4, 5)));
int auth_ar_print(struct osmtpd_ctx *, const char *);
int dkim_key_text_parse(struct dkim_signature *, const char *);

char *authservid;
EVP_ENCODE_CTX *ectx = NULL;

int
main(int argc, char *argv[])
{
	if (argc != 1)
		osmtpd_errx(1, "Invalid argument count");

	OpenSSL_add_all_digests();

	if (pledge("tmppath stdio dns", NULL) == -1)
		osmtpd_err(1, "pledge");

	if ((ectx = EVP_ENCODE_CTX_new()) == NULL)
		osmtpd_err(1, "EVP_ENCODE_CTX_new");

	osmtpd_need(OSMTPD_NEED_SRC|OSMTPD_NEED_FCRDNS|OSMTPD_NEED_IDENTITY|OSMTPD_NEED_GREETING);
	osmtpd_register_conf(auth_conf);
	osmtpd_register_filter_dataline(auth_dataline);
	osmtpd_register_filter_commit(auth_commit);
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
			osmtpd_err(1, "malloc");
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
		ses->iprev = IPREV_PASS;
	else
		ses->iprev = IPREV_FAIL;

	memcpy(&ses->src, src, sizeof(struct sockaddr_storage));
}

void
spf_identity(struct osmtpd_ctx *ctx, const char *identity)
{
	char from[HOST_NAME_MAX + 12];

	struct session *ses = ctx->local_session;

	snprintf(from, sizeof(from), "postmaster@%s", identity);

	if ((ses->spf_helo =
			spf_record_new(ctx, from, osmtpd_filter_proceed))
			== NULL) {
		auth_warn(ctx, "spf_record_new: %s", from);
		return;
	}
}

void
spf_mailfrom(struct osmtpd_ctx *ctx, const char *from)
{
	struct session *ses = ctx->local_session;

	if (ses->spf_mailfrom)
		spf_record_free(ses->spf_mailfrom);

	if ((ses->spf_mailfrom =
			spf_record_new(ctx, from, osmtpd_filter_proceed))
			== NULL) {
		auth_warn(ctx, "spf_record_new: %s", from);
		return;
	}
}

void
auth_dataline(struct osmtpd_ctx *ctx, const char *line)
{
	struct message *msg = ctx->local_message;
	size_t i;

	if (msg->err) {
		if (line[0] == '.' && line[1] =='\0') {
			msg->readdone = 1;
			osmtpd_filter_dataline(ctx, ".");
		}
		return;
	}

	if (fprintf(msg->origf, "%s\n", line) < 0) {
		auth_err(ctx, "Couldn't write to tempfile");
		return;
	}
	if (line[0] == '.') {
		line++;
		if (line[0] == '\0') {
			msg->readdone = 1;
			for (i = 0; i < msg->nheaders; i++) {
				if (msg->header[i].sig == NULL)
					continue;
				dkim_body_verify(msg->header[i].sig);
			}
			auth_message_verify(msg);
			return;
		}
	}
	if (msg->parsing_headers) {
		dkim_header_add(ctx, line);
		if (line[0] == '\0') {
			msg->parsing_headers = 0;
			for (i = 0; i < msg->nheaders; i++) {
				if (msg->header[i].sig == NULL)
					continue;
				if (msg->header[i].sig->query == NULL)
					dkim_signature_verify(
					    msg->header[i].sig);
			}
		}
		return;
	} else {
		dkim_body_parse(msg, line);
	}
}

void
auth_commit(struct osmtpd_ctx *ctx)
{
	struct message *msg = ctx->local_message;

	if (msg->err)
		osmtpd_filter_disconnect(ctx, "Internal server error");
	else
		osmtpd_filter_proceed(ctx);
}

void *
spf_record_new(struct osmtpd_ctx *ctx, const char *from,
	void (*cb)(struct osmtpd_ctx *))
{
	int i;
	const char *at;
	struct spf_record *spf;

	if ((spf = malloc(sizeof(*spf))) == NULL)
		osmtpd_err(1, NULL);

	spf->cb = cb;
	spf->ctx = ctx;
	spf->state = SPF_NONE;
	spf->state_reason = NULL;
	spf->nqueries = 0;
	spf->running = 0;
	spf->done = 0;

	for (i = 0; i < SPF_DNS_LOOKUP_LIMIT; i++) {
		spf->queries[i].domain = NULL;
		spf->queries[i].txt = NULL;
	}

	from = osmtpd_ltok_skip_cfws(from, 1);

	if (strchr(from, '<') != NULL)
		from = osmtpd_ltok_skip_display_name(from, 1);

	if (*from == '<')
		from++;

	if ((at = osmtpd_ltok_skip_local_part(from, 0)) == NULL)
		goto fail;

	if ((spf->sender_local = strndup(from, at - from)) == NULL) {
		auth_err(ctx, "malloc");
		goto fail;
	}

	if (*at != '@')
		goto fail_local;
	at++;

	if ((from = osmtpd_ltok_skip_domain(at, 0)) == NULL)
		goto fail_local;


	if ((spf->sender_domain = strndup(at, from - at)) == NULL) {
		auth_err(ctx, "malloc");
		goto fail_local;
	}

	spf_lookup_record(
		spf, spf->sender_domain, T_TXT, SPF_PASS, 0, 0);

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
		if(spf->queries[i].domain)
			free(spf->queries[i].domain);
		if(spf->queries[i].txt)
			free(spf->queries[i].txt);
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
		osmtpd_err(1, NULL);

	ses->ctx = ctx;
	ses->iprev = IPREV_NONE;

	ses->spf_helo = NULL;
	ses->spf_mailfrom = NULL;

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

	free(ses);
}

void *
auth_message_new(struct osmtpd_ctx *ctx)
{
	struct message *msg;

	if ((msg = malloc(sizeof(*msg))) == NULL)
		osmtpd_err(1, NULL);

	if ((msg->origf = tmpfile()) == NULL) {
		auth_err(ctx, "Can't open tempfile");
		return NULL;
	}
	msg->ctx = ctx;
	msg->parsing_headers = 1;
	msg->body_whitelines = 0;
	msg->has_body = 0;
	msg->header = NULL;
	msg->nheaders = 0;
	msg->err = 0;
	msg->readdone = 0;
	msg->spf_from = NULL;

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
			for (j = 0; msg->header[i].sig->h != NULL &&
			    msg->header[i].sig->h[j] != NULL; j++)
				free(msg->header[i].sig->h[j]);
			free(msg->header[i].sig->h);
			EVP_PKEY_free(msg->header[i].sig->p);
		}
		free(msg->header[i].buf);
		free(msg->header[i].sig);
	}
	free(msg->header);

	if (msg->spf_from)
		spf_record_free(msg->spf_from);

	free(msg);
}

void
dkim_header_add(struct osmtpd_ctx *ctx, const char *line)
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
				dkim_signature_parse(
				    &msg->header[msg->nheaders - 1]);
			if (line[0] == '\0')
				return;
		} else {
			dkim_header_cat(ctx, line);
			return;
		}
	}
	if (msg->nheaders % 10 == 0) {
		if ((headers = recallocarray(msg->header, msg->nheaders,
		    msg->nheaders + 10, sizeof(*msg->header))) == NULL) {
			auth_err(ctx, "malloc");
			return;
		}
		msg->header = headers;
		for (i = 0; i < msg->nheaders; i++) {
			if (msg->header[i].sig == NULL)
				continue;
			msg->header[i].sig->header = &msg->header[i];
		}
	}
	msg->header[msg->nheaders].msg = msg;
	msg->nheaders++;
	dkim_header_cat(ctx, line);
}

void
dkim_header_cat(struct osmtpd_ctx *ctx, const char *line)
{
	struct message *msg = ctx->local_message;
	struct header *header = &msg->header[msg->nheaders - 1];
	char *buf;

	size_t needed = header->buflen + strlen(line) + 2;

	if (needed > (header->buflen / 1024) + 1) {
		buf = reallocarray(header->buf, (needed / 1024) + 1, 1024);
		if (buf == NULL) {
			auth_err(ctx, "malloc");
			return;
		}
		header->buf = buf;
	}
	header->buflen += snprintf(header->buf + header->buflen,
	    (((needed / 1024) + 1) * 1024) - header->buflen, "%s%s",
	    header->buflen == 0 ? "" : "\r\n", line);
}

void
dkim_signature_parse(struct header *header)
{
	struct dkim_signature *sig;
	struct asr_query *query;
	const char *buf, *i, *end;
	char tagname[3];
	char subdomain[HOST_NAME_MAX + 1];
	size_t ilen, dlen;

	/* Format checked by dkim_header_add */
	buf = osmtpd_ltok_skip_field_name(header->buf, 0);
	buf = osmtpd_ltok_skip_wsp(buf, 1) + 1;

	if ((header->sig = calloc(1, sizeof(*header->sig))) == NULL) {
		auth_err(header->msg->ctx, "malloc");
		return;
	}
	sig = header->sig;
	sig->header = header;
	sig->l = -1;
	sig->t = -1;
	sig->x = -1;

	end = osmtpd_ltok_skip_tag_list(buf, 0);
	if (end == NULL || end[0] != '\0') {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid tag-list");
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
		if (strcmp(tagname, "v") == 0)
			dkim_signature_parse_v(sig, buf, end);
		else if (strcmp(tagname, "a") == 0)
			dkim_signature_parse_a(sig, buf, end);
		else if (strcmp(tagname, "b") == 0)
			dkim_signature_parse_b(sig, buf, end);
		else if (strcmp(tagname, "bh") == 0)
			dkim_signature_parse_bh(sig, buf, end);
		else if (strcmp(tagname, "c") == 0)
			dkim_signature_parse_c(sig, buf, end);
		else if (strcmp(tagname, "d") == 0)
			dkim_signature_parse_d(sig, buf, end);
		else if (strcmp(tagname, "h") == 0)
			dkim_signature_parse_h(sig, buf, end);
		else if (strcmp(tagname, "i") == 0)
			dkim_signature_parse_i(sig, buf, end);
		else if (strcmp(tagname, "l") == 0)
			dkim_signature_parse_l(sig, buf, end);
		else if (strcmp(tagname, "q") == 0)
			dkim_signature_parse_q(sig, buf, end);
		else if (strcmp(tagname, "s") == 0)
			dkim_signature_parse_s(sig, buf, end);
		else if (strcmp(tagname, "t") == 0)
			dkim_signature_parse_t(sig, buf, end);
		else if (strcmp(tagname, "x") == 0)
			dkim_signature_parse_x(sig, buf, end);
		else if (strcmp(tagname, "z") == 0)
			dkim_signature_parse_z(sig, buf, end);

		buf = osmtpd_ltok_skip_fws(end, 1);
		if (buf[0] == ';')
			buf++;
		else if (buf[0] != '\0') {
			dkim_signature_state(sig, DKIM_PERMERROR,
			    "Invalid tag-list");
			return;
		}
	}
	if (sig->state != DKIM_UNKNOWN)
		return;

	if (sig->v != 1)
		dkim_signature_state(sig, DKIM_PERMERROR, "Missing v tag");
	else if (sig->ah == NULL)
		dkim_signature_state(sig, DKIM_PERMERROR, "Missing a tag");
	else if (sig->b == NULL)
		dkim_signature_state(sig, DKIM_PERMERROR, "Missing b tag");
	else if (sig->bhsz == 0)
		dkim_signature_state(sig, DKIM_PERMERROR, "Missing bh tag");
	else if (sig->d[0] == '\0')
		dkim_signature_state(sig, DKIM_PERMERROR, "Missing d tag");
	else if (sig->h == NULL)
		dkim_signature_state(sig, DKIM_PERMERROR, "Missing h tag");
	else if (sig->s[0] == '\0')
		dkim_signature_state(sig, DKIM_PERMERROR, "Missing s tag");
	if (sig->state != DKIM_UNKNOWN)
		return;

	if (sig->i != NULL) {
		i = osmtpd_ltok_skip_local_part(sig->i, 1) + 1;
		ilen = sig->isz - (size_t)(i - sig->i);
		dlen = strlen(sig->d);
		if (ilen < dlen) {
			dkim_signature_state(sig, DKIM_PERMERROR,
			    "i tag not subdomain of d");
			return;
		}
		i += ilen - dlen;
		if ((i[-1] != '.' && i[-1] != '@') ||
		    strncasecmp(i, sig->d, dlen) != 0) {
			dkim_signature_state(sig, DKIM_PERMERROR,
			    "i tag not subdomain of d");
			return;
		}
	}
	if (sig->t != -1 && sig->x != -1 && sig->t > sig->x) {
		dkim_signature_state(sig, DKIM_PERMERROR, "t tag after x tag");
		return;
	}

	if ((size_t)snprintf(subdomain, sizeof(subdomain), "%s._domainkey.%s",
	    sig->s, sig->d) >= sizeof(subdomain)) {
		dkim_signature_state(sig, DKIM_PERMERROR,
		    "dns/txt query too long");
		return;
	}

	if ((query = res_query_async(subdomain, C_IN, T_TXT, NULL)) == NULL) {
		auth_err(header->msg->ctx, "res_query_async");
		return;
	}
	if ((sig->query = event_asr_run(query, dkim_rr_resolve, sig)) == NULL) {
		auth_err(header->msg->ctx, "event_asr_run");
		asr_abort(query);
		return;
	}
}

void
dkim_signature_parse_v(struct dkim_signature *sig, const char *start, const char *end)
{
	if (sig->v != 0) {	/* Duplicate tag */
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate v tag");
		return;
	}
	/* Unsupported version */
	if (start[0] != '1' || start + 1 != end)
		dkim_signature_state(sig, DKIM_NEUTRAL, "Unsupported v tag");
	else
		sig->v = 1;
}

void
dkim_signature_parse_a(struct dkim_signature *sig, const char *start, const char *end)
{
	char ah[sizeof("sha256")];

	if (sig->ah != NULL) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate a tag");
		return;
	}

	if (osmtpd_ltok_skip_sig_a_tag_alg(start, 0) != end) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid a tag");
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
		dkim_signature_state(sig, DKIM_NEUTRAL, "Unsuppored a tag k");
		return;
	}
	if ((size_t)(end - start) >= sizeof(ah)) {
		dkim_signature_state(sig, DKIM_NEUTRAL, "Unsuppored a tag h");
		return;
	}
	strlcpy(ah, start, sizeof(ah));
	ah[end - start] = '\0';
	if ((sig->ah = EVP_get_digestbyname(ah)) == NULL) {
		dkim_signature_state(sig, DKIM_NEUTRAL, "Unsuppored a tag h");
		return;
	}
	if ((sig->bhctx = EVP_MD_CTX_new()) == NULL) {
		auth_err(sig->header->msg->ctx, "EVP_MD_CTX_new");
		return;
	}
	if (EVP_DigestInit_ex(sig->bhctx, sig->ah, NULL) <= 0) {
		auth_err(sig->header->msg->ctx, "EVP_DigestInit_ex");
		return;
	}
}

void
dkim_signature_parse_b(struct dkim_signature *sig, const char *start, const char *end)
{
	int decodesz;

	if (sig->b != NULL) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate b tag");
		return;
	}
	sig->bheader = start;
	if ((sig->b = malloc((((end - start) / 4) + 1) * 3)) == NULL) {
		auth_err(sig->header->msg->ctx, "malloc");
		return;
	}
	/* EVP_DecodeBlock doesn't handle internal whitespace */
	EVP_DecodeInit(ectx);
	if (EVP_DecodeUpdate(ectx, sig->b, &decodesz, start,
	    (int)(end - start)) == -1) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid b tag");
		return;
	}
	sig->bsz = decodesz;
	if (EVP_DecodeFinal(ectx, sig->b + sig->bsz,
	    &decodesz) == -1) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid b tag");
		return;
	}
	sig->bsz += decodesz;
}

void
dkim_signature_parse_bh(struct dkim_signature *sig, const char *start, const char *end)
{
	const char *b64;
	size_t n;
	int decodesz;

	if (sig->bhsz != 0) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate bh tag");
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
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid bh tag");
		return;
	}
	/* EVP_DecodeBlock doesn't handle internal whitespace */
	EVP_DecodeInit(ectx);
	if (EVP_DecodeUpdate(ectx, sig->bh, &decodesz, start,
	    (int)(end - start)) == -1) {
		/* Paranoia check */
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid bh tag");
		return;
	}
	sig->bhsz = decodesz;
	if (EVP_DecodeFinal(ectx, sig->bh + sig->bhsz, &decodesz) == -1) {
		/* Paranoia check */
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid bh tag");
		return;
	}
	sig->bhsz += decodesz;
}

void
dkim_signature_parse_c(struct dkim_signature *sig, const char *start, const char *end)
{
	if (sig->c != 0) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate c tag");
		return;
	}
	if (strncmp(start, "simple", 6) == 0) {
		sig->c = CANON_HEADER_SIMPLE;
		start += 6;
	} else if (strncmp(start, "relaxed", 7) == 0) {
		sig->c = CANON_HEADER_RELAXED;
		start += 7;
	} else {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid c tag");
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
			dkim_signature_state(sig, DKIM_PERMERROR,
			    "Invalid c tag");
			return;
		}
	}

	if (start != end) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid c tag");
		return;
	}
	sig->c |= CANON_DONE;
}

void
dkim_signature_parse_d(struct dkim_signature *sig, const char *start, const char *end)
{
	if (sig->d[0] != '\0') {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate d tag");
		return;
	}
	if (osmtpd_ltok_skip_sig_d_tag_value(start, 0) != end ||
	    (size_t)(end - start) >= sizeof(sig->d)) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid d tag");
		return;
	}
	strlcpy(sig->d, start, end - start + 1);
}

void
dkim_signature_parse_h(struct dkim_signature *sig, const char *start, const char *end)
{
	const char *h;
	size_t n = 0;

	if (sig->h != NULL) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate h tag");
		return;
	}
	if (osmtpd_ltok_skip_sig_h_tag_value(start, 0) < end) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid h tag");
		return;
	}
	h = start;
	while (1) {
		if ((h = osmtpd_ltok_skip_hdr_name(h, 0)) == NULL) {
			dkim_signature_state(sig, DKIM_PERMERROR,
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
	if ((sig->h = calloc(n + 1, sizeof(*sig->h))) == NULL) {
		auth_err(sig->header->msg->ctx, "malloc");
		return;
	}
	n = 0;
	h = start;
	while (1) {
		h = osmtpd_ltok_skip_hdr_name(start, 0);
		/* ';' is part of hdr-name */
		if (h > end) {
			sig->h[n] = strndup(start, end - start);
			break;
		}
		if ((sig->h[n++] = strndup(start, h - start)) == NULL) {
			auth_err(sig->header->msg->ctx, "malloc");
			return;
		}
		start = osmtpd_ltok_skip_fws(h, 1);
		if (start[0] != ':')
			break;
		start = osmtpd_ltok_skip_fws(start + 1, 1);
	}
}

void
dkim_signature_parse_i(struct dkim_signature *sig, const char *start, const char *end)
{
	if (sig->i != NULL) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate i tag");
		return;
	}
	if (osmtpd_ltok_skip_sig_i_tag_value(start, 0) != end) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid i tag");
		return;
	}
	sig->i = start;
	sig->isz = (size_t)(end - start);
}

void
dkim_signature_parse_l(struct dkim_signature *sig, const char *start, const char *end)
{
	long long l;
	char *lend;

	if (sig->l != -1) {	/* Duplicate tag */
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate l tag");
		return;
	}
	errno = 0;
	l = strtoll(start, &lend, 10);
	/* > 76 digits in stroll is an overflow */
	if (osmtpd_ltok_skip_digit(start, 0) == NULL ||
	    lend != end || errno != 0) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid l tag");
		return;
	}
	if (l > SSIZE_MAX) {
		dkim_signature_state(sig, DKIM_PERMERROR, "l tag too large");
		return;
	}
	sig->l = (ssize_t)l;
}

void
dkim_signature_parse_q(struct dkim_signature *sig, const char *start, const char *end)
{
	const char *qend;

	if (sig->q != 0) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate q tag");
		return;
	}

	while (1) {
		start = osmtpd_ltok_skip_fws(start, 1);
		qend = osmtpd_ltok_skip_sig_q_tag_method(start, 0);
		if (qend == NULL) {
			dkim_signature_state(sig, DKIM_PERMERROR, "Invalid q tag");
			return;
		}
		if (strncmp(start, "dns/txt", qend - start) == 0)
			sig->q = 1;
		start = osmtpd_ltok_skip_fws(qend, 1);
		if (start[0] != ':')
			break;
	}
	if (start != end) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid q tag");
		return;
	}
	if (sig->q != 1) {
		sig->q = 1;
		dkim_signature_state(sig, DKIM_NEUTRAL, "No useable q found");
		return;
	}
}

void
dkim_signature_parse_s(struct dkim_signature *sig, const char *start, const char *end)
{
	if (sig->s[0] != '\0') {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate s tag");
		return;
	}
	if (osmtpd_ltok_skip_selector(start, 0) != end) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid s tag");
		return;
	}
	strlcpy(sig->s, start, end - start + 1);
}

void
dkim_signature_parse_t(struct dkim_signature *sig, const char *start, const char *end)
{
	char *tend;

	if (sig->t != -1) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate t tag");
		return;
	}
	errno = 0;
	sig->t = strtoll(start, &tend, 10);
	if (osmtpd_ltok_skip_digit(start, 0) == NULL || tend != end ||
	    tend - start > 12 || errno != 0) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid t tag");
		return;
	}
}

void
dkim_signature_parse_x(struct dkim_signature *sig, const char *start, const char *end)
{
	char *xend;

	if (sig->x != -1) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate x tag");
		return;
	}
	errno = 0;
	sig->x = strtoll(start, &xend, 10);
	if (osmtpd_ltok_skip_digit(start, 0) == NULL || xend != end ||
	    xend - start > 12 || errno != 0) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid x tag");
		return;
	}
}

void
dkim_signature_parse_z(struct dkim_signature *sig, const char *start, const char *end)
{
	if (sig->z != 0) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate z tag");
		return;
	}

	sig->z = 1;
	if (osmtpd_ltok_skip_sig_z_tag_value(start, 0) != end) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid z tag");
		return;
	}
}

void
dkim_signature_verify(struct dkim_signature *sig)
{
	struct message *msg = sig->header->msg;
	static EVP_MD_CTX *bctx = NULL;
	char digest[EVP_MAX_MD_SIZE];
	unsigned int digestsz;
	const char *end;
	size_t i, header;

	if (sig->state != DKIM_UNKNOWN)
		return;

	if (bctx == NULL) {
		if ((bctx = EVP_MD_CTX_new()) == NULL) {
			auth_errx(msg->ctx, "EVP_MD_CTX_new");
			return;
		}
	}
	EVP_MD_CTX_reset(bctx);
	if (!sig->sephash) {
		if (EVP_DigestVerifyInit(bctx, NULL, sig->ah, NULL,
		    sig->p) != 1) {
			auth_errx(msg->ctx, "EVP_DigestVerifyInit");
			return;
		}
	} else {
		if (EVP_DigestInit_ex(bctx, sig->ah, NULL) != 1) {
			auth_errx(msg->ctx, "EVP_DigestInit_ex");
			return;
		}
	}

	for (i = 0; i < msg->nheaders; i++)
		msg->header[i].parsed = 0;

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
			dkim_signature_header(bctx, sig, &(msg->header[i]));
			msg->header[i].parsed = 1;
			break;
		}
	}
	dkim_signature_header(bctx, sig, sig->header);
	if (!sig->sephash) {
		if (EVP_DigestVerifyFinal(bctx, sig->b, sig->bsz) != 1)
			dkim_signature_state(sig, DKIM_FAIL, "b mismatch");
	} else {
		if (EVP_DigestFinal_ex(bctx, digest, &digestsz) == 0) {
			auth_errx(msg->ctx, "EVP_DigestFinal_ex");
			return;
		}
		if (EVP_DigestVerifyInit(bctx, NULL, NULL, NULL, sig->p) != 1) {
			auth_errx(msg->ctx, "EVP_DigestVerifyInit");
			return;
		}
		switch (EVP_DigestVerify(bctx, sig->b, sig->bsz, digest,
		    digestsz)) {
		case 1:
			break;
		case 0:
			dkim_signature_state(sig, DKIM_FAIL, "b mismatch");
			break;
		default:
			auth_errx(msg->ctx, "EVP_DigestVerify");
			return;
		}
	}
}

/* EVP_DigestVerifyUpdate is a macro, so we can't alias this on a variable */
#define dkim_b_digest_update(a, b, c)					\
	(sig->sephash ? EVP_DigestUpdate((a), (b), (c)) :\
	    EVP_DigestVerifyUpdate((a), (b), (c)))

void
dkim_signature_header(EVP_MD_CTX *bctx, struct dkim_signature *sig,
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
			if (dkim_b_digest_update(bctx, &c, 1) == 0) {
				auth_errx(sig->header->msg->ctx,
				    "dkim_b_digest_update");
				return;
			}
			continue;
		}
		end = osmtpd_ltok_skip_fws(ptr, 1);
		if (end == ptr) {
			if (sig->header == header && ptr == sig->bheader) {
				ptr = osmtpd_ltok_skip_tag_value(
				    ptr, 0) - 1;
				continue;
			}
			if (dkim_b_digest_update(bctx, ptr, 1) == 0) {
				auth_errx(sig->header->msg->ctx,
				    "dkim_b_digest_update");
				return;
			}
		} else {
			if (canon == CANON_HEADER_RELAXED) {
				if (end[0] == '\0')
					continue;
				if (dkim_b_digest_update(bctx, " ", 1) == 0) {
					auth_errx(sig->header->msg->ctx,
					    "dkim_b_digest_update");
					return;
				}
			} else {
				if (dkim_b_digest_update(bctx, ptr,
				    end - ptr) == 0) {
					auth_errx(sig->header->msg->ctx,
					    "dkim_b_digest_update");
					return;
				}
			}
			ptr = end - 1;
		}
			
	}
	if (sig->header != header) {
		if (dkim_b_digest_update(bctx, "\r\n", 2) == 0) {
			auth_errx(sig->header->msg->ctx, "dkim_b_digest_update");
			return;
		}
	}
}

void
dkim_signature_state(struct dkim_signature *sig, enum dkim_state state,
    const char *reason)
{
	if (sig->query != NULL) {
		event_asr_abort(sig->query);
		sig->query = NULL;
	}
	switch (sig->state) {
	case DKIM_UNKNOWN:
		break;
	case DKIM_PASS:
	case DKIM_FAIL:
		osmtpd_errx(1, "Unexpected transition");
	case DKIM_POLICY:
		if (state == DKIM_PASS)
			return;
		break;
	case DKIM_NEUTRAL:
		if (state == DKIM_PASS)
			return;
		if (state == DKIM_TEMPERROR || state == DKIM_PERMERROR)
			break;
		osmtpd_errx(1, "Unexpected transition");
	case DKIM_TEMPERROR:
		if (state == DKIM_PERMERROR)
			break;
		return;
	case DKIM_PERMERROR:
		return;
	}
	sig->state = state;
	sig->state_reason = reason;
}

const char *
dkim_state2str(enum dkim_state state)
{
	switch (state)
	{
	case DKIM_UNKNOWN:
		return "unknown";
	case DKIM_PASS:
		return "pass";
	case DKIM_FAIL:
		return "fail";
	case DKIM_POLICY:
		return "policy";
	case DKIM_NEUTRAL:
		return "neutral";
	case DKIM_TEMPERROR:
		return "temperror";
	case DKIM_PERMERROR:
		return "permerror";
	}
}

void
dkim_rr_resolve(struct asr_result *ar, void *arg)
{
	struct dkim_signature *sig = arg;
	char key[UINT16_MAX + 1];
	const char *rr_txt;
	size_t keylen, cstrlen;
	struct unpack pack;
	struct dns_header h;
	struct dns_query q;
	struct dns_rr rr;

	sig->query = NULL;

	if (ar->ar_h_errno == TRY_AGAIN || ar->ar_h_errno == NO_RECOVERY) {
		dkim_signature_state(sig, DKIM_TEMPERROR,
		    hstrerror(ar->ar_h_errno));
		goto verify;
	}
	if (ar->ar_h_errno != NETDB_SUCCESS) {
		dkim_signature_state(sig, DKIM_PERMERROR,
		    hstrerror(ar->ar_h_errno));
		goto verify;
	}

	unpack_init(&pack, ar->ar_data, ar->ar_datalen);
	if (unpack_header(&pack, &h) != 0 ||
	    unpack_query(&pack, &q) != 0) {
		auth_warn(sig->header->msg->ctx,
				  "Mallformed DKIM DNS response for domain %s: %s",
				  q.q_dname, pack.err);
		dkim_signature_state(sig, DKIM_PERMERROR, pack.err);
		goto verify;
	}

	for (; h.ancount > 0; h.ancount--) {
		if (unpack_rr(&pack, &rr) != 0) {
			auth_warn(sig->header->msg->ctx,
					  "Mallformed DKIM DNS record for domain %s: %s",
					  q.q_dname, pack.err);
			continue;
		}

		if (rr.rr_type != T_TXT) {
			auth_warn(sig->header->msg->ctx,
					  "Unexpected DKIM DNS record: %d for domain %s",
					  rr.rr_type, q.q_dname);
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

		if (dkim_key_text_parse(sig, key))
			break;
	}

	if (h.ancount == 0) {
		dkim_signature_state(sig, DKIM_PERMERROR,
		    "No matching key found");
	} else {
		/* Only verify if all headers have been read */
		if (!sig->header->msg->parsing_headers)
			dkim_signature_verify(sig);
	}
 verify:
	free(ar->ar_data);
	auth_message_verify(sig->header->msg);
}

int
dkim_key_text_parse(struct dkim_signature *sig, const char *key)
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
				if (hashname == NULL) {
					auth_err(sig->header->msg->ctx, "malloc");
					return 0;
				}
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
		dkim_signature_state(sig, DKIM_PERMERROR, "Key is revoked");
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
		if ((bio = BIO_new_mem_buf(pkimp, pkoff)) == NULL) {
			auth_err(sig->header->msg->ctx, "BIO_new_mem_buf");
			return 1;
		}
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
dkim_body_parse(struct message *msg, const char *line)
{
	struct dkim_signature *sig;
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
			    sig->state != DKIM_UNKNOWN)
				continue;
			hashn = sig->l == -1 ? 2 : MIN(2, sig->l);
			sig->l -= sig->l == -1 ? 0 : hashn;
			if (EVP_DigestUpdate(sig->bhctx, "\r\n", hashn) == 0) {
				auth_errx(msg->ctx, "EVP_DigestUpdate");
				return;
			}
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
			if (sig == NULL || sig->state != DKIM_UNKNOWN)
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
			if (ret == 0) {
				auth_errx(msg->ctx, "EVP_DigestUpdate");
				return;
			}
		}
		line = end;
	}
	for (i = 0; i < msg->nheaders; i++) {
		sig = msg->header[i].sig;
		if (sig == NULL || sig->state != DKIM_UNKNOWN)
			continue;
		hashn = sig->l == -1 ? 2 : MIN(2, sig->l);
		sig->l -= sig->l == -1 ? 0 : hashn;
		ret = EVP_DigestUpdate(sig->bhctx, "\r\n", hashn);
		if (ret == 0) {
			auth_errx(msg->ctx, "EVP_DigestUpdate");
			return;
		}
	}
}

void
dkim_body_verify(struct dkim_signature *sig)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digestsz;

	if (sig->state != DKIM_UNKNOWN)
		return;

	if ((sig->c & CANON_BODY) == CANON_BODY_SIMPLE &&
	    !sig->header->msg->has_body) {
		if (EVP_DigestUpdate(sig->bhctx, "\r\n",
		    sig->l == -1 ? 2 : MIN(2, sig->l)) <= 0) {
			auth_errx(sig->header->msg->ctx,
			    "Can't update hash context");
			return;
		}
	}
	if (sig->l > 0) {
		dkim_signature_state(sig, DKIM_PERMERROR,
		    "l tag larger than body");
		return;
	}

	if (EVP_DigestFinal_ex(sig->bhctx, digest, &digestsz) == 0) {
		auth_errx(sig->header->msg->ctx, "EVP_DigestFinal_ex");
		return;
	}

	if (digestsz != sig->bhsz || memcmp(digest, sig->bh, digestsz) != 0)
		dkim_signature_state(sig, DKIM_FAIL, "bh mismatch");
}

const char *
iprev_state2str(enum iprev_state state)
{
	switch (state)
	{
	case IPREV_NONE:
		return "none";
	case IPREV_PASS:
		return "pass";
	case IPREV_FAIL:
		return "fail";
	}
}

void
spf_lookup_record(struct spf_record *spf, const char *domain, int type,
	enum spf_state qualifier, int include, int exists)
{
	struct asr_query *aq;
	struct spf_query *query;

	if (spf->nqueries >= SPF_DNS_LOOKUP_LIMIT) {
		spf_done(spf, SPF_PERMERROR, "To many DNS queries");
		return;
	}

	if (domain == NULL) {
		domain = "";
	}

	query = &spf->queries[spf->nqueries];
	query->spf = spf;
	query->q = qualifier;
	query->include = include;
	query->exists = exists;
	query->txt = NULL;
	query->eva = NULL;

	if ((query->domain = strdup(domain)) == NULL) {
		spf_done(spf, SPF_NEUTRAL, NULL);
		auth_err(spf->ctx, "malloc");
		return;
	}

	if ((aq = res_query_async(query->domain, C_IN, type, NULL)) == NULL) {
		auth_err(spf->ctx, "res_query_async");
		return;
	}

	if ((query->eva = event_asr_run(aq, spf_resolve, query)) == NULL) {
		auth_err(spf->ctx, "event_asr_run");
		asr_abort(aq);
		return;
	}

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

	query->eva = NULL;
	query->spf->running--;

	if (ar->ar_h_errno == NETDB_INTERNAL) {
		auth_err(query->spf->ctx, "res_query_async");
		return;
	}

	if (ar->ar_h_errno == TRY_AGAIN
		|| ar->ar_h_errno == NO_RECOVERY) {
		spf_done(query->spf, SPF_TEMPERROR, hstrerror(ar->ar_h_errno));
		goto end;
	}

	if (ar->ar_h_errno == HOST_NOT_FOUND
		|| ar->ar_h_errno == NO_DATA
		|| ar->ar_h_errno == NO_ADDRESS) {
		if (query->include && !query->exists)
			spf_done(query->spf,
				SPF_PERMERROR, hstrerror(ar->ar_h_errno));
		goto consume;
	}

	unpack_init(&pack, ar->ar_data, ar->ar_datalen);
	if (unpack_header(&pack, &h) != 0 ||
	    unpack_query(&pack, &q) != 0) {
		auth_warn(query->spf->ctx,
				  "Mallformed SPF DNS response for domain %s: %s",
				  q.q_dname, pack.err);
		spf_done(query->spf, SPF_TEMPERROR, pack.err);
		goto end;
	}

	for (; h.ancount; h.ancount--) {
		if (unpack_rr(&pack, &rr) != 0) {
			auth_warn(query->spf->ctx,
					  "Mallformed SPF DNS record for domain %s: %s",
					  q.q_dname, pack.err);
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

		default:
			auth_warn(spf->ctx,
					  "Unexpected SPF DNS record: %d for domain %s",
					  rr.rr_type, q.q_dname);
			spf_done(query->spf, SPF_TEMPERROR, "Unexpected record");
			break;
		}

		if (spf->done)
			goto end;
	}

consume:
	if (spf->running > 0)
		return;

	for (i = spf->nqueries - 1; i >= 0; i--) {
		if (spf->queries[i].txt != NULL) {
			if (spf_execute_txt(&spf->queries[i]) != 0)
				break;
		}
	}

end:
	if (spf->running == 0)
		spf->cb(spf->ctx);
}

void
spf_resolve_txt(struct dns_rr *rr, struct spf_query *query)
{
	char *txt;
	txt = spf_parse_txt(rr->rr.other.rdata, rr->rr.other.rdlen);
	if (txt == NULL) {
		auth_err(query->spf->ctx, "spf_parse_txt");
		return;
	}

	if (strncasecmp("v=spf1 ", txt, 7)) {
		free(txt);
		return;
	}

	if (query->txt != NULL) {
		free(txt);
		spf_done(query->spf, SPF_PERMERROR, "Duplicated SPF record");
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

	print_dname(rr->rr.mx.exchange, buf, sizeof(buf));
	buf[strlen(buf) - 1] = '\0';
	if (buf[strlen(buf) - 1] == '.')
		buf[strlen(buf) - 1] = '\0';

	spf_lookup_record(query->spf, buf, T_A,
		query->q, query->include, 0);
	spf_lookup_record(query->spf, buf, T_AAAA,
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
		return NULL;

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

	enum spf_state q = query->q;

	while ((ap = strsep(&in, " ")) != NULL) {
		if (strcasecmp(ap, "v=spf1") == 0)
			continue;

		end = ap + strlen(ap)-1;
		if (*end == '.')
			*end = '\0';

		if (*ap == '+') {
			q = SPF_PASS;
			ap++;
		} else if (*ap == '-') {
			q = SPF_FAIL;
			ap++;
		} else if (*ap == '~') {
			q = SPF_SOFTFAIL;
			ap++;
		} else if (*ap == '?') {
			q = SPF_NEUTRAL;
			ap++;
		}

		if (q != SPF_PASS && query->include)
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
spf_done(struct spf_record *spf, enum spf_state state, const char *reason)
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
}

const char *
spf_state2str(enum spf_state state)
{
	switch (state)
	{
	case SPF_NONE:
		return "none";
	case SPF_NEUTRAL:
		return "neutral";
	case SPF_PASS:
		return "pass";
	case SPF_FAIL:
		return "fail";
	case SPF_SOFTFAIL:
		return "softfail";
	case SPF_TEMPERROR:
		return "temperror";
	case SPF_PERMERROR:
		return "permerror";
	}
}

int
spf_ar_cat(const char *type, struct spf_record *spf, char **line, size_t *linelen, ssize_t *aroff)
{
	if (spf == NULL)
		return 0;

	if ((*aroff =
			auth_ar_cat(line, linelen, *aroff,
				"; spf=%s", spf_state2str(spf->state))
			) == -1) {
		return -1;
	}
	if (spf->state_reason != NULL)
	{
		if ((*aroff =
				auth_ar_cat(line, linelen, *aroff,
					" reason=\"%s\"", spf->state_reason)
				) == -1) {
			return -1;
		}
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

	return 0;
}

void
auth_message_verify(struct message *msg)
{
	size_t i;
	const char *from = NULL;

	if (!msg->readdone)
		return;

	for (i = 0; i < msg->nheaders; i++) {
		if (strncasecmp(msg->header[i].buf, "From:",
				sizeof("From:") - 1) == 0)
			from = msg->header[i].buf + sizeof("From:") - 1;
		if (msg->header[i].sig == NULL)
			continue;
		if (msg->header[i].sig->query != NULL)
			return;
		if (msg->header[i].sig->state != DKIM_UNKNOWN)
			continue;
		dkim_signature_state(msg->header[i].sig, DKIM_PASS, NULL);
	}

	if (from == NULL) {
		auth_ar_create(msg->ctx);
		return;
	}

	if (msg->spf_from)
		spf_record_free(msg->spf_from);

	if ((msg->spf_from = spf_record_new(msg->ctx, from, auth_ar_create))
			== NULL) {
		auth_warn(msg->ctx, "spf_record_new: %s", from);
		auth_ar_create(msg->ctx);
	}
}

void
auth_ar_create(struct osmtpd_ctx *ctx)
{
	struct dkim_signature *sig;
	size_t i;
	ssize_t n, aroff = 0;
	int found = 0;
	char *line = NULL;
	size_t linelen = 0;
	struct session *ses = ctx->local_session;
	struct message *msg = ctx->local_message;

	if ((aroff = auth_ar_cat(&line, &linelen, aroff,
	    "Authentication-Results: %s", authservid)) == -1) {
		auth_err(msg->ctx, "malloc");
		goto fail;
	}
	for (i = 0; i < msg->nheaders; i++) {
		sig = msg->header[i].sig;
		if (sig == NULL)
			continue;
		found = 1;
		if ((aroff = auth_ar_cat(&line, &linelen, aroff, "; dkim=%s",
		    dkim_state2str(sig->state))) == -1) {
			auth_err(msg->ctx, "malloc");
			goto fail;
		}
		if (sig->state_reason != NULL) {
			if ((aroff = auth_ar_cat(&line, &linelen, aroff,
			    " reason=\"%s\"", sig->state_reason)) == -1) {
				auth_err(msg->ctx, "malloc");
				goto fail;
			}
		}
		if (sig->s[0] != '\0') {
			if ((aroff = auth_ar_cat(&line, &linelen, aroff,
			    " header.s=%s", sig->s)) == -1) {
				auth_err(msg->ctx, "malloc");
				goto fail;
			}
		}
		if (sig->d[0] != '\0') {
			if ((aroff = auth_ar_cat(&line, &linelen, aroff,
			    " header.d=%s", sig->d)) == -1) {
				auth_err(msg->ctx, "malloc");
				goto fail;
			}
		}
		/*
		 * Don't print i-tag, since localpart can be a quoted-string,
		 * which can contain FWS and CFWS.
		 */
		if (sig->a != NULL) {
			if ((aroff = auth_ar_cat(&line, &linelen, aroff,
			    " header.a=%.*s", (int)sig->asz, sig->a)) == -1) {
				auth_err(msg->ctx, "malloc");
				goto fail;
			}
		}
	}
	if (!found) {
		aroff = auth_ar_cat(&line, &linelen, aroff, "; dkim=none");
		if (aroff == -1) {
			auth_err(msg->ctx, "malloc");
			goto fail;
		}
	}

	if ((aroff = auth_ar_cat(&line, &linelen, aroff,
	    "; iprev=%s", iprev_state2str(ses->iprev))) == -1) {
		auth_err(msg->ctx, "malloc");
		goto fail;
	}

	if (spf_ar_cat("smtp.helo", ses->spf_helo,
			&line, &linelen, &aroff) != 0) {
		auth_err(msg->ctx, "malloc");
		goto fail;
	}

	if (spf_ar_cat("smtp.mailfrom", ses->spf_mailfrom,
			&line, &linelen, &aroff) != 0) {
		auth_err(msg->ctx, "malloc");
		goto fail;
	}

	if (spf_ar_cat("header.from", msg->spf_from,
			&line, &linelen, &aroff) != 0) {
		auth_err(msg->ctx, "malloc");
		goto fail;
	}

	if (aroff == -1) {
		auth_err(msg->ctx, "malloc");
		goto fail;
	}

	if (auth_ar_print(msg->ctx, line) != 0)
		auth_warn(msg->ctx, "Invalid AR line: %s", line);

	rewind(msg->origf);
	while ((n = getline(&line, &linelen, msg->origf)) != -1) {
		line[n - 1] = '\0';
		osmtpd_filter_dataline(msg->ctx, "%s", line);
	}
	if (ferror(msg->origf))
		auth_err(msg->ctx, "getline");
 fail:
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
			/* authserv-id */
			if (arid) {
				ncheckpoint = osmtpd_ltok_skip_value(
				    ncheckpoint, 0);
				arid = 0;
			/* methodspec */
			} else if (strncmp(ncheckpoint, "dkim",
			    sizeof("dkim") - 1) == 0) {
				ncheckpoint = osmtpd_ltok_skip_keyword(
				    ncheckpoint + sizeof("dkim"), 0);
			} else if (strncmp(ncheckpoint, "iprev",
			    sizeof("iprev") - 1) == 0) {
				ncheckpoint = osmtpd_ltok_skip_keyword(
				    ncheckpoint + sizeof("iprev"), 0);
			} else if (strncmp(ncheckpoint, "spf",
			    sizeof("spf") - 1) == 0) {
				ncheckpoint = osmtpd_ltok_skip_keyword(
				    ncheckpoint + sizeof("spf"), 0);
			/* reasonspec */
			} else if (strncmp(ncheckpoint, "reason",
			    sizeof("reason") - 1) == 0) {
				ncheckpoint = osmtpd_ltok_skip_value(
				    ncheckpoint + sizeof("reason"), 0);
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
	if (size + aroff <= *n)
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

void
auth_err(struct osmtpd_ctx *ctx, char *text)
{
	struct message *msg = ctx->local_message;

	fprintf(stderr, "%016"PRIx64" %s: %s\n",
			ctx->reqid, text, strerror(errno));

	if (msg != NULL)
		msg->err = 1;
	else
		osmtpd_filter_disconnect(ctx, "Internal server error");
}

void
auth_errx(struct osmtpd_ctx *ctx, char *text)
{
	struct message *msg = ctx->local_message;

	fprintf(stderr, "%016"PRIx64" %s\n",
			ctx->reqid, text);

	if (msg != NULL)
		msg->err = 1;
	else
		osmtpd_filter_disconnect(ctx, "Internal server error");
}

void
auth_warn(struct osmtpd_ctx *ctx, const char* format, ...)
{
    va_list args;

	fprintf(stderr, "%016"PRIx64" ", ctx->reqid);

	va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fprintf(stderr, "\n");
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: filter-auth\n");
	exit(1);
}
