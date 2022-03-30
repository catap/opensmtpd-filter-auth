/*
 * Copyright (c) 2022 Martijn van Duren <martijn@openbsd.org>
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <asr.h>

#include "opensmtpd.h"
#include "unpack_dns.h"
#include "ltok.h"

/*
 * Use RFC8601 (Authentication-Results) codes instead of RFC6376 codes,
 * since they're more expressive.
 */
enum state {
	DKIM_UNKNOWN,
	DKIM_PASS,
	DKIM_FAIL,
	DKIM_POLICY,
	DKIM_NEUTRAL,
	DKIM_TEMPERROR,
	DKIM_PERMERROR
};

struct signature {
	struct header *header;
	enum state state;
	const char *state_reason;
	int v;
	const char *a;
	size_t asz;
	int ak;
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

struct header {
	struct message *msg;
	uint8_t readdone;
	uint8_t parsed;
	char *buf;
	size_t buflen;
	struct signature *sig;
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
};

void usage(void);
void dkim_err(struct message *, char *);
void dkim_errx(struct message *, char *);
void dkim_conf(const char *, const char *);
void dkim_dataline(struct osmtpd_ctx *, const char *);
void dkim_commit(struct osmtpd_ctx *);
void *dkim_message_new(struct osmtpd_ctx *);
void dkim_message_free(struct osmtpd_ctx *, void *);
void dkim_header_add(struct osmtpd_ctx *, const char *);
void dkim_signature_parse(struct header *);
void dkim_signature_parse_v(struct signature *, const char *, const char *);
void dkim_signature_parse_a(struct signature *, const char *, const char *);
void dkim_signature_parse_b(struct signature *, const char *, const char *);
void dkim_signature_parse_bh(struct signature *, const char *, const char *);
void dkim_signature_parse_c(struct signature *, const char *, const char *);
void dkim_signature_parse_d(struct signature *, const char *, const char *);
void dkim_signature_parse_h(struct signature *, const char *, const char *);
void dkim_signature_parse_i(struct signature *, const char *, const char *);
void dkim_signature_parse_l(struct signature *, const char *, const char *);
void dkim_signature_parse_q(struct signature *, const char *, const char *);
void dkim_signature_parse_s(struct signature *, const char *, const char *);
void dkim_signature_parse_t(struct signature *, const char *, const char *);
void dkim_signature_parse_x(struct signature *, const char *, const char *);
void dkim_signature_parse_z(struct signature *, const char *, const char *);
void dkim_signature_verify(struct signature *);
void dkim_signature_header(EVP_MD_CTX *, struct signature *, struct header *);
void dkim_signature_state(struct signature *, enum state, const char *);
const char *dkim_state2str(enum state);
void dkim_header_cat(struct osmtpd_ctx *, const char *);
void dkim_body_parse(struct message *, const char *);
void dkim_body_verify(struct signature *);
void dkim_rr_resolve(struct asr_result *, void *);
void dkim_message_verify(struct message *);
ssize_t dkim_ar_cat(char **ar, size_t *n, size_t aroff, const char *fmt, ...)
    __attribute__((__format__ (printf, 4, 5)));
void dkim_ar_print(struct osmtpd_ctx *, const char *);
int dkim_key_text_parse(struct signature *, const char *);

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

	osmtpd_register_conf(dkim_conf);
	osmtpd_register_filter_dataline(dkim_dataline);
	osmtpd_register_filter_commit(dkim_commit);
	osmtpd_local_message(dkim_message_new, dkim_message_free);
	osmtpd_run();

	return 0;
}

void
dkim_conf(const char *key, const char *value)
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
dkim_dataline(struct osmtpd_ctx *ctx, const char *line)
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
		dkim_err(msg, "Couldn't write to tempfile");
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
			dkim_message_verify(msg);
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
dkim_commit(struct osmtpd_ctx *ctx)
{
	struct message *msg = ctx->local_message;

	if (msg->err)
		osmtpd_filter_disconnect(ctx, "Internal server error");
	else
		osmtpd_filter_proceed(ctx);
}

void *
dkim_message_new(struct osmtpd_ctx *ctx)
{
	struct message *msg;

	if ((msg = malloc(sizeof(*msg))) == NULL)
		osmtpd_err(1, NULL);

	if ((msg->origf = tmpfile()) == NULL) {
		dkim_err(msg, "Can't open tempfile");
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

	return msg;
}

void
dkim_message_free(struct osmtpd_ctx *ctx, void *data)
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
			dkim_err(msg, "malloc");
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
			dkim_err(msg, "malloc");
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
	struct signature *sig;
	struct asr_query *query;
	const char *buf, *i, *end;
	char tagname[3];
	char subdomain[HOST_NAME_MAX + 1];
	size_t ilen, dlen;

	/* Format checked by dkim_header_add */
	buf = osmtpd_ltok_skip_field_name(header->buf, 0);
	buf = osmtpd_ltok_skip_wsp(buf, 1) + 1;

	if ((header->sig = calloc(1, sizeof(*header->sig))) == NULL) {
		dkim_err(header->msg, "malloc");
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
		    strncmp(i, sig->d, dlen) != 0) {
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
		dkim_err(header->msg, "res_query_async");
		return;
	}
	if ((sig->query = event_asr_run(query, dkim_rr_resolve, sig)) == NULL) {
		dkim_err(header->msg, "event_asr_run");
		asr_abort(query);
		return;
	}
}

void
dkim_signature_parse_v(struct signature *sig, const char *start, const char *end)
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
dkim_signature_parse_a(struct signature *sig, const char *start, const char *end)
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
		dkim_err(sig->header->msg, "EVP_MD_CTX_new");
		return;
	}
	if (EVP_DigestInit_ex(sig->bhctx, sig->ah, NULL) <= 0) {
		dkim_err(sig->header->msg, "EVP_DigestInit_ex");
		return;
	}
}

void
dkim_signature_parse_b(struct signature *sig, const char *start, const char *end)
{
	int decodesz;

	if (sig->b != NULL) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate b tag");
		return;
	}
	sig->bheader = start;
	if ((sig->b = malloc((((end - start) / 4) + 1) * 3)) == NULL) {
		dkim_err(sig->header->msg, "malloc");
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
dkim_signature_parse_bh(struct signature *sig, const char *start, const char *end)
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
dkim_signature_parse_c(struct signature *sig, const char *start, const char *end)
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
dkim_signature_parse_d(struct signature *sig, const char *start, const char *end)
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
dkim_signature_parse_h(struct signature *sig, const char *start, const char *end)
{
	const char *h;
	size_t n = 0;

	if (sig->h != NULL) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Duplicate h tag");
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
	if (h != end) {
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid h tag");
		return;
	}
	if ((sig->h = calloc(n + 1, sizeof(*sig->h))) == NULL) {
		dkim_err(sig->header->msg, "malloc");
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
			dkim_err(sig->header->msg, "malloc");
			return;
		}
		start = osmtpd_ltok_skip_fws(h, 1);
		if (start[0] != ':')
			break;
		start = osmtpd_ltok_skip_fws(start + 1, 1);
	}
}

void
dkim_signature_parse_i(struct signature *sig, const char *start, const char *end)
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
dkim_signature_parse_l(struct signature *sig, const char *start, const char *end)
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
dkim_signature_parse_q(struct signature *sig, const char *start, const char *end)
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
dkim_signature_parse_s(struct signature *sig, const char *start, const char *end)
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
dkim_signature_parse_t(struct signature *sig, const char *start, const char *end)
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
dkim_signature_parse_x(struct signature *sig, const char *start, const char *end)
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
dkim_signature_parse_z(struct signature *sig, const char *start, const char *end)
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
dkim_signature_verify(struct signature *sig)
{
	struct message *msg = sig->header->msg;
	static EVP_MD_CTX *bctx = NULL;
	const char *end;
	size_t i, header;

	if (sig->state != DKIM_UNKNOWN)
		return;

	if (bctx == NULL) {
		if ((bctx = EVP_MD_CTX_new()) == NULL) {
			dkim_errx(msg, "EVP_MD_CTX_new");
			return;
		}
	}
	EVP_MD_CTX_reset(bctx);
	if (EVP_DigestVerifyInit(bctx, NULL, sig->ah, NULL, sig->p) != 1) {
		dkim_errx(msg, "EVP_DigestVerifyInit");
		return;
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
		}
	}
	dkim_signature_header(bctx, sig, sig->header);
	if (EVP_DigestVerifyFinal(bctx, sig->b, sig->bsz) != 1)
		dkim_signature_state(sig, DKIM_FAIL, "b mismatch");
}

void
dkim_signature_header(EVP_MD_CTX *bctx, struct signature *sig,
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
			if (EVP_DigestVerifyUpdate(bctx, &c, 1) == 0) {
				dkim_errx(sig->header->msg,
				    "EVP_DigestVerifyUpdate");
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
			if (EVP_DigestVerifyUpdate(bctx, ptr, 1) == 0) {
				dkim_errx(sig->header->msg,
				    "EVP_DigestVerifyUpdate");
				return;
			}
		} else {
			if (canon == CANON_HEADER_RELAXED) {
				if (end[0] == '\0')
					continue;
				if (EVP_DigestVerifyUpdate(bctx, " ", 1) == 0) {
					dkim_errx(sig->header->msg,
					    "EVP_DigestVerifyUpdate");
					return;
				}
			} else {
				if (EVP_DigestVerifyUpdate(bctx, ptr,
				    end - ptr) == 0) {
					dkim_errx(sig->header->msg,
					    "EVP_DigestVerifyUpdate");
					return;
				}
			}
			ptr = end - 1;
		}
			
	}
	if (sig->header != header) {
		if (EVP_DigestVerifyUpdate(bctx, "\r\n", 2) == 0) {
			dkim_errx(sig->header->msg, "EVP_DigestVerifyUpdate");
			return;
		}
	}
}

void
dkim_signature_state(struct signature *sig, enum state state,
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
dkim_state2str(enum state state)
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
	struct signature *sig = arg;
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
		dkim_signature_state(sig, DKIM_PERMERROR, "Invalid dns/txt");
		goto verify;
	}
	for (; h.ancount > 0; h.ancount--) {
		unpack_rr(&pack, &rr);
		if (rr.rr_type != T_TXT)
			continue;

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
	dkim_message_verify(sig->header->msg);
}

int
dkim_key_text_parse(struct signature *sig, const char *key)
{
	char tagname, *hashname;
	const char *end, *tagvend;
	char pkraw[UINT16_MAX] = "", pkimp[UINT16_MAX];
	size_t pkoff, linelen;
	int h = 0, k = 0, n = 0, p = 0, s = 0, t = 0, first = 1;
	BIO *bio;

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
					dkim_err(sig->header->msg, "malloc");
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
			if (strncmp(key, "rsa", end - key) != 0)
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
			tagvend = osmtpd_ltok_skip_base64string(key, 1);
			/* Invalid tag value */
			if (tagvend != end ||
			    (size_t)(end - key) >= sizeof(pkraw))
				return 0;
			strlcpy(pkraw, key, tagvend - key + 1);
			key = end;
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

	if (p == 0)		/* Missing tag */
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
			pkimp[pkoff++] = key[0];
			if (++linelen == 64) {
				pkimp[pkoff++] = '\n';
				linelen = 0;
			}
			key = osmtpd_ltok_skip_fws(key + 1, 1);
		}
		/* Leverage pkoff check in loop */
		if (linelen != 0)
			pkimp[pkoff++] = '\n';
		/* PEM_read_bio_PUBKEY will catch truncated keys */
		pkoff += strlcpy(pkimp + pkoff, "-----END PUBLIC KEY-----\n",
		    sizeof(pkimp) - pkoff);
		if ((bio = BIO_new_mem_buf(pkimp, pkoff)) == NULL) {
			dkim_err(sig->header->msg, "BIO_new_mem_buf");
			return 1;
		}
		sig->p = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
		BIO_free(bio);
		if (sig->p == NULL) {
			/*
			 * XXX No clue how to differentiate between invalid key
			 * and temporary failure like *alloc.
			 * Assume invalid key, because it's more likely.
			 */
			return 0;
		}
		break;
	}
	return 1;
}

void
dkim_body_parse(struct message *msg, const char *line)
{
	struct signature *sig;
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
				dkim_errx(msg, "EVP_DigestUpdate");
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
				dkim_errx(msg, "EVP_DigestUpdate");
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
			dkim_errx(msg, "EVP_DigestUpdate");
			return;
		}
	}
}

void
dkim_body_verify(struct signature *sig)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digestsz;

	if (sig->state != DKIM_UNKNOWN)
		return;

	if ((sig->c & CANON_BODY) == CANON_BODY_SIMPLE &&
	    !sig->header->msg->has_body) {
		if (EVP_DigestUpdate(sig->bhctx, "\r\n",
		    sig->l == -1 ? 2 : MIN(2, sig->l)) <= 0) {
			dkim_errx(sig->header->msg,
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
		dkim_errx(sig->header->msg, "Can't finalize hash context");
		return;
	}

	if (digestsz != sig->bhsz || memcmp(digest, sig->bh, digestsz) != 0)
		dkim_signature_state(sig, DKIM_FAIL, "bh mismatch");
}

void
dkim_message_verify(struct message *msg)
{
	struct signature *sig;
	size_t i;
	ssize_t n, aroff = 0;
	int found = 0;
	char *line = NULL;
	size_t linelen = 0;

	if (!msg->readdone)
		return;

	for (i = 0; i < msg->nheaders; i++) {
		if (msg->header[i].sig == NULL)
			continue;
		if (msg->header[i].sig->query != NULL)
			return;
		if (msg->header[i].sig->state != DKIM_UNKNOWN)
			continue;
		dkim_signature_state(msg->header[i].sig, DKIM_PASS, NULL);
	}
	
	if ((aroff = dkim_ar_cat(&line, &linelen, aroff,
	    "Authentication-Results: %s", authservid)) == -1) {
		dkim_err(msg, "malloc");
		goto fail;
	}
	for (i = 0; i < msg->nheaders; i++) {
		sig = msg->header[i].sig;
		if (sig == NULL)
			continue;
		found = 1;
		if ((aroff = dkim_ar_cat(&line, &linelen, aroff, "; dkim=%s",
		    dkim_state2str(sig->state))) == -1) {
			dkim_err(msg, "malloc");
			goto fail;
		}
		if (sig->state_reason != NULL) {
			if ((aroff = dkim_ar_cat(&line, &linelen, aroff,
			    " reason=\"%s\"", sig->state_reason)) == -1) {
				dkim_err(msg, "malloc");
				goto fail;
			}
		}
		if (sig->s[0] != '\0') {
			if ((aroff = dkim_ar_cat(&line, &linelen, aroff,
			    " header.s=%s", sig->s)) == -1) {
				dkim_err(msg, "malloc");
				goto fail;
			}
		}
		if (sig->d[0] != '\0') {
			if ((aroff = dkim_ar_cat(&line, &linelen, aroff,
			    " header.d=%s", sig->d)) == -1) {
				dkim_err(msg, "malloc");
				goto fail;
			}
		}
		/*
		 * Don't print i-tag, since localpart can be a quoted-string,
		 * which can contain FWS and CFWS.
		 */
		if (sig->a != NULL) {
			if ((aroff = dkim_ar_cat(&line, &linelen, aroff,
			    " header.a=%.*s", (int)sig->asz, sig->a)) == -1) {
				dkim_err(msg, "malloc");
				goto fail;
			}
		}
	}
	if (!found) {
		aroff = dkim_ar_cat(&line, &linelen, aroff, "; dkim=none");
		if (aroff == -1) {
			dkim_err(msg, "malloc");
			goto fail;
		}
	}
	dkim_ar_print(msg->ctx, line);

	rewind(msg->origf);
	while ((n = getline(&line, &linelen, msg->origf)) != -1) {
		line[n - 1] = '\0';
		osmtpd_filter_dataline(msg->ctx, "%s", line);
	}
	if (ferror(msg->origf))
		dkim_err(msg, "getline");
 fail:
	free(line);
	return;
}

void
dkim_ar_print(struct osmtpd_ctx *ctx, const char *start)
{
	const char *scan, *checkpoint, *ncheckpoint;
	size_t arlen = 0;
	int first = 1, arid = 1;

	checkpoint = start;
	ncheckpoint = osmtpd_ltok_skip_hdr_name(start, 0) + 1;
	for (scan = start; scan[0] != '\0'; scan++) {
		if (scan[0] == '\t')
			arlen = (arlen + 8) & ~7;
		else
			arlen++;
		if (arlen >= AUTHENTICATION_RESULTS_LINELEN) {
			osmtpd_filter_dataline(ctx, "%s%.*s", first ? "" : "\t",
			    (int)((checkpoint == start ?
			    ncheckpoint : checkpoint) - start), start);
			start = osmtpd_ltok_skip_cfws(checkpoint, 1);
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
			/* reasonspec */
			} else if (strncmp(ncheckpoint, "reason",
			    sizeof("reason") - 1) == 0) {
				ncheckpoint = osmtpd_ltok_skip_value(
				    ncheckpoint + sizeof("reason"), 0);
			/* propspec */
			} else {
				ncheckpoint += sizeof("header.x=") - 1;
				ncheckpoint = osmtpd_ltok_skip_ar_pvalue(
				    ncheckpoint, 0);
				if (ncheckpoint[0] == ';')
					ncheckpoint++;
			}
		}
	}
	osmtpd_filter_dataline(ctx, "%s%s", first ? "" : "\t", start);
}

ssize_t
dkim_ar_cat(char **ar, size_t *n, size_t aroff, const char *fmt, ...)
{
	va_list ap;
	char *artmp;
	int size;
	size_t nn;

	assert(*n >= aroff);
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
dkim_err(struct message *msg, char *text)
{
	msg->err = 1;
	fprintf(stderr, "%s: %s\n", text, strerror(errno));
}

void
dkim_errx(struct message *msg, char *text)
{
	msg->err = 1;
	fprintf(stderr, "%s\n", text);
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: filter-dkimverify\n");
	exit(1);
}
