/*
 * Copyright (c) 2020 Martijn van Duren <martijn@openbsd.org>
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

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "ltok.h"

#include <stdio.h>

/* RFC 5234 - Augmented BNF for Syntax Specifications: ABNF */
const char *
osmtpd_ltok_skip_alpha(const char *ptr, int optional)
{
	if ((ptr[0] >= 0x41 && ptr[0] <= 0x5a) ||
	    (ptr[0] >= 0x61 && ptr[0] <= 0x7a))
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_bit(const char *ptr, int optional)
{
	if (ptr[0] == '0' || ptr[0] == '1')
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_char(const char *ptr, int optional)
{
	if (ptr[0] >= 0x01 && ptr[0] <= 0x7f)
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_cr(const char *ptr, int optional)
{
	if (ptr[0] == 0xd)
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_crlf(const char *ptr, int optional)
{
	if (ptr[0] == 13 && ptr[1] == 10)
		return ptr + 2;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_ctl(const char *ptr, int optional)
{
	if ((ptr[0] >= 0x00 && ptr[0] <= 0x1f) || ptr[0] == 0x7f)
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_digit(const char *ptr, int optional)
{
	if (ptr[0] >= 0x30 && ptr[0] <= 0x39)
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_dquote(const char *ptr, int optional)
{
	if (ptr[0] == 0x22)
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_hexdig(const char *ptr, int optional)
{
	const char *start = ptr;
	char l;

	if ((ptr = osmtpd_ltok_skip_digit(ptr, 0)) != NULL)
		return ptr;
	l = tolower(ptr[0]);
	if (l == 'a' || l == 'b' || l == 'c' || l == 'd' ||
	    l == 'e' || l == 'f')
		return ptr + 1;
	return optional ? start : NULL;
}

const char *
osmtpd_ltok_skip_htab(const char *ptr, int optional)
{
	if (ptr[0] == 0x9)
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_lf(const char *ptr, int optional)
{
	if (ptr[0] == 0xa)
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_octet(const char *ptr, int optional)
{
	return ptr + 1;
}

const char *
osmtpd_ltok_skip_sp(const char *ptr, int optional)
{
	if (ptr[0] == 0x20)
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_vchar(const char *ptr, int optional)
{
	if (ptr[0] >= 0x21 && ptr[0] <= 0x7e)
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_wsp(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_sp(start, 0)) != NULL ||
	    (ptr = osmtpd_ltok_skip_htab(start, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

/* RFC 5321 - Simple Mail Transfer Protocol */
const char *
osmtpd_ltok_skip_keyword(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_ldh_string(ptr, optional);
}

const char *
osmtpd_ltok_skip_sub_domain(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_let_dig(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return osmtpd_ltok_skip_ldh_string(ptr, 1);
}

const char *
osmtpd_ltok_skip_let_dig(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_alpha(start, 0)) == NULL &&
	    (ptr = osmtpd_ltok_skip_digit(start, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_ldh_string(const char *ptr, int optional)
{
	const char *start = ptr, *prev;
	int letdig = 0;

	while (1) {
		prev = ptr;
		if ((ptr = osmtpd_ltok_skip_alpha(prev, 0)) != NULL ||
		    (ptr = osmtpd_ltok_skip_digit(prev, 0)) != NULL) {
			letdig = 1;
			continue;
		}
		if (prev[0] == '-') {
			letdig = 0;
			ptr = prev + 1;
			continue;
		}
		ptr = prev;
		break;
	}
	if (letdig)
		return ptr;
	if (ptr == start)
		return optional ? start : NULL;
	return ptr;
}

/* RFC 5322 - Internet Message Format */
const char *
osmtpd_ltok_skip_quoted_pair(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] == '\\' && (
	    (ptr = osmtpd_ltok_skip_vchar(start + 1, 0)) != NULL ||
	    (ptr = osmtpd_ltok_skip_wsp(start + 1, 0)) != NULL))
		return ptr;
	return osmtpd_ltok_skip_obs_qp(start, optional);
}

const char *
osmtpd_ltok_skip_fws(const char *ptr, int optional)
{
	const char *start = ptr, *prev = ptr;

	while ((ptr = osmtpd_ltok_skip_wsp(ptr, 0)) != NULL)
		prev = ptr;
	if ((ptr = osmtpd_ltok_skip_crlf(prev, 1)) == prev)
		ptr = start;
	if ((ptr = osmtpd_ltok_skip_wsp(ptr, 0)) == NULL)
		return osmtpd_ltok_skip_obs_fws(start, optional);
	prev = ptr;
	while ((ptr = osmtpd_ltok_skip_wsp(ptr, 0)) != NULL)
		prev = ptr;
	return prev;
}

const char *
osmtpd_ltok_skip_ctext(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr[0] >= 33 && ptr[0] <= 39) || (ptr[0] >= 42 && ptr[0] <= 91) ||
	    (ptr[0] >= 93 && ptr[0] <= 126))
		return ptr + 1;
	if ((ptr = osmtpd_ltok_skip_obs_ctext(ptr, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

const char *
osmtpd_ltok_skip_ccontent(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_ctext(ptr, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_ltok_skip_quoted_pair(start, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_ltok_skip_comment(start, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

const char *
osmtpd_ltok_skip_comment(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr++[0] != '(')
		return optional ? start : NULL;
	while (1) {
		ptr = osmtpd_ltok_skip_fws(ptr, 1);
		if (ptr[0] == ')')
			return ptr + 1;
		if ((ptr = osmtpd_ltok_skip_ccontent(ptr, 0)) == NULL)
			return optional ? start : NULL;
	}
}

const char *
osmtpd_ltok_skip_cfws(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	while (1) {
		ptr = osmtpd_ltok_skip_fws(ptr, 1);
		prev = ptr;
		if ((ptr = osmtpd_ltok_skip_comment(ptr, 0)) == NULL) {
			ptr = prev;
			break;
		}
	}
	return ptr == start && !optional ? NULL : ptr;
}

const char *
osmtpd_ltok_skip_atext(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_alpha(start, 0)) != NULL ||
	    (ptr = osmtpd_ltok_skip_digit(start, 0)) != NULL)
		return ptr;
	ptr = start;
	if (ptr[0] == '!' || ptr[0] == '#' || ptr[0] == '$' || ptr[0] == '%' ||
	    ptr[0] == '&' || ptr[0] == '\'' || ptr[0] == '*' || ptr[0] == '+' ||
	    ptr[0] == '-' || ptr[0] == '/' || ptr[0] == '=' || ptr[0] == '?' ||
	    ptr[0] == '^' || ptr[0] == '_' || ptr[0] == '`' || ptr[0] == '{' ||
	    ptr[0] == '|' || ptr[0] == '}' || ptr[0] == '~')
		return ptr + 1;
	return optional ? start : NULL;
}

const char *
osmtpd_ltok_skip_atom(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	ptr = osmtpd_ltok_skip_cfws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_atext(ptr, 0)) == NULL)
		return optional ? start : NULL;
	do {
		prev = ptr;
		ptr = osmtpd_ltok_skip_atext(ptr, 1);
	} while (prev != ptr);
	return osmtpd_ltok_skip_cfws(ptr, 1);
}

const char *
osmtpd_ltok_skip_dot_atom_text(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	if ((ptr = osmtpd_ltok_skip_atext(ptr, 0)) == NULL)
		return optional ? start : NULL;
	do {
		prev = ptr;
		ptr = osmtpd_ltok_skip_atext(ptr, 1);
	} while (ptr != prev);

	while (ptr[0] == '.') {
		ptr++;
		if ((ptr = osmtpd_ltok_skip_atext(ptr, 0)) == NULL)
			return prev;
		do {
			prev = ptr;
			ptr = osmtpd_ltok_skip_atext(ptr, 1);
		} while (ptr != prev);
	}
	return ptr;
}

const char *
osmtpd_ltok_skip_dot_atom(const char *ptr, int optional)
{
	const char *start = ptr;

	ptr = osmtpd_ltok_skip_cfws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_dot_atom_text(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return osmtpd_ltok_skip_cfws(ptr, 1);
}

const char *
osmtpd_ltok_skip_qtext(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] == 33 || (ptr[0] >= 35 && ptr[0] <= 91) ||
	    (ptr[0] >= 93 && ptr[0] <= 126))
		return ptr + 1;
	if ((ptr = osmtpd_ltok_skip_obs_qtext(ptr, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

const char *
osmtpd_ltok_skip_qcontent(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_qtext(ptr, 0)) != NULL)
		return ptr;
	return osmtpd_ltok_skip_quoted_pair(start, optional);
}

const char *
osmtpd_ltok_skip_quoted_string(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	ptr = osmtpd_ltok_skip_cfws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_dquote(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while (1) {
		ptr = osmtpd_ltok_skip_fws(ptr, 1);
		if ((ptr = osmtpd_ltok_skip_qcontent(ptr, 0)) == NULL)
			break;
		prev = ptr;
	}
	if ((ptr = osmtpd_ltok_skip_dquote(prev, 0)) == NULL)
		return optional ? start : NULL;
	return osmtpd_ltok_skip_cfws(ptr, 1);
}

const char *
osmtpd_ltok_skip_word(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_atom(ptr, 0)) != NULL)
		return ptr;
	return osmtpd_ltok_skip_quoted_string(start, optional);
}

const char *
osmtpd_ltok_skip_phrase(const char *ptr, int optional)
{
	/* obs-phrase is a superset of phrae */
	return osmtpd_ltok_skip_obs_phrase(ptr, optional);
}

const char *
osmtpd_ltok_skip_name_addr(const char *ptr, int optional)
{
	const char *start = ptr;

	ptr = osmtpd_ltok_skip_display_name(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_angle_addr(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_angle_addr(const char *ptr, int optional)
{
	const char *start = ptr;

	ptr = osmtpd_ltok_skip_cfws(ptr, 1);
	if (ptr++[0] != '<')
		return osmtpd_ltok_skip_obs_angle_addr(start, optional);
	if ((ptr = osmtpd_ltok_skip_addr_spec(ptr, 0)) == NULL)
		return osmtpd_ltok_skip_obs_angle_addr(start, optional);
	if (ptr++[0] != '>')
		return osmtpd_ltok_skip_obs_angle_addr(start, optional);
	return osmtpd_ltok_skip_cfws(ptr, 1);
}

const char *
osmtpd_ltok_skip_display_name(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_phrase(ptr, optional);
}

const char *
osmtpd_ltok_skip_addr_spec(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_local_part(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr++[0] != '@')
		return optional ? start : NULL;
	if ((ptr = osmtpd_ltok_skip_domain(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_local_part(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_dot_atom(ptr, 0)) != NULL)
		return ptr;
	ptr = start;
	if ((ptr = osmtpd_ltok_skip_quoted_string(ptr, 0)) != NULL)
		return ptr;
	return osmtpd_ltok_skip_obs_local_part(start, optional);
}

const char *
osmtpd_ltok_skip_domain(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_dot_atom(start, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_ltok_skip_domain_literal(start, 0)) != NULL)
		return ptr;
	return osmtpd_ltok_skip_obs_domain(start, optional);
}

const char *
osmtpd_ltok_skip_domain_literal(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	ptr = osmtpd_ltok_skip_cfws(ptr, 1);
	if (ptr++[0] != '[')
		return optional ? start : NULL;
	while (1) {
		ptr = osmtpd_ltok_skip_fws(ptr, 1);
		prev = ptr;
		if ((ptr = osmtpd_ltok_skip_dtext(ptr, 0)) == NULL) {
			ptr = prev;
			break;
		}
	}
	if (ptr[0] != ']')
		return optional ? start : NULL;
	ptr++;
	return osmtpd_ltok_skip_cfws(ptr, 1);
}

const char *
osmtpd_ltok_skip_dtext(const char *ptr, int optional)
{
	if ((ptr[0] >= 33 && ptr[0] <= 90) || (ptr[0] >= 94 && ptr[0] <= 126))
		return ptr + 1;
	return osmtpd_ltok_skip_obs_dtext(ptr, optional);

}

const char *
osmtpd_ltok_skip_field_name(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_ftext(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		start = ptr;
		if ((ptr = osmtpd_ltok_skip_ftext(ptr, 0)) == NULL)
			return start;
	}
}

const char *
osmtpd_ltok_skip_ftext(const char *ptr, int optional)
{
	if ((ptr[0] >= 33 && ptr[0] <= 57) ||
	    (ptr[0] >= 59 && ptr[0] <= 126))
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_obs_no_ws_ctl(const char *ptr, int optional)
{
	if ((ptr[0] >= 1 && ptr[0] <= 8) || ptr[0] == 11 || ptr[0] == 12 ||
	    (ptr[0] >= 14 && ptr[0] <= 31) || ptr[0] == 127)
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_obs_ctext(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_obs_no_ws_ctl(ptr, optional);
}

const char *
osmtpd_ltok_skip_obs_qtext(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_obs_no_ws_ctl(ptr, optional);
}

const char *
osmtpd_ltok_skip_obs_qp(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] == '\\' && (
	    (ptr = osmtpd_ltok_skip_obs_no_ws_ctl(start + 1, 0)) != NULL ||
	    (ptr = osmtpd_ltok_skip_lf(start + 1, 0)) != NULL ||
	    (ptr = osmtpd_ltok_skip_cr(start + 1, 0)) != NULL))
		return ptr;
	return optional ? start : NULL;
}

const char *
osmtpd_ltok_skip_obs_phrase(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	if ((ptr = osmtpd_ltok_skip_word(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		prev = ptr;
		if ((ptr = osmtpd_ltok_skip_word(ptr, 0)) != NULL)
			continue;
		ptr = prev;
		if (ptr[0] == '.') {
			ptr++;
			continue;
		}
		if ((ptr = osmtpd_ltok_skip_cfws(ptr, 0)) != NULL)
			continue;
		return prev;
	}
}

const char *
osmtpd_ltok_skip_obs_fws(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	if ((ptr = osmtpd_ltok_skip_wsp(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while ((ptr = osmtpd_ltok_skip_wsp(ptr, 0)) != NULL)
		prev = ptr;

	ptr = prev;
	while (1) {
		if ((ptr = osmtpd_ltok_skip_crlf(ptr, 0)) == NULL)
			return prev;
		if ((ptr = osmtpd_ltok_skip_wsp(ptr, 0)) == NULL)
			return prev;
		prev = ptr;
		while ((ptr = osmtpd_ltok_skip_wsp(ptr, 0)) != NULL)
			prev = ptr;
		ptr = prev;
	}
}

const char *
osmtpd_ltok_skip_obs_angle_addr(const char *ptr, int optional)
{
	const char *start = ptr;

	ptr = osmtpd_ltok_skip_cfws(ptr, 1);
	if (ptr++[0] != '<')
		return optional ? start : NULL;
	if ((ptr = osmtpd_ltok_skip_obs_route(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if ((ptr = osmtpd_ltok_skip_addr_spec(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr++[0] != '>')
		return optional ? start : NULL;
	return osmtpd_ltok_skip_cfws(ptr, 1);
}

const char *
osmtpd_ltok_skip_obs_route(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_obs_domain_list(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr++[0] != ':')
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_obs_domain_list(const char *ptr, int optional)
{
	const char *start = ptr, *prev = ptr;

	while (1) {
		if (ptr[0] == ',') {
			ptr++;
			prev = ptr;
			continue;
		} else if ((ptr = osmtpd_ltok_skip_cfws(ptr, 0)) != NULL) {
			prev = ptr;
			continue;
		}
		break;
	}
	ptr = prev;

	if (ptr++[0] != '@')
		return optional ? start : NULL;
	if ((ptr = osmtpd_ltok_skip_domain(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		if (ptr[0] != ',')
			break;
		ptr++;
		ptr = osmtpd_ltok_skip_cfws(ptr, 1);
		if (ptr[0] != '@')
			continue;
		prev = ptr;
		if ((ptr = osmtpd_ltok_skip_domain(ptr + 1, 0)) == NULL) {
			ptr = prev;
			break;
		}
	}
	return ptr;
}

const char *
osmtpd_ltok_skip_obs_local_part(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	if ((ptr = osmtpd_ltok_skip_word(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while (ptr[0] == '.') {
		ptr++;
		if ((ptr = osmtpd_ltok_skip_word(ptr, 0)) == NULL)
			return prev;
		prev = ptr;
	}
	return ptr;
}

const char *
osmtpd_ltok_skip_obs_domain(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	if ((ptr = osmtpd_ltok_skip_atom(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while (1) {
		if (ptr++[0] != '.')
			return prev;
		if ((ptr = osmtpd_ltok_skip_atom(ptr, 0)) == NULL)
			return prev;
		prev = ptr;
	}
}

const char *
osmtpd_ltok_skip_obs_dtext(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_obs_no_ws_ctl(ptr, 0)) != NULL)
		return ptr;
	return osmtpd_ltok_skip_quoted_pair(start, optional);
}

/* RFC 2045 - Multipurpose Internet Mail Extensions */
const char *
osmtpd_ltok_skip_value(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_token(start, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_ltok_skip_quoted_string(start, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

const char *
osmtpd_ltok_skip_token(const char *ptr, int optional)
{
	const char *start;
	int first = 1;

	while (1) {
		start = ptr;
		if ((ptr = osmtpd_ltok_skip_char(start, 0)) != NULL &&
		    osmtpd_ltok_skip_sp(start, 0) == NULL &&
		    osmtpd_ltok_skip_ctl(start, 0) == NULL &&
		    osmtpd_ltok_skip_tspecials(start, 0) == NULL) {
			first = 0;
			continue;
		}
		return optional || !first ? start : NULL;
	}
}

const char *
osmtpd_ltok_skip_tspecials(const char *ptr, int optional)
{
	if (ptr[0] == '(' || ptr[0] == ')' || ptr[0] == '<' || ptr[0] == '>' ||
	    ptr[0] == '@' || ptr[0] == ',' || ptr[0] == ';' || ptr[0] == ':' ||
	    ptr[0] == '\\' || ptr[0] == '"' || ptr[0] == '/' || ptr[0] == '[' ||
	    ptr[0] == ']' || ptr[0] == '?' || ptr[0] == '=')
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_qp_section(const char *ptr, int optional)
{
	const char *prev, *last = ptr;

	while (1) {
		prev = ptr;
		if ((ptr = osmtpd_ltok_skip_ptext(prev, 0)) != NULL)
			last = ptr;
		else if ((ptr = osmtpd_ltok_skip_sp(prev, 0)) == NULL &&
		    (ptr = osmtpd_ltok_skip_htab(prev, 0)) == NULL)
			return last;
	}
}

const char *
osmtpd_ltok_skip_ptext(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_hex_octet(start, 0)) == NULL &&
	    (ptr = osmtpd_ltok_skip_safe_char(start, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_safe_char(const char *ptr, int optional)
{
	if ((ptr[0] >= 33 && ptr[0] <= 60) || (ptr[0] >= 62 && ptr[0] <= 126))
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_hex_octet(const char *ptr, int optional)
{
	const char *start = ptr;
	char l;

	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr++;
	l = tolower(ptr[0]);
	if (l == 'a' || l == 'b' || l == 'c' || l == 'd' ||
	    l == 'e' || l == 'f')
		ptr++;
	else if ((ptr = osmtpd_ltok_skip_digit(ptr, 0)) == NULL)
		return optional ? start : NULL;
	l = tolower(ptr[0]);
	start = ptr;
	if (l == 'a' || l == 'b' || l == 'c' || l == 'd' ||
	    l == 'e' || l == 'f')
		ptr++;
	else if ((ptr = osmtpd_ltok_skip_digit(ptr, 0)) == NULL)
		return start;
	return ptr;
}

/* RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures */
const char *
osmtpd_ltok_skip_hyphenated_word(const char *ptr, int optional)
{
	const char *start = ptr, *end, *hyphen;

	if ((ptr = osmtpd_ltok_skip_alpha(ptr, 0)) == NULL)
		return optional ? start : NULL;

	end = ptr;
	while (1) {
		if (ptr[0] == '-') {
			hyphen = hyphen == NULL ? ptr - 1 : hyphen;
			ptr++;
			continue;
		}
		start = ptr;
		if ((ptr = osmtpd_ltok_skip_alpha(start, 0)) == NULL &&
		    (ptr = osmtpd_ltok_skip_digit(start, 0)) == NULL)
			break;
		hyphen = NULL;
		end = ptr;
		
	}
	return hyphen == NULL ? end : hyphen;
}

const char *
osmtpd_ltok_skip_alphadigitps(const char *ptr, int optional)
{
	const char *end;

	if ((end = osmtpd_ltok_skip_alpha(ptr, 0)) == NULL &&
	    (end = osmtpd_ltok_skip_digit(ptr, 0)) == NULL &&
	    ptr[0] != '+' && ptr[0] != '/')
		return optional ? ptr : NULL;
	return end == NULL ? ptr + 1 : end;
}

const char *
osmtpd_ltok_skip_base64string(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_alphadigitps(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		start = ptr;
		ptr = osmtpd_ltok_skip_fws(ptr, 1);
		if ((ptr = osmtpd_ltok_skip_alphadigitps(ptr, 0)) == NULL)
			break;
	}
	ptr = start;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if (ptr[0] == '=') {
		ptr++;
		start = ptr;
		ptr = osmtpd_ltok_skip_fws(ptr, 1);
		if (ptr[0] == '=')
			ptr++;
		else
			ptr = start;
	} else
		ptr = start;
	return ptr;
}

const char *
osmtpd_ltok_skip_hdr_name(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_field_name(ptr, optional);
}

const char *
osmtpd_ltok_skip_qp_hdr_value(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_dkim_quoted_printable(ptr, optional);
}

const char *
osmtpd_ltok_skip_dkim_quoted_printable(const char *ptr, int optional)
{
	const char *start;

	while (1) {
		start = ptr;
		if ((ptr = osmtpd_ltok_skip_fws(start, 0)) != NULL)
			continue;
		if ((ptr = osmtpd_ltok_skip_hex_octet(start, 0)) != NULL)
			continue;
		ptr = osmtpd_ltok_skip_dkim_safe_char(start, 0);
		if (ptr == NULL)
			break;
	}
	return start;
}

const char *
osmtpd_ltok_skip_dkim_safe_char(const char *ptr, int optional)
{
	if ((ptr[0] >= 0x21 && ptr[0] <= 0x3a) || ptr[0] == 0x3c ||
	    (ptr[0] >= 0x3e && ptr[0] <= 0x7e))
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_selector(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_sub_domain(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		start = ptr;
		if (ptr[0] != '.')
			return start;
		ptr++;
		if ((ptr = osmtpd_ltok_skip_sub_domain(ptr, 0)) == NULL)
			return start;
	}
}

const char *
osmtpd_ltok_skip_tag_list(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_tag_spec(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		/* Starting or trailing ';' */
		if (ptr[0] != ';')
			return ptr;
		ptr++;
		start = ptr;
		if ((ptr = osmtpd_ltok_skip_tag_spec(ptr, 0)) == NULL)
			return start;
	}
}

const char *
osmtpd_ltok_skip_tag_spec(const char *ptr, int optional)
{
	const char *start = ptr;

	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_tag_name(ptr, 0)) == NULL)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr++;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return osmtpd_ltok_skip_fws(ptr, 1);
}

const char *
osmtpd_ltok_skip_tag_name(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	if ((ptr = osmtpd_ltok_skip_alpha(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while ((ptr = osmtpd_ltok_skip_alnumpunc(ptr, 0)) != NULL)
		prev = ptr;
	return prev;
}

const char *
osmtpd_ltok_skip_tag_value(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	if ((ptr = osmtpd_ltok_skip_tval(ptr, 0)) == NULL)
		return start;

	while (1) {
		start = ptr;
		/* FWS contains WSP */
		if ((ptr = osmtpd_ltok_skip_fws(ptr, 0)) == NULL)
			return start;
		prev = ptr;
		while ((ptr = osmtpd_ltok_skip_fws(ptr, 0)) != NULL)
			prev = ptr;
		ptr = prev;
		if ((ptr = osmtpd_ltok_skip_tval(ptr, 0)) == NULL)
			return start;
	}
}

const char *
osmtpd_ltok_skip_tval(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	if ((ptr = osmtpd_ltok_skip_valchar(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while ((ptr = osmtpd_ltok_skip_valchar(ptr, 0)) != NULL)
		prev = ptr;
	return prev;
}

const char *
osmtpd_ltok_skip_valchar(const char *ptr, int optional)
{
	if ((ptr[0] >= 0x21 && ptr[0] <= 0x3A) ||
	    (ptr[0] >= 0x3C && ptr[0] <= 0x7E))
		return ptr + 1;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_alnumpunc(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_alpha(start, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_ltok_skip_digit(start, 0)) != NULL)
		return ptr;
	if (start[0] == '_')
		return start + 1;
	return optional ? start : NULL;
}

const char *
osmtpd_ltok_skip_sig_v_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x76)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_v_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_v_tag_value(const char *ptr, int optional)
{
	const char *start = ptr, *prev;

	if ((ptr = osmtpd_ltok_skip_digit(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		prev = ptr;
		if ((ptr = osmtpd_ltok_skip_digit(ptr, 0)) == NULL)
			return prev;
	}
}

const char *
osmtpd_ltok_skip_sig_a_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x61)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_a_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_a_tag_value(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_sig_a_tag_alg(ptr, optional);
}

const char *
osmtpd_ltok_skip_sig_a_tag_alg(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_sig_a_tag_k(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr[0] != '-')
		return optional ? start : NULL;
	ptr++;
	if ((ptr = osmtpd_ltok_skip_sig_a_tag_h(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_a_tag_k(const char *ptr, int optional)
{
	/* sha1 / sha256 covered by x-sig-a-tag-k */
	return osmtpd_ltok_skip_x_sig_a_tag_k(ptr, optional);
}

const char *
osmtpd_ltok_skip_sig_a_tag_h(const char *ptr, int optional)
{
	/* rsa / ed25519 covered by x-sig-a-tag-h */
	return osmtpd_ltok_skip_x_sig_a_tag_h(ptr, optional);
}

const char *
osmtpd_ltok_skip_x_sig_a_tag_k(const char *ptr, int optional)
{
	const char *start = ptr, *prev, *end;

	if ((ptr = osmtpd_ltok_skip_alpha(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while ((end = osmtpd_ltok_skip_alpha(ptr, 0)) != NULL ||
	    (end = osmtpd_ltok_skip_digit(ptr, 0)) != NULL) {
		ptr = end;
		prev = end;
	}
	return prev;
}

const char *
osmtpd_ltok_skip_x_sig_a_tag_h(const char *ptr, int optional)
{
	const char *start = ptr, *prev, *end;

	if ((ptr = osmtpd_ltok_skip_alpha(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while ((end = osmtpd_ltok_skip_alpha(ptr, 0)) != NULL ||
	    (end = osmtpd_ltok_skip_digit(ptr, 0)) != NULL) {
		ptr = end;
		prev = end;
	}
	return prev;
}

const char *
osmtpd_ltok_skip_sig_b_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x62)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_b_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_b_tag_value(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_sig_b_tag_data(ptr, optional);
}

const char *
osmtpd_ltok_skip_sig_b_tag_data(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_base64string(ptr, optional);
}

const char *
osmtpd_ltok_skip_sig_bh_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x62 && ptr[0] != 0x68)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 2, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_bh_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_bh_tag_value(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_sig_bh_tag_data(ptr, optional);
}

const char *
osmtpd_ltok_skip_sig_bh_tag_data(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_base64string(ptr, optional);
}

const char *
osmtpd_ltok_skip_sig_c_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x63)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_c_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_c_tag_value(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_sig_c_tag_alg(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr[0] == '/') {
		start = ptr;
		if ((ptr = osmtpd_ltok_skip_sig_c_tag_alg(ptr, 0)) == NULL)
			return start;
	}
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_c_tag_alg(const char *ptr, int optional)
{
	/* simple / relaxed covered by x-sig-c-tag-alga */
	return osmtpd_ltok_skip_x_sig_c_tag_alg(ptr, optional);
}

const char *
osmtpd_ltok_skip_x_sig_c_tag_alg(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_hyphenated_word(ptr, optional);
}

const char *
osmtpd_ltok_skip_sig_d_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x64)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_d_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_d_tag_value(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_domain_name(ptr, optional);
}

const char *
osmtpd_ltok_skip_domain_name(const char *ptr, int optional)
{
	const char *prev = ptr;

	if ((ptr = osmtpd_ltok_skip_sub_domain(ptr, 0)) == NULL)
		return optional ? prev : NULL;
	while (1) {
		prev = ptr;
		if (ptr[0] != '.' ||
		    (ptr = osmtpd_ltok_skip_sub_domain(ptr + 1, 0)) == NULL)
			return prev;
	}
}

const char *
osmtpd_ltok_skip_sig_h_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x68)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_h_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_h_tag_value(const char *ptr, int optional)
{
	const char *prev = ptr;

	if ((ptr = osmtpd_ltok_skip_hdr_name(ptr, 0)) == NULL)
		return optional ? prev : NULL;
	while (1) {
		prev = ptr;
		ptr = osmtpd_ltok_skip_fws(ptr, 1);
		if (ptr[0] != ':')
			return prev;
		ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
		if ((ptr = osmtpd_ltok_skip_hdr_name(ptr, 0)) == NULL)
			return prev;
	}
}

const char *
osmtpd_ltok_skip_sig_i_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x69)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_i_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_i_tag_value(const char *ptr, int optional)
{
	const char *start = ptr;

	ptr = osmtpd_ltok_skip_local_part(ptr, 1);
	if (ptr[0] != '@' ||
	    (ptr = osmtpd_ltok_skip_domain_name(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_l_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x6c)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_l_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_l_tag_value(const char *ptr, int optional)
{
	size_t i;

	for (i = 0; i < 76; i++) {
		if (osmtpd_ltok_skip_digit(ptr + i, 0) == NULL)
			break;
	}
	if (i >= 1 && i <= 76)
		return ptr + i;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_sig_q_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x71)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_q_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_q_tag_value(const char *ptr, int optional)
{
	const char *prev = ptr;
	if ((ptr = osmtpd_ltok_skip_sig_q_tag_method(ptr, 0)) == NULL)
		return optional ? prev : NULL;
	while (1) {
		prev = ptr;
		ptr = osmtpd_ltok_skip_fws(ptr, 1);
		if (ptr[0] != ':')
			return prev;
		ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
		if ((ptr = osmtpd_ltok_skip_sig_q_tag_method(ptr, 0)) == NULL)
			return prev;
	}
}

const char *
osmtpd_ltok_skip_sig_q_tag_method(const char *ptr, int optional)
{
	const char *start = ptr;

	/* dns/txt covered by x-sig-q-tag-type ["/" x-sig-q-tag-args] */
	if ((ptr = osmtpd_ltok_skip_x_sig_q_tag_type(ptr, 0)) == NULL)
		return optional ? start : NULL;
	start = ptr;
	if (ptr[0] != '/')
		return ptr;
	if ((ptr = osmtpd_ltok_skip_x_sig_q_tag_args(ptr, 0)) == NULL)
		return start;
	return ptr;
}

const char *
osmtpd_ltok_skip_x_sig_q_tag_type(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_hyphenated_word(ptr, optional);
}

const char *
osmtpd_ltok_skip_x_sig_q_tag_args(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_qp_hdr_value(ptr, optional);
}

const char *
osmtpd_ltok_skip_sig_s_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x73)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_s_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_s_tag_value(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_selector(ptr, optional);
}

const char *
osmtpd_ltok_skip_sig_t_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x74)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_t_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_t_tag_value(const char *ptr, int optional)
{
	size_t i;

	for (i = 0; i < 12; i++) {
		if (osmtpd_ltok_skip_digit(ptr + i, 0) == NULL)
			break;
	}
	if (i >= 1 && i <= 12)
		return ptr + i;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_sig_x_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x78)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_x_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_x_tag_value(const char *ptr, int optional)
{
	size_t i;

	for (i = 0; i < 12; i++) {
		if (osmtpd_ltok_skip_digit(ptr + i, 0) == NULL)
			break;
	}
	if (i >= 1 && i <= 12)
		return ptr + i;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_sig_z_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x7a)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_sig_z_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_sig_z_tag_value(const char *ptr, int optional)
{
	const char *prev = ptr;

	if ((ptr = osmtpd_ltok_skip_sig_z_tag_copy(ptr, 0)) == NULL)
		return optional ? ptr : NULL;
	while (1) {
		prev = ptr;
		if (ptr[0] != '|')
			return prev;
		ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
		if ((ptr = osmtpd_ltok_skip_sig_z_tag_copy(ptr, 0)) == NULL)
			return prev;
	}
}

const char *
osmtpd_ltok_skip_sig_z_tag_copy(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_hdr_name(ptr, 0)) == NULL)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if (ptr[0] != ':')
		return optional ? start : NULL;
	if ((ptr = osmtpd_ltok_skip_qp_hdr_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_key_v_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x76)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_key_v_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_key_v_tag_value(const char *ptr, int optional)
{
	if (ptr[0] == 0x44 && ptr[1] == 0x4b && ptr[2] == 0x49 &&
	    ptr[3] == 0x4d && ptr[4] == 0x31)
		return ptr + 5;
	return optional ? ptr : NULL;
}

const char *
osmtpd_ltok_skip_key_h_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x68)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_key_h_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_key_h_tag_value(const char *ptr, int optional)
{
	const char *prev = ptr;

	if ((prev = osmtpd_ltok_skip_key_h_tag_alg(ptr, 0)) == NULL)
		return optional ? prev : NULL;
	while (1) {
		prev = ptr;
		ptr = osmtpd_ltok_skip_fws(ptr, 1);
		if (ptr[0] != ':')
			return prev;
		ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
		if ((ptr = osmtpd_ltok_skip_key_h_tag_alg(ptr, 0)) == NULL)
			return prev;
	}
}

const char *
osmtpd_ltok_skip_key_h_tag_alg(const char *ptr, int optional)
{
	/* sha1 / sha256 covered by x-key-h-tag-alg */
	return osmtpd_ltok_skip_x_key_h_tag_alg(ptr, optional);
}

const char *
osmtpd_ltok_skip_x_key_h_tag_alg(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_hyphenated_word(ptr, optional);
}

const char *
osmtpd_ltok_skip_key_k_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x6b)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_key_k_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_key_k_tag_value(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_key_k_tag_type(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_key_k_tag_type(const char *ptr, int optional)
{
	/* rsa covered by x-key-k-tag-type */
	return osmtpd_ltok_skip_x_key_k_tag_type(ptr, optional);
}

const char *
osmtpd_ltok_skip_x_key_k_tag_type(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_hyphenated_word(ptr, optional);
}

const char *
osmtpd_ltok_skip_key_n_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x6e)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_key_n_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_key_n_tag_value(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_qp_section(ptr, optional);
}

const char *
osmtpd_ltok_skip_key_p_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x70)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_key_p_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_key_p_tag_value(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_base64string(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_key_s_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x73)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_key_s_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_key_s_tag_value(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_key_s_tag_type(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		start = ptr;
		ptr = osmtpd_ltok_skip_fws(ptr, 1);
		if (ptr[0] != ':')
			return start;
		ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
		ptr = osmtpd_ltok_skip_key_s_tag_type(ptr, 0);
		if (ptr == NULL)
			return start;
	}
}

const char *
osmtpd_ltok_skip_key_s_tag_type(const char *ptr, int optional)
{
	if (ptr[0] == '*')
		return ptr + 1;
	/* email covered by x-key-s-tag-type */
	return osmtpd_ltok_skip_x_key_s_tag_type(ptr, optional);
}

const char *
osmtpd_ltok_skip_x_key_s_tag_type(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_hyphenated_word(ptr, optional);
}

const char *
osmtpd_ltok_skip_key_t_tag(const char *ptr, int optional)
{
	const char *start = ptr;

	if (ptr[0] != 0x74)
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr = osmtpd_ltok_skip_fws(ptr, 1);
	if ((ptr = osmtpd_ltok_skip_key_t_tag_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

const char *
osmtpd_ltok_skip_key_t_tag_value(const char *ptr, int optional)
{
	const char *start = ptr;

	if ((ptr = osmtpd_ltok_skip_key_t_tag_flag(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		start = ptr;
		ptr = osmtpd_ltok_skip_fws(ptr, 1);
		if (ptr[0] != ':')
			return start;
		ptr = osmtpd_ltok_skip_fws(ptr + 1, 1);
		ptr = osmtpd_ltok_skip_key_t_tag_flag(ptr, 0);
		if (ptr == NULL)
			return start;
	}
}

const char *
osmtpd_ltok_skip_key_t_tag_flag(const char *ptr, int optional)
{
	/* y / s covered by x-key-t-tag-flag */
	return osmtpd_ltok_skip_x_key_t_tag_flag(ptr, optional);
}

const char *
osmtpd_ltok_skip_x_key_t_tag_flag(const char *ptr, int optional)
{
	return osmtpd_ltok_skip_hyphenated_word(ptr, optional);
}

const char *
osmtpd_ltok_skip_ar_pvalue(const char *ptr, int optional)
{
	const char *start = ptr, *tmp;

	ptr = osmtpd_ltok_skip_cfws(ptr, 1);
	if ((tmp = osmtpd_ltok_skip_value(ptr, 0)) != NULL)
		return tmp;
	ptr = osmtpd_ltok_skip_local_part(ptr, 1);
	if (ptr[0] == '@')
		ptr++;
	if ((ptr = osmtpd_ltok_skip_domain(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}
