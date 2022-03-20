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

#include "mheader.h"

#include <stdio.h>

char *
osmtpd_mheader_skip_sp(char *ptr, int optional)
{
	if (ptr[0] == 0x20)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_htab(char *ptr, int optional)
{
	if (ptr[0] == 0x9)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_char(char *ptr, int optional)
{
	if (ptr[0] >= 0x01 && ptr[0] <= 0x7f)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_ctl(char *ptr, int optional)
{
	if ((ptr[0] >= 0x00 && ptr[0] <= 0x1f) || ptr[0] == 0x7f)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_wsp(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_sp(start, 0)) != NULL ||
	    (ptr = osmtpd_mheader_skip_htab(start, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

char *
osmtpd_mheader_skip_crlf(char *ptr, int optional)
{
	if (ptr[0] == 13 && ptr[1] == 10)
		return ptr + 2;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_vchar(char *ptr, int optional)
{
	if (ptr[0] >= 0x21 && ptr[0] <= 0x7e)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_lf(char *ptr, int optional)
{
	if (ptr[0] == 0xa)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_cr(char *ptr, int optional)
{
	if (ptr[0] == 0xd)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_alpha(char *ptr, int optional)
{
	if ((ptr[0] >= 0x41 && ptr[0] <= 0x5a) ||
	    (ptr[0] >= 0x61 && ptr[0] <= 0x7a))
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_digit(char *ptr, int optional)
{
	if (ptr[0] >= 0x30 && ptr[0] <= 0x39)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_letdig(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_alpha(start, 0)) == NULL &&
	    (ptr = osmtpd_mheader_skip_digit(start, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

char *
osmtpd_mheader_skip_ldhstring(char *ptr, int optional)
{
	char *start = ptr, *prev;
	int letdig = 0;

	while (1) {
		prev = ptr;
		if ((ptr = osmtpd_mheader_skip_alpha(prev, 0)) != NULL ||
		    (ptr = osmtpd_mheader_skip_digit(prev, 0)) != NULL) {
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

char *
osmtpd_mheader_skip_dquote(char *ptr, int optional)
{
	if (ptr[0] == 0x22)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_hexoctet(char *ptr, int optional)
{
	char *start = ptr;

	if (ptr[0] != '=')
		return optional ? ptr : NULL;
	ptr++;
	if (ptr[0] == 'A' || ptr[0] == 'B' || ptr[0] == 'C' || ptr[0] == 'D' ||
	    ptr[0] == 'E' || ptr[0] == 'F')
		ptr++;
	else if ((ptr = osmtpd_mheader_skip_digit(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr[0] == 'A' || ptr[0] == 'B' || ptr[0] == 'C' || ptr[0] == 'D' ||
	    ptr[0] == 'E' || ptr[0] == 'F')
		ptr++;
	else if ((ptr = osmtpd_mheader_skip_digit(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

char *
osmtpd_mheader_skip_obs_fws(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) != NULL)
		prev = ptr;

	ptr = prev;
	while (1) {
		if ((ptr = osmtpd_mheader_skip_crlf(ptr, 0)) == NULL)
			return prev;
		if ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) == NULL)
			return prev;
		prev = ptr;
		while ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) != NULL)
			prev = ptr;
		ptr = prev;
	}
}

char *
osmtpd_mheader_skip_fws(char *ptr, int optional)
{
	char *start = ptr, *prev = ptr;

	while ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) != NULL)
		prev = ptr;
	if ((ptr = osmtpd_mheader_skip_crlf(prev, 1)) == prev)
		ptr = start;
	if ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) == NULL)
		return osmtpd_mheader_skip_obs_fws(start, optional);
	prev = ptr;
	while ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) != NULL)
		prev = ptr;
	return prev;
}

char *
osmtpd_mheader_skip_obs_no_ws_ctl(char *ptr, int optional)
{
	if ((ptr[0] >= 1 && ptr[0] <= 8) || ptr[0] == 11 || ptr[0] == 12 ||
	    (ptr[0] >= 14 && ptr[0] <= 31) || ptr[0] == 127)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_obs_ctext(char *ptr, int optional)
{
	return osmtpd_mheader_skip_obs_no_ws_ctl(ptr, optional);
}

char *
osmtpd_mheader_skip_ctext(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr[0] >= 33 && ptr[0] <= 39) || (ptr[0] >= 42 && ptr[0] <= 91) ||
	    (ptr[0] >= 93 && ptr[0] <= 126))
		return ptr + 1;
	if ((ptr = osmtpd_mheader_skip_obs_ctext(ptr, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

char *
osmtpd_mheader_skip_obs_qp(char *ptr, int optional)
{
	char *start = ptr;

	if (ptr[0] == '\\' && (
	    (ptr = osmtpd_mheader_skip_obs_no_ws_ctl(start + 1, 0)) != NULL ||
	    (ptr = osmtpd_mheader_skip_lf(start + 1, 0)) != NULL ||
	    (ptr = osmtpd_mheader_skip_cr(start + 1, 0)) != NULL))
		return ptr;
	return optional ? start : NULL;
}

char *
osmtpd_mheader_skip_quoted_pair(char *ptr, int optional)
{
	char *start = ptr;

	if (ptr[0] == '\\' && (
	    (ptr = osmtpd_mheader_skip_vchar(start + 1, 0)) != NULL ||
	    (ptr = osmtpd_mheader_skip_wsp(start + 1, 0)) != NULL))
		return ptr;
	return osmtpd_mheader_skip_obs_qp(start, optional);
}

char *
osmtpd_mheader_skip_ccontent(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_ctext(ptr, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_mheader_skip_quoted_pair(start, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_mheader_skip_comment(start, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

char *
osmtpd_mheader_skip_comment(char *ptr, int optional)
{
	char *start = ptr;

	if (ptr++[0] != '(')
		return optional ? start : NULL;
	while (1) {
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		if (ptr[0] == ')')
			return ptr + 1;
		if ((ptr = osmtpd_mheader_skip_ccontent(ptr, 0)) == NULL)
			return optional ? start : NULL;
	}
}

char *
osmtpd_mheader_skip_cfws(char *ptr, int optional)
{
	char *start = ptr, *prev;

	while (1) {
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		prev = ptr;
		if ((ptr = osmtpd_mheader_skip_comment(ptr, 0)) == NULL) {
			ptr = prev;
			break;
		}
	}
	return ptr == start && !optional ? NULL : ptr;
}

char *
osmtpd_mheader_skip_atext(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_alpha(start, 0)) != NULL ||
	    (ptr = osmtpd_mheader_skip_digit(start, 0)) != NULL)
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

char *
osmtpd_mheader_skip_atom(char *ptr, int optional)
{
	char *start = ptr, *prev;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if ((ptr = osmtpd_mheader_skip_atext(ptr, 0)) == NULL)
		return optional ? start : NULL;
	do {
		prev = ptr;
		ptr = osmtpd_mheader_skip_atext(ptr, 1);
	} while (prev != ptr);
	return osmtpd_mheader_skip_cfws(ptr, 1);
}

char *
osmtpd_mheader_skip_dot_atom_text(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_atext(ptr, 0)) == NULL)
		return optional ? start : NULL;
	do {
		prev = ptr;
		ptr = osmtpd_mheader_skip_atext(ptr, 1);
	} while (ptr != prev);

	while (ptr[0] == '.') {
		ptr++;
		if ((ptr = osmtpd_mheader_skip_atext(ptr, 0)) == NULL)
			return prev;
		do {
			prev = ptr;
			ptr = osmtpd_mheader_skip_atext(ptr, 1);
		} while (ptr != prev);
	}
	return ptr;
}

char *
osmtpd_mheader_skip_dot_atom(char *ptr, int optional)
{
	char *start = ptr;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if ((ptr = osmtpd_mheader_skip_dot_atom_text(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return osmtpd_mheader_skip_cfws(ptr, 1);
}

char *
osmtpd_mheader_skip_obs_qtext(char *ptr, int optional)
{
	return osmtpd_mheader_skip_obs_no_ws_ctl(ptr, optional);
}

char *
osmtpd_mheader_skip_qtext(char *ptr, int optional)
{
	char *start = ptr;

	if (ptr[0] == 33 || (ptr[0] >= 35 && ptr[0] <= 91) ||
	    (ptr[0] >= 93 && ptr[0] <= 126))
		return ptr + 1;
	if ((ptr = osmtpd_mheader_skip_obs_qtext(ptr, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

char *
osmtpd_mheader_skip_qcontent(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_qtext(ptr, 0)) != NULL)
		return ptr;
	return osmtpd_mheader_skip_quoted_pair(start, optional);
}

char *
osmtpd_mheader_skip_quoted_string(char *ptr, int optional)
{
	char *start = ptr, *prev;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if ((ptr = osmtpd_mheader_skip_dquote(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while (1) {
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		if ((ptr = osmtpd_mheader_skip_qcontent(ptr, 0)) == NULL)
			break;
		prev = ptr;
	}
	if ((ptr = osmtpd_mheader_skip_dquote(prev, 0)) == NULL)
		return optional ? start : NULL;
	return osmtpd_mheader_skip_cfws(ptr, 1);
}

char *
osmtpd_mheader_skip_keyword(char *ptr, int optional)
{
	return osmtpd_mheader_skip_ldhstring(ptr, optional);
}

char *
osmtpd_mheader_skip_word(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_atom(ptr, 0)) != NULL)
		return ptr;
	return osmtpd_mheader_skip_quoted_string(start, optional);
}

char *
osmtpd_mheader_skip_obs_phrase(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_word(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		prev = ptr;
		if ((ptr = osmtpd_mheader_skip_word(ptr, 0)) != NULL)
			continue;
		ptr = prev;
		if (ptr[0] == '.') {
			ptr++;
			continue;
		}
		if ((ptr = osmtpd_mheader_skip_cfws(ptr, 0)) != NULL)
			continue;
		return prev;
	}
}

char *
osmtpd_mheader_skip_phrase(char *ptr, int optional)
{
	/* obs-phrase is a superset of phrae */
	return osmtpd_mheader_skip_obs_phrase(ptr, optional);
#if 0
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_word(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		prev = ptr;
		if ((ptr = osmtpd_mheader_skip_word(ptr, 0)) == NULL)
			return prev;
	}
#endif
}

char *
osmtpd_mheader_skip_obs_local_part(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_word(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while (ptr[0] == '.') {
		ptr++;
		if ((ptr = osmtpd_mheader_skip_word(ptr, 0)) == NULL)
			return prev;
		prev = ptr;
	}
	return ptr;
}

char *
osmtpd_mheader_skip_local_part(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_dot_atom(ptr, 0)) != NULL)
		return ptr;
	ptr = start;
	if ((ptr = osmtpd_mheader_skip_quoted_string(ptr, 0)) != NULL)
		return ptr;
	return osmtpd_mheader_skip_obs_local_part(start, optional);
}

char *
osmtpd_mheader_skip_subdomain(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_letdig(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return osmtpd_mheader_skip_ldhstring(ptr, 1);
}

char *
osmtpd_mheader_skip_obs_dtext(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_obs_no_ws_ctl(ptr, 0)) != NULL)
		return ptr;
	return osmtpd_mheader_skip_quoted_pair(start, optional);
}

char *
osmtpd_mheader_skip_dtext(char *ptr, int optional)
{
	if ((ptr[0] >= 33 && ptr[0] <= 90) || (ptr[0] >= 94 && ptr[0] <= 126))
		return ptr + 1;
	return osmtpd_mheader_skip_obs_dtext(ptr, optional);

}

char *
osmtpd_mheader_skip_domain_literal(char *ptr, int optional)
{
	char *start = ptr, *prev;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if (ptr++[0] != '[')
		return optional ? start : NULL;
	while (1) {
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		prev = ptr;
		if ((ptr = osmtpd_mheader_skip_dtext(ptr, 0)) == NULL) {
			ptr = prev;
			break;
		}
	}
	if (ptr[0] != ']')
		return optional ? start : NULL;
	ptr++;
	return osmtpd_mheader_skip_cfws(ptr, 1);
}

char *
osmtpd_mheader_skip_obs_domain(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_atom(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while (1) {
		if (ptr++[0] != '.')
			return prev;
		if ((ptr = osmtpd_mheader_skip_atom(ptr, 0)) == NULL)
			return prev;
		prev = ptr;
	}
}

char *
osmtpd_mheader_skip_domain(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_dot_atom(start, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_mheader_skip_domain_literal(start, 0)) != NULL)
		return ptr;
	return osmtpd_mheader_skip_obs_domain(start, optional);
}

char *
osmtpd_mheader_skip_display_name(char *ptr, int optional)
{
	return osmtpd_mheader_skip_phrase(ptr, optional);
}

char *
osmtpd_mheader_skip_obs_domain_list(char *ptr, int optional)
{
	char *start = ptr, *prev = ptr;

	while (1) {
		if (ptr[0] == ',') {
			ptr++;
			prev = ptr;
			continue;
		} else if ((ptr = osmtpd_mheader_skip_cfws(ptr, 0)) != NULL) {
			prev = ptr;
			continue;
		}
		break;
	}
	ptr = prev;

	if (ptr++[0] != '@')
		return optional ? start : NULL;
	if ((ptr = osmtpd_mheader_skip_domain(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		if (ptr[0] != ',')
			break;
		ptr++;
		ptr = osmtpd_mheader_skip_cfws(ptr, 1);
		if (ptr[0] != '@')
			continue;
		prev = ptr;
		if ((ptr = osmtpd_mheader_skip_domain(ptr + 1, 0)) == NULL) {
			ptr = prev;
			break;
		}
	}
	return ptr;
}

char *
osmtpd_mheader_skip_obs_route(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_obs_domain_list(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr++[0] != ':')
		return optional ? start : NULL;
	return ptr;
}

char *
osmtpd_mheader_skip_addr_spec(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_local_part(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr++[0] != '@')
		return optional ? start : NULL;
	if ((ptr = osmtpd_mheader_skip_domain(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

char *
osmtpd_mheader_skip_obs_angle_addr(char *ptr, int optional)
{
	char *start = ptr;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if (ptr++[0] != '<')
		return optional ? start : NULL;
	if ((ptr = osmtpd_mheader_skip_obs_route(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if ((ptr = osmtpd_mheader_skip_addr_spec(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr++[0] != '>')
		return optional ? start : NULL;
	return osmtpd_mheader_skip_cfws(ptr, 1);
}

char *
osmtpd_mheader_skip_angle_addr(char *ptr, int optional)
{
	char *start = ptr;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if (ptr++[0] != '<')
		return osmtpd_mheader_skip_obs_angle_addr(start, optional);
	if ((ptr = osmtpd_mheader_skip_addr_spec(ptr, 0)) == NULL)
		return osmtpd_mheader_skip_obs_angle_addr(start, optional);
	if (ptr++[0] != '>')
		return osmtpd_mheader_skip_obs_angle_addr(start, optional);
	return osmtpd_mheader_skip_cfws(ptr, 1);
}

char *
osmtpd_mheader_skip_name_addr(char *ptr, int optional)
{
	char *start = ptr;

	ptr = osmtpd_mheader_skip_display_name(ptr, 1);
	if ((ptr = osmtpd_mheader_skip_angle_addr(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

char *
osmtpd_mheader_skip_alphadigitps(char *ptr, int optional)
{
	char *end;

	if ((end = osmtpd_mheader_skip_alpha(ptr, 0)) == NULL &&
	    (end = osmtpd_mheader_skip_digit(ptr, 0)) == NULL &&
	    ptr[0] != '+' && ptr[0] != '/')
		return optional ? ptr : NULL;
	return end == NULL ? ptr + 1 : end;
}

char *
osmtpd_mheader_skip_base64string(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_alphadigitps(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		start = ptr;
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		if ((ptr = osmtpd_mheader_skip_alphadigitps(ptr, 0)) == NULL)
			break;
	}
	ptr = start;
	ptr = osmtpd_mheader_skip_fws(ptr, 1);
	if (ptr[0] == '=') {
		ptr++;
		start = ptr;
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		if (ptr[0] == '=')
			ptr++;
		else
			ptr = start;
	} else
		ptr = start;
	return ptr;
}

char *
osmtpd_mheader_skip_hyphenatedword(char *ptr, int optional)
{
	char *start = ptr, *end, *hyphen;

	if ((ptr = osmtpd_mheader_skip_alpha(ptr, 0)) == NULL)
		return optional ? start : NULL;

	end = ptr;
	while (1) {
		if (ptr[0] == '-') {
			hyphen = hyphen == NULL ? ptr - 1 : hyphen;
			ptr++;
			continue;
		}
		start = ptr;
		if ((ptr = osmtpd_mheader_skip_alpha(start, 0)) == NULL &&
		    (ptr = osmtpd_mheader_skip_digit(start, 0)) == NULL)
			break;
		hyphen = NULL;
		end = ptr;
		
	}
	return hyphen == NULL ? end : hyphen;
}

char *
osmtpd_mheader_skip_ftext(char *ptr, int optional)
{
	if ((ptr[0] >= 33 && ptr[0] <= 57) ||
	    (ptr[0] >= 59 && ptr[0] <= 126))
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_fieldname(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_ftext(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		start = ptr;
		if ((ptr = osmtpd_mheader_skip_ftext(ptr, 0)) == NULL)
			return start;
	}
}

char *
osmtpd_mheader_skip_hdrname(char *ptr, int optional)
{
	return osmtpd_mheader_skip_fieldname(ptr, optional);
}

char *
osmtpd_mheader_skip_tspecials(char *ptr, int optional)
{
	if (ptr[0] == '(' || ptr[0] == ')' || ptr[0] == '<' || ptr[0] == '>' ||
	    ptr[0] == '@' || ptr[0] == ',' || ptr[0] == ';' || ptr[0] == ':' ||
	    ptr[0] == '\\' || ptr[0] == '"' || ptr[0] == '/' || ptr[0] == '[' ||
	    ptr[0] == ']' || ptr[0] == '?' || ptr[0] == '=')
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_token(char *ptr, int optional)
{
	char *start;
	int first = 1;

	while (1) {
		start = ptr;
		if ((ptr = osmtpd_mheader_skip_char(start, 0)) != NULL &&
		    osmtpd_mheader_skip_sp(start, 0) == NULL &&
		    osmtpd_mheader_skip_ctl(start, 0) == NULL &&
		    osmtpd_mheader_skip_tspecials(start, 0) == NULL) {
			first = 0;
			continue;
		}
		return optional || !first ? start : NULL;
	}
}

char *
osmtpd_mheader_skip_value(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_token(start, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_mheader_skip_quoted_string(start, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

char *
osmtpd_mheader_skip_dkim_safe_char(char *ptr, int optional)
{
	if ((ptr[0] >= 0x21 && ptr[0] <= 0x3a) || ptr[0] == 0x3c ||
	    (ptr[0] >= 0x3e && ptr[0] <= 0x7e))
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_dkim_quoted_printable(char *ptr, int optional)
{
	char *start;

	while (1) {
		start = ptr;
		if ((ptr = osmtpd_mheader_skip_fws(start, 0)) != NULL)
			continue;
		if ((ptr = osmtpd_mheader_skip_hexoctet(start, 0)) != NULL)
			continue;
		ptr = osmtpd_mheader_skip_dkim_safe_char(start, 0);
		if (ptr == NULL)
			break;
	}
	return start;
}

char *
osmtpd_mheader_skip_dkim_qp_hdr_value(char *ptr, int optional)
{
	return osmtpd_mheader_skip_dkim_quoted_printable(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_alnumpunc(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_alpha(start, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_mheader_skip_digit(start, 0)) != NULL)
		return ptr;
	if (start[0] == '_')
		return start + 1;
	return optional ? start : NULL;
}

char *
osmtpd_mheader_skip_dkimsig_valchar(char *ptr, int optional)
{
	if ((ptr[0] >= 0x21 && ptr[0] <= 0x3A) ||
	    (ptr[0] >= 0x3C && ptr[0] <= 0x7E))
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_dkimsig_tval(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_dkimsig_valchar(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while ((ptr = osmtpd_mheader_skip_dkimsig_valchar(ptr, 0)) != NULL)
		prev = ptr;
	return prev;
}

char *
osmtpd_mheader_skip_dkimsig_tagvalue(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_dkimsig_tval(ptr, 0)) == NULL)
		return start;

	while (1) {
		start = ptr;
		/* FWS contains WSP */
		if ((ptr = osmtpd_mheader_skip_fws(ptr, 0)) == NULL)
			return start;
		prev = ptr;
		while ((ptr = osmtpd_mheader_skip_fws(ptr, 0)) != NULL)
			prev = ptr;
		ptr = prev;
		if ((ptr = osmtpd_mheader_skip_dkimsig_tval(ptr, 0)) == NULL)
			return start;
	}
}

char *
osmtpd_mheader_skip_dkimsig_tagname(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_alpha(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while ((ptr = osmtpd_mheader_skip_dkimsig_alnumpunc(ptr, 0)) != NULL)
		prev = ptr;
	return prev;
}

char *
osmtpd_mheader_skip_dkimsig_tagspec(char *ptr, int optional)
{
	char *start = ptr;

	ptr = osmtpd_mheader_skip_fws(ptr, 1);
	if ((ptr = osmtpd_mheader_skip_dkimsig_tagname(ptr, 0)) == NULL)
		return optional ? start : NULL;
	ptr = osmtpd_mheader_skip_fws(ptr, 1);
	if (ptr[0] != '=')
		return optional ? start : NULL;
	ptr++;
	ptr = osmtpd_mheader_skip_fws(ptr, 1);
	if ((ptr = osmtpd_mheader_skip_dkimsig_tagvalue(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return osmtpd_mheader_skip_fws(ptr, 1);
}

char *
osmtpd_mheader_skip_dkimsig_taglist(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_dkimsig_tagspec(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		/* Starting or trailing ';' */
		if (ptr[0] != ';')
			return ptr;
		ptr++;
		start = ptr;
		if ((ptr = osmtpd_mheader_skip_dkimsig_tagspec(ptr, 0)) == NULL)
			return start;
	}
}

char *
osmtpd_mheader_skip_dkimsig_xsigatagh(char *ptr, int optional)
{
	char *start = ptr, *prev, *end;

	if ((ptr = osmtpd_mheader_skip_alpha(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while ((end = osmtpd_mheader_skip_alpha(ptr, 0)) != NULL ||
	    (end = osmtpd_mheader_skip_digit(ptr, 0)) != NULL) {
		ptr = end;
		prev = end;
	}
	return prev;
}

char *
osmtpd_mheader_skip_dkimsig_xsigatagk(char *ptr, int optional)
{
	char *start = ptr, *prev, *end;

	if ((ptr = osmtpd_mheader_skip_alpha(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while ((end = osmtpd_mheader_skip_alpha(ptr, 0)) != NULL ||
	    (end = osmtpd_mheader_skip_digit(ptr, 0)) != NULL) {
		ptr = end;
		prev = end;
	}
	return prev;
}

char *
osmtpd_mheader_skip_dkimsig_sigatagh(char *ptr, int optional)
{
	/* rsa / ed25519 covered by x-sig-a-tag-h */
	return osmtpd_mheader_skip_dkimsig_xsigatagh(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_sigatagk(char *ptr, int optional)
{
	/* sha1 / sha256 covered by x-sig-a-tag-k */
	return osmtpd_mheader_skip_dkimsig_xsigatagk(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_sigatagalg(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_dkimsig_sigatagk(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr[0] != '-')
		return optional ? start : NULL;
	ptr++;
	if ((ptr = osmtpd_mheader_skip_dkimsig_sigatagh(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

char *
osmtpd_mheader_skip_dkimsig_xsigctagalg(char *ptr, int optional)
{
	return osmtpd_mheader_skip_hyphenatedword(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_sigctagalg(char *ptr, int optional)
{
	/* simple / relaxed covered by x-sig-c-tag-alga */
	return osmtpd_mheader_skip_dkimsig_xsigctagalg(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_xkeyhtagalg(char *ptr, int optional)
{
	return osmtpd_mheader_skip_hyphenatedword(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_keyhtagalg(char *ptr, int optional)
{
	/* sha1 / sha256 covered by x-key-h-tag-alg */
	return osmtpd_mheader_skip_dkimsig_xkeyhtagalg(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_keyhtagvalue(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_dkimsig_keyhtagalg(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		start = ptr;
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		if (ptr[0] != ':')
			return start;
		ptr = osmtpd_mheader_skip_fws(ptr + 1, 1);
		ptr = osmtpd_mheader_skip_dkimsig_keyhtagalg(ptr, 0);
		if (ptr == NULL)
			return start;
	}
}

char *
osmtpd_mheader_skip_dkimsig_xsigqtagargs(char *ptr, int optional)
{
	return osmtpd_mheader_skip_dkim_qp_hdr_value(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_xsigqtagtype(char *ptr, int optional)
{
	return osmtpd_mheader_skip_hyphenatedword(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_sigqtagmethod(char *ptr, int optional)
{
	char *start = ptr;

	/* dns/txt covered by x-sig-q-tag-type ["/" x-sig-q-tag-args] */
	if ((ptr = osmtpd_mheader_skip_dkimsig_xsigqtagtype(ptr, 0)) == NULL)
		return optional ? start : NULL;
	start = ptr;
	if (ptr[0] != '/')
		return ptr;
	if ((ptr = osmtpd_mheader_skip_dkimsig_xsigqtagargs(ptr, 0)) == NULL)
		return start;
	return ptr;
}

char *
osmtpd_mheader_skip_dkimsig_sigztagcopy(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_hdrname(ptr, 0)) == NULL)
		return optional ? start : NULL;
	ptr = osmtpd_mheader_skip_fws(ptr, 1);
	if (ptr[0] != ':')
		return optional ? start : NULL;
	if ((ptr = osmtpd_mheader_skip_dkim_qp_hdr_value(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

char *
osmtpd_mheader_skip_dkimsig_sigztagvalue(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_dkimsig_sigztagcopy(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		start = ptr;
		if (ptr[0] != '|')
			return start;
		osmtpd_mheader_skip_fws(ptr + 1, 1);
		ptr = osmtpd_mheader_skip_dkimsig_sigztagcopy(ptr, 0);
		if (ptr == NULL)
			return start;
	}
}

char *
osmtpd_mheader_skip_dkimsig_xkeystagtype(char *ptr, int optional)
{
	return osmtpd_mheader_skip_hyphenatedword(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_keystagtype(char *ptr, int optional)
{
	if (ptr[0] == '*')
		return ptr + 1;
	/* email covered by x-key-s-tag-type */
	return osmtpd_mheader_skip_dkimsig_xkeystagtype(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_keystagvalue(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_dkimsig_keystagtype(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		start = ptr;
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		if (ptr[0] != ':')
			return start;
		ptr = osmtpd_mheader_skip_fws(ptr + 1, 1);
		ptr = osmtpd_mheader_skip_dkimsig_keystagtype(ptr, 0);
		if (ptr == NULL)
			return start;
	}
	
}

char *
osmtpd_mheader_skip_dkimsig_xkeyttagflag(char *ptr, int optional)
{
	return osmtpd_mheader_skip_hyphenatedword(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_keyttagflag(char *ptr, int optional)
{
	/* y / s covered by x-key-t-tag-flag */
	return osmtpd_mheader_skip_dkimsig_xkeyttagflag(ptr, optional);
}

char *
osmtpd_mheader_skip_dkimsig_keyttagvalue(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_dkimsig_keyttagflag(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		start = ptr;
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		if (ptr[0] != ':')
			return start;
		ptr = osmtpd_mheader_skip_fws(ptr + 1, 1);
		ptr = osmtpd_mheader_skip_dkimsig_keyttagflag(ptr, 0);
		if (ptr == NULL)
			return start;
	}
}

char *
osmtpd_mheader_skip_dkimsig_selector(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_subdomain(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		start = ptr;
		if (ptr[0] != '.')
			return start;
		ptr++;
		if ((ptr = osmtpd_mheader_skip_subdomain(ptr, 0)) == NULL)
			return start;
	}
}

char *
osmtpd_mheader_skip_ar_pvalue(char *ptr, int optional)
{
	char *start = ptr, *tmp;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if ((tmp = osmtpd_mheader_skip_value(ptr, 0)) != NULL)
		return tmp;
	ptr = osmtpd_mheader_skip_local_part(ptr, 1);
	if (ptr[0] == '@')
		ptr++;
	if ((ptr = osmtpd_mheader_skip_domain(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

char *
osmtpd_mheader_domain_uncomment(char *ptr)
{
	char *domain0, *domain, *tmp, *end;

	if (osmtpd_mheader_skip_dot_atom(ptr, 0) != NULL) {
		ptr = osmtpd_mheader_skip_cfws(ptr, 1);
		return strndup(ptr,
		    osmtpd_mheader_skip_dot_atom_text(ptr, 0) - ptr);
	}
	if ((tmp = osmtpd_mheader_skip_domain_literal(ptr, 0)) != NULL) {
		ptr = osmtpd_mheader_skip_cfws(ptr, 1) + 1;
		domain0 = domain = strndup(ptr, (size_t)(tmp - ptr));
		if (domain0 == NULL)
			return NULL;
		end = domain0 + (tmp - ptr) + 1;
		domain++;
		while (1) {
			tmp = osmtpd_mheader_skip_fws(domain, 1);
			if (tmp != domain) {
				memmove(domain, tmp, end - tmp);
				end -= (tmp - domain);
			}
			tmp = osmtpd_mheader_skip_dtext(domain, 0);
			if (tmp == NULL)
				break;
			domain = tmp;
		}
		/* domain[0] ==  ']' */
		domain[0] = '\0';
		return domain0;
	}
	return strndup(ptr, osmtpd_mheader_skip_obs_domain(ptr, 1) - ptr);
}

/* Return the domain component of the first mailbox */
char *
osmtpd_mheader_from_domain(char *ptr)
{
	char *tmp;

	/* from */
	if (strncasecmp(ptr, "from:", 5) == 0) {
		ptr += 5;
	/* obs-from */
	} else if (strncasecmp(ptr, "from", 4) == 0) {
		ptr += 4;
		do {
			tmp = ptr;
		} while ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) != NULL);
		ptr = tmp;
		if (ptr++[0] != ':')
			return NULL;
	} else {
		errno = EINVAL;
		return NULL;
	}

	/* Both from and obs-from use Mailbox-list CRLF */
	/* obs-mbox-list has just a prefix compared to mailbox-list */
	while (1) {
		tmp = ptr;
		ptr = osmtpd_mheader_skip_cfws(ptr, 1);
		if (ptr++[0] != ',') {
			ptr = tmp;
			break;
		}
	}
	/* We're only interested in the first mailbox */
	if (osmtpd_mheader_skip_name_addr(ptr, 0) != NULL) {
		ptr = osmtpd_mheader_skip_display_name(ptr, 1);
		ptr = osmtpd_mheader_skip_cfws(ptr, 1);
		/* < */
		ptr++;
		/* addr-spec */
		ptr = osmtpd_mheader_skip_local_part(ptr, 0);
		/* @ */
		ptr++;
		return osmtpd_mheader_domain_uncomment(ptr);
	}
	if (osmtpd_mheader_skip_addr_spec(ptr, 0) != NULL) {
		ptr = osmtpd_mheader_skip_local_part(ptr, 0);
		/* @ */
		ptr++;
		return osmtpd_mheader_domain_uncomment(ptr);
	}
	errno = EINVAL;
	return NULL;
}

char *
osmtpd_mheader_quoted_string_normalize(char *ptr)
{
	char *end;
	size_t d = 0, s;

	end = osmtpd_mheader_skip_cfws(ptr, 1);
	s = end - ptr;
	if (osmtpd_mheader_skip_dquote(end, 0) == NULL)
		return NULL;
	ptr[d++] = ptr[s++];
	while (ptr[s] != '\0') {
		if (osmtpd_mheader_skip_quoted_pair(ptr + s, 0) != NULL) {
			end = osmtpd_mheader_skip_qtext(ptr + s + 1, 0);
			if (end != NULL)
				s++;
			else
				ptr[d++] = ptr[s++];
			ptr[d++] = ptr[s++];
			continue;
		} else if (osmtpd_mheader_skip_qtext(ptr + s, 0) != NULL) {
			ptr[d++] = ptr[s++];
		} else if ((end = osmtpd_mheader_skip_fws(
		    ptr + s, 0)) != NULL) {
			ptr[d++] = ' ';
			s = end - ptr;
		} else
			return NULL;
	}
	if (osmtpd_mheader_skip_dquote(end, 0) == NULL)
		return NULL;
	ptr[d++] = ptr[s++];
	end = osmtpd_mheader_skip_cfws(ptr + s, 1);
	if (end[0] != '\0')
		return NULL;
	ptr[d] = '\0';
	return ptr;
}
