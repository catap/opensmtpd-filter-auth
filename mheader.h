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

char *osmtpd_mheader_skip_sp(char *, int);
char *osmtpd_mheader_skip_htab(char *, int);
char *osmtpd_mheader_skip_char(char *, int);
char *osmtpd_mheader_skip_ctl(char *, int);
char *osmtpd_mheader_skip_wsp(char *, int);
char *osmtpd_mheader_skip_crlf(char *, int);
char *osmtpd_mheader_skip_vchar(char *, int);
char *osmtpd_mheader_skip_lf(char *, int);
char *osmtpd_mheader_skip_cr(char *, int);
char *osmtpd_mheader_skip_alpha(char *, int);
char *osmtpd_mheader_skip_digit(char *, int);
char *osmtpd_mheader_skip_letdig(char *, int);
char *osmtpd_mheader_skip_ldhstring(char *, int);
char *osmtpd_mheader_skip_dquote(char *, int);
char *osmtpd_mheader_skip_hexoctet(char *, int);
char *osmtpd_mheader_skip_obs_fws(char *, int);
char *osmtpd_mheader_skip_fws(char *, int);
char *osmtpd_mheader_skip_obs_no_ws_ctl(char *, int);
char *osmtpd_mheader_skip_obs_ctext(char *, int);
char *osmtpd_mheader_skip_obs_qp(char *, int);
char *osmtpd_mheader_skip_quoted_pair(char *, int);
char *osmtpd_mheader_skip_ctext(char *, int);
char *osmtpd_mheader_skip_ccontent(char *, int);
char *osmtpd_mheader_skip_comment(char *, int);
char *osmtpd_mheader_skip_cfws(char *, int);
char *osmtpd_mheader_skip_atext(char *, int);
char *osmtpd_mheader_skip_atom(char *, int);
char *osmtpd_mheader_skip_dot_atom_text(char *, int);
char *osmtpd_mheader_skip_dot_atom(char *, int);
char *osmtpd_mheader_skip_obs_qtext(char *, int);
char *osmtpd_mheader_skip_qtext(char *, int);
char *osmtpd_mheader_skip_qcontent(char *, int);
char *osmtpd_mheader_skip_quoted_string(char *, int);
char *osmtpd_mheader_skip_keyword(char *, int);
char *osmtpd_mheader_skip_word(char *, int);
char *osmtpd_mheader_skip_obs_phrase(char *, int);
char *osmtpd_mheader_skip_phrase(char *, int);
char *osmtpd_mheader_skip_obs_local_part(char *, int);
char *osmtpd_mheader_skip_local_part(char *, int);
char *osmtpd_mheader_skip_subdomain(char *, int);
char *osmtpd_mheader_skip_obs_dtext(char *, int);
char *osmtpd_mheader_skip_dtext(char *, int);
char *osmtpd_mheader_skip_domain_literal(char *, int);
char *osmtpd_mheader_skip_obs_domain(char *, int);
char *osmtpd_mheader_skip_domain(char *, int);
char *osmtpd_mheader_skip_display_name(char *, int);
char *osmtpd_mheader_skip_obs_domain_list(char *, int);
char *osmtpd_mheader_skip_obs_route(char *, int);
char *osmtpd_mheader_skip_addr_spec(char *, int);
char *osmtpd_mheader_skip_obs_angle_addr(char *, int);
char *osmtpd_mheader_skip_angle_addr(char *, int);
char *osmtpd_mheader_skip_name_addr(char *, int);
char *osmtpd_mheader_skip_alphadigitps(char *, int);
char *osmtpd_mheader_skip_base64string(char *, int);
char *osmtpd_mheader_skip_hyphenatedword(char *, int);
char *osmtpd_mheader_skip_ftext(char *, int);
char *osmtpd_mheader_skip_fieldname(char *, int);
char *osmtpd_mheader_skip_hdrname(char *, int);
char *osmtpd_mheader_skip_tspecials(char *, int);
char *osmtpd_mheader_skip_token(char *, int);
char *osmtpd_mheader_skip_value(char *, int);

/* DKIM-Signature */
char *osmtpd_mheader_skip_dkim_safe_char(char *, int);
char *osmtpd_mheader_skip_dkim_quoted_printable(char *, int);
char *osmtpd_mheader_skip_dkim_qp_hdr_value(char *, int);
char *osmtpd_mheader_skip_dkimsig_alnumpunc(char *, int);
char *osmtpd_mheader_skip_dkimsig_valchar(char *, int);
char *osmtpd_mheader_skip_dkimsig_tval(char *, int);
char *osmtpd_mheader_skip_dkimsig_tagvalue(char *, int);
char *osmtpd_mheader_skip_dkimsig_tagname(char *, int);
char *osmtpd_mheader_skip_dkimsig_tagspec(char *, int);
char *osmtpd_mheader_skip_dkimsig_taglist(char *, int);
char *osmtpd_mheader_skip_dkimsig_xsigatagh(char *, int);
char *osmtpd_mheader_skip_dkimsig_xsigatagk(char *, int);
char *osmtpd_mheader_skip_dkimsig_sigatagh(char *, int);
char *osmtpd_mheader_skip_dkimsig_sigatagk(char *, int);
char *osmtpd_mheader_skip_dkimsig_sigatagalg(char *, int);
char *osmtpd_mheader_skip_dkimsig_xsigctagalg(char *, int);
char *osmtpd_mheader_skip_dkimsig_sigctagalg(char *, int);
char *osmtpd_mheader_skip_dkimsig_xkeyhtagalg(char *, int);
char *osmtpd_mheader_skip_dkimsig_xsigqtagargs(char *, int);
char *osmtpd_mheader_skip_dkimsig_xsigqtagtype(char *, int);
char *osmtpd_mheader_skip_dkimsig_sigqtagmethod(char *, int);
char *osmtpd_mheader_skip_dkimsig_sigztagcopy(char *, int);
char *osmtpd_mheader_skip_dkimsig_sigztagvalue(char *, int);
char *osmtpd_mheader_skip_dkimsig_keyhtagalg(char *, int);
char *osmtpd_mheader_skip_dkimsig_keyhtagvalue(char *, int);
char *osmtpd_mheader_skip_dkimsig_xkeystagtype(char *, int);
char *osmtpd_mheader_skip_dkimsig_keystagtype(char *, int);
char *osmtpd_mheader_skip_dkimsig_keystagvalue(char *, int);
char *osmtpd_mheader_skip_dkimsig_xkeyttagflag(char *, int);
char *osmtpd_mheader_skip_dkimsig_keyttagflag(char *, int);
char *osmtpd_mheader_skip_dkimsig_keyttagvalue(char *, int);
char *osmtpd_mheader_skip_dkimsig_selector(char *, int);

/* Authentication-Results */
char *osmtpd_mheader_skip_ar_pvalue(char *, int);

char *osmtpd_mheader_domain_uncomment(char *);
char *osmtpd_mheader_from_domain(char *);

char *osmtpd_mheader_quoted_string_normalize(char *);
