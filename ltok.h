/*
 * Copyright (c) 2020-2022 Martijn van Duren <martijn@openbsd.org>
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

/* RFC 5234 - Augmented BNF for Syntax Specifications: ABNF */
const char *osmtpd_ltok_skip_alpha(const char *, int);
const char *osmtpd_ltok_skip_bit(const char *, int);
const char *osmtpd_ltok_skip_char(const char *, int);
const char *osmtpd_ltok_skip_cr(const char *, int);
const char *osmtpd_ltok_skip_crlf(const char *, int);
const char *osmtpd_ltok_skip_ctl(const char *, int);
const char *osmtpd_ltok_skip_digit(const char *, int);
const char *osmtpd_ltok_skip_dquote(const char *, int);
const char *osmtpd_ltok_skip_hexdig(const char *, int);
const char *osmtpd_ltok_skip_htab(const char *, int);
const char *osmtpd_ltok_skip_lf(const char *, int);
const char *osmtpd_ltok_skip_octet(const char *, int);
const char *osmtpd_ltok_skip_sp(const char *, int);
const char *osmtpd_ltok_skip_vchar(const char *, int);
const char *osmtpd_ltok_skip_wsp(const char *, int);

/* RFC 5321 - Simple Mail Transfer Protocol */
const char *osmtpd_ltok_skip_keyword(const char *, int);
const char *osmtpd_ltok_skip_sub_domain(const char *, int);
const char *osmtpd_ltok_skip_let_dig(const char *, int);
const char *osmtpd_ltok_skip_ldh_string(const char *, int);

/* RFC 5322 - Internet Message Format */
const char *osmtpd_ltok_skip_quoted_pair(const char *, int);
const char *osmtpd_ltok_skip_fws(const char *, int);
const char *osmtpd_ltok_skip_ctext(const char *, int);
const char *osmtpd_ltok_skip_ccontent(const char *, int);
const char *osmtpd_ltok_skip_comment(const char *, int);
const char *osmtpd_ltok_skip_cfws(const char *, int);
const char *osmtpd_ltok_skip_atext(const char *, int);
const char *osmtpd_ltok_skip_atom(const char *, int);
const char *osmtpd_ltok_skip_dot_atom_text(const char *, int);
const char *osmtpd_ltok_skip_dot_atom(const char *, int);
const char *osmtpd_ltok_skip_qtext(const char *, int);
const char *osmtpd_ltok_skip_qcontent(const char *, int);
const char *osmtpd_ltok_skip_quoted_string(const char *, int);
const char *osmtpd_ltok_skip_word(const char *, int);
const char *osmtpd_ltok_skip_phrase(const char *, int);
const char *osmtpd_ltok_skip_name_addr(const char *, int);
const char *osmtpd_ltok_skip_angle_addr(const char *, int);
const char *osmtpd_ltok_skip_display_name(const char *, int);
const char *osmtpd_ltok_skip_addr_spec(const char *, int);
const char *osmtpd_ltok_skip_local_part(const char *, int);
const char *osmtpd_ltok_skip_domain(const char *, int);
const char *osmtpd_ltok_skip_domain_literal(const char *, int);
const char *osmtpd_ltok_skip_dtext(const char *, int);
const char *osmtpd_ltok_skip_field_name(const char *, int);
const char *osmtpd_ltok_skip_ftext(const char *, int);
const char *osmtpd_ltok_skip_obs_no_ws_ctl(const char *, int);
const char *osmtpd_ltok_skip_obs_ctext(const char *, int);
const char *osmtpd_ltok_skip_obs_qtext(const char *, int);
const char *osmtpd_ltok_skip_obs_qp(const char *, int);
const char *osmtpd_ltok_skip_obs_phrase(const char *, int);
const char *osmtpd_ltok_skip_obs_fws(const char *, int);
const char *osmtpd_ltok_skip_obs_angle_addr(const char *, int);
const char *osmtpd_ltok_skip_obs_route(const char *, int);
const char *osmtpd_ltok_skip_obs_domain_list(const char *, int);
const char *osmtpd_ltok_skip_obs_local_part(const char *, int);
const char *osmtpd_ltok_skip_obs_domain(const char *, int);
const char *osmtpd_ltok_skip_obs_dtext(const char *, int);

/* RFC 2045 - Multipurpose Internet Mail Extensions */
const char *osmtpd_ltok_skip_value(const char *, int);
const char *osmtpd_ltok_skip_token(const char *, int);
const char *osmtpd_ltok_skip_tspecials(const char *, int);
const char *osmtpd_ltok_skip_qp_section(const char *, int);
const char *osmtpd_ltok_skip_ptext(const char *, int);
const char *osmtpd_ltok_skip_safe_char(const char *, int);
const char *osmtpd_ltok_skip_hex_octet(const char *, int);

/* RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures */
const char *osmtpd_ltok_skip_hyphenated_word(const char *, int);
const char *osmtpd_ltok_skip_alphadigitps(const char *, int);
const char *osmtpd_ltok_skip_base64string(const char *, int);
const char *osmtpd_ltok_skip_hdr_name(const char *, int);
const char *osmtpd_ltok_skip_qp_hdr_value(const char *, int);
const char *osmtpd_ltok_skip_dkim_quoted_printable(const char *, int);
const char *osmtpd_ltok_skip_dkim_safe_char(const char *, int);
const char *osmtpd_ltok_skip_selector(const char *, int);
const char *osmtpd_ltok_skip_tag_list(const char *, int);
const char *osmtpd_ltok_skip_tag_spec(const char *, int);
const char *osmtpd_ltok_skip_tag_name(const char *, int);
const char *osmtpd_ltok_skip_tag_value(const char *, int);
const char *osmtpd_ltok_skip_tval(const char *, int);
const char *osmtpd_ltok_skip_valchar(const char *, int);
const char *osmtpd_ltok_skip_alnumpunc(const char *, int);
const char *osmtpd_ltok_skip_sig_v_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_v_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_a_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_a_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_a_tag_alg(const char *, int);
const char *osmtpd_ltok_skip_sig_a_tag_k(const char *, int);
const char *osmtpd_ltok_skip_sig_a_tag_h(const char *, int);
const char *osmtpd_ltok_skip_x_sig_a_tag_k(const char *, int);
const char *osmtpd_ltok_skip_x_sig_a_tag_h(const char *, int);
const char *osmtpd_ltok_skip_sig_b_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_b_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_b_tag_data(const char *, int);
const char *osmtpd_ltok_skip_sig_bh_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_bh_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_bh_tag_data(const char *, int);
const char *osmtpd_ltok_skip_sig_c_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_c_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_c_tag_alg(const char *, int);
const char *osmtpd_ltok_skip_x_sig_c_tag_alg(const char *, int);
const char *osmtpd_ltok_skip_sig_d_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_d_tag_value(const char *, int);
const char *osmtpd_ltok_skip_domain_name(const char *, int);
const char *osmtpd_ltok_skip_sig_h_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_h_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_i_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_i_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_l_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_l_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_q_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_q_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_q_tag_method(const char *, int);
const char *osmtpd_ltok_skip_x_sig_q_tag_type(const char *, int);
const char *osmtpd_ltok_skip_x_sig_q_tag_args(const char *, int);
const char *osmtpd_ltok_skip_sig_s_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_s_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_t_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_t_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_x_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_x_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_z_tag(const char *, int);
const char *osmtpd_ltok_skip_sig_z_tag_value(const char *, int);
const char *osmtpd_ltok_skip_sig_z_tag_copy(const char *, int);
const char *osmtpd_ltok_skip_key_v_tag(const char *, int);
const char *osmtpd_ltok_skip_key_v_tag_value(const char *, int);
const char *osmtpd_ltok_skip_key_h_tag(const char *, int);
const char *osmtpd_ltok_skip_key_h_tag_value(const char *, int);
const char *osmtpd_ltok_skip_key_h_tag_alg(const char *, int);
const char *osmtpd_ltok_skip_x_key_h_tag_alg(const char *, int);
const char *osmtpd_ltok_skip_key_k_tag(const char *, int);
const char *osmtpd_ltok_skip_key_k_tag_value(const char *, int);
const char *osmtpd_ltok_skip_key_k_tag_type(const char *, int);
const char *osmtpd_ltok_skip_x_key_k_tag_type(const char *, int);
const char *osmtpd_ltok_skip_key_n_tag(const char *, int);
const char *osmtpd_ltok_skip_key_n_tag_value(const char *, int);
const char *osmtpd_ltok_skip_key_p_tag(const char *, int);
const char *osmtpd_ltok_skip_key_p_tag_value(const char *, int);
const char *osmtpd_ltok_skip_key_s_tag(const char *, int);
const char *osmtpd_ltok_skip_key_s_tag_value(const char *, int);
const char *osmtpd_ltok_skip_key_s_tag_type(const char *, int);
const char *osmtpd_ltok_skip_x_key_s_tag_type(const char *, int);
const char *osmtpd_ltok_skip_key_t_tag(const char *, int);
const char *osmtpd_ltok_skip_key_t_tag_value(const char *, int);
const char *osmtpd_ltok_skip_key_t_tag_flag(const char *, int);
const char *osmtpd_ltok_skip_x_key_t_tag_flag(const char *, int);

/* Authentication-Results */
const char *osmtpd_ltok_skip_ar_pvalue(const char *, int);

const char *osmtpd_ltok_domain_uncomment(const char *);
const char *osmtpd_ltok_from_domain(const char *);

const char *osmtpd_ltok_quoted_string_normalize(const char *);
