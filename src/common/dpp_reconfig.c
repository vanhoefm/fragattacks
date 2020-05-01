/*
 * DPP reconfiguration
 * Copyright (c) 2020, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "crypto/crypto.h"
#include "dpp.h"
#include "dpp_i.h"


#ifdef CONFIG_DPP2

static void dpp_build_attr_csign_key_hash(struct wpabuf *msg, const u8 *hash)
{
	if (hash) {
		wpa_printf(MSG_DEBUG, "DPP: Configurator C-sign key Hash");
		wpabuf_put_le16(msg, DPP_ATTR_C_SIGN_KEY_HASH);
		wpabuf_put_le16(msg, SHA256_MAC_LEN);
		wpabuf_put_data(msg, hash, SHA256_MAC_LEN);
	}
}


struct wpabuf * dpp_build_reconfig_announcement(const u8 *csign_key,
						size_t csign_key_len)
{
	struct wpabuf *msg;
	EVP_PKEY *csign = NULL;
	const unsigned char *p;
	struct wpabuf *uncomp;
	u8 hash[SHA256_MAC_LEN];
	const u8 *addr[1];
	size_t len[1];
	int res;

	wpa_printf(MSG_DEBUG, "DPP: Build Reconfig Announcement frame");

	p = csign_key;
	csign = d2i_PUBKEY(NULL, &p, csign_key_len);
	if (!csign) {
		wpa_printf(MSG_ERROR,
			   "DPP: Failed to parse local C-sign-key information");
		return NULL;
	}

	uncomp = dpp_get_pubkey_point(csign, 1);
	EVP_PKEY_free(csign);
	if (!uncomp)
		return NULL;
	addr[0] = wpabuf_head(uncomp);
	len[0] = wpabuf_len(uncomp);
	wpa_hexdump(MSG_DEBUG, "DPP: Uncompressed C-sign key", addr[0], len[0]);
	res = sha256_vector(1, addr, len, hash);
	wpabuf_free(uncomp);
	if (res < 0)
		return NULL;
	wpa_hexdump(MSG_DEBUG, "DPP: kid = SHA256(uncompressed C-sign key)",
		    hash, SHA256_MAC_LEN);

	msg = dpp_alloc_msg(DPP_PA_RECONFIG_ANNOUNCEMENT, 4 + SHA256_MAC_LEN);
	if (!msg)
		return NULL;

	/* Configurator C-sign key Hash */
	dpp_build_attr_csign_key_hash(msg, hash);
	wpa_hexdump_buf(MSG_DEBUG,
			"DPP: Reconfig Announcement frame attributes", msg);
	return msg;
}
#endif /* CONFIG_DPP2 */
