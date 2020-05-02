/*
 * DPP reconfiguration
 * Copyright (c) 2020, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/json.h"
#include "crypto/crypto.h"
#include "crypto/random.h"
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


static struct wpabuf * dpp_reconfig_build_req(struct dpp_authentication *auth)
{
	struct wpabuf *msg;
	size_t attr_len;

	/* Build DPP Reconfig Authentication Request frame attributes */
	attr_len = 4 + 1 + 4 + 1 + 4 + os_strlen(auth->conf->connector) +
		4 + auth->curve->nonce_len;
	msg = dpp_alloc_msg(DPP_PA_RECONFIG_AUTH_REQ, attr_len);
	if (!msg)
		return NULL;

	/* Transaction ID */
	wpabuf_put_le16(msg, DPP_ATTR_TRANSACTION_ID);
	wpabuf_put_le16(msg, 1);
	wpabuf_put_u8(msg, auth->transaction_id);

	/* Protocol Version */
	wpabuf_put_le16(msg, DPP_ATTR_PROTOCOL_VERSION);
	wpabuf_put_le16(msg, 1);
	wpabuf_put_u8(msg, DPP_VERSION);

	/* DPP Connector */
	wpabuf_put_le16(msg, DPP_ATTR_CONNECTOR);
	wpabuf_put_le16(msg, os_strlen(auth->conf->connector));
	wpabuf_put_str(msg, auth->conf->connector);

	/* I-nonce */
	wpabuf_put_le16(msg, DPP_ATTR_I_NONCE);
	wpabuf_put_le16(msg, auth->curve->nonce_len);
	wpabuf_put_data(msg, auth->i_nonce, auth->curve->nonce_len);

	wpa_hexdump_buf(MSG_DEBUG,
			"DPP: Reconfig Authentication Request frame attributes",
			msg);

	return msg;
}


static int dpp_configurator_build_own_connector(struct dpp_configurator *conf)
{
	struct wpabuf *dppcon = NULL;
	int ret = -1;

	if (conf->connector)
		return 0; /* already generated */

	wpa_printf(MSG_DEBUG,
		   "DPP: Sign own Configurator Connector for reconfiguration with curve %s",
		   conf->curve->name);
	conf->connector_key = dpp_gen_keypair(conf->curve);
	if (!conf->connector_key)
		goto fail;

	/* Connector (JSON dppCon object) */
	dppcon = wpabuf_alloc(1000 + 2 * conf->curve->prime_len * 4 / 3);
	if (!dppcon)
		goto fail;
	json_start_object(dppcon, NULL);
	json_start_array(dppcon, "groups");
	json_start_object(dppcon, NULL);
	json_add_string(dppcon, "groupId", "*");
	json_value_sep(dppcon);
	json_add_string(dppcon, "netRole", "configurator");
	json_end_object(dppcon);
	json_end_array(dppcon);
	json_value_sep(dppcon);
	if (dpp_build_jwk(dppcon, "netAccessKey", conf->connector_key, NULL,
			  conf->curve) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Failed to build netAccessKey JWK");
		goto fail;
	}
	json_end_object(dppcon);
	wpa_printf(MSG_DEBUG, "DPP: dppCon: %s",
		   (const char *) wpabuf_head(dppcon));

	conf->connector = dpp_sign_connector(conf, dppcon);
	if (!conf->connector)
		goto fail;
	wpa_printf(MSG_DEBUG, "DPP: signedConnector: %s", conf->connector);

	ret = 0;
fail:
	wpabuf_free(dppcon);
	return ret;
}


struct dpp_authentication *
dpp_reconfig_init(struct dpp_global *dpp, void *msg_ctx,
		  struct dpp_configurator *conf, unsigned int freq)
{
	struct dpp_authentication *auth;

	auth = dpp_alloc_auth(dpp, msg_ctx);
	if (!auth)
		return NULL;

	auth->conf = conf;
	auth->reconfig = 1;
	auth->initiator = 1;
	auth->waiting_auth_resp = 1;
	auth->allowed_roles = DPP_CAPAB_CONFIGURATOR;
	auth->configurator = 1;
	auth->curve = conf->curve;
	auth->transaction_id = 1;
	if (dpp_prepare_channel_list(auth, freq, NULL, 0) < 0)
		goto fail;

	if (dpp_configurator_build_own_connector(conf) < 0)
		goto fail;

	if (random_get_bytes(auth->i_nonce, auth->curve->nonce_len)) {
		wpa_printf(MSG_ERROR, "DPP: Failed to generate I-nonce");
		goto fail;
	}

	auth->reconfig_req_msg = dpp_reconfig_build_req(auth);
	if (!auth->reconfig_req_msg)
		goto fail;

out:
	return auth;
fail:
	dpp_auth_deinit(auth);
	auth = NULL;
	goto out;
}

#endif /* CONFIG_DPP2 */
