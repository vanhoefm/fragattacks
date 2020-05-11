/*
 * DPP reconfiguration
 * Copyright (c) 2020, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include <openssl/opensslv.h>
#include <openssl/err.h>

#include "utils/common.h"
#include "utils/json.h"
#include "crypto/crypto.h"
#include "crypto/random.h"
#include "crypto/aes.h"
#include "crypto/aes_siv.h"
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
	if (freq && dpp_prepare_channel_list(auth, freq, NULL, 0) < 0)
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


static int dpp_reconfig_build_resp(struct dpp_authentication *auth,
				   const char *own_connector,
				   struct wpabuf *conn_status)
{
	struct wpabuf *msg = NULL, *clear, *pr = NULL;
	u8 *attr_start, *attr_end;
	size_t clear_len, attr_len, len[2];
	const u8 *addr[2];
	u8 *wrapped;
	int res = -1;

	/* Build DPP Reconfig Authentication Response frame attributes */
	clear_len = 2 * (4 + auth->curve->nonce_len) +
		4 + wpabuf_len(conn_status);
	clear = wpabuf_alloc(clear_len);
	if (!clear)
		goto fail;

	/* I-nonce (wrapped) */
	wpabuf_put_le16(clear, DPP_ATTR_I_NONCE);
	wpabuf_put_le16(clear, auth->curve->nonce_len);
	wpabuf_put_data(clear, auth->i_nonce, auth->curve->nonce_len);

	/* R-nonce (wrapped) */
	wpabuf_put_le16(clear, DPP_ATTR_R_NONCE);
	wpabuf_put_le16(clear, auth->curve->nonce_len);
	wpabuf_put_data(clear, auth->r_nonce, auth->curve->nonce_len);

	/* Connection Status (wrapped) */
	wpabuf_put_le16(clear, DPP_ATTR_CONN_STATUS);
	wpabuf_put_le16(clear, wpabuf_len(conn_status));
	wpabuf_put_buf(clear, conn_status);

	pr = dpp_get_pubkey_point(auth->own_protocol_key, 0);
	if (!pr)
		goto fail;

	attr_len = 4 + 1 + 4 + 1 +
		4 + os_strlen(own_connector) +
		4 + wpabuf_len(pr) +
		4 + wpabuf_len(clear) + AES_BLOCK_SIZE;
	msg = dpp_alloc_msg(DPP_PA_RECONFIG_AUTH_RESP, attr_len);
	if (!msg)
		goto fail;

	attr_start = wpabuf_put(msg, 0);

	/* Transaction ID */
	wpabuf_put_le16(msg, DPP_ATTR_TRANSACTION_ID);
	wpabuf_put_le16(msg, 1);
	wpabuf_put_u8(msg, auth->transaction_id);

	/* Protocol Version */
	wpabuf_put_le16(msg, DPP_ATTR_PROTOCOL_VERSION);
	wpabuf_put_le16(msg, 1);
	wpabuf_put_u8(msg, DPP_VERSION);

	/* R-Connector */
	wpabuf_put_le16(msg, DPP_ATTR_CONNECTOR);
	wpabuf_put_le16(msg, os_strlen(own_connector));
	wpabuf_put_str(msg, own_connector);

	/* Responder Protocol Key (Pr) */
	wpabuf_put_le16(msg, DPP_ATTR_R_PROTOCOL_KEY);
	wpabuf_put_le16(msg, wpabuf_len(pr));
	wpabuf_put_buf(msg, pr);

	attr_end = wpabuf_put(msg, 0);

	/* OUI, OUI type, Crypto Suite, DPP frame type */
	addr[0] = wpabuf_head_u8(msg) + 2;
	len[0] = 3 + 1 + 1 + 1;
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD[0]", addr[0], len[0]);

	/* Attributes before Wrapped Data */
	addr[1] = attr_start;
	len[1] = attr_end - attr_start;
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD[1]", addr[1], len[1]);

	/* Wrapped Data: {I-nonce, R-nonce, Connection Status}ke */
	wpabuf_put_le16(msg, DPP_ATTR_WRAPPED_DATA);
	wpabuf_put_le16(msg, wpabuf_len(clear) + AES_BLOCK_SIZE);
	wrapped = wpabuf_put(msg, wpabuf_len(clear) + AES_BLOCK_SIZE);

	wpa_hexdump_buf(MSG_DEBUG, "DPP: AES-SIV cleartext", clear);
	if (aes_siv_encrypt(auth->ke, auth->curve->hash_len,
			    wpabuf_head(clear), wpabuf_len(clear),
			    2, addr, len, wrapped) < 0)
		goto fail;

	wpa_hexdump_buf(MSG_DEBUG,
			"DPP: Reconfig Authentication Response frame attributes",
			msg);

	wpabuf_free(auth->reconfig_resp_msg);
	auth->reconfig_resp_msg = msg;

	res = 0;
out:
	wpabuf_free(clear);
	wpabuf_free(pr);
	return res;
fail:
	wpabuf_free(msg);
	goto out;
}


struct dpp_authentication *
dpp_reconfig_auth_req_rx(struct dpp_global *dpp, void *msg_ctx,
			 const char *own_connector,
			 const u8 *net_access_key, size_t net_access_key_len,
			 const u8 *csign_key, size_t csign_key_len,
			 unsigned int freq, const u8 *hdr,
			 const u8 *attr_start, size_t attr_len)
{
	struct dpp_authentication *auth = NULL;
	const u8 *trans_id, *version, *i_connector, *i_nonce;
	u16 trans_id_len, version_len, i_connector_len, i_nonce_len;
	struct dpp_signed_connector_info info;
	enum dpp_status_error res;
	struct json_token *root = NULL, *own_root = NULL, *token;
	unsigned char *own_conn = NULL;
	struct wpabuf *conn_status = NULL;

	os_memset(&info, 0, sizeof(info));

	trans_id = dpp_get_attr(attr_start, attr_len, DPP_ATTR_TRANSACTION_ID,
			       &trans_id_len);
	if (!trans_id || trans_id_len != 1) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Peer did not include Transaction ID");
		goto fail;
	}

	version = dpp_get_attr(attr_start, attr_len, DPP_ATTR_PROTOCOL_VERSION,
			       &version_len);
	if (!version || version_len < 1 || version[0] < 2) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid Protocol Version attribute");
		goto fail;
	}

	i_connector = dpp_get_attr(attr_start, attr_len, DPP_ATTR_CONNECTOR,
			       &i_connector_len);
	if (!i_connector) {
		wpa_printf(MSG_DEBUG, "DPP: Missing I-Connector attribute");
		goto fail;
	}
	wpa_hexdump_ascii(MSG_DEBUG, "DPP: I-Connector",
			  i_connector, i_connector_len);

	i_nonce = dpp_get_attr(attr_start, attr_len, DPP_ATTR_I_NONCE,
			       &i_nonce_len);
	if (!i_nonce || i_nonce_len > DPP_MAX_NONCE_LEN) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Missing or invalid I-Nonce attribute");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: I-Nonce", i_nonce, i_nonce_len);

	res = dpp_check_signed_connector(&info, csign_key, csign_key_len,
					 i_connector, i_connector_len);
	if (res != DPP_STATUS_OK) {
		wpa_printf(MSG_DEBUG, "DPP: Invalid I-Connector");
		goto fail;
	}

	root = json_parse((const char *) info.payload, info.payload_len);
	own_root = dpp_parse_own_connector(own_connector);
	if (!root || !own_root ||
	    !dpp_connector_match_groups(own_root, root, true)) {
		wpa_printf(MSG_DEBUG,
			   "DPP: I-Connector does not include compatible group netrole with own connector");
		goto fail;
	}

	token = json_get_member(root, "expiry");
	if (token && token->type == JSON_STRING &&
	    dpp_key_expired(token->string, NULL)) {
		wpa_printf(MSG_DEBUG,
			   "DPP: I-Connector (netAccessKey) has expired");
		goto fail;
	}

	token = json_get_member(root, "netAccessKey");
	if (!token || token->type != JSON_OBJECT) {
		wpa_printf(MSG_DEBUG, "DPP: No netAccessKey object found");
		goto fail;
	}

	auth = dpp_alloc_auth(dpp, msg_ctx);
	if (!auth)
		return NULL;

	auth->reconfig = 1;
	auth->allowed_roles = DPP_CAPAB_ENROLLEE;
	if (dpp_prepare_channel_list(auth, freq, NULL, 0) < 0)
		goto fail;

	auth->transaction_id = trans_id[0];

	auth->peer_version = version[0];
	wpa_printf(MSG_DEBUG, "DPP: Peer protocol version %u",
		   auth->peer_version);

	os_memcpy(auth->i_nonce, i_nonce, i_nonce_len);

	if (dpp_reconfig_derive_ke_responder(auth, net_access_key,
					     net_access_key_len, token) < 0)
		goto fail;

	if (i_nonce_len != auth->curve->nonce_len) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Unexpected I-nonce length %u (curve nonce len %zu)",
			   i_nonce_len, auth->curve->nonce_len);
		goto fail;
	}

	if (random_get_bytes(auth->r_nonce, auth->curve->nonce_len)) {
		wpa_printf(MSG_ERROR, "DPP: Failed to generate R-nonce");
		goto fail;
	}
	wpa_hexdump_key(MSG_DEBUG, "DPP: R-nonce",
			auth->r_nonce, auth->curve->nonce_len);

	/* Build Connection Status object */
	/* TODO: Get appropriate result value */
	/* TODO: ssid64 and channelList */
	conn_status = dpp_build_conn_status(DPP_STATUS_NO_AP, NULL, 0, NULL);
	if (!conn_status)
		goto fail;

	if (dpp_reconfig_build_resp(auth, own_connector, conn_status) < 0)
		goto fail;

out:
	os_free(info.payload);
	os_free(own_conn);
	json_free(root);
	json_free(own_root);
	wpabuf_free(conn_status);
	return auth;
fail:
	dpp_auth_deinit(auth);
	auth = NULL;
	goto out;
}


static struct wpabuf *
dpp_build_reconfig_flags(enum dpp_connector_key connector_key)
{
	struct wpabuf *json;

	json = wpabuf_alloc(100);
	if (!json)
		return NULL;
	json_start_object(json, NULL);
	json_add_int(json, "connectorKey", connector_key);
	json_end_object(json);
	wpa_hexdump_ascii(MSG_DEBUG, "DPP: Reconfig-Flags JSON",
			  wpabuf_head(json), wpabuf_len(json));

	return json;
}


struct wpabuf *
dpp_reconfig_build_conf(struct dpp_authentication *auth)
{
	struct wpabuf *msg = NULL, *clear = NULL, *reconfig_flags;
	u8 *attr_start, *attr_end;
	size_t clear_len, attr_len, len[2];
	const u8 *addr[2];
	u8 *wrapped;

	reconfig_flags = dpp_build_reconfig_flags(DPP_CONFIG_REPLACEKEY);
	if (!reconfig_flags)
		goto fail;

	/* Build DPP Reconfig Authentication Confirm frame attributes */
	clear_len = 4 + 1 + 4 + 1 + 2 * (4 + auth->curve->nonce_len) +
		4 + wpabuf_len(reconfig_flags);
	clear = wpabuf_alloc(clear_len);
	if (!clear)
		goto fail;

	/* Transaction ID */
	wpabuf_put_le16(clear, DPP_ATTR_TRANSACTION_ID);
	wpabuf_put_le16(clear, 1);
	wpabuf_put_u8(clear, auth->transaction_id);

	/* Protocol Version */
	wpabuf_put_le16(clear, DPP_ATTR_PROTOCOL_VERSION);
	wpabuf_put_le16(clear, 1);
	wpabuf_put_u8(clear, auth->peer_version);

	/* I-nonce (wrapped) */
	wpabuf_put_le16(clear, DPP_ATTR_I_NONCE);
	wpabuf_put_le16(clear, auth->curve->nonce_len);
	wpabuf_put_data(clear, auth->i_nonce, auth->curve->nonce_len);

	/* R-nonce (wrapped) */
	wpabuf_put_le16(clear, DPP_ATTR_R_NONCE);
	wpabuf_put_le16(clear, auth->curve->nonce_len);
	wpabuf_put_data(clear, auth->r_nonce, auth->curve->nonce_len);

	/* Reconfig-Flags (wrapped) */
	wpabuf_put_le16(clear, DPP_ATTR_RECONFIG_FLAGS);
	wpabuf_put_le16(clear, wpabuf_len(reconfig_flags));
	wpabuf_put_buf(clear, reconfig_flags);

	attr_len = 4 + wpabuf_len(clear) + AES_BLOCK_SIZE;
	msg = dpp_alloc_msg(DPP_PA_RECONFIG_AUTH_CONF, attr_len);
	if (!msg)
		goto fail;

	attr_start = wpabuf_put(msg, 0);
	attr_end = wpabuf_put(msg, 0);

	/* OUI, OUI type, Crypto Suite, DPP frame type */
	addr[0] = wpabuf_head_u8(msg) + 2;
	len[0] = 3 + 1 + 1 + 1;
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD[0]", addr[0], len[0]);

	/* Attributes before Wrapped Data */
	addr[1] = attr_start;
	len[1] = attr_end - attr_start;
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD[1]", addr[1], len[1]);

	/* Wrapped Data */
	wpabuf_put_le16(msg, DPP_ATTR_WRAPPED_DATA);
	wpabuf_put_le16(msg, wpabuf_len(clear) + AES_BLOCK_SIZE);
	wrapped = wpabuf_put(msg, wpabuf_len(clear) + AES_BLOCK_SIZE);

	wpa_hexdump_buf(MSG_DEBUG, "DPP: AES-SIV cleartext", clear);
	if (aes_siv_encrypt(auth->ke, auth->curve->hash_len,
			    wpabuf_head(clear), wpabuf_len(clear),
			    2, addr, len, wrapped) < 0)
		goto fail;

	wpa_hexdump_buf(MSG_DEBUG,
			"DPP: Reconfig Authentication Confirm frame attributes",
			msg);

out:
	wpabuf_free(reconfig_flags);
	wpabuf_free(clear);
	return msg;
fail:
	wpabuf_free(msg);
	msg = NULL;
	goto out;
}


struct wpabuf *
dpp_reconfig_auth_resp_rx(struct dpp_authentication *auth, const u8 *hdr,
			 const u8 *attr_start, size_t attr_len)
{
	const u8 *trans_id, *version, *r_connector, *r_proto, *wrapped_data,
		*i_nonce, *r_nonce, *conn_status;
	u16 trans_id_len, version_len, r_connector_len, r_proto_len,
		wrapped_data_len, i_nonce_len, r_nonce_len, conn_status_len;
	struct wpabuf *conf = NULL;
	char *signed_connector = NULL;
	struct dpp_signed_connector_info info;
	enum dpp_status_error res;
	struct json_token *root = NULL, *token, *conn_status_json = NULL;
	const u8 *addr[2];
	size_t len[2];
	u8 *unwrapped = NULL;
	size_t unwrapped_len = 0;

	os_memset(&info, 0, sizeof(info));

	if (!auth->reconfig || !auth->configurator)
		goto fail;

	wrapped_data = dpp_get_attr(attr_start, attr_len, DPP_ATTR_WRAPPED_DATA,
				    &wrapped_data_len);
	if (!wrapped_data || wrapped_data_len < AES_BLOCK_SIZE) {
		dpp_auth_fail(auth,
			      "Missing or invalid required Wrapped Data attribute");
		goto fail;
	}
	wpa_hexdump(MSG_MSGDUMP, "DPP: Wrapped Data",
		    wrapped_data, wrapped_data_len);
	attr_len = wrapped_data - 4 - attr_start;

	trans_id = dpp_get_attr(attr_start, attr_len, DPP_ATTR_TRANSACTION_ID,
			       &trans_id_len);
	if (!trans_id || trans_id_len != 1) {
		dpp_auth_fail(auth, "Peer did not include Transaction ID");
		goto fail;
	}
	if (trans_id[0] != auth->transaction_id) {
		dpp_auth_fail(auth, "Transaction ID mismatch");
		goto fail;
	}

	version = dpp_get_attr(attr_start, attr_len, DPP_ATTR_PROTOCOL_VERSION,
			       &version_len);
	if (!version || version_len < 1 || version[0] < 2) {
		dpp_auth_fail(auth,
			      "Missing or invalid Protocol Version attribute");
		goto fail;
	}
	auth->peer_version = version[0];
	wpa_printf(MSG_DEBUG, "DPP: Peer protocol version %u",
		   auth->peer_version);

	r_connector = dpp_get_attr(attr_start, attr_len, DPP_ATTR_CONNECTOR,
				   &r_connector_len);
	if (!r_connector) {
		dpp_auth_fail(auth, " Missing R-Connector attribute");
		goto fail;
	}
	wpa_hexdump_ascii(MSG_DEBUG, "DPP: R-Connector",
			  r_connector, r_connector_len);

	r_proto = dpp_get_attr(attr_start, attr_len, DPP_ATTR_R_PROTOCOL_KEY,
			       &r_proto_len);
	if (!r_proto) {
		dpp_auth_fail(auth,
			      "Missing required Responder Protocol Key attribute");
		goto fail;
	}
	wpa_hexdump(MSG_MSGDUMP, "DPP: Responder Protocol Key",
		    r_proto, r_proto_len);

	signed_connector = os_malloc(r_connector_len + 1);
	if (!signed_connector)
		goto fail;
	os_memcpy(signed_connector, r_connector, r_connector_len);
	signed_connector[r_connector_len] = '\0';

	res = dpp_process_signed_connector(&info, auth->conf->csign,
					   signed_connector);
	if (res != DPP_STATUS_OK) {
		dpp_auth_fail(auth, "Invalid R-Connector");
		goto fail;
	}

	root = json_parse((const char *) info.payload, info.payload_len);
	if (!root) {
		dpp_auth_fail(auth, "Invalid Connector payload");
		goto fail;
	}

	/* Do not check netAccessKey expiration for reconfiguration to allow
	 * expired Connector to be updated. */

	token = json_get_member(root, "netAccessKey");
	if (!token || token->type != JSON_OBJECT) {
		dpp_auth_fail(auth, "No netAccessKey object found");
		goto fail;
	}

	if (dpp_reconfig_derive_ke_initiator(auth, r_proto, r_proto_len,
					     token) < 0)
		goto fail;

	addr[0] = hdr;
	len[0] = DPP_HDR_LEN;
	addr[1] = attr_start;
	len[1] = attr_len;
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD[0]", addr[0], len[0]);
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD[1]", addr[1], len[1]);
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped_data, wrapped_data_len);
	unwrapped_len = wrapped_data_len - AES_BLOCK_SIZE;
	unwrapped = os_malloc(unwrapped_len);
	if (!unwrapped)
		goto fail;
	if (aes_siv_decrypt(auth->ke, auth->curve->hash_len,
			    wrapped_data, wrapped_data_len,
			    2, addr, len, unwrapped) < 0) {
		dpp_auth_fail(auth, "AES-SIV decryption failed");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV cleartext",
		    unwrapped, unwrapped_len);

	if (dpp_check_attrs(unwrapped, unwrapped_len) < 0) {
		dpp_auth_fail(auth, "Invalid attribute in unwrapped data");
		goto fail;
	}

	i_nonce = dpp_get_attr(unwrapped, unwrapped_len, DPP_ATTR_I_NONCE,
			       &i_nonce_len);
	if (!i_nonce || i_nonce_len != auth->curve->nonce_len ||
	    os_memcmp(i_nonce, auth->i_nonce, i_nonce_len) != 0) {
		dpp_auth_fail(auth, "Missing or invalid I-nonce");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: I-nonce", i_nonce, i_nonce_len);

	r_nonce = dpp_get_attr(unwrapped, unwrapped_len, DPP_ATTR_R_NONCE,
			       &r_nonce_len);
	if (!r_nonce || r_nonce_len != auth->curve->nonce_len) {
		dpp_auth_fail(auth, "Missing or invalid R-nonce");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: R-nonce", r_nonce, r_nonce_len);
	os_memcpy(auth->r_nonce, r_nonce, r_nonce_len);

	conn_status = dpp_get_attr(unwrapped, unwrapped_len,
				   DPP_ATTR_CONN_STATUS, &conn_status_len);
	if (!conn_status) {
		dpp_auth_fail(auth, "Missing Connection Status attribute");
		goto fail;
	}
	wpa_hexdump_ascii(MSG_DEBUG, "DPP: connStatus",
			  conn_status, conn_status_len);

	conn_status_json = json_parse((const char *) conn_status,
				      conn_status_len);
	if (!conn_status_json) {
		dpp_auth_fail(auth, "Could not parse connStatus");
		goto fail;
	}
	/* TODO: use connStatus information */

	conf = dpp_reconfig_build_conf(auth);
	if (conf)
		auth->reconfig_success = true;

out:
	json_free(root);
	json_free(conn_status_json);
	bin_clear_free(unwrapped, unwrapped_len);
	os_free(info.payload);
	os_free(signed_connector);
	return conf;
fail:
	wpabuf_free(conf);
	conf = NULL;
	goto out;
}


int dpp_reconfig_auth_conf_rx(struct dpp_authentication *auth, const u8 *hdr,
			      const u8 *attr_start, size_t attr_len)
{
	const u8 *trans_id, *version, *wrapped_data, *i_nonce, *r_nonce,
		*reconfig_flags;
	u16 trans_id_len, version_len, wrapped_data_len, i_nonce_len,
		r_nonce_len, reconfig_flags_len;
	const u8 *addr[2];
	size_t len[2];
	u8 *unwrapped = NULL;
	size_t unwrapped_len = 0;
	struct json_token *root = NULL, *token;
	int res = -1;

	if (!auth->reconfig || auth->configurator)
		goto fail;

	wrapped_data = dpp_get_attr(attr_start, attr_len, DPP_ATTR_WRAPPED_DATA,
				    &wrapped_data_len);
	if (!wrapped_data || wrapped_data_len < AES_BLOCK_SIZE) {
		dpp_auth_fail(auth,
			      "Missing or invalid required Wrapped Data attribute");
		goto fail;
	}
	wpa_hexdump(MSG_MSGDUMP, "DPP: Wrapped Data",
		    wrapped_data, wrapped_data_len);

	addr[0] = hdr;
	len[0] = DPP_HDR_LEN;
	addr[1] = attr_start;
	len[1] = 0;
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD[0]", addr[0], len[0]);
	wpa_hexdump(MSG_DEBUG, "DDP: AES-SIV AD[1]", addr[1], len[1]);
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV ciphertext",
		    wrapped_data, wrapped_data_len);
	unwrapped_len = wrapped_data_len - AES_BLOCK_SIZE;
	unwrapped = os_malloc(unwrapped_len);
	if (!unwrapped)
		goto fail;
	if (aes_siv_decrypt(auth->ke, auth->curve->hash_len,
			    wrapped_data, wrapped_data_len,
			    2, addr, len, unwrapped) < 0) {
		dpp_auth_fail(auth, "AES-SIV decryption failed");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: AES-SIV cleartext",
		    unwrapped, unwrapped_len);

	if (dpp_check_attrs(unwrapped, unwrapped_len) < 0) {
		dpp_auth_fail(auth, "Invalid attribute in unwrapped data");
		goto fail;
	}

	trans_id = dpp_get_attr(unwrapped, unwrapped_len,
				DPP_ATTR_TRANSACTION_ID, &trans_id_len);
	if (!trans_id || trans_id_len != 1 ||
	    trans_id[0] != auth->transaction_id) {
		dpp_auth_fail(auth,
			      "Peer did not include valid Transaction ID");
		goto fail;
	}

	version = dpp_get_attr(unwrapped, unwrapped_len,
			       DPP_ATTR_PROTOCOL_VERSION, &version_len);
	if (!version || version_len < 1 || version[0] != DPP_VERSION) {
		dpp_auth_fail(auth,
			      "Missing or invalid Protocol Version attribute");
		goto fail;
	}

	i_nonce = dpp_get_attr(unwrapped, unwrapped_len, DPP_ATTR_I_NONCE,
			       &i_nonce_len);
	if (!i_nonce || i_nonce_len != auth->curve->nonce_len ||
	    os_memcmp(i_nonce, auth->i_nonce, i_nonce_len) != 0) {
		dpp_auth_fail(auth, "Missing or invalid I-nonce");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: I-nonce", i_nonce, i_nonce_len);

	r_nonce = dpp_get_attr(unwrapped, unwrapped_len, DPP_ATTR_R_NONCE,
			       &r_nonce_len);
	if (!r_nonce || r_nonce_len != auth->curve->nonce_len ||
	    os_memcmp(r_nonce, auth->r_nonce, r_nonce_len) != 0) {
		dpp_auth_fail(auth, "Missing or invalid R-nonce");
		goto fail;
	}
	wpa_hexdump(MSG_DEBUG, "DPP: R-nonce", r_nonce, r_nonce_len);

	reconfig_flags = dpp_get_attr(unwrapped, unwrapped_len,
				      DPP_ATTR_RECONFIG_FLAGS,
				      &reconfig_flags_len);
	if (!reconfig_flags) {
		dpp_auth_fail(auth, "Missing or invalid Reconfig-Flags");
		goto fail;
	}
	wpa_hexdump_ascii(MSG_DEBUG, "DPP: Reconfig-Flags",
			  reconfig_flags, reconfig_flags_len);
	root = json_parse((const char *) reconfig_flags, reconfig_flags_len);
	if (!root) {
		dpp_auth_fail(auth, "Could not parse Reconfig-Flags");
		goto fail;
	}
	token = json_get_member(root, "connectorKey");
	if (!token || token->type != JSON_NUMBER) {
		dpp_auth_fail(auth, "No connectorKey in Reconfig-Flags");
		goto fail;
	}
	if (token->number != DPP_CONFIG_REUSEKEY &&
	    token->number != DPP_CONFIG_REPLACEKEY) {
		dpp_auth_fail(auth,
			      "Unsupported connectorKey value in Reconfig-Flags");
		goto fail;
	}
	auth->reconfig_connector_key = token->number;

	auth->reconfig_success = true;
	res = 0;
fail:
	json_free(root);
	bin_clear_free(unwrapped, unwrapped_len);
	return res;
}

#endif /* CONFIG_DPP2 */
