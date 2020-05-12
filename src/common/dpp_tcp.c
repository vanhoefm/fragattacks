/*
 * DPP over TCP
 * Copyright (c) 2019-2020, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include <fcntl.h>

#include "utils/common.h"
#include "utils/ip_addr.h"
#include "utils/eloop.h"
#include "common/ieee802_11_common.h"
#include "common/wpa_ctrl.h"
#include "dpp.h"
#include "dpp_i.h"

#ifdef CONFIG_DPP2

struct dpp_connection {
	struct dl_list list;
	struct dpp_controller *ctrl;
	struct dpp_relay_controller *relay;
	struct dpp_global *global;
	struct dpp_authentication *auth;
	int sock;
	u8 mac_addr[ETH_ALEN];
	unsigned int freq;
	u8 msg_len[4];
	size_t msg_len_octets;
	struct wpabuf *msg;
	struct wpabuf *msg_out;
	size_t msg_out_pos;
	unsigned int read_eloop:1;
	unsigned int write_eloop:1;
	unsigned int on_tcp_tx_complete_gas_done:1;
	unsigned int on_tcp_tx_complete_remove:1;
	unsigned int on_tcp_tx_complete_auth_ok:1;
};

/* Remote Controller */
struct dpp_relay_controller {
	struct dl_list list;
	struct dpp_global *global;
	u8 pkhash[SHA256_MAC_LEN];
	struct hostapd_ip_addr ipaddr;
	void *cb_ctx;
	void (*tx)(void *ctx, const u8 *addr, unsigned int freq, const u8 *msg,
		   size_t len);
	void (*gas_resp_tx)(void *ctx, const u8 *addr, u8 dialog_token,
			    int prot, struct wpabuf *buf);
	struct dl_list conn; /* struct dpp_connection */
};

/* Local Controller */
struct dpp_controller {
	struct dpp_global *global;
	u8 allowed_roles;
	int qr_mutual;
	int sock;
	struct dl_list conn; /* struct dpp_connection */
	char *configurator_params;
};

static void dpp_controller_rx(int sd, void *eloop_ctx, void *sock_ctx);
static void dpp_conn_tx_ready(int sock, void *eloop_ctx, void *sock_ctx);
static void dpp_controller_auth_success(struct dpp_connection *conn,
					int initiator);


static void dpp_connection_free(struct dpp_connection *conn)
{
	if (conn->sock >= 0) {
		wpa_printf(MSG_DEBUG, "DPP: Close Controller socket %d",
			   conn->sock);
		eloop_unregister_sock(conn->sock, EVENT_TYPE_READ);
		eloop_unregister_sock(conn->sock, EVENT_TYPE_WRITE);
		close(conn->sock);
	}
	eloop_cancel_timeout(dpp_controller_conn_status_result_wait_timeout,
			     conn, NULL);
	wpabuf_free(conn->msg);
	wpabuf_free(conn->msg_out);
	dpp_auth_deinit(conn->auth);
	os_free(conn);
}


static void dpp_connection_remove(struct dpp_connection *conn)
{
	dl_list_del(&conn->list);
	dpp_connection_free(conn);
}


int dpp_relay_add_controller(struct dpp_global *dpp,
			     struct dpp_relay_config *config)
{
	struct dpp_relay_controller *ctrl;

	if (!dpp)
		return -1;

	ctrl = os_zalloc(sizeof(*ctrl));
	if (!ctrl)
		return -1;
	dl_list_init(&ctrl->conn);
	ctrl->global = dpp;
	os_memcpy(&ctrl->ipaddr, config->ipaddr, sizeof(*config->ipaddr));
	os_memcpy(ctrl->pkhash, config->pkhash, SHA256_MAC_LEN);
	ctrl->cb_ctx = config->cb_ctx;
	ctrl->tx = config->tx;
	ctrl->gas_resp_tx = config->gas_resp_tx;
	dl_list_add(&dpp->controllers, &ctrl->list);
	return 0;
}


static struct dpp_relay_controller *
dpp_relay_controller_get(struct dpp_global *dpp, const u8 *pkhash)
{
	struct dpp_relay_controller *ctrl;

	if (!dpp)
		return NULL;

	dl_list_for_each(ctrl, &dpp->controllers, struct dpp_relay_controller,
			 list) {
		if (os_memcmp(pkhash, ctrl->pkhash, SHA256_MAC_LEN) == 0)
			return ctrl;
	}

	return NULL;
}


static void dpp_controller_gas_done(struct dpp_connection *conn)
{
	struct dpp_authentication *auth = conn->auth;
	void *msg_ctx;

	if (auth->peer_version >= 2 &&
	    auth->conf_resp_status == DPP_STATUS_OK) {
		wpa_printf(MSG_DEBUG, "DPP: Wait for Configuration Result");
		auth->waiting_conf_result = 1;
		return;
	}

	if (conn->ctrl)
		msg_ctx = conn->ctrl->global->msg_ctx;
	else
		msg_ctx = auth->msg_ctx;
	wpa_msg(msg_ctx, MSG_INFO, DPP_EVENT_CONF_SENT);
	dpp_connection_remove(conn);
}


static int dpp_tcp_send(struct dpp_connection *conn)
{
	int res;

	if (!conn->msg_out) {
		eloop_unregister_sock(conn->sock, EVENT_TYPE_WRITE);
		conn->write_eloop = 0;
		return -1;
	}
	res = send(conn->sock,
		   wpabuf_head_u8(conn->msg_out) + conn->msg_out_pos,
		   wpabuf_len(conn->msg_out) - conn->msg_out_pos, 0);
	if (res < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Failed to send buffer: %s",
			   strerror(errno));
		dpp_connection_remove(conn);
		return -1;
	}

	conn->msg_out_pos += res;
	if (wpabuf_len(conn->msg_out) > conn->msg_out_pos) {
		wpa_printf(MSG_DEBUG,
			   "DPP: %u/%u bytes of message sent to Controller",
			   (unsigned int) conn->msg_out_pos,
			   (unsigned int) wpabuf_len(conn->msg_out));
		if (!conn->write_eloop &&
		    eloop_register_sock(conn->sock, EVENT_TYPE_WRITE,
					dpp_conn_tx_ready, conn, NULL) == 0)
			conn->write_eloop = 1;
		return 1;
	}

	wpa_printf(MSG_DEBUG, "DPP: Full message sent over TCP");
	wpabuf_free(conn->msg_out);
	conn->msg_out = NULL;
	conn->msg_out_pos = 0;
	eloop_unregister_sock(conn->sock, EVENT_TYPE_WRITE);
	conn->write_eloop = 0;
	if (!conn->read_eloop &&
	    eloop_register_sock(conn->sock, EVENT_TYPE_READ,
				dpp_controller_rx, conn, NULL) == 0)
		conn->read_eloop = 1;
	if (conn->on_tcp_tx_complete_remove) {
		dpp_connection_remove(conn);
	} else if (conn->auth && (conn->ctrl || conn->auth->configurator) &&
		   conn->on_tcp_tx_complete_gas_done) {
		dpp_controller_gas_done(conn);
	} else if (conn->on_tcp_tx_complete_auth_ok) {
		conn->on_tcp_tx_complete_auth_ok = 0;
		dpp_controller_auth_success(conn, 1);
	}

	return 0;
}


static int dpp_tcp_send_msg(struct dpp_connection *conn,
			    const struct wpabuf *msg)
{
	wpabuf_free(conn->msg_out);
	conn->msg_out_pos = 0;
	conn->msg_out = wpabuf_alloc(4 + wpabuf_len(msg) - 1);
	if (!conn->msg_out)
		return -1;
	wpabuf_put_be32(conn->msg_out, wpabuf_len(msg) - 1);
	wpabuf_put_data(conn->msg_out, wpabuf_head_u8(msg) + 1,
			wpabuf_len(msg) - 1);

	if (dpp_tcp_send(conn) == 1) {
		if (!conn->write_eloop) {
			if (eloop_register_sock(conn->sock, EVENT_TYPE_WRITE,
						dpp_conn_tx_ready,
						conn, NULL) < 0)
				return -1;
			conn->write_eloop = 1;
		}
	}

	return 0;
}


static void dpp_controller_start_gas_client(struct dpp_connection *conn)
{
	struct dpp_authentication *auth = conn->auth;
	struct wpabuf *buf;
	int netrole_ap = 0; /* TODO: make this configurable */

	buf = dpp_build_conf_req_helper(auth, "Test", netrole_ap, NULL, NULL);
	if (!buf) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No configuration request data available");
		return;
	}

	dpp_tcp_send_msg(conn, buf);
	wpabuf_free(buf);
}


static void dpp_controller_auth_success(struct dpp_connection *conn,
					int initiator)
{
	struct dpp_authentication *auth = conn->auth;

	if (!auth)
		return;

	wpa_printf(MSG_DEBUG, "DPP: Authentication succeeded");
	wpa_msg(conn->global->msg_ctx, MSG_INFO,
		DPP_EVENT_AUTH_SUCCESS "init=%d", initiator);
#ifdef CONFIG_TESTING_OPTIONS
	if (dpp_test == DPP_TEST_STOP_AT_AUTH_CONF) {
		wpa_printf(MSG_INFO,
			   "DPP: TESTING - stop at Authentication Confirm");
		if (auth->configurator) {
			/* Prevent GAS response */
			auth->auth_success = 0;
		}
		return;
	}
#endif /* CONFIG_TESTING_OPTIONS */

	if (!auth->configurator)
		dpp_controller_start_gas_client(conn);
}


static void dpp_conn_tx_ready(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct dpp_connection *conn = eloop_ctx;

	wpa_printf(MSG_DEBUG, "DPP: TCP socket %d ready for TX", sock);
	dpp_tcp_send(conn);
}


static int dpp_ipaddr_to_sockaddr(struct sockaddr *addr, socklen_t *addrlen,
				  const struct hostapd_ip_addr *ipaddr,
				  int port)
{
	struct sockaddr_in *dst;
#ifdef CONFIG_IPV6
	struct sockaddr_in6 *dst6;
#endif /* CONFIG_IPV6 */

	switch (ipaddr->af) {
	case AF_INET:
		dst = (struct sockaddr_in *) addr;
		os_memset(dst, 0, sizeof(*dst));
		dst->sin_family = AF_INET;
		dst->sin_addr.s_addr = ipaddr->u.v4.s_addr;
		dst->sin_port = htons(port);
		*addrlen = sizeof(*dst);
		break;
#ifdef CONFIG_IPV6
	case AF_INET6:
		dst6 = (struct sockaddr_in6 *) addr;
		os_memset(dst6, 0, sizeof(*dst6));
		dst6->sin6_family = AF_INET6;
		os_memcpy(&dst6->sin6_addr, &ipaddr->u.v6,
			  sizeof(struct in6_addr));
		dst6->sin6_port = htons(port);
		*addrlen = sizeof(*dst6);
		break;
#endif /* CONFIG_IPV6 */
	default:
		return -1;
	}

	return 0;
}


static struct dpp_connection *
dpp_relay_new_conn(struct dpp_relay_controller *ctrl, const u8 *src,
		   unsigned int freq)
{
	struct dpp_connection *conn;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	char txt[100];

	if (dl_list_len(&ctrl->conn) >= 15) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Too many ongoing Relay connections to the Controller - cannot start a new one");
		return NULL;
	}

	if (dpp_ipaddr_to_sockaddr((struct sockaddr *) &addr, &addrlen,
				   &ctrl->ipaddr, DPP_TCP_PORT) < 0)
		return NULL;

	conn = os_zalloc(sizeof(*conn));
	if (!conn)
		return NULL;

	conn->global = ctrl->global;
	conn->relay = ctrl;
	os_memcpy(conn->mac_addr, src, ETH_ALEN);
	conn->freq = freq;

	conn->sock = socket(AF_INET, SOCK_STREAM, 0);
	if (conn->sock < 0)
		goto fail;
	wpa_printf(MSG_DEBUG, "DPP: TCP relay socket %d connection to %s",
		   conn->sock, hostapd_ip_txt(&ctrl->ipaddr, txt, sizeof(txt)));

	if (fcntl(conn->sock, F_SETFL, O_NONBLOCK) != 0) {
		wpa_printf(MSG_DEBUG, "DPP: fnctl(O_NONBLOCK) failed: %s",
			   strerror(errno));
		goto fail;
	}

	if (connect(conn->sock, (struct sockaddr *) &addr, addrlen) < 0) {
		if (errno != EINPROGRESS) {
			wpa_printf(MSG_DEBUG, "DPP: Failed to connect: %s",
				   strerror(errno));
			goto fail;
		}

		/*
		 * Continue connecting in the background; eloop will call us
		 * once the connection is ready (or failed).
		 */
	}

	if (eloop_register_sock(conn->sock, EVENT_TYPE_WRITE,
				dpp_conn_tx_ready, conn, NULL) < 0)
		goto fail;
	conn->write_eloop = 1;

	/* TODO: eloop timeout to clear a connection if it does not complete
	 * properly */

	dl_list_add(&ctrl->conn, &conn->list);
	return conn;
fail:
	dpp_connection_free(conn);
	return NULL;
}


static struct wpabuf * dpp_tcp_encaps(const u8 *hdr, const u8 *buf, size_t len)
{
	struct wpabuf *msg;

	msg = wpabuf_alloc(4 + 1 + DPP_HDR_LEN + len);
	if (!msg)
		return NULL;
	wpabuf_put_be32(msg, 1 + DPP_HDR_LEN + len);
	wpabuf_put_u8(msg, WLAN_PA_VENDOR_SPECIFIC);
	wpabuf_put_data(msg, hdr, DPP_HDR_LEN);
	wpabuf_put_data(msg, buf, len);
	wpa_hexdump_buf(MSG_MSGDUMP, "DPP: Outgoing TCP message", msg);
	return msg;
}


static int dpp_relay_tx(struct dpp_connection *conn, const u8 *hdr,
			const u8 *buf, size_t len)
{
	u8 type = hdr[DPP_HDR_LEN - 1];

	wpa_printf(MSG_DEBUG,
		   "DPP: Continue already established Relay/Controller connection for this session");
	wpabuf_free(conn->msg_out);
	conn->msg_out_pos = 0;
	conn->msg_out = dpp_tcp_encaps(hdr, buf, len);
	if (!conn->msg_out) {
		dpp_connection_remove(conn);
		return -1;
	}

	/* TODO: for proto ver 1, need to do remove connection based on GAS Resp
	 * TX status */
	if (type == DPP_PA_CONFIGURATION_RESULT)
		conn->on_tcp_tx_complete_remove = 1;
	dpp_tcp_send(conn);
	return 0;
}


int dpp_relay_rx_action(struct dpp_global *dpp, const u8 *src, const u8 *hdr,
			const u8 *buf, size_t len, unsigned int freq,
			const u8 *i_bootstrap, const u8 *r_bootstrap)
{
	struct dpp_relay_controller *ctrl;
	struct dpp_connection *conn;
	u8 type = hdr[DPP_HDR_LEN - 1];

	/* Check if there is an already started session for this peer and if so,
	 * continue that session (send this over TCP) and return 0.
	 */
	if (type != DPP_PA_PEER_DISCOVERY_REQ &&
	    type != DPP_PA_PEER_DISCOVERY_RESP &&
	    type != DPP_PA_PRESENCE_ANNOUNCEMENT &&
	    type != DPP_PA_RECONFIG_ANNOUNCEMENT) {
		dl_list_for_each(ctrl, &dpp->controllers,
				 struct dpp_relay_controller, list) {
			dl_list_for_each(conn, &ctrl->conn,
					 struct dpp_connection, list) {
				if (os_memcmp(src, conn->mac_addr,
					      ETH_ALEN) == 0)
					return dpp_relay_tx(conn, hdr, buf, len);
			}
		}
	}

	if (type == DPP_PA_PRESENCE_ANNOUNCEMENT ||
	    type == DPP_PA_RECONFIG_ANNOUNCEMENT) {
		/* TODO: Could send this to all configured Controllers. For now,
		 * only the first Controller is supported. */
		ctrl = dl_list_first(&dpp->controllers,
				     struct dpp_relay_controller, list);
	} else {
		if (!r_bootstrap)
			return -1;
		ctrl = dpp_relay_controller_get(dpp, r_bootstrap);
	}
	if (!ctrl)
		return -1;

	wpa_printf(MSG_DEBUG,
		   "DPP: Authentication Request for a configured Controller");
	conn = dpp_relay_new_conn(ctrl, src, freq);
	if (!conn)
		return -1;

	conn->msg_out = dpp_tcp_encaps(hdr, buf, len);
	if (!conn->msg_out) {
		dpp_connection_remove(conn);
		return -1;
	}
	/* Message will be sent in dpp_conn_tx_ready() */

	return 0;
}


int dpp_relay_rx_gas_req(struct dpp_global *dpp, const u8 *src, const u8 *data,
			 size_t data_len)
{
	struct dpp_relay_controller *ctrl;
	struct dpp_connection *conn, *found = NULL;
	struct wpabuf *msg;

	/* Check if there is a successfully completed authentication for this
	 * and if so, continue that session (send this over TCP) and return 0.
	 */
	dl_list_for_each(ctrl, &dpp->controllers,
			 struct dpp_relay_controller, list) {
		if (found)
			break;
		dl_list_for_each(conn, &ctrl->conn,
				 struct dpp_connection, list) {
			if (os_memcmp(src, conn->mac_addr,
				      ETH_ALEN) == 0) {
				found = conn;
				break;
			}
		}
	}

	if (!found)
		return -1;

	msg = wpabuf_alloc(4 + 1 + data_len);
	if (!msg)
		return -1;
	wpabuf_put_be32(msg, 1 + data_len);
	wpabuf_put_u8(msg, WLAN_PA_GAS_INITIAL_REQ);
	wpabuf_put_data(msg, data, data_len);
	wpa_hexdump_buf(MSG_MSGDUMP, "DPP: Outgoing TCP message", msg);

	wpabuf_free(conn->msg_out);
	conn->msg_out_pos = 0;
	conn->msg_out = msg;
	dpp_tcp_send(conn);
	return 0;
}


static void dpp_controller_free(struct dpp_controller *ctrl)
{
	struct dpp_connection *conn, *tmp;

	if (!ctrl)
		return;

	dl_list_for_each_safe(conn, tmp, &ctrl->conn, struct dpp_connection,
			      list)
		dpp_connection_remove(conn);

	if (ctrl->sock >= 0) {
		close(ctrl->sock);
		eloop_unregister_sock(ctrl->sock, EVENT_TYPE_READ);
	}
	os_free(ctrl->configurator_params);
	os_free(ctrl);
}


static int dpp_controller_rx_auth_req(struct dpp_connection *conn,
				      const u8 *hdr, const u8 *buf, size_t len)
{
	const u8 *r_bootstrap, *i_bootstrap;
	u16 r_bootstrap_len, i_bootstrap_len;
	struct dpp_bootstrap_info *own_bi = NULL, *peer_bi = NULL;

	if (!conn->ctrl)
		return 0;

	wpa_printf(MSG_DEBUG, "DPP: Authentication Request");

	r_bootstrap = dpp_get_attr(buf, len, DPP_ATTR_R_BOOTSTRAP_KEY_HASH,
				   &r_bootstrap_len);
	if (!r_bootstrap || r_bootstrap_len != SHA256_MAC_LEN) {
		wpa_printf(MSG_INFO,
			   "Missing or invalid required Responder Bootstrapping Key Hash attribute");
		return -1;
	}
	wpa_hexdump(MSG_MSGDUMP, "DPP: Responder Bootstrapping Key Hash",
		    r_bootstrap, r_bootstrap_len);

	i_bootstrap = dpp_get_attr(buf, len, DPP_ATTR_I_BOOTSTRAP_KEY_HASH,
				   &i_bootstrap_len);
	if (!i_bootstrap || i_bootstrap_len != SHA256_MAC_LEN) {
		wpa_printf(MSG_INFO,
			   "Missing or invalid required Initiator Bootstrapping Key Hash attribute");
		return -1;
	}
	wpa_hexdump(MSG_MSGDUMP, "DPP: Initiator Bootstrapping Key Hash",
		    i_bootstrap, i_bootstrap_len);

	/* Try to find own and peer bootstrapping key matches based on the
	 * received hash values */
	dpp_bootstrap_find_pair(conn->ctrl->global, i_bootstrap, r_bootstrap,
				&own_bi, &peer_bi);
	if (!own_bi) {
		wpa_printf(MSG_INFO,
			"No matching own bootstrapping key found - ignore message");
		return -1;
	}

	if (conn->auth) {
		wpa_printf(MSG_INFO,
			   "Already in DPP authentication exchange - ignore new one");
		return 0;
	}

	conn->auth = dpp_auth_req_rx(conn->ctrl->global,
				     conn->ctrl->global->msg_ctx,
				     conn->ctrl->allowed_roles,
				     conn->ctrl->qr_mutual,
				     peer_bi, own_bi, -1, hdr, buf, len);
	if (!conn->auth) {
		wpa_printf(MSG_DEBUG, "DPP: No response generated");
		return -1;
	}

	if (dpp_set_configurator(conn->auth,
				 conn->ctrl->configurator_params) < 0) {
		dpp_connection_remove(conn);
		return -1;
	}

	return dpp_tcp_send_msg(conn, conn->auth->resp_msg);
}


static int dpp_controller_rx_auth_resp(struct dpp_connection *conn,
				       const u8 *hdr, const u8 *buf, size_t len)
{
	struct dpp_authentication *auth = conn->auth;
	struct wpabuf *msg;
	int res;

	if (!auth)
		return -1;

	wpa_printf(MSG_DEBUG, "DPP: Authentication Response");

	msg = dpp_auth_resp_rx(auth, hdr, buf, len);
	if (!msg) {
		if (auth->auth_resp_status == DPP_STATUS_RESPONSE_PENDING) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Start wait for full response");
			return -1;
		}
		wpa_printf(MSG_DEBUG, "DPP: No confirm generated");
		dpp_connection_remove(conn);
		return -1;
	}

	conn->on_tcp_tx_complete_auth_ok = 1;
	res = dpp_tcp_send_msg(conn, msg);
	wpabuf_free(msg);
	return res;
}


static int dpp_controller_rx_auth_conf(struct dpp_connection *conn,
				       const u8 *hdr, const u8 *buf, size_t len)
{
	struct dpp_authentication *auth = conn->auth;

	wpa_printf(MSG_DEBUG, "DPP: Authentication Confirmation");

	if (!auth) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No DPP Authentication in progress - drop");
		return -1;
	}

	if (dpp_auth_conf_rx(auth, hdr, buf, len) < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Authentication failed");
		return -1;
	}

	dpp_controller_auth_success(conn, 0);
	return 0;
}


void dpp_controller_conn_status_result_wait_timeout(void *eloop_ctx,
						    void *timeout_ctx)
{
	struct dpp_connection *conn = eloop_ctx;

	if (!conn->auth->waiting_conf_result)
		return;

	wpa_printf(MSG_DEBUG,
		   "DPP: Timeout while waiting for Connection Status Result");
	wpa_msg(conn->ctrl->global->msg_ctx, MSG_INFO,
		DPP_EVENT_CONN_STATUS_RESULT "timeout");
	dpp_connection_remove(conn);
}


static int dpp_controller_rx_conf_result(struct dpp_connection *conn,
					 const u8 *hdr, const u8 *buf,
					 size_t len)
{
	struct dpp_authentication *auth = conn->auth;
	enum dpp_status_error status;
	void *msg_ctx;

	if (!conn->ctrl && (!auth || !auth->configurator))
		return 0;

	wpa_printf(MSG_DEBUG, "DPP: Configuration Result");

	if (!auth || !auth->waiting_conf_result) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No DPP Configuration waiting for result - drop");
		return -1;
	}
	if (conn->ctrl)
		msg_ctx = conn->ctrl->global->msg_ctx;
	else
		msg_ctx = auth->msg_ctx;

	status = dpp_conf_result_rx(auth, hdr, buf, len);
	if (status == DPP_STATUS_OK && auth->send_conn_status) {
		wpa_msg(msg_ctx, MSG_INFO,
			DPP_EVENT_CONF_SENT "wait_conn_status=1");
		wpa_printf(MSG_DEBUG, "DPP: Wait for Connection Status Result");
		eloop_cancel_timeout(
			dpp_controller_conn_status_result_wait_timeout,
			conn, NULL);
		eloop_register_timeout(
			16, 0, dpp_controller_conn_status_result_wait_timeout,
			conn, NULL);
		return 0;
	}
	if (status == DPP_STATUS_OK)
		wpa_msg(msg_ctx, MSG_INFO, DPP_EVENT_CONF_SENT);
	else
		wpa_msg(msg_ctx, MSG_INFO, DPP_EVENT_CONF_FAILED);
	return -1; /* to remove the completed connection */
}


static int dpp_controller_rx_conn_status_result(struct dpp_connection *conn,
						const u8 *hdr, const u8 *buf,
						size_t len)
{
	struct dpp_authentication *auth = conn->auth;
	enum dpp_status_error status;
	u8 ssid[SSID_MAX_LEN];
	size_t ssid_len = 0;
	char *channel_list = NULL;

	if (!conn->ctrl)
		return 0;

	wpa_printf(MSG_DEBUG, "DPP: Connection Status Result");

	if (!auth || !auth->waiting_conn_status_result) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No DPP Configuration waiting for connection status result - drop");
		return -1;
	}

	status = dpp_conn_status_result_rx(auth, hdr, buf, len,
					   ssid, &ssid_len, &channel_list);
	wpa_msg(conn->ctrl->global->msg_ctx, MSG_INFO,
		DPP_EVENT_CONN_STATUS_RESULT
		"result=%d ssid=%s channel_list=%s",
		status, wpa_ssid_txt(ssid, ssid_len),
		channel_list ? channel_list : "N/A");
	os_free(channel_list);
	return -1; /* to remove the completed connection */
}


static int dpp_controller_rx_presence_announcement(struct dpp_connection *conn,
						   const u8 *hdr, const u8 *buf,
						   size_t len)
{
	const u8 *r_bootstrap;
	u16 r_bootstrap_len;
	struct dpp_bootstrap_info *peer_bi;
	struct dpp_authentication *auth;
	struct dpp_global *dpp = conn->ctrl->global;

	if (conn->auth) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Ignore Presence Announcement during ongoing Authentication");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "DPP: Presence Announcement");

	r_bootstrap = dpp_get_attr(buf, len, DPP_ATTR_R_BOOTSTRAP_KEY_HASH,
				   &r_bootstrap_len);
	if (!r_bootstrap || r_bootstrap_len != SHA256_MAC_LEN) {
		wpa_msg(dpp->msg_ctx, MSG_INFO, DPP_EVENT_FAIL
			"Missing or invalid required Responder Bootstrapping Key Hash attribute");
		return -1;
	}
	wpa_hexdump(MSG_MSGDUMP, "DPP: Responder Bootstrapping Key Hash",
		    r_bootstrap, r_bootstrap_len);
	peer_bi = dpp_bootstrap_find_chirp(dpp, r_bootstrap);
	if (!peer_bi) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No matching bootstrapping information found");
		return -1;
	}

	auth = dpp_auth_init(dpp, dpp->msg_ctx, peer_bi, NULL,
			     DPP_CAPAB_CONFIGURATOR, -1, NULL, 0);
	if (!auth)
		return -1;
	if (dpp_set_configurator(auth, conn->ctrl->configurator_params) < 0) {
		dpp_auth_deinit(auth);
		dpp_connection_remove(conn);
		return -1;
	}

	conn->auth = auth;
	return dpp_tcp_send_msg(conn, conn->auth->req_msg);
}


static int dpp_controller_rx_reconfig_announcement(struct dpp_connection *conn,
						   const u8 *hdr, const u8 *buf,
						   size_t len)
{
	const u8 *csign_hash;
	u16 csign_hash_len;
	struct dpp_configurator *conf;
	struct dpp_global *dpp = conn->ctrl->global;
	struct dpp_authentication *auth;

	if (conn->auth) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Ignore Reconfig Announcement during ongoing Authentication");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "DPP: Reconfig Announcement");

	csign_hash = dpp_get_attr(buf, len, DPP_ATTR_C_SIGN_KEY_HASH,
				  &csign_hash_len);
	if (!csign_hash || csign_hash_len != SHA256_MAC_LEN) {
		wpa_msg(dpp->msg_ctx, MSG_INFO, DPP_EVENT_FAIL
			"Missing or invalid required Configurator C-sign key Hash attribute");
		return -1;
	}
	wpa_hexdump(MSG_MSGDUMP, "DPP: Configurator C-sign key Hash (kid)",
		    csign_hash, csign_hash_len);
	conf = dpp_configurator_find_kid(dpp, csign_hash);
	if (!conf) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No matching Configurator information found");
		return -1;
	}

	auth = dpp_reconfig_init(dpp, dpp->msg_ctx, conf, 0);
	if (!auth)
		return -1;
	if (dpp_set_configurator(auth, conn->ctrl->configurator_params) < 0) {
		dpp_auth_deinit(auth);
		return -1;
	}

	conn->auth = auth;
	return dpp_tcp_send_msg(conn, auth->reconfig_req_msg);
}


static int dpp_controller_rx_reconfig_auth_resp(struct dpp_connection *conn,
						const u8 *hdr, const u8 *buf,
						size_t len)
{
	struct dpp_authentication *auth = conn->auth;
	struct wpabuf *conf;
	int res;

	wpa_printf(MSG_DEBUG, "DPP: Reconfig Authentication Response");

	if (!auth || !auth->reconfig || !auth->configurator) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No DPP Reconfig Authentication in progress - drop");
		return -1;
	}

	conf = dpp_reconfig_auth_resp_rx(auth, hdr, buf, len);
	if (!conf)
		return -1;

	res = dpp_tcp_send_msg(conn, conf);
	wpabuf_free(conf);
	return res;
}


static int dpp_controller_rx_action(struct dpp_connection *conn, const u8 *msg,
				    size_t len)
{
	const u8 *pos, *end;
	u8 type;

	wpa_printf(MSG_DEBUG, "DPP: Received DPP Action frame over TCP");
	pos = msg;
	end = msg + len;

	if (end - pos < DPP_HDR_LEN ||
	    WPA_GET_BE24(pos) != OUI_WFA ||
	    pos[3] != DPP_OUI_TYPE) {
		wpa_printf(MSG_DEBUG, "DPP: Unrecognized header");
		return -1;
	}

	if (pos[4] != 1) {
		wpa_printf(MSG_DEBUG, "DPP: Unsupported Crypto Suite %u",
			   pos[4]);
		return -1;
	}
	type = pos[5];
	wpa_printf(MSG_DEBUG, "DPP: Received message type %u", type);
	pos += DPP_HDR_LEN;

	wpa_hexdump(MSG_MSGDUMP, "DPP: Received message attributes",
		    pos, end - pos);
	if (dpp_check_attrs(pos, end - pos) < 0)
		return -1;

	if (conn->relay) {
		wpa_printf(MSG_DEBUG, "DPP: Relay - send over WLAN");
		conn->relay->tx(conn->relay->cb_ctx, conn->mac_addr,
				conn->freq, msg, len);
		return 0;
	}

	switch (type) {
	case DPP_PA_AUTHENTICATION_REQ:
		return dpp_controller_rx_auth_req(conn, msg, pos, end - pos);
	case DPP_PA_AUTHENTICATION_RESP:
		return dpp_controller_rx_auth_resp(conn, msg, pos, end - pos);
	case DPP_PA_AUTHENTICATION_CONF:
		return dpp_controller_rx_auth_conf(conn, msg, pos, end - pos);
	case DPP_PA_CONFIGURATION_RESULT:
		return dpp_controller_rx_conf_result(conn, msg, pos, end - pos);
	case DPP_PA_CONNECTION_STATUS_RESULT:
		return dpp_controller_rx_conn_status_result(conn, msg, pos,
							    end - pos);
	case DPP_PA_PRESENCE_ANNOUNCEMENT:
		return dpp_controller_rx_presence_announcement(conn, msg, pos,
							       end - pos);
	case DPP_PA_RECONFIG_ANNOUNCEMENT:
		return dpp_controller_rx_reconfig_announcement(conn, msg, pos,
							       end - pos);
	case DPP_PA_RECONFIG_AUTH_RESP:
		return dpp_controller_rx_reconfig_auth_resp(conn, msg, pos,
							    end - pos);
	default:
		/* TODO: missing messages types */
		wpa_printf(MSG_DEBUG,
			   "DPP: Unsupported frame subtype %d", type);
		return -1;
	}
}


static int dpp_controller_rx_gas_req(struct dpp_connection *conn, const u8 *msg,
				     size_t len)
{
	const u8 *pos, *end, *next;
	u8 dialog_token;
	const u8 *adv_proto;
	u16 slen;
	struct wpabuf *resp, *buf;
	struct dpp_authentication *auth = conn->auth;

	if (len < 1 + 2)
		return -1;

	wpa_printf(MSG_DEBUG,
		   "DPP: Received DPP Configuration Request over TCP");

	if (!auth || (!conn->ctrl && !auth->configurator) ||
	    (!auth->auth_success && !auth->reconfig_success)) {
		wpa_printf(MSG_DEBUG, "DPP: No matching exchange in progress");
		return -1;
	}

	pos = msg;
	end = msg + len;

	dialog_token = *pos++;
	adv_proto = pos++;
	slen = *pos++;
	if (*adv_proto != WLAN_EID_ADV_PROTO ||
	    slen > end - pos || slen < 2)
		return -1;

	next = pos + slen;
	pos++; /* skip QueryRespLenLimit and PAME-BI */

	if (slen != 8 || *pos != WLAN_EID_VENDOR_SPECIFIC ||
	    pos[1] != 5 || WPA_GET_BE24(&pos[2]) != OUI_WFA ||
	    pos[5] != DPP_OUI_TYPE || pos[6] != 0x01)
		return -1;

	pos = next;
	/* Query Request */
	if (end - pos < 2)
		return -1;
	slen = WPA_GET_LE16(pos);
	pos += 2;
	if (slen > end - pos)
		return -1;

	resp = dpp_conf_req_rx(auth, pos, slen);
	if (!resp)
		return -1;

	buf = wpabuf_alloc(4 + 18 + wpabuf_len(resp));
	if (!buf) {
		wpabuf_free(resp);
		return -1;
	}

	wpabuf_put_be32(buf, 18 + wpabuf_len(resp));

	wpabuf_put_u8(buf, WLAN_PA_GAS_INITIAL_RESP);
	wpabuf_put_u8(buf, dialog_token);
	wpabuf_put_le16(buf, WLAN_STATUS_SUCCESS);
	wpabuf_put_le16(buf, 0); /* GAS Comeback Delay */

	dpp_write_adv_proto(buf);
	dpp_write_gas_query(buf, resp);
	wpabuf_free(resp);

	/* Send Config Response over TCP; GAS fragmentation is taken care of by
	 * the Relay */
	wpa_hexdump_buf(MSG_MSGDUMP, "DPP: Outgoing TCP message", buf);
	wpabuf_free(conn->msg_out);
	conn->msg_out_pos = 0;
	conn->msg_out = buf;
	conn->on_tcp_tx_complete_gas_done = 1;
	dpp_tcp_send(conn);
	return 0;
}


static int dpp_tcp_rx_gas_resp(struct dpp_connection *conn, struct wpabuf *resp)
{
	struct dpp_authentication *auth = conn->auth;
	int res;
	struct wpabuf *msg;
	enum dpp_status_error status;

	wpa_printf(MSG_DEBUG,
		   "DPP: Configuration Response for local stack from TCP");

	if (auth)
		res = dpp_conf_resp_rx(auth, resp);
	else
		res = -1;
	wpabuf_free(resp);
	if (res < 0) {
		wpa_printf(MSG_DEBUG, "DPP: Configuration attempt failed");
		return -1;
	}

	if (conn->global->process_conf_obj)
		res = conn->global->process_conf_obj(conn->global->cb_ctx,
						     auth);
	else
		res = 0;

	if (auth->peer_version < 2 || auth->conf_resp_status != DPP_STATUS_OK)
		return -1;

	wpa_printf(MSG_DEBUG, "DPP: Send DPP Configuration Result");
	status = res < 0 ? DPP_STATUS_CONFIG_REJECTED : DPP_STATUS_OK;
	msg = dpp_build_conf_result(auth, status);
	if (!msg)
		return -1;

	conn->on_tcp_tx_complete_remove = 1;
	res = dpp_tcp_send_msg(conn, msg);
	wpabuf_free(msg);

	/* This exchange will be terminated in the TX status handler */

	return res;
}


static int dpp_rx_gas_resp(struct dpp_connection *conn, const u8 *msg,
			   size_t len)
{
	struct wpabuf *buf;
	u8 dialog_token;
	const u8 *pos, *end, *next, *adv_proto;
	u16 status, slen;

	if (len < 5 + 2)
		return -1;

	wpa_printf(MSG_DEBUG,
		   "DPP: Received DPP Configuration Response over TCP");

	pos = msg;
	end = msg + len;

	dialog_token = *pos++;
	status = WPA_GET_LE16(pos);
	if (status != WLAN_STATUS_SUCCESS) {
		wpa_printf(MSG_DEBUG, "DPP: Unexpected Status Code %u", status);
		return -1;
	}
	pos += 2;
	pos += 2; /* ignore GAS Comeback Delay */

	adv_proto = pos++;
	slen = *pos++;
	if (*adv_proto != WLAN_EID_ADV_PROTO ||
	    slen > end - pos || slen < 2)
		return -1;

	next = pos + slen;
	pos++; /* skip QueryRespLenLimit and PAME-BI */

	if (slen != 8 || *pos != WLAN_EID_VENDOR_SPECIFIC ||
	    pos[1] != 5 || WPA_GET_BE24(&pos[2]) != OUI_WFA ||
	    pos[5] != DPP_OUI_TYPE || pos[6] != 0x01)
		return -1;

	pos = next;
	/* Query Response */
	if (end - pos < 2)
		return -1;
	slen = WPA_GET_LE16(pos);
	pos += 2;
	if (slen > end - pos)
		return -1;

	buf = wpabuf_alloc(slen);
	if (!buf)
		return -1;
	wpabuf_put_data(buf, pos, slen);

	if (!conn->relay &&
	    (!conn->ctrl || (conn->ctrl->allowed_roles & DPP_CAPAB_ENROLLEE)))
		return dpp_tcp_rx_gas_resp(conn, buf);

	if (!conn->relay) {
		wpa_printf(MSG_DEBUG, "DPP: No matching exchange in progress");
		wpabuf_free(buf);
		return -1;
	}
	wpa_printf(MSG_DEBUG, "DPP: Relay - send over WLAN");
	conn->relay->gas_resp_tx(conn->relay->cb_ctx, conn->mac_addr,
				 dialog_token, 0, buf);

	return 0;
}


static void dpp_controller_rx(int sd, void *eloop_ctx, void *sock_ctx)
{
	struct dpp_connection *conn = eloop_ctx;
	int res;
	const u8 *pos;

	wpa_printf(MSG_DEBUG, "DPP: TCP data available for reading (sock %d)",
		   sd);

	if (conn->msg_len_octets < 4) {
		u32 msglen;

		res = recv(sd, &conn->msg_len[conn->msg_len_octets],
			   4 - conn->msg_len_octets, 0);
		if (res < 0) {
			wpa_printf(MSG_DEBUG, "DPP: recv failed: %s",
				   strerror(errno));
			dpp_connection_remove(conn);
			return;
		}
		if (res == 0) {
			wpa_printf(MSG_DEBUG,
				   "DPP: No more data available over TCP");
			dpp_connection_remove(conn);
			return;
		}
		wpa_printf(MSG_DEBUG,
			   "DPP: Received %d/%d octet(s) of message length field",
			   res, (int) (4 - conn->msg_len_octets));
		conn->msg_len_octets += res;

		if (conn->msg_len_octets < 4) {
			wpa_printf(MSG_DEBUG,
				   "DPP: Need %d more octets of message length field",
				   (int) (4 - conn->msg_len_octets));
			return;
		}

		msglen = WPA_GET_BE32(conn->msg_len);
		wpa_printf(MSG_DEBUG, "DPP: Message length: %u", msglen);
		if (msglen > 65535) {
			wpa_printf(MSG_INFO, "DPP: Unexpectedly long message");
			dpp_connection_remove(conn);
			return;
		}

		wpabuf_free(conn->msg);
		conn->msg = wpabuf_alloc(msglen);
	}

	if (!conn->msg) {
		wpa_printf(MSG_DEBUG,
			   "DPP: No buffer available for receiving the message");
		dpp_connection_remove(conn);
		return;
	}

	wpa_printf(MSG_DEBUG, "DPP: Need %u more octets of message payload",
		   (unsigned int) wpabuf_tailroom(conn->msg));

	res = recv(sd, wpabuf_put(conn->msg, 0), wpabuf_tailroom(conn->msg), 0);
	if (res < 0) {
		wpa_printf(MSG_DEBUG, "DPP: recv failed: %s", strerror(errno));
		dpp_connection_remove(conn);
		return;
	}
	if (res == 0) {
		wpa_printf(MSG_DEBUG, "DPP: No more data available over TCP");
		dpp_connection_remove(conn);
		return;
	}
	wpa_printf(MSG_DEBUG, "DPP: Received %d octets", res);
	wpabuf_put(conn->msg, res);

	if (wpabuf_tailroom(conn->msg) > 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Need %u more octets of message payload",
			   (unsigned int) wpabuf_tailroom(conn->msg));
		return;
	}

	conn->msg_len_octets = 0;
	wpa_hexdump_buf(MSG_DEBUG, "DPP: Received TCP message", conn->msg);
	if (wpabuf_len(conn->msg) < 1) {
		dpp_connection_remove(conn);
		return;
	}

	pos = wpabuf_head(conn->msg);
	switch (*pos) {
	case WLAN_PA_VENDOR_SPECIFIC:
		if (dpp_controller_rx_action(conn, pos + 1,
					     wpabuf_len(conn->msg) - 1) < 0)
			dpp_connection_remove(conn);
		break;
	case WLAN_PA_GAS_INITIAL_REQ:
		if (dpp_controller_rx_gas_req(conn, pos + 1,
					      wpabuf_len(conn->msg) - 1) < 0)
			dpp_connection_remove(conn);
		break;
	case WLAN_PA_GAS_INITIAL_RESP:
		if (dpp_rx_gas_resp(conn, pos + 1,
				    wpabuf_len(conn->msg) - 1) < 0)
			dpp_connection_remove(conn);
		break;
	default:
		wpa_printf(MSG_DEBUG, "DPP: Ignore unsupported message type %u",
			   *pos);
		break;
	}
}


static void dpp_controller_tcp_cb(int sd, void *eloop_ctx, void *sock_ctx)
{
	struct dpp_controller *ctrl = eloop_ctx;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	int fd;
	struct dpp_connection *conn;

	wpa_printf(MSG_DEBUG, "DPP: New TCP connection");

	fd = accept(ctrl->sock, (struct sockaddr *) &addr, &addr_len);
	if (fd < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: Failed to accept new connection: %s",
			   strerror(errno));
		return;
	}
	wpa_printf(MSG_DEBUG, "DPP: Connection from %s:%d",
		   inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

	conn = os_zalloc(sizeof(*conn));
	if (!conn)
		goto fail;

	conn->global = ctrl->global;
	conn->ctrl = ctrl;
	conn->sock = fd;

	if (fcntl(conn->sock, F_SETFL, O_NONBLOCK) != 0) {
		wpa_printf(MSG_DEBUG, "DPP: fnctl(O_NONBLOCK) failed: %s",
			   strerror(errno));
		goto fail;
	}

	if (eloop_register_sock(conn->sock, EVENT_TYPE_READ,
				dpp_controller_rx, conn, NULL) < 0)
		goto fail;
	conn->read_eloop = 1;

	/* TODO: eloop timeout to expire connections that do not complete in
	 * reasonable time */
	dl_list_add(&ctrl->conn, &conn->list);
	return;

fail:
	close(fd);
	os_free(conn);
}


int dpp_tcp_init(struct dpp_global *dpp, struct dpp_authentication *auth,
		 const struct hostapd_ip_addr *addr, int port)
{
	struct dpp_connection *conn;
	struct sockaddr_storage saddr;
	socklen_t addrlen;
	const u8 *hdr, *pos, *end;
	char txt[100];

	wpa_printf(MSG_DEBUG, "DPP: Initialize TCP connection to %s port %d",
		   hostapd_ip_txt(addr, txt, sizeof(txt)), port);
	if (dpp_ipaddr_to_sockaddr((struct sockaddr *) &saddr, &addrlen,
				   addr, port) < 0) {
		dpp_auth_deinit(auth);
		return -1;
	}

	conn = os_zalloc(sizeof(*conn));
	if (!conn) {
		dpp_auth_deinit(auth);
		return -1;
	}

	conn->global = dpp;
	conn->auth = auth;
	conn->sock = socket(AF_INET, SOCK_STREAM, 0);
	if (conn->sock < 0)
		goto fail;

	if (fcntl(conn->sock, F_SETFL, O_NONBLOCK) != 0) {
		wpa_printf(MSG_DEBUG, "DPP: fnctl(O_NONBLOCK) failed: %s",
			   strerror(errno));
		goto fail;
	}

	if (connect(conn->sock, (struct sockaddr *) &saddr, addrlen) < 0) {
		if (errno != EINPROGRESS) {
			wpa_printf(MSG_DEBUG, "DPP: Failed to connect: %s",
				   strerror(errno));
			goto fail;
		}

		/*
		 * Continue connecting in the background; eloop will call us
		 * once the connection is ready (or failed).
		 */
	}

	if (eloop_register_sock(conn->sock, EVENT_TYPE_WRITE,
				dpp_conn_tx_ready, conn, NULL) < 0)
		goto fail;
	conn->write_eloop = 1;

	hdr = wpabuf_head(auth->req_msg);
	end = hdr + wpabuf_len(auth->req_msg);
	hdr += 2; /* skip Category and Actiom */
	pos = hdr + DPP_HDR_LEN;
	conn->msg_out = dpp_tcp_encaps(hdr, pos, end - pos);
	if (!conn->msg_out)
		goto fail;
	/* Message will be sent in dpp_conn_tx_ready() */

	/* TODO: eloop timeout to clear a connection if it does not complete
	 * properly */
	dl_list_add(&dpp->tcp_init, &conn->list);
	return 0;
fail:
	dpp_connection_free(conn);
	return -1;
}


int dpp_controller_start(struct dpp_global *dpp,
			 struct dpp_controller_config *config)
{
	struct dpp_controller *ctrl;
	int on = 1;
	struct sockaddr_in sin;
	int port;

	if (!dpp || dpp->controller)
		return -1;

	ctrl = os_zalloc(sizeof(*ctrl));
	if (!ctrl)
		return -1;
	ctrl->global = dpp;
	if (config->configurator_params)
		ctrl->configurator_params =
			os_strdup(config->configurator_params);
	dl_list_init(&ctrl->conn);
	ctrl->allowed_roles = config->allowed_roles;
	ctrl->qr_mutual = 0;

	ctrl->sock = socket(AF_INET, SOCK_STREAM, 0);
	if (ctrl->sock < 0)
		goto fail;

	if (setsockopt(ctrl->sock, SOL_SOCKET, SO_REUSEADDR,
		       &on, sizeof(on)) < 0) {
		wpa_printf(MSG_DEBUG,
			   "DPP: setsockopt(SO_REUSEADDR) failed: %s",
			   strerror(errno));
		/* try to continue anyway */
	}

	if (fcntl(ctrl->sock, F_SETFL, O_NONBLOCK) < 0) {
		wpa_printf(MSG_INFO, "DPP: fnctl(O_NONBLOCK) failed: %s",
			   strerror(errno));
		goto fail;
	}

	/* TODO: IPv6 */
	os_memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	port = config->tcp_port ? config->tcp_port : DPP_TCP_PORT;
	sin.sin_port = htons(port);
	if (bind(ctrl->sock, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		wpa_printf(MSG_INFO,
			   "DPP: Failed to bind Controller TCP port: %s",
			   strerror(errno));
		goto fail;
	}
	if (listen(ctrl->sock, 10 /* max backlog */) < 0 ||
	    fcntl(ctrl->sock, F_SETFL, O_NONBLOCK) < 0 ||
	    eloop_register_sock(ctrl->sock, EVENT_TYPE_READ,
				dpp_controller_tcp_cb, ctrl, NULL))
		goto fail;

	dpp->controller = ctrl;
	wpa_printf(MSG_DEBUG, "DPP: Controller started on TCP port %d", port);
	return 0;
fail:
	dpp_controller_free(ctrl);
	return -1;
}


void dpp_controller_stop(struct dpp_global *dpp)
{
	if (dpp) {
		dpp_controller_free(dpp->controller);
		dpp->controller = NULL;
	}
}


void dpp_tcp_init_flush(struct dpp_global *dpp)
{
	struct dpp_connection *conn, *tmp;

	dl_list_for_each_safe(conn, tmp, &dpp->tcp_init, struct dpp_connection,
			      list)
		dpp_connection_remove(conn);
}


static void dpp_relay_controller_free(struct dpp_relay_controller *ctrl)
{
	struct dpp_connection *conn, *tmp;

	dl_list_for_each_safe(conn, tmp, &ctrl->conn, struct dpp_connection,
			      list)
		dpp_connection_remove(conn);
	os_free(ctrl);
}


void dpp_relay_flush_controllers(struct dpp_global *dpp)
{
	struct dpp_relay_controller *ctrl, *tmp;

	if (!dpp)
		return;

	dl_list_for_each_safe(ctrl, tmp, &dpp->controllers,
			      struct dpp_relay_controller, list) {
		dl_list_del(&ctrl->list);
		dpp_relay_controller_free(ctrl);
	}
}

#endif /* CONFIG_DPP2 */
