/*
 * Operating Channel Validation (OCV)
 * Copyright (c) 2018, Mathy Vanhoef
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "drivers/driver.h"
#include "common/ieee802_11_common.h"
#include "ocv.h"

/**
 * Caller of OCV functionality may use various debug output functions, so store
 * the error here and let the caller use an appropriate debug output function.
 */
char ocv_errorstr[256];


int ocv_derive_all_parameters(struct oci_info *oci)
{
	const struct oper_class_map *op_class_map;

	oci->freq = ieee80211_chan_to_freq(NULL, oci->op_class, oci->channel);
	if (oci->freq < 0) {
		wpa_printf(MSG_INFO,
			   "Error interpreting OCI: unrecognized opclass/channel pair (%d/%d)",
			   oci->op_class, oci->channel);
		return -1;
	}

	op_class_map = get_oper_class(NULL, oci->op_class);
	if (!op_class_map) {
		wpa_printf(MSG_INFO,
			   "Error interpreting OCI: Unrecognized opclass (%d)",
			   oci->op_class);
		return -1;
	}

	oci->chanwidth = oper_class_bw_to_int(op_class_map);
	oci->sec_channel = 0;
	if (op_class_map->bw == BW40PLUS)
		oci->sec_channel = 1;
	else if (op_class_map->bw == BW40MINUS)
		oci->sec_channel = -1;

	return 0;
}


int ocv_insert_oci(struct wpa_channel_info *ci, u8 **argpos)
{
	u8 op_class, channel;
	u8 *pos = *argpos;

	if (ieee80211_chaninfo_to_channel(ci->frequency, ci->chanwidth,
					  ci->sec_channel,
					  &op_class, &channel) < 0) {
		wpa_printf(MSG_WARNING,
			   "Cannot determine operating class and channel for OCI element");
		return -1;
	}

	*pos++ = op_class;
	*pos++ = channel;
	*pos++ = ci->seg1_idx;

	*argpos = pos;
	return 0;
}


int ocv_insert_oci_kde(struct wpa_channel_info *ci, u8 **argpos)
{
	u8 *pos = *argpos;

	*pos++ = WLAN_EID_VENDOR_SPECIFIC;
	*pos++ = RSN_SELECTOR_LEN + 3;
	RSN_SELECTOR_PUT(pos, RSN_KEY_DATA_OCI);
	pos += RSN_SELECTOR_LEN;

	*argpos = pos;
	return ocv_insert_oci(ci, argpos);
}


int ocv_insert_extended_oci(struct wpa_channel_info *ci, u8 *pos)
{
	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = 1 + OCV_OCI_LEN;
	*pos++ = WLAN_EID_EXT_OCV_OCI;
	return ocv_insert_oci(ci, &pos);
}
