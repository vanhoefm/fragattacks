/*
 * hostapd / IEEE 802.11ax HE
 * Copyright (c) 2016-2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "hostapd.h"
#include "ap_config.h"
#include "beacon.h"
#include "ieee802_11.h"
#include "dfs.h"

u8 * hostapd_eid_he_capab(struct hostapd_data *hapd, u8 *eid)
{
	struct ieee80211_he_capabilities *cap;
	struct hostapd_hw_modes *mode = hapd->iface->current_mode;
	u8 *pos = eid;

	if (!mode)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = 1 + sizeof(struct ieee80211_he_capabilities);
	*pos++ = WLAN_EID_EXT_HE_CAPABILITIES;

	cap = (struct ieee80211_he_capabilities *) pos;
	os_memset(cap, 0, sizeof(*cap));

	os_memcpy(cap->he_mac_capab_info, mode->he_capab.mac_cap,
		  HE_MAX_MAC_CAPAB_SIZE);
	os_memcpy(cap->he_phy_capab_info, mode->he_capab.phy_cap,
		  HE_MAX_PHY_CAPAB_SIZE);
	os_memcpy(cap->he_txrx_mcs_support, mode->he_capab.mcs,
		  HE_MAX_MCS_CAPAB_SIZE);

	if (hapd->iface->conf->he_phy_capab.he_su_beamformer)
		cap->he_phy_capab_info[HE_PHYCAP_SU_BEAMFORMER_CAPAB_IDX] |=
			HE_PHYCAP_SU_BEAMFORMER_CAPAB;

	if (hapd->iface->conf->he_phy_capab.he_su_beamformee)
		cap->he_phy_capab_info[HE_PHYCAP_SU_BEAMFORMEE_CAPAB_IDX] |=
			HE_PHYCAP_SU_BEAMFORMEE_CAPAB;

	if (hapd->iface->conf->he_phy_capab.he_mu_beamformer)
		cap->he_phy_capab_info[HE_PHYCAP_MU_BEAMFORMER_CAPAB_IDX] |=
			HE_PHYCAP_MU_BEAMFORMER_CAPAB;

	pos += sizeof(*cap);

	return pos;
}


u8 * hostapd_eid_he_operation(struct hostapd_data *hapd, u8 *eid)
{
	struct ieee80211_he_operation *oper;
	u8 *pos = eid;
	int oper_size = 6;
	u32 params = 0;

	if (!hapd->iface->current_mode)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = 1 + oper_size;
	*pos++ = WLAN_EID_EXT_HE_OPERATION;

	oper = (struct ieee80211_he_operation *) pos;
	os_memset(oper, 0, sizeof(*oper));

	if (hapd->iface->conf->he_op.he_default_pe_duration)
		params |= (hapd->iface->conf->he_op.he_default_pe_duration <<
			   HE_OPERATION_DFLT_PE_DURATION_OFFSET);

	if (hapd->iface->conf->he_op.he_twt_required)
		params |= HE_OPERATION_TWT_REQUIRED;

	if (hapd->iface->conf->he_op.he_rts_threshold)
		params |= (hapd->iface->conf->he_op.he_rts_threshold <<
			   HE_OPERATION_RTS_THRESHOLD_OFFSET);

	if (hapd->iface->conf->he_op.he_bss_color)
		params |= (hapd->iface->conf->he_op.he_bss_color <<
			   HE_OPERATION_BSS_COLOR_OFFSET);

	/* TODO: conditional MaxBSSID Indicator subfield */

	oper->he_oper_params = host_to_le32(params);

	pos += oper_size;

	return pos;
}


u8 * hostapd_eid_he_mu_edca_parameter_set(struct hostapd_data *hapd, u8 *eid)
{
	struct ieee80211_he_mu_edca_parameter_set *edca;
	u8 *pos;
	size_t i;

	pos = (u8 *) &hapd->iface->conf->he_mu_edca;
	for (i = 0; i < sizeof(*edca); i++) {
		if (pos[i])
			break;
	}
	if (i == sizeof(*edca))
		return eid; /* no MU EDCA Parameters configured */

	pos = eid;
	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = 1 + sizeof(*edca);
	*pos++ = WLAN_EID_EXT_HE_MU_EDCA_PARAMS;

	edca = (struct ieee80211_he_mu_edca_parameter_set *) pos;
	os_memcpy(edca, &hapd->iface->conf->he_mu_edca, sizeof(*edca));

	wpa_hexdump(MSG_DEBUG, "HE: MU EDCA Parameter Set element",
		    pos, sizeof(*edca));

	pos += sizeof(*edca);

	return pos;
}


u8 * hostapd_eid_spatial_reuse(struct hostapd_data *hapd, u8 *eid)
{
	struct ieee80211_spatial_reuse *spr;
	u8 *pos = eid, *spr_param;
	u8 sz = 1;

	if (hapd->iface->conf->spr.sr_control &
	    SPATIAL_REUSE_NON_SRG_OFFSET_PRESENT)
		sz++;

	if (hapd->iface->conf->spr.sr_control &
	    SPATIAL_REUSE_SRG_INFORMATION_PRESENT)
		sz += 18;

	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = 1 + sz;
	*pos++ = WLAN_EID_EXT_SPATIAL_REUSE;

	spr = (struct ieee80211_spatial_reuse *) pos;
	os_memset(spr, 0, sizeof(*spr));

	spr->sr_ctrl = hapd->iface->conf->spr.sr_control;
	pos++;
	spr_param = spr->params;
	if (spr->sr_ctrl & SPATIAL_REUSE_NON_SRG_OFFSET_PRESENT) {
		*spr_param++ =
			hapd->iface->conf->spr.non_srg_obss_pd_max_offset;
		pos++;
	}
	if (spr->sr_ctrl & SPATIAL_REUSE_SRG_INFORMATION_PRESENT) {
		*spr_param++ = hapd->iface->conf->spr.srg_obss_pd_min_offset;
		*spr_param++ = hapd->iface->conf->spr.srg_obss_pd_max_offset;
		pos += 18;
	}

	return pos;
}
