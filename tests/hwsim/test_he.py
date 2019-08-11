# HE tests
# Copyright (c) 2019, The Linux Foundation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd

def test_he_open(dev, apdev):
    """HE AP with open mode configuration"""
    params = {"ssid": "he",
              "ieee80211ax": "1",
              "he_bss_color": "42",
              "he_mu_edca_ac_be_ecwmin": "7",
              "he_mu_edca_ac_be_ecwmax": "15"}
    hapd = hostapd.add_ap(apdev[0], params)
    if hapd.get_status_field("ieee80211ax") != "1":
        raise Exception("STATUS did not indicate ieee80211ac=1")
    dev[0].connect("he", key_mgmt="NONE", scan_freq="2412")

def test_he_params(dev, apdev):
    """HE AP parameters"""
    params = {"ssid": "he",
              "ieee80211ax": "1",
              "he_bss_color": "42",
              "he_mu_edca_ac_be_ecwmin": "7",
              "he_mu_edca_ac_be_ecwmax": "15",
              "he_su_beamformer": "0",
              "he_su_beamformee": "0",
              "he_default_pe_duration": "4",
              "he_twt_required": "1",
              "he_rts_threshold": "64",
              "he_basic_mcs_nss_set": "65535",
              "he_mu_edca_qos_info_param_count": "0",
              "he_mu_edca_qos_info_q_ack": "0",
              "he_mu_edca_qos_info_queue_request": "1",
              "he_mu_edca_qos_info_txop_request": "0",
              "he_mu_edca_ac_be_aifsn": "0",
              "he_mu_edca_ac_be_ecwmin": "15",
              "he_mu_edca_ac_be_ecwmax": "15",
              "he_mu_edca_ac_be_timer": "255",
              "he_mu_edca_ac_bk_aifsn": "0",
              "he_mu_edca_ac_bk_aci": "1",
              "he_mu_edca_ac_bk_ecwmin": "15",
              "he_mu_edca_ac_bk_ecwmax": "15",
              "he_mu_edca_ac_bk_timer": "255",
              "he_mu_edca_ac_vi_ecwmin": "15",
              "he_mu_edca_ac_vi_ecwmax": "15",
              "he_mu_edca_ac_vi_aifsn": "0",
              "he_mu_edca_ac_vi_aci": "2",
              "he_mu_edca_ac_vi_timer": "255",
              "he_mu_edca_ac_vo_aifsn": "0",
              "he_mu_edca_ac_vo_aci": "3",
              "he_mu_edca_ac_vo_ecwmin": "15",
              "he_mu_edca_ac_vo_ecwmax": "15",
              "he_mu_edca_ac_vo_timer": "255",
              "he_spr_sr_control": "0",
              "he_spr_non_srg_obss_pd_max_offset": "0",
              "he_spr_srg_obss_pd_min_offset": "0",
              "he_spr_srg_obss_pd_max_offset": "0",
              "he_oper_chwidth": "0",
              "he_oper_centr_freq_seg0_idx": "1",
              "he_oper_centr_freq_seg1_idx": "0"}
    hapd = hostapd.add_ap(apdev[0], params)
    if hapd.get_status_field("ieee80211ax") != "1":
        raise Exception("STATUS did not indicate ieee80211ac=1")
    dev[0].connect("he", key_mgmt="NONE", scan_freq="2412")
