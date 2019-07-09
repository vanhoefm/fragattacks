# EAP authentication tests
# Copyright (c) 2019, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd

from test_ap_eap import check_eap_capa, int_eap_server_params, eap_connect, \
    eap_reauth

def int_teap_server_params(eap_teap_auth=None, eap_teap_pac_no_inner=None):
    params = int_eap_server_params()
    params['pac_opaque_encr_key'] = "000102030405060708090a0b0c0dff00"
    params['eap_fast_a_id'] = "101112131415161718191a1b1c1dff00"
    params['eap_fast_a_id_info'] = "test server 0"
    if eap_teap_auth:
        params['eap_teap_auth'] = eap_teap_auth
    if eap_teap_pac_no_inner:
        params['eap_teap_pac_no_inner'] = eap_teap_pac_no_inner
    return params

def test_eap_teap_eap_mschapv2(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                pac_file="blob://teap_pac")
    eap_reauth(dev[0], "TEAP")

def test_eap_teap_eap_pwd(dev, apdev):
    """EAP-TEAP with inner EAP-PWD"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "PWD")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user-pwd-2",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=PWD",
                pac_file="blob://teap_pac")

def test_eap_teap_eap_eke(dev, apdev):
    """EAP-TEAP with inner EAP-EKE"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "EKE")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user-eke-2",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=EKE",
                pac_file="blob://teap_pac")

def test_eap_teap_basic_password_auth(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem",
                pac_file="blob://teap_pac")

def test_eap_teap_basic_password_auth_failure(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth failure"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="incorrect",
                ca_cert="auth_serv/ca.pem",
                pac_file="blob://teap_pac", expect_failure=True)

def test_eap_teap_basic_password_auth_no_password(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth and no password configured"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP",
                ca_cert="auth_serv/ca.pem",
                pac_file="blob://teap_pac", expect_failure=True)

def test_eap_teap_peer_outer_tlvs(dev, apdev):
    """EAP-TEAP with peer Outer TLVs"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                pac_file="blob://teap_pac", phase1="teap_test_outer_tlvs=1")

def test_eap_teap_eap_mschapv2_pac(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 and PAC provisioning"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                phase1="teap_provisioning=2",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                pac_file="blob://teap_pac")
    res = eap_reauth(dev[0], "TEAP")
    if res['tls_session_reused'] != '1':
        raise Exception("EAP-TEAP could not use PAC session ticket")

def test_eap_teap_eap_mschapv2_pac_no_inner_eap(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 and PAC without inner EAP"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = int_teap_server_params(eap_teap_pac_no_inner="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                phase1="teap_provisioning=2",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                pac_file="blob://teap_pac")
    res = eap_reauth(dev[0], "TEAP")
    if res['tls_session_reused'] != '1':
        raise Exception("EAP-TEAP could not use PAC session ticket")

def test_eap_teap_eap_mschapv2_pac_no_ca_cert(dev, apdev):
    """EAP-TEAP with inner EAP-MSCHAPv2 and PAC provisioning attempt without ca_cert"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "MSCHAPV2")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                phase1="teap_provisioning=2",
                phase2="auth=MSCHAPV2",
                pac_file="blob://teap_pac")
    res = eap_reauth(dev[0], "TEAP")
    if res['tls_session_reused'] == '1':
        raise Exception("Unexpected use of PAC session ticket")

def test_eap_teap_basic_password_auth_pac(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth and PAC"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                phase1="teap_provisioning=2",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                pac_file="blob://teap_pac")
    res = eap_reauth(dev[0], "TEAP")
    if res['tls_session_reused'] != '1':
        raise Exception("EAP-TEAP could not use PAC session ticket")

def test_eap_teap_basic_password_auth_pac_no_inner_eap(dev, apdev):
    """EAP-TEAP with Basic-Password-Auth and PAC without inner auth"""
    check_eap_capa(dev[0], "TEAP")
    params = int_teap_server_params(eap_teap_auth="1",
                                    eap_teap_pac_no_inner="1")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user",
                anonymous_identity="TEAP", password="password",
                phase1="teap_provisioning=2",
                ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                pac_file="blob://teap_pac")
    res = eap_reauth(dev[0], "TEAP")
    if res['tls_session_reused'] != '1':
        raise Exception("EAP-TEAP could not use PAC session ticket")

def test_eap_teap_eap_eke_unauth_server_prov(dev, apdev):
    """EAP-TEAP with inner EAP-EKE and unauthenticated server provisioning"""
    check_eap_capa(dev[0], "TEAP")
    check_eap_capa(dev[0], "EKE")
    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TEAP", "user-eke-2",
                anonymous_identity="TEAP", password="password",
                phase1="teap_provisioning=1",
                phase2="auth=EKE", pac_file="blob://teap_pac")
    res = eap_reauth(dev[0], "TEAP")
    if res['tls_session_reused'] != '1':
        raise Exception("EAP-TEAP could not use PAC session ticket")
