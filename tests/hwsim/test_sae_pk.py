# Test cases for SAE-PK
# Copyright (c) 2020, The Linux Foundation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd
from utils import *

def run_sae_pk(apdev, dev, ssid, pw, m, pk, ap_groups=None):
    params = hostapd.wpa2_params(ssid=ssid)
    params['wpa_key_mgmt'] = 'SAE'
    params['sae_password'] = ['%s|pk=%s:%s' % (pw, m, pk)]
    if ap_groups:
        params['sae_groups'] = ap_groups
    hapd = hostapd.add_ap(apdev, params)
    bssid = hapd.own_addr()

    dev.connect(ssid, sae_password=pw, key_mgmt="SAE", scan_freq="2412")
    bss = dev.get_bss(bssid)
    if 'flags' not in bss:
        raise Exception("Could not get BSS flags from BSS table")
    if "[SAE-H2E]" not in bss['flags'] or "[SAE-PK]" not in bss['flags']:
        raise Exception("Unexpected BSS flags: " + bss['flags'])
    dev.request("REMOVE_NETWORK *")
    dev.wait_disconnected()
    hapd.disable()

def test_sae_pk(dev, apdev):
    """SAE-PK"""
    check_sae_pk_capab(dev[0])
    dev[0].set("sae_groups", "")

    ssid = "SAE-PK test"
    pw = "dwxm-zv66-p5ue-fotp-owjy-lfby-2xpg-vmwq-chtz-hilu-m3t2-qleg"
    m = "431ff8322f93b9dc50ded9f3d14ace22"
    pk = "MHcCAQEEIAJIGlfnteonDb7rQyP/SGQjwzrZAnfrXIm4280VWajYoAoGCCqGSM49AwEHoUQDQgAEeRkstKQV+FSAMqBayqFknn2nAQsdsh/MhdX6tiHOTAFin/sUMFRMyspPtIu7YvlKdsexhI0jPVhaYZn1jKWhZg=="

    for i in range(14, len(pw) + 1):
        p = pw[:i]
        if p.endswith('-'):
            continue
        run_sae_pk(apdev[0], dev[0], ssid, p, m, pk)

def test_sae_pk_group_negotiation(dev, apdev):
    """SAE-PK"""
    check_sae_pk_capab(dev[0])
    dev[0].set("sae_groups", "20 19")

    ssid = "SAE-PK test"
    pw = "dwxm-zv66-p5ue-fotp-owjy-lfby-2xpg-vmwq-chtz-hilu-m3t2-qleg"
    m = "431ff8322f93b9dc50ded9f3d14ace22"
    pk = "MHcCAQEEIAJIGlfnteonDb7rQyP/SGQjwzrZAnfrXIm4280VWajYoAoGCCqGSM49AwEHoUQDQgAEeRkstKQV+FSAMqBayqFknn2nAQsdsh/MhdX6tiHOTAFin/sUMFRMyspPtIu7YvlKdsexhI0jPVhaYZn1jKWhZg=="

    try:
        run_sae_pk(apdev[0], dev[0], ssid, pw, m, pk, ap_groups="19 20")
    finally:
        dev[0].set("sae_groups", "")

def test_sae_pk_sec_2(dev, apdev):
    """SAE-PK with Sec 2"""
    check_sae_pk_capab(dev[0])
    dev[0].set("sae_groups", "")

    ssid = "SAE-PK test"
    pw = "dwxm-zv66-p5ue"
    m = "431ff8322f93b9dc50ded9f3d14ace22"
    pk = "MHcCAQEEIAJIGlfnteonDb7rQyP/SGQjwzrZAnfrXIm4280VWajYoAoGCCqGSM49AwEHoUQDQgAEeRkstKQV+FSAMqBayqFknn2nAQsdsh/MhdX6tiHOTAFin/sUMFRMyspPtIu7YvlKdsexhI0jPVhaYZn1jKWhZg=="

    run_sae_pk(apdev[0], dev[0], ssid, pw, m, pk)

def test_sae_pk_sec_3(dev, apdev):
    """SAE-PK with Sec 3"""
    check_sae_pk_capab(dev[0])
    dev[0].set("sae_groups", "")

    ssid = "SAE-PK test"
    pw = "iian-qey6-pu5t"
    m = "128e51ddb5e2e24388f9ed14b687e2eb"
    pk = "MHcCAQEEIAJIGlfnteonDb7rQyP/SGQjwzrZAnfrXIm4280VWajYoAoGCCqGSM49AwEHoUQDQgAEeRkstKQV+FSAMqBayqFknn2nAQsdsh/MhdX6tiHOTAFin/sUMFRMyspPtIu7YvlKdsexhI0jPVhaYZn1jKWhZg=="

    run_sae_pk(apdev[0], dev[0], ssid, pw, m, pk)

def test_sae_pk_sec_4(dev, apdev):
    """SAE-PK with Sec 4"""
    check_sae_pk_capab(dev[0])
    dev[0].set("sae_groups", "")

    ssid = "SAE-PK test"
    pw = "ssko-2lmu-7hzs-bqct"
    m = "a5e38c7251ea310cc348fbcdadfa8bcb"
    pk = "MHcCAQEEIAJIGlfnteonDb7rQyP/SGQjwzrZAnfrXIm4280VWajYoAoGCCqGSM49AwEHoUQDQgAEeRkstKQV+FSAMqBayqFknn2nAQsdsh/MhdX6tiHOTAFin/sUMFRMyspPtIu7YvlKdsexhI0jPVhaYZn1jKWhZg=="

    run_sae_pk(apdev[0], dev[0], ssid, pw, m, pk)

def test_sae_pk_sec_5(dev, apdev):
    """SAE-PK with Sec 5"""
    check_sae_pk_capab(dev[0])
    dev[0].set("sae_groups", "")

    ssid = "SAE-PK test"
    pw = "3qqu-f4xq-dz37-fes3-fbgc"
    m = "d2e5fa27d1be8897f987f2d480d2af6b"
    pk = "MHcCAQEEIAJIGlfnteonDb7rQyP/SGQjwzrZAnfrXIm4280VWajYoAoGCCqGSM49AwEHoUQDQgAEeRkstKQV+FSAMqBayqFknn2nAQsdsh/MhdX6tiHOTAFin/sUMFRMyspPtIu7YvlKdsexhI0jPVhaYZn1jKWhZg=="

    run_sae_pk(apdev[0], dev[0], ssid, pw, m, pk)

def test_sae_pk_group_20(dev, apdev):
    """SAE-PK with group 20"""
    check_sae_pk_capab(dev[0])
    dev[0].set("sae_groups", "20")

    ssid = "SAE-PK test"
    pw = "f3bh-5un3-wz7o-al3p"
    m = "50bf37ba0033ed110a74e3a7aa52f4e9"
    pk = "MIGkAgEBBDA4wpA6w/fK0g3a2V6QmcoxNoFCVuQPyzWvKYimJkgXsVsXt2ERXQ7dGOVXeycM5DqgBwYFK4EEACKhZANiAARTdszGBNe2PGCnc8Wvs+IDvdVEf4PPBrty0meRZf6UTbGouquTHpy6KKTq5sxrulYzsQFimg4op0UJBGxAzqo0EtTgMlLiBvY0I3Nl3N69MhWo8nvnmguvGGN32AAPXpQ="

    try:
        run_sae_pk(apdev[0], dev[0], ssid, pw, m, pk, ap_groups="20")
    finally:
        dev[0].set("sae_groups", "")
