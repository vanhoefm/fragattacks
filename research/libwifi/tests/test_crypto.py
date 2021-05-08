from libwifi.crypto import *

def get_ciphertext_mic(encrypted):
	dot11ccmp = encrypted[Dot11CCMP].payload
	ciphertext = dot11ccmp.load
	mic = dot11ccmp.payload.load
	return ciphertext, mic

def test_ccmp():
	payload = b"A" * 16
	ptk = b'\x00' * 48
	tk = ptk[32:48]
	pn = 0

	plaintext = Dot11(type="Data", subtype=0, FCfield="to-DS", addr1="11:11:11:11:11:11",\
			  addr2="22:22:22:22:22:22", addr3="33:33:33:33:33:33", SC=0)
	plaintext = plaintext/Raw(payload)
	encrypted = encrypt_ccmp(plaintext, tk, pn)
	ciphertext, mic = get_ciphertext_mic(encrypted)
	assert ciphertext == bytes.fromhex("bedf2769dcdde9e002ab5b9df9342bc6")
	assert mic == bytes.fromhex("3a49543fa1ecb1e0")

	plaintext.SC = 1
	encrypted = encrypt_ccmp(plaintext, tk, pn)
	ciphertext, mic = get_ciphertext_mic(encrypted)
	assert ciphertext == bytes.fromhex("bedf2769dcdde9e002ab5b9df9342bc6")
	assert mic == bytes.fromhex("1fdbedc0538f98f2")

	plaintext.FCfield |= Dot11(FCfield="MF").FCfield
	encrypted = encrypt_ccmp(plaintext, tk, pn)
	ciphertext, mic = get_ciphertext_mic(encrypted)
	assert ciphertext == bytes.fromhex("bedf2769dcdde9e002ab5b9df9342bc6")
	assert mic == bytes.fromhex("8795d9c3fba25e76")

	pn = 0x1122
	plaintext.FCfield |= Dot11(FCfield="MF").FCfield
	encrypted = encrypt_ccmp(plaintext, tk, pn)
	ciphertext, mic = get_ciphertext_mic(encrypted)
	assert ciphertext == bytes.fromhex("ff76206822afb77decc7ee87568a02c6")
	assert mic == bytes.fromhex("8d6fd7578170ecb1")

