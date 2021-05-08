from libwifi.mschap import *

def test_mschap():
	username = b"peapuser"
	password = "password"
	auth_challenge = binascii.unhexlify("59 ff 64 4c 14 62 df 4d 59 a4 46 5d 6b c8 09 6c".replace(" ", ""))
	peer_challenge = binascii.unhexlify("0d 60 5a 24 da 8d 6e f7 58 ee 23 69 8f 37 04 46".replace(" ", ""))

	nt_response = generate_nt_response_mschap2(auth_challenge, peer_challenge, username, password)
	assert nt_response == b"\xd8\xf7\xd6\x10\xa6\x1f\x0c\x0b\x49\x1d\x21\xac\xbb\xd3\x6d\x86\xb9\x91\x6f\x8e\x69\xa6\x5f\x97"

	auth_resp = generate_authenticator_response(password, nt_response, peer_challenge, auth_challenge, username)
	assert auth_resp == b"\x0f\x91\x69\x7e\x8e\x8f\xd6\xb7\x25\xf3\x3c\x30\xd8\x1d\x67\xa7\x47\xfc\xba\x01"

