#!/usr/bin/env python3
import binascii, struct
from Crypto.Hash import MD4, SHA
from Crypto.Cipher import DES


def des_encrypt(clear, key, offset):
	cNext = 0
	cWorking = 0
	hexKey = {}

	for x in range(0,8):
		cWorking = 0xFF & key[x + offset]
		hexKey[x] = ((cWorking >> x) | cNext | 1) & 0xFF
		cWorking = 0xFF & key[x + offset]
		cNext = ((cWorking << (7 - x)))

	newKey = b""
	for x in range(0, len(hexKey)):
		newKey += struct.pack(">B", hexKey[x])

	des = DES.new(newKey, DES.MODE_ECB)
	return des.encrypt(clear)

def challenge_hash(peer_challenge, authenticator_challenge, username):
	challenge = SHA.new(peer_challenge + authenticator_challenge + username).digest()
	return challenge[0:8]

def nt_password_hash(password):
	unicode_pw = password.encode("utf-16-le")
	return MD4.new(unicode_pw).digest()

def hash_nt_password_hash(password_hash):
	md4 = MD4.new()
	md4.update(password_hash)
	return md4.digest()

def challenge_response(challenge, pwhash):
	# for some reason in python we need to pad an extra byte so that
	# the offset works out correctly when we call DesEncrypt
	pwhash += b'\x00' * (22 - len(pwhash))

	response = b""
	for x in range(0, 3):
		encrypted = des_encrypt(challenge, pwhash, x * 7)
		response += encrypted

	return response

def generate_nt_response_mschap2(authenticator_challenge, peer_challenge, username, password):
	challenge = challenge_hash(peer_challenge, authenticator_challenge, username)
	password_hash = nt_password_hash(password)
	return challenge_response(challenge, password_hash)

def generate_authenticator_response(password, nt_response, peer_challenge, authenticator_challenge, username):
	magic1 = b"\x4D\x61\x67\x69\x63\x20\x73\x65\x72\x76\x65\x72\x20\x74\x6F\x20\x63\x6C\x69\x65\x6E\x74\x20\x73\x69\x67\x6E\x69\x6E\x67\x20\x63\x6F\x6E\x73\x74\x61\x6E\x74"
	magic2 = b"\x50\x61\x64\x20\x74\x6F\x20\x6D\x61\x6B\x65\x20\x69\x74\x20\x64\x6F\x20\x6D\x6F\x72\x65\x20\x74\x68\x61\x6E\x20\x6F\x6E\x65\x20\x69\x74\x65\x72\x61\x74\x69\x6F\x6E"

	password_hash = nt_password_hash(password)
	password_hash_hash = hash_nt_password_hash(password_hash)

	sha_hash = SHA.new()
	sha_hash.update(password_hash_hash)
	sha_hash.update(nt_response)
	sha_hash.update(magic1)
	digest = sha_hash.digest()

	challenge = challenge_hash(peer_challenge, authenticator_challenge, username)

	sha_hash = SHA.new()
	sha_hash.update(digest)
	sha_hash.update(challenge)
	sha_hash.update(magic2)
	digest = sha_hash.digest()

	return digest

