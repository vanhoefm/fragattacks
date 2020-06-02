/*
 * SAE-PK password/modifier generator
 * Copyright (c) 2020, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/base64.h"
#include "crypto/crypto.h"
#include "common/sae.h"


int main(int argc, char *argv[])
{
	char *der = NULL;
	size_t der_len;
	struct crypto_ec_key *key = NULL;
	struct wpabuf *pub = NULL;
	u8 *data = NULL, *m;
	size_t data_len;
	char *b64 = NULL, *pw = NULL, *pos, *src;
	int sec, j;
	int ret = -1;
	u8 hash[SAE_MAX_HASH_LEN], fingerprint[SAE_MAX_HASH_LEN];
	int group;
	size_t hash_len;
	unsigned long long i, expected;
	char m_hex[2 * SAE_PK_M_LEN + 1];

	wpa_debug_level = MSG_INFO;
	if (os_program_init() < 0)
		goto fail;

	if (argc != 4) {
		fprintf(stderr,
			"usage: sae_pk_gen <DER ECPrivateKey file> <Sec:2..5> <SSID>\n");
		goto fail;
	}

	sec = atoi(argv[2]);
	if (sec < 2 || sec > 5) {
		fprintf(stderr, "Invalid Sec value (allowed range: 2..5)\n");
		goto fail;
	}
	expected = 1;
	for (j = 0; j < sec; j++)
		expected *= 256;

	der = os_readfile(argv[1], &der_len);
	if (!der) {
		fprintf(stderr, "Could not read %s: %s\n",
			argv[1], strerror(errno));
		goto fail;
	}

	key = crypto_ec_key_parse_priv((u8 *) der, der_len);
	if (!key) {
		fprintf(stderr, "Could not parse ECPrivateKey\n");
		goto fail;
	}

	pub = crypto_ec_key_get_subject_public_key(key);
	if (!pub) {
		fprintf(stderr, "Failed to build SubjectPublicKey\n");
		goto fail;
	}

	group = crypto_ec_key_group(key);
	switch (group) {
	case 19:
		hash_len = 32;
		break;
	case 20:
		hash_len = 48;
		break;
	case 21:
		hash_len = 64;
		break;
	default:
		fprintf(stderr, "Unsupported private key group\n");
		goto fail;
	}

	data_len = os_strlen(argv[3]) + SAE_PK_M_LEN + wpabuf_len(pub);
	data = os_malloc(data_len);
	if (!data) {
		fprintf(stderr, "No memory for data buffer\n");
		goto fail;
	}
	os_memcpy(data, argv[3], os_strlen(argv[3]));
	m = data + os_strlen(argv[3]);
	if (os_get_random(m, SAE_PK_M_LEN) < 0) {
		fprintf(stderr, "Could not generate random Modifier M\n");
		goto fail;
	}
	os_memcpy(m + SAE_PK_M_LEN, wpabuf_head(pub), wpabuf_len(pub));

	fprintf(stderr, "Searching for a suitable Modifier M value\n");
	for (i = 0;; i++) {
		if (sae_hash(hash_len, data, data_len, hash) < 0) {
			fprintf(stderr, "Hash failed\n");
			goto fail;
		}
		if (hash[0] == 0 && hash[1] == 0) {
			if (sec == 2 || (hash[2] & 0xf0) == 0)
				fprintf(stderr, "\r%3.2f%%",
					100.0 * (double) i / (double) expected);
			for (j = 2; j < sec; j++) {
				if (hash[j])
					break;
			}
			if (j == sec)
				break;
		}
		inc_byte_array(m, SAE_PK_M_LEN);
	}

	fprintf(stderr, "\nFound a valid hash in %llu iterations\n", i);
	wpa_hexdump(MSG_DEBUG, "Valid hash", hash, hash_len);
	fingerprint[0] = (sec - 2) << 6 | hash[sec] >> 2;
	for (i = 1; i < hash_len - sec; i++)
		fingerprint[i] = hash[sec + i - 1] << 6 | hash[sec + i] >> 2;
	wpa_hexdump(MSG_DEBUG, "Fingerprint part for password",
		    fingerprint, hash_len - sec);

	b64 = base64_encode(der, der_len, NULL);
	pw = sae_pk_base32_encode(fingerprint, (hash_len - sec) * 8 - 2);
	if (!b64 || !pw ||
	    wpa_snprintf_hex(m_hex, sizeof(m_hex), m, SAE_PK_M_LEN) < 0)
		goto fail;
	src = pos = b64;
	while (*src) {
		if (*src != '\n')
			*pos++ = *src;
		src++;
	}
	*pos = '\0';

	printf("# SAE-PK password/M/private key for Sec=%d.\n", sec);
	printf("# The password can be truncated from right to improve\n");
	printf("# usability at the cost of security.\n");
	printf("sae_password=%s|pk=%s:%s\n", pw, m_hex, b64);

	ret = 0;
fail:
	os_free(der);
	wpabuf_free(pub);
	crypto_ec_key_deinit(key);
	os_free(data);
	os_free(b64);
	os_free(pw);

	os_program_deinit();

	return ret;
}
