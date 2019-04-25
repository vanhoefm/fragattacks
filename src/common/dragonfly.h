/*
 * Shared Dragonfly functionality
 * Copyright (c) 2012-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2019, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DRAGONFLY_H
#define DRAGONFLY_H

struct crypto_bignum;

int dragonfly_suitable_group(int group, int ecc_only);
int dragonfly_get_random_qr_qnr(const struct crypto_bignum *prime,
				struct crypto_bignum **qr,
				struct crypto_bignum **qnr);
struct crypto_bignum *
dragonfly_get_rand_1_to_p_1(const struct crypto_bignum *prime);

#endif /* DRAGONFLY_H */
