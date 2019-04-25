/*
 * Shared Dragonfly functionality
 * Copyright (c) 2012-2016, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2019, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "dragonfly.h"


int dragonfly_suitable_group(int group, int ecc_only)
{
	/* Enforce REVmd rules on which SAE groups are suitable for production
	 * purposes: FFC groups whose prime is >= 3072 bits and ECC groups
	 * defined over a prime field whose prime is >= 256 bits. Furthermore,
	 * ECC groups defined over a characteristic 2 finite field and ECC
	 * groups with a co-factor greater than 1 are not suitable. */
	return group == 19 || group == 20 || group == 21 ||
		group == 28 || group == 29 || group == 30 ||
		(!ecc_only &&
		 (group == 15 || group == 16 || group == 17 || group == 18));
}
