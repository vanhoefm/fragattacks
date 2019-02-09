/*
 * JSON parser - test program
 * Copyright (c) 2019, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/os.h"
#include "utils/json.h"


int main(int argc, char *argv[])
{
	char *buf;
	size_t len;
	struct json_token *root;

	if (argc < 2)
		return -1;

	buf = os_readfile(argv[1], &len);
	if (!buf)
		return -1;

	root = json_parse(buf, len);
	os_free(buf);
	if (root) {
		size_t buflen = 10000;

		buf = os_zalloc(buflen);
		if (buf) {
			json_print_tree(root, buf, buflen);
			printf("%s\n", buf);
			os_free(buf);
		}
		json_free(root);
	} else {
		printf("JSON parsing failed\n");
	}

	return 0;
}
