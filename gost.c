/*
 * GOST Algorithms Support
 *
 * Copyright (c) 2011-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "includes.h"

#ifdef WITH_OPENSSL

#include "gost.h"

#define DEFINE_DIGEST(name, algo)				\
const EVP_MD *							\
EVP_##name(void)						\
{								\
	return EVP_get_digestbyname(algo);			\
}

DEFINE_DIGEST(gosthash, "md_gost94")

DEFINE_DIGEST(stribog_256, "md_gost12_256")
DEFINE_DIGEST(stribog_512, "md_gost12_512")

#define DEFINE_CIPHER(name, algo)				\
const EVP_CIPHER *						\
EVP_##name(void)						\
{								\
	return EVP_get_cipherbyname(algo);			\
}

DEFINE_CIPHER(gost89_cbc, "gost89-cbc")
DEFINE_CIPHER(gost89_cfb, "gost89")      /* CFB + key meshing        */
DEFINE_CIPHER(gost89_cnt, "gost89-cnt")  /* OFB + key and IV meshing */
DEFINE_CIPHER(gost89_ctr, "gost89-ctr")

const EVP_CIPHER *
EVP_gost89_ofb(void)  /* CNT + guarantee that we can turn off meshing */
{
	static const EVP_CIPHER *algo;
	EVP_CIPHER_CTX *c;

	if (algo != NULL)
		return algo;

	if ((algo = EVP_gost89_cnt()) == NULL)
		return NULL;

	if ((c = EVP_CIPHER_CTX_new()) == NULL)
		goto no_ctx;

	if (!EVP_CipherInit (c, algo, NULL, NULL, 1) ||
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 1, "plain") <= 0)
		goto no_plain;

	EVP_CIPHER_CTX_free(c);
	return algo;
no_plain:
	EVP_CIPHER_CTX_free(c);
no_ctx:
	algo = NULL;
	return NULL;
}

#define DEFINE_CIPHER2(name, algo1, algo2)			\
const EVP_CIPHER *						\
EVP_##name(void)						\
{								\
	const EVP_CIPHER *c = EVP_get_cipherbyname (algo1);	\
								\
	return c != NULL ? c : EVP_get_cipherbyname(algo2);	\
}

DEFINE_CIPHER2(kuznechik_cbc, "grasshopper-cbc", "kuznyechik-cbc")
DEFINE_CIPHER2(kuznechik_cfb, "grasshopper-cfb", "kuznyechik-cfb")
DEFINE_CIPHER2(kuznechik_ctr, "grasshopper-ctr", "kuznyechik-ctr")
DEFINE_CIPHER2(kuznechik_ofb, "grasshopper-ofb", "kuznyechik-ofb")

#endif  /* WITH_OPENSSL */
