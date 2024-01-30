/*
 * OpenSSL Envelope API Helpers
 *
 * Copyright (c) 2011-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "includes.h"

#if defined (WITH_OPENSSL) && defined (OPENSSL_HAS_ECC)

#include "evp.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#define EVP_MD_CTX_new()       EVP_MD_CTX_create()
#define EVP_MD_CTX_free(o)     EVP_MD_CTX_destroy(o)

#endif

/*
 * Sign data with key and store signature into sig field. Returns size
 * of generated signatute or zero on error.
 */
size_t
evp_sign(EVP_PKEY *key, const void *data, size_t size, void *sig, size_t len)
{
	EVP_MD_CTX *c;
	size_t siglen = len;
	int ok;

	if ((c = EVP_MD_CTX_new()) == NULL)
		return 0;

	ok = EVP_DigestSignInit(c, NULL, NULL, NULL, key) == 1 &&
	     EVP_DigestSignUpdate(c, data, size)          == 1 &&
	     EVP_DigestSignFinal(c, sig, &siglen)         == 1;

	EVP_MD_CTX_free(c);
	return ok ? siglen : 0;
}

/*
 * Verify data with supplied key and signatute. Returns non-zero on
 * success or zero on error.
 */
int
evp_verify(EVP_PKEY *key, const void *data, size_t size,
	   const void *sig, size_t len)
{
	EVP_MD_CTX *c;
	int ok;

	if ((c = EVP_MD_CTX_new()) == NULL)
		return 0;

	ok = EVP_DigestVerifyInit(c, NULL, NULL, NULL, key) == 1 &&
	     EVP_DigestVerifyUpdate(c, data, size)          == 1 &&
	     EVP_DigestVerifyFinal(c, sig, len)             == 1;

	EVP_MD_CTX_free(c);
	return ok;
}

/*
 * Creates Elliptic Curve key for specified algorithm nid and curve nid
 */
EC_KEY *
EC_KEY_new_by_curve_name_ng(int algo, int curve)
{
	EVP_PKEY_CTX *c;
	EVP_PKEY *pkey = NULL;
	int ok;
	EC_KEY *key;

	if (algo == 0)
		return EC_KEY_new_by_curve_name(curve);

	if ((c = EVP_PKEY_CTX_new_id(algo, NULL)) == NULL)
		return NULL;

	ok = EVP_PKEY_paramgen_init(c) == 1 &&
	     EVP_PKEY_CTX_ctrl(c, -1, -1, EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID,
			       curve, NULL) > 0 &&
	     EVP_PKEY_paramgen(c, &pkey) == 1;

	EVP_PKEY_CTX_free(c);

	if (!ok)
		return NULL;

	/*
	 * We can not use EVP_PKEY_get1_EC_KEY here: for some algorithms
	 * pkey->type != EVP_PKEY_EC. GOST EC key as an example. Thus, get
	 * it directly and increment reference.
	 */
	key = EVP_PKEY_get0(pkey);
	EC_KEY_up_ref(key);
	EVP_PKEY_free(pkey);
	return key;
}

#endif  /* WITH_OPENSSL and OPENSSL_HAS_ECC */
