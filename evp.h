/*
 * OpenSSL Envelope API Helpers
 *
 * Copyright (c) 2011-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef EVP_H
#define EVP_H  1

#include <openssl/ec.h>
#include <openssl/evp.h>

/*
 * Sign data with key and store signature into sig field. Returns size
 * of generated signatute or zero on error.
 */
size_t evp_sign(EVP_PKEY *key, const void *data, size_t size,
		void *sig, size_t len);

/*
 * Verify data with supplied key and signatute. Returns non-zero on
 * success or zero on error.
 */
int evp_verify(EVP_PKEY *key, const void *data, size_t size,
	       const void *sig, size_t len);

/*
 * Creates Elliptic Curve key for specified algorithm nid and curve nid
 */
EC_KEY *EC_KEY_new_by_curve_name_ex(int algo, int curve);

#endif  /* EVP_H */
