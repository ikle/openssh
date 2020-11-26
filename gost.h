/*
 * GOST Algorithms Support
 *
 * Copyright (c) 2011-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef GOST_H
#define GOST_H  1

#include <openssl/evp.h>

/*
 * The following three message digest algorithms have been added:
 *
 * *  gosthash    -- GOST R 34.11-94, 256 bit;
 * *  stribog-256 -- GOST R 34.11-2012, 256 bit;
 * *  stribog-512 -- GOST R 34.11-2012, 512 bit.
 *
 * GOST R 34.11-94 aka Gosthash is officially considered obsolete. However,
 * it is still widely used and has no known vulnerabilities. Moreover, it
 * uses internally the GOST 28147-89 cipher algorithm, which is adopted as
 * part of the new GOST R 34.12-2015 standard under the name Magma (256 bit
 * key size, 64 bit block size), which also has no known vulnerabilities.
 *
 * The main reason for exclusion Gosthash from the new standard is its
 * significantly lower operating speed compared to the new Stribog algorithm.
 *
 * The Stribog algorithm with a digest size of 256 bits is, in fact, the
 * same Stribog algorithm with a digest size of 512 bits with a different
 * IV and a truncated lower half of the output value and nothing more.
 *
 * Stribog is the name of Prince Oleg's horse from the saga of St. Oleg.
 * The name has been transliterated from Cyrillic to Latin according to the
 * ISO/IEC 7501-1-2013 standard in force in Russia: do not try to replace
 * it with English-like transcription "Streebog" -- this is wrong.
 */

#define DECLARE_DIGEST(name)	const EVP_MD *EVP_##name(void);

DECLARE_DIGEST(gosthash)
DECLARE_DIGEST(stribog_256)
DECLARE_DIGEST(stribog_512)

/*
 * The following two groups of cipher algorithms have been added:
 *
 * *  GOST 28147-89, GOST R 34.12-2015 256-bit key, 64-bit block:
 *
 *    *  gost89-cbc -- CBC mode;
 *    *  gost89-cfb -- CFB mode with key meshing;
 *    *  gost89-cnt -- OFB mode with key and IV meshing.
 *    *  gost89-ctr -- CTR mode;
 *    *  gost89-ofb -- CNT + guarantee that we can turn off meshing.
 *
 * *  GOST R 34.12-2015 256-bit key, 128-bit block aka Kuznechik:
 *
 *    *  kuznechik-cbc -- CBC mode;
 *    *  kuznechik-cfb -- CFB mode;
 *    *  kuznechik-ctr -- CTR mode;
 *    *  kuznechik-ofb -- OFB mode.
 *
 * Note that the key meshing mode is incompatible with the current procedure
 * for moving the state after authentication: to restore the state, it is
 * not enough to know the initial key and the current initialization vector.
 * We need to disable key and IV meshing mode where it is enabled by default.
 *
 * The name of GOST R 34.12-2015 128-bit block cipher has been trans-
 * literated from Cyrillic to Latin according to the ISO/IEC 7501-1-2013
 * standard in force in Russia: do not try to replace it with "Kuznyechik"
 * -- that's a mistake in standard.
 */

#ifndef EVP_CTRL_AEAD_SET_TAG
#define EVP_CTRL_AEAD_SET_TAG	0x11
#endif

#ifndef EVP_CTRL_KEY_MESH
#define EVP_CTRL_KEY_MESH	0x20
#endif

#define DECLARE_CIPHER(name)	const EVP_CIPHER *EVP_##name(void);

DECLARE_CIPHER(gost89_cbc)
DECLARE_CIPHER(gost89_cfb)  /* CFB + key meshing        */
DECLARE_CIPHER(gost89_cnt)  /* OFB + key and IV meshing */
DECLARE_CIPHER(gost89_ctr)
DECLARE_CIPHER(gost89_ofb)  /* CNT + guarantee that we can turn off meshing */

DECLARE_CIPHER(kuznechik_cbc)
DECLARE_CIPHER(kuznechik_cfb)
DECLARE_CIPHER(kuznechik_ctr)
DECLARE_CIPHER(kuznechik_ofb)

#endif  /* GOST_H */
