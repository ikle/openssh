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

#endif  /* GOST_H */
