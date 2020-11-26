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

#endif  /* WITH_OPENSSL */
