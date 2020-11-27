/*
 * GOST Elliptic Curve Digital Signature
 *
 * Copyright (c) 2011-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "includes.h"

#if defined (WITH_OPENSSL) && defined (OPENSSL_HAS_ECC)

#include <stdio.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/pem.h>

#include "evp.h"
#include "ssherr.h"
#include "sshkey.h"
#include "ssh-ecgost.h"

/* info */

struct ecgost_info {
	const char *type;
	int key_size, algo, curve;
};

static const struct ecgost_info ecgost_info[] = {
#ifdef NID_id_GostR3410_2012_256
	{ "ssh-gost2012-256-cpa", 256,
	  NID_id_GostR3410_2012_256, NID_id_GostR3410_2001_CryptoPro_A_ParamSet },
	{ "ssh-gost2012-256-cpb", 256,
	  NID_id_GostR3410_2012_256, NID_id_GostR3410_2001_CryptoPro_B_ParamSet },
	{ "ssh-gost2012-256-cpc", 256,
	  NID_id_GostR3410_2012_256, NID_id_GostR3410_2001_CryptoPro_C_ParamSet },
#ifdef NID_id_tc26_gost_3410_2012_512_paramSetA
	{ "ssh-gost2012-512-tc26a", 512,
	  NID_id_GostR3410_2012_512, NID_id_tc26_gost_3410_2012_512_paramSetA },
	{ "ssh-gost2012-512-tc26b", 512,
	  NID_id_GostR3410_2012_512, NID_id_tc26_gost_3410_2012_512_paramSetB },
#endif  /* TC26 paramsets */
#endif  /* GOST R 34.10-2012 */

#ifdef NID_id_GostR3410_2001_CryptoPro_A_ParamSet
	{ "ssh-gost2001-cpa", 256,
	  NID_id_GostR3410_2001, NID_id_GostR3410_2001_CryptoPro_A_ParamSet },
#endif  /* GOST R 34.10 CryptoPro Paramset */
#ifdef NID_id_GostR3410_2001_ParamSet_cc
	{ "ssh-gost2001-cc", 256,
	  NID_id_GostR3410_2001, NID_id_GostR3410_2001_ParamSet_cc },
#endif  /* GOST R 34.10 CryptoCom Paramset */
	{},
};

static const struct ecgost_info *
ecgost_get_info(const char *type)
{
	const struct ecgost_info *p;

	for (p = ecgost_info; p->type != NULL; ++p)
		if (strcmp(p->type, type) == 0)
			return p;

	return NULL;
}

static const struct ecgost_info *
ecgost_find_info(int key_size)
{
	const struct ecgost_info *p;

	for (p = ecgost_info; p->type != NULL; ++p)
		if (p->key_size == key_size)
			return p;

	return NULL;
}

/* EC GOST ssh helpers */

static int
ssh_ecgost_init(struct sshkey *k, EC_KEY *key, const struct ecgost_info *info)
{
	k->type  = KEY_ECGOST;
	k->ecdsa = key;
	k->info  = info;
	return 0;
}

static int
ssh_ecgost_is_valid(const struct sshkey *k)
{
	return k->type == KEY_ECGOST && k->ecdsa != NULL && k->info != NULL;
}

static int
ssh_ecgost_is_empty(const struct sshkey *k)
{
	return (k->type == KEY_ECGOST && k->ecdsa == NULL) ||
		k->type == KEY_UNSPEC;
}

unsigned
ssh_ecgost_name_to_bits(const char *type)
{
	const struct ecgost_info *info;

	return (info = ecgost_get_info(type)) != NULL ? info->key_size : 0;
}

unsigned
ssh_ecgost_key_size(const struct sshkey *k)
{
	const struct ecgost_info *info = k->info;

	return ssh_ecgost_is_valid(k) ? info->key_size : 0;
}

int
ssh_ecgost_equal_public(const struct sshkey *a, const struct sshkey *b)
{
	const EC_POINT *pa, *pb;

	if (a->ecdsa == NULL || b->ecdsa == NULL)
		return 0;

	if ((pa = EC_KEY_get0_public_key(a->ecdsa)) == NULL ||
	    (pb = EC_KEY_get0_public_key(b->ecdsa)) == NULL)
		return 0;

	if (EC_GROUP_cmp(EC_KEY_get0_group(a->ecdsa),
			 EC_KEY_get0_group(b->ecdsa), NULL) != 0)
		return 0;

	return EC_POINT_cmp(EC_KEY_get0_group(a->ecdsa), pa, pb, NULL) == 0;
}

int
sshbuf_put_ecgost(struct sshbuf *b, const struct sshkey *k, int header, int priv)
{
	const struct ecgost_info *info = k->info;
	int r;

	if (!ssh_ecgost_is_valid(k))
		return SSH_ERR_INVALID_ARGUMENT;

	if ((header && (r = sshbuf_put_cstring(b, info->type)) != 0) ||
	    (r = sshbuf_put_eckey(b, k->ecdsa)) != 0)
		return r;

	return priv ?
	       sshbuf_put_bignum2(b, EC_KEY_get0_private_key(k->ecdsa)) : 0;
}

static int
sshbuf_get_ecgost_private(struct sshbuf *b, EC_KEY *key)
{
	BIGNUM *exponent = NULL;
	int r;

	if ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		return r;

	if (EC_KEY_set_private_key(key, exponent) != 1) {
		BN_clear_free(exponent);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}

	BN_clear_free(exponent);
	return sshkey_ec_validate_private(key);
}

int
sshbuf_get_ecgost(struct sshbuf *b, const char *type, int priv,
		  struct sshkey *res)
{
	const struct ecgost_info *info;
	EC_KEY *key;
	int r;

	if (!ssh_ecgost_is_empty(res))
		return SSH_ERR_INVALID_ARGUMENT;

	if ((info = ecgost_get_info(type)) == NULL)
		return SSH_ERR_INVALID_FORMAT;

	if ((key = EC_KEY_new_by_curve_name_ex(info->algo, info->curve)) == NULL)
		return SSH_ERR_EC_CURVE_INVALID;

	if ((r = sshbuf_get_eckey(b, key)) != 0)
		goto error;

	if (sshkey_ec_validate_public(EC_KEY_get0_group(key),
				      EC_KEY_get0_public_key(key)) != 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto error;
	}

	if (priv && (r = sshbuf_get_ecgost_private(b, key)) != 0)
		goto error;

	return ssh_ecgost_init(res, key, info);
error:
	EC_KEY_free(key);
	return r;
}

int
ssh_ecgost_get_public_key(const struct sshkey *k, struct sshkey *res)
{
	const struct ecgost_info *info = k->info;
	EC_KEY *key;

	if (!ssh_ecgost_is_empty(res))
		return SSH_ERR_INVALID_ARGUMENT;

	if ((key = EC_KEY_new_by_curve_name_ex(info->algo, info->curve)) == NULL)
		return SSH_ERR_EC_CURVE_INVALID;

	if (EC_KEY_set_public_key(key, EC_KEY_get0_public_key(k->ecdsa)) != 1)
		goto no_public;

	return ssh_ecgost_init(res, key, info);
no_public:
	EC_KEY_free(key);
	return SSH_ERR_LIBCRYPTO_ERROR;
}

int
ssh_ecgost_generate_private_key(unsigned bits, struct sshkey *res)
{
	const struct ecgost_info *info;
	EVP_PKEY_CTX *c;
	EVP_PKEY *pkey;
	EC_KEY *key;

	if (!ssh_ecgost_is_empty(res))
		return SSH_ERR_INVALID_ARGUMENT;

	if ((info = ecgost_find_info(bits)) == NULL)
		return SSH_ERR_KEY_LENGTH;

	if ((c = EVP_PKEY_CTX_new_id(info->algo, NULL)) == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;

	if (EVP_PKEY_keygen_init(c) != 1 ||
	    EVP_PKEY_CTX_ctrl(c, -1, -1, EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID,
			      info->curve, NULL) <= 0 ||
	    EVP_PKEY_keygen(c, &pkey) != 1)
		goto no_key;

	EVP_PKEY_CTX_free(c);

	key = EVP_PKEY_get0(pkey);
	EC_KEY_up_ref(key);
	EVP_PKEY_free(pkey);

	return ssh_ecgost_init(res, key, info);
no_key:
	EVP_PKEY_CTX_free(c);
	return SSH_ERR_LIBCRYPTO_ERROR;
}

int
ssh_ecgost_public_to_pem(const struct sshkey *k, FILE *to)
{
	return PEM_write_EC_PUBKEY(to, k->ecdsa);
}

int
ssh_ecgost_private_to_pem(const struct sshkey *k, FILE *to)
{
	return PEM_write_ECPrivateKey(to, k->ecdsa, NULL, NULL, 0, NULL, NULL);
}

int
ssh_ecgost_private_to_pem_bio(const struct sshkey *k, const EVP_CIPHER *cipher,
			      const void *passphrase, size_t len, BIO *bio)
{
	return PEM_write_bio_ECPrivateKey(bio, k->ecdsa, cipher,
					  (void *) passphrase, len,
					  NULL, NULL);
}

int
ssh_ecgost_private_to_pkey(const struct sshkey *k, EVP_PKEY *pkey)
{
	return EVP_PKEY_set1_EC_KEY(pkey, k->ecdsa);
}

static const struct ecgost_info *
ecgost_info_from_key(const EVP_PKEY *pkey)
{
	int algo = EVP_PKEY_id(pkey);
	const struct ecgost_info *p;
	const EC_GROUP *g;
	EC_GROUP *e;
	int ok;

	for (p = ecgost_info; p->type != NULL; ++p) {
		if (p->algo != algo)
			continue;

		g = EC_KEY_get0_group(EVP_PKEY_get0(pkey));

		if (p->curve == EC_GROUP_get_curve_name(g))
			return p;

		if ((e = EC_GROUP_new_by_curve_name(p->curve)) == NULL)
			return NULL;

		ok = EC_GROUP_cmp(g, e, NULL) == 0;
		EC_GROUP_free(e);

		if (ok)
			return p;
	}

	return NULL;
}

int
ssh_ecgost_private_from_pkey(EVP_PKEY *pkey, struct sshkey *res)
{
	const struct ecgost_info *info;
	EC_KEY *key;

	if (!ssh_ecgost_is_empty(res) ||
	    (info = ecgost_info_from_key(pkey)) == NULL)
		return 0;

	key = EVP_PKEY_get0(pkey);

	if (sshkey_ec_validate_public(EC_KEY_get0_group(key),
				      EC_KEY_get0_public_key(key)) != 0 ||
	    sshkey_ec_validate_private(key) != 0)
		return 0;

	EC_KEY_up_ref(key);

	return ssh_ecgost_init(res, key, info) == 0;
}

static EVP_PKEY *
ssh_ecgost_get_pkey(const struct sshkey *k)
{
	EVP_PKEY *key;

	if ((key = EVP_PKEY_new()) == NULL)
		return NULL;

	if (ssh_ecgost_private_to_pkey(k, key))
		return key;

	EVP_PKEY_free(key);
	return NULL;
}

int
ssh_ecgost_sign(const struct sshkey *k, u_char **sig, size_t *siglen,
		const u_char *data, size_t size, unsigned compat)
{
	const struct ecgost_info *info = k->info;
	EVP_PKEY *key;
	unsigned char buf[EVP_MAX_MD_SIZE * 2];  /* EVP_PKEY_size */
	size_t len;
	int ok;
	struct sshbuf *b;
	int r;

	if ((key = ssh_ecgost_get_pkey(k)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	ok = (len = evp_sign(key, data, size, buf, sizeof (buf))) > 0;
	EVP_PKEY_free(key);

	if (!ok)
		return SSH_ERR_LIBCRYPTO_ERROR;

	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((r = sshbuf_put_cstring(b, info->type)) != 0 ||
	    (r = sshbuf_put_string (b, buf, len))   != 0)
		goto error;

	len = sshbuf_len(b);

	if (siglen != NULL)
		*siglen = len;

	if (sig != NULL) {
		if ((*sig = malloc(len)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto error;
		}

		memcpy(*sig, sshbuf_ptr(b), len);
	}

	sshbuf_free(b);
	return 0;
error:
	sshbuf_free(b);
	return r;
}

int
ssh_ecgost_verify(const struct sshkey *k, const u_char *sig, size_t siglen,
		  const u_char *data, size_t size, unsigned compat)
{
	const struct ecgost_info *info = k->info;
	EVP_PKEY *key;
	int r = 0;

	struct sshbuf *b = NULL;
	char *type = NULL;
	unsigned char *sigdata;
	size_t len;

	if ((key = ssh_ecgost_get_pkey(k)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((b = sshbuf_from(sig, siglen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = sshbuf_get_cstring(b, &type, NULL)) != 0)
		goto out;

	if (strcmp(type, info->type) != 0) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	if ((r = sshbuf_get_string(b, &sigdata, &len)) != 0)
		goto out;

	if (!evp_verify(key, data, size, sigdata, len))
		r = SSH_ERR_SIGNATURE_INVALID;

	free(sigdata);
out:
	free(type);
	sshbuf_free(b);
	EVP_PKEY_free(key);
	return r;
}

#endif  /* WITH_OPENSSL and OPENSSL_HAS_ECC */
