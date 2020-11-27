/*
 * GOST Elliptic Curve Digital Signature
 *
 * Copyright (c) 2011-2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef SSH_ECGOST_H
#define SSH_ECGOST_H  1

#include <openssl/evp.h>

#include "sshbuf.h"

struct sshkey;

unsigned ssh_ecgost_name_to_bits(const char *type);
unsigned ssh_ecgost_key_size(const struct sshkey *k);
int ssh_ecgost_equal_public(const struct sshkey *a, const struct sshkey *b);

int sshbuf_put_ecgost(struct sshbuf *b, const struct sshkey *k,
		      int header, int priv);
int sshbuf_get_ecgost(struct sshbuf *b, const char *type, int priv,
		      struct sshkey *res);

int ssh_ecgost_get_public_key(const struct sshkey *k, struct sshkey *res);
int ssh_ecgost_generate_private_key(unsigned bits, struct sshkey *res);

int ssh_ecgost_public_to_pem(const struct sshkey *k, FILE *to);
int ssh_ecgost_private_to_pem(const struct sshkey *k, FILE *to);

int ssh_ecgost_private_to_pem_bio(const struct sshkey *k,
				  const EVP_CIPHER *cipher,
				  const void *passphrase, size_t len, BIO *bio);
int ssh_ecgost_private_to_pkey(const struct sshkey *k, EVP_PKEY *pkey);
int ssh_ecgost_private_from_pkey(EVP_PKEY *pkey, struct sshkey *res);

int ssh_ecgost_sign(const struct sshkey *k, u_char **sign, size_t *len,
		    const u_char *data, size_t size, unsigned compat);
int ssh_ecgost_verify(const struct sshkey *k, const u_char *sig, size_t len,
		      const u_char *data, size_t size, unsigned compat);

#endif  /* SSH_ECGOST_H */
