/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROV_CIPHER_ASCON128_H
# define OSSL_PROV_CIPHER_ASCON128_H

# include "cipher_ascon.h"

/*********************************************************************
 *
 *  ASCON-128 AEAD Function Declarations
 *
 *****/

/* OSSL_FUNC_cipher_* function pointers */
void *ossl_cipher_ascon128_newctx(void *vprovctx);
int ossl_cipher_ascon128_encrypt_init(void *vctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[]);
int ossl_cipher_ascon128_decrypt_init(void *vctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[]);
int ossl_cipher_ascon128_update(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsize, const unsigned char *in, size_t inl);
int ossl_cipher_ascon128_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize);
void *ossl_cipher_ascon128_dupctx(void *vctx);
void ossl_cipher_ascon128_freectx(void *vctx);
int ossl_cipher_ascon128_get_params(OSSL_PARAM params[]);
const OSSL_PARAM *ossl_cipher_ascon128_gettable_params(void *provctx);
int ossl_cipher_ascon128_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
int ossl_cipher_ascon128_get_ctx_params(void *vctx, OSSL_PARAM params[]);
const OSSL_PARAM *ossl_cipher_ascon128_settable_ctx_params(void *cctx, void *provctx);
const OSSL_PARAM *ossl_cipher_ascon128_gettable_ctx_params(void *cctx, void *provctx);

/* Note: get_iv_length and get_tag_length are helper functions but not
 * part of the OpenSSL dispatch table. IV and tag lengths are retrieved
 * via get_ctx_params instead.
 */
size_t ossl_cipher_ascon128_get_iv_length(void *vctx);
size_t ossl_cipher_ascon128_get_tag_length(void *vctx);

/* Dispatch table for ASCON-128 */
extern const OSSL_DISPATCH ossl_ascon128_functions[];

#endif /* OSSL_PROV_CIPHER_ASCON128_H */

