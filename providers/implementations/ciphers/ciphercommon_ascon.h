/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROV_CIPHERCOMMON_ASCON_H
# define OSSL_PROV_CIPHERCOMMON_ASCON_H

# include <stdlib.h>
# include <string.h>
# include <stdint.h>
# include <stdbool.h>

# include <openssl/core.h>
# include <openssl/core_dispatch.h>
# include <openssl/core_names.h>
# include <openssl/params.h>
# include <openssl/err.h>

# include <ascon.h>

/* Return value constants */
# define OSSL_RV_SUCCESS 1
# define OSSL_RV_ERROR 0

/* Common definitions */
# define FIXED_TAG_LENGTH ASCON_AEAD_TAG_MIN_SECURE_LEN

/*********************************************************************
 *
 *  Error Definitions
 *
 *****/

# define ASCON_NO_KEYLEN_SET 1
# define ASCON_ONGOING_OPERATION 2
# define ASCON_NONCE_INCORRECT_LEN 3
# define ASCON_NO_TAG_SET 4
# define ASCON_NO_CTX_SET 5
# define ASCON_NO_ONGOING_OPERATION 6
# define ASCON_ONLY_FIXED_TAG_LENGTH_SUPPORTED 7
# define ASCON_NOT_IMPLEMENTED_YET 8

extern const OSSL_ITEM reason_strings[];

/*********************************************************************
 *
 *  Provider Context
 *
 *****/

struct provider_ctx_st
{
    const OSSL_CORE_HANDLE *core_handle;
};

void provider_ctx_free(struct provider_ctx_st *ctx);
struct provider_ctx_st *provider_ctx_new(const OSSL_CORE_HANDLE *core,
                                         const OSSL_DISPATCH *in);

/*********************************************************************
 *
 *  Provider Entry Point
 *
 *****/

/* OSSL_provider_init - main entry point for the provider */
int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx);

#endif /* OSSL_PROV_CIPHERCOMMON_ASCON_H */

