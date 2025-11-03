/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

# include "ciphercommon_ascon.h"
# include "ciphercommon_ascon_compat.h"

/*********************************************************************
 *
 *  Error Strings
 *
 *****/

const OSSL_ITEM reason_strings[] = {
    {ASCON_NO_KEYLEN_SET, "no key length has been set"},
    {ASCON_ONGOING_OPERATION, "an operation is underway"},
    {ASCON_NONCE_INCORRECT_LEN, "incorrect length for nonce"},
    {ASCON_NO_TAG_SET, "no tag has been set"},
    {ASCON_NO_CTX_SET, "no context has been set"},
    {ASCON_NO_ONGOING_OPERATION, "No operation is underway"},
    {ASCON_ONLY_FIXED_TAG_LENGTH_SUPPORTED, "Only a fixed tag length of 16 bytes is supported by this implementation"},
    {ASCON_NOT_IMPLEMENTED_YET, "Not implemented yet"},
    {0, NULL}};

/*********************************************************************
 *
 *  Provider Context Implementation
 *
 *****/

void provider_ctx_free(struct provider_ctx_st *ctx)
{
    if (ctx != NULL)
        OPENSSL_clear_free(ctx, sizeof(*ctx));
}

struct provider_ctx_st *provider_ctx_new(const OSSL_CORE_HANDLE *core,
                                        const OSSL_DISPATCH *in)
{
    struct provider_ctx_st *ctx;

    if ((ctx = OPENSSL_malloc(sizeof(*ctx))) != NULL)
    {
        ctx->core_handle = core;
    }
    return ctx;
}

