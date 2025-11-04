/* CC0 license applied, see LICENCE.md */

#include "akif_ascon_common.h"

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
        proverr_free_handle(ctx->proverr_handle);
    free(ctx);
}

struct provider_ctx_st *provider_ctx_new(const OSSL_CORE_HANDLE *core,
                                        const OSSL_DISPATCH *in)
{
    struct provider_ctx_st *ctx;

    if ((ctx = malloc(sizeof(*ctx))) != NULL && (ctx->proverr_handle = proverr_new_handle(core, in)) != NULL)
    {
        ctx->core_handle = core;
    }
    else
    {
        provider_ctx_free(ctx);
        ctx = NULL;
    }
    return ctx;
}


