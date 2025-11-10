/* CC0 license applied, see LICENCE.md */

#include <string.h>
#include "akif_ascon_common.h"
#include "akif_ascon_aead128.h"

/*
 * Forward declarations to ensure we get signatures right.  All the
 * OSSL_FUNC_* types come from <openssl/core_dispatch.h>
 */
static OSSL_FUNC_provider_query_operation_fn ascon_prov_operation;
static OSSL_FUNC_provider_get_params_fn ascon_prov_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn ascon_prov_get_reason_strings;

/*********************************************************************
 *
 *  Provider Setup
 *
 *****/


typedef void (*funcptr_t)(void);

/* The Akif-Ascon dispatch table */
static const OSSL_DISPATCH akifascon128_functions[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)akifascon128_newctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)akifascon128_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)akifascon128_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)akifascon128_update},
    {OSSL_FUNC_CIPHER_FINAL, (funcptr_t)akifascon128_final},
    {OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)akifascon128_dupctx},
    {OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)akifascon128_freectx},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)akifascon128_get_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)akifascon128_gettable_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)akifascon128_get_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (funcptr_t)akifascon128_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)akifascon128_set_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (funcptr_t)akifascon128_settable_ctx_params},
    { OSSL_FUNC_CIPHER_GET_IV_LENGTH,  (void (*)(void))ascon_cipher_get_iv_length },
    { OSSL_FUNC_CIPHER_GET_TAG_LENGTH, (void (*)(void))ascon_cipher_get_tag_length },
    {0, NULL}
    };


/* The table of ciphers this provider offers */
static const OSSL_ALGORITHM ascon_ciphers[] = {
    {"ascon128", "x.author='" AUTHOR "'", akifascon128_functions},
    {NULL, NULL, NULL}};

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *ascon_prov_operation(void *vprovctx,
                                                       int operation_id,
                                                       int *no_cache)
{
    *no_cache = 0;
    switch (operation_id)
    {
    case OSSL_OP_CIPHER:
        return ascon_ciphers;
    }
    return NULL;
}

static const OSSL_ITEM *ascon_prov_get_reason_strings(void *provctx)
{
    return reason_strings;
}

static int ascon_prov_get_params(void *provctx, OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (ascon_params_parse(p->key))
        {
        case V_PARAM_version:
            *(const void **)p->data = VERSION;
            p->return_size = strlen(VERSION);
            break;
        case V_PARAM_buildinfo:
            if (BUILDTYPE[0] != '\0')
            {
                *(const void **)p->data = BUILDTYPE;
                p->return_size = strlen(BUILDTYPE);
            }
            break;
        case V_PARAM_author:
            if (AUTHOR[0] != '\0')
            {
                *(const void **)p->data = AUTHOR;
                p->return_size = strlen(AUTHOR);
            }
            break;
        }
    return ok;
}

/* The function that tears down this provider */
static void ascon_prov_teardown(void *vprovctx)
{
    provider_ctx_free(vprovctx);
}

typedef void (*funcptr_t)(void);

/* The base dispatch table */
static const OSSL_DISPATCH provider_functions[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (funcptr_t)ascon_prov_teardown},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)ascon_prov_operation},
    {OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
     (funcptr_t)ascon_prov_get_reason_strings},
    {OSSL_FUNC_PROVIDER_GET_PARAMS,
     (funcptr_t)ascon_prov_get_params},
    {0, NULL}};

int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **vprovctx)
{
    if ((*vprovctx = provider_ctx_new(core, in)) == NULL)
        return 0;
    *out = provider_functions;
    return OSSL_RV_SUCCESS;
}
/* Added by Jack Barsa */
/* These helper functions tell OpenSSL the IV and tag sizes for Ascon AEAD */

static size_t ascon_cipher_get_iv_length(void *vctx)
{
    /* Ascon uses a 128-bit (16-byte) IV */
    return 16;
}

static size_t ascon_cipher_get_tag_length(void *vctx)
{
    /* Ascon authentication tag is also 16 bytes (128 bits) */
    return 16;
}
