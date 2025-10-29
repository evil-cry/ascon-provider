/* CC0 license applied, see LICENCE.md */

#include <string.h>
#include "akif_ascon_common.h"
#include "akif_ascon_aead128.h"

/*
 * Forward declarations to ensure we get signatures right.  All the
 * OSSL_FUNC_* types come from <openssl/core_dispatch.h>
 */
static OSSL_FUNC_provider_query_operation_fn akif_ascon_prov_operation;
static OSSL_FUNC_provider_get_params_fn akif_ascon_prov_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn akif_ascon_prov_get_reason_strings;

/*********************************************************************
 *
 *  Provider Setup
 *
 *****/

/* The table of ciphers this provider offers */
static const OSSL_ALGORITHM akif_ascon_ciphers[] = {
    {"akifascon128", "x.author='" AUTHOR "'", akifascon128_functions},
    {NULL, NULL, NULL}};

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *akif_ascon_prov_operation(void *vprovctx,
                                                       int operation_id,
                                                       int *no_cache)
{
    *no_cache = 0;
    switch (operation_id)
    {
    case OSSL_OP_CIPHER:
        return akif_ascon_ciphers;
    }
    return NULL;
}

static const OSSL_ITEM *akif_ascon_prov_get_reason_strings(void *provctx)
{
    return reason_strings;
}

static int akif_ascon_prov_get_params(void *provctx, OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (akif_ascon_params_parse(p->key))
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
static void akif_ascon_prov_teardown(void *vprovctx)
{
    provider_ctx_free(vprovctx);
}

typedef void (*funcptr_t)(void);

/* The base dispatch table */
static const OSSL_DISPATCH provider_functions[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (funcptr_t)akif_ascon_prov_teardown},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)akif_ascon_prov_operation},
    {OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
     (funcptr_t)akif_ascon_prov_get_reason_strings},
    {OSSL_FUNC_PROVIDER_GET_PARAMS,
     (funcptr_t)akif_ascon_prov_get_params},
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
