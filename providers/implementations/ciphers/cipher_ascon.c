/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

# include <string.h>
# include <openssl/core_names.h>
# include "ciphercommon_ascon.h"
# include "cipher_ascon128.h"

/* Provider version and metadata */
# ifndef VERSION
#  define VERSION "1.0.0"
# endif

# ifndef AUTHOR
#  define AUTHOR "OpenSSL Project"
# endif

# ifndef BUILDTYPE
#  define BUILDTYPE ""
# endif

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

/* The table of ciphers this provider offers */
static const OSSL_ALGORITHM ascon_ciphers[] = {
    {"ascon128", "x.author='" AUTHOR "'", ossl_ascon128_functions},
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

    for (p = params; p->key != NULL; p++) {
        if (strcmp(p->key, "version") == 0) {
            *(const void **)p->data = VERSION;
            p->return_size = strlen(VERSION);
        } else if (strcmp(p->key, "buildinfo") == 0) {
            if (BUILDTYPE[0] != '\0')
            {
                *(const void **)p->data = BUILDTYPE;
                p->return_size = strlen(BUILDTYPE);
            }
        } else if (strcmp(p->key, "author") == 0) {
            if (AUTHOR[0] != '\0')
            {
                *(const void **)p->data = AUTHOR;
                p->return_size = strlen(AUTHOR);
            }
        }
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

