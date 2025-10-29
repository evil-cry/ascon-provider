/* CC0 license applied, see LICENCE.md */

#ifndef AKIF_ASCON_COMMON_H
#define AKIF_ASCON_COMMON_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include "prov/err.h"
#include "prov/num.h"
#include "akif_ascon_params.h"

#include <ascon.h>

/* Return value constants */
#define OSSL_RV_SUCCESS 1
#define OSSL_RV_ERROR 0

/* Common definitions */
#define FIXED_TAG_LENGTH ASCON_AEAD_TAG_MIN_SECURE_LEN

/*********************************************************************
 *
 *  Error Definitions
 *
 *****/

#define ASCON_NO_KEYLEN_SET 1
#define ASCON_ONGOING_OPERATION 2
#define ASCON_NONCE_INCORRECT_LEN 3
#define ASCON_NO_TAG_SET 4
#define ASCON_NO_CTX_SET 5
#define ASCON_NO_ONGOING_OPERATION 6
#define ASCON_ONLY_FIXED_TAG_LENGTH_SUPPORTED 7
#define ASCON_NOT_IMPLEMENTED_YET 8

extern const OSSL_ITEM reason_strings[];

/*********************************************************************
 *
 *  Provider Context
 *
 *****/

struct provider_ctx_st
{
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;
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

#endif /* AKIF_ASCON_COMMON_H */

