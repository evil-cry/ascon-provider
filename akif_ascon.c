/* CC0 license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include "prov/err.h"
#include "prov/num.h"
#include "akif_ascon_params.h"

#include <ascon.h>

#define OSSL_RV_SUCCESS 1
#define OSSL_RV_ERROR 0

#define FIXED_TAG_LENGTH ASCON_AEAD_TAG_MIN_SECURE_LEN

/*********************************************************************
 *
 *  Errors
 *
 *****/

/* The error reasons used here */
#define ASCON_NO_KEYLEN_SET 1
#define ASCON_ONGOING_OPERATION 2
#define ASCON_NONCE_INCORRECT_LEN 3
#define ASCON_NO_TAG_SET 4
#define ASCON_NO_CTX_SET 5
#define ASCON_NO_ONGOING_OPERATION 6
#define ASCON_ONLY_FIXED_TAG_LENGTH_SUPPORTED 7
#define ASCON_NOT_IMPLEMENTED_YET 8

static const OSSL_ITEM reason_strings[] = {
    {ASCON_NO_KEYLEN_SET, "no key length has been set"},
    {ASCON_ONGOING_OPERATION, "an operation is underway"},
    {ASCON_NONCE_INCORRECT_LEN, "incorrect length for nonce"},
    {ASCON_NO_TAG_SET, "no tag has been set"},
    {ASCON_NO_CTX_SET, "no contect has been set"},
    {ASCON_NO_ONGOING_OPERATION, "No operation is underway"},
    {ASCON_ONLY_FIXED_TAG_LENGTH_SUPPORTED, "Only a fixed tag length of 16 bytes is supported by this implementation"},
    {ASCON_NOT_IMPLEMENTED_YET, "Not implemented yet"},
    {0, NULL}};

/*********************************************************************
 *
 *  Provider context
 *
 *****/

struct provider_ctx_st
{
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;
};

static void provider_ctx_free(struct provider_ctx_st *ctx)
{
    if (ctx != NULL)
        proverr_free_handle(ctx->proverr_handle);
    free(ctx);
}

static struct provider_ctx_st *provider_ctx_new(const OSSL_CORE_HANDLE *core,
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

/*********************************************************************
 *
 *  The implementation itself
 *
 *****/

/*
 * Forward declarations to ensure we get signatures right.  All the
 * OSSL_FUNC_* types come from <openssl/core_dispatch.h>
 */
static OSSL_FUNC_provider_query_operation_fn akif_ascon_prov_operation;
static OSSL_FUNC_provider_get_params_fn akif_ascon_prov_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn akif_ascon_prov_get_reason_strings;

static OSSL_FUNC_cipher_newctx_fn akifascon128_newctx;
static OSSL_FUNC_cipher_encrypt_init_fn akifascon128_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn akifascon128_decrypt_init;
static OSSL_FUNC_cipher_update_fn akifascon128_update;
static OSSL_FUNC_cipher_final_fn akifascon128_final;
static OSSL_FUNC_cipher_dupctx_fn akifascon128_dupctx;
static OSSL_FUNC_cipher_freectx_fn akifascon128_freectx;
static OSSL_FUNC_cipher_get_params_fn akifascon128_get_params;
static OSSL_FUNC_cipher_gettable_params_fn akifascon128_gettable_params;
static OSSL_FUNC_cipher_set_ctx_params_fn akifascon128_set_ctx_params;
static OSSL_FUNC_cipher_get_ctx_params_fn akifascon128_get_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn akifascon128_settable_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn akifascon128_gettable_ctx_params;

#define DEFAULT_KEYLENGTH 16 /* amount of bytes == 128 bits */
#define BLOCKSIZE 1          /* amount of bytes */

/* Helper function to determine the key length */
static size_t keylen()
{
    /*
     * Give the user a chance to decide a default.
     * With 'openssl enc', this is the only viable way for the user
     * to set an arbitrary key length.
     * Note that the length is expressed in bytes.
     */
    const char *user_keyl = getenv("ASCON_KEYLEN");
    size_t keyl = DEFAULT_KEYLENGTH;

    if (user_keyl != NULL)
        keyl = strtoul(user_keyl, NULL, 0);
    return keyl;
}

typedef enum direction_et
{
    ENCRYPTION,
    DECRYPTION
} direction_t;

typedef ascon_aead_ctx_t intctx_t;

/*
 * The context used throughout all these functions.
 */
struct akif_ascon_ctx_st
{

    struct provider_ctx_st *provctx;

    uint8_t tag[FIXED_TAG_LENGTH]; // storing the tag with fixed length
    bool is_tag_set;               // whether a tag has been computed or set

    direction_t direction;  /* either encryption or decryption */
    bool is_ongoing;        /* true = operation has started */
    intctx_t *internal_ctx; /* a handle for the implementation internal context*/
    bool assoc_data_processed;  /* whether associated data has been processed */
    size_t tag_len;          /* tag length being used */
};
#define ERR_HANDLE(ctx) ((ctx)->provctx->proverr_handle)

static void *akifascon128_newctx(void *vprovctx)
{
    struct akif_ascon_ctx_st *ctx = malloc(sizeof(*ctx));

    if (ctx != NULL)
    {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = vprovctx;
        ctx->is_tag_set = false;
        ctx->is_ongoing = false;
        ctx->assoc_data_processed = false;
        ctx->tag_len = FIXED_TAG_LENGTH;  /* default tag length */

        intctx_t *intctx = calloc(1, sizeof(*intctx));
        if (intctx != NULL)
        {
            ctx->internal_ctx = intctx;
        }
        else
        {
            free(ctx);
            return NULL;
        }
    }
    return ctx;
}

static void akifascon128_cleanctx(void *vctx)
{
    struct akif_ascon_ctx_st *ctx = vctx;

    ctx->is_tag_set = false;
    ctx->is_ongoing = false;
    ctx->assoc_data_processed = false;
    ctx->tag_len = FIXED_TAG_LENGTH;
    memset(ctx->internal_ctx, 0, sizeof(*(ctx->internal_ctx)));
    memset(ctx->tag, 0, sizeof(ctx->tag));
}

static void *akifascon128_dupctx(void *vctx)
{
    struct akif_ascon_ctx_st *src = vctx;
    struct akif_ascon_ctx_st *dst = NULL;

    if (src == NULL)
        return NULL;

    // Create new context using the same provider context
    if ((dst = akifascon128_newctx(src->provctx)) == NULL)
        return NULL;

    // Copy all context fields
    dst->direction = src->direction;
    dst->is_ongoing = src->is_ongoing;
    dst->is_tag_set = src->is_tag_set;
    dst->assoc_data_processed = src->assoc_data_processed;
    dst->tag_len = src->tag_len;

    // Copy tag if it's set
    if (src->is_tag_set) {
        memcpy(dst->tag, src->tag, FIXED_TAG_LENGTH);
    }

    // Deep copy the internal LibAscon context
    if (src->internal_ctx != NULL && dst->internal_ctx != NULL) {
        memcpy(dst->internal_ctx, src->internal_ctx, sizeof(*dst->internal_ctx));
    }

    return dst;
}

static void akifascon128_freectx(void *vctx)
{
    struct akif_ascon_ctx_st *ctx = vctx;

    if (ctx == NULL)
        return;

    ctx->provctx = NULL;
    akifascon128_cleanctx(ctx);
    free(ctx->internal_ctx);
    free(ctx);
}

/* MY INTERNAL INIT FUNCTION (glue) */

static int akifascon128_internal_init(void *vctx, direction_t direction,
                                      const unsigned char *key, size_t keylen,
                                      const unsigned char *nonce, size_t noncelen,
                                      const OSSL_PARAM params[])
{
    struct akif_ascon_ctx_st *ctx = vctx;

    assert(ctx != NULL);
    akifascon128_cleanctx(ctx);

    if (nonce != NULL)
    {
        if (noncelen != ASCON_AEAD_NONCE_LEN)
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_NONCE_INCORRECT_LEN);
            return OSSL_RV_ERROR;
        }
    }

    ctx->direction = direction;

    if (key != NULL && nonce != NULL)
    {

        ascon_aead128_init(ctx->internal_ctx, key, nonce);
        ctx->is_ongoing = true;
        return OSSL_RV_SUCCESS;
    }
    return OSSL_RV_SUCCESS;
}

static int akifascon128_encrypt_init(void *vctx,
                                     const unsigned char *key, size_t keylen,
                                     const unsigned char *nonce, size_t noncelen,
                                     const OSSL_PARAM params[])
{
    return akifascon128_internal_init(vctx, ENCRYPTION, key, keylen, nonce, noncelen, params);
}

static int akifascon128_decrypt_init(void *vctx,
                                     const unsigned char *key, size_t keylen,
                                     const unsigned char *nonce, size_t noncelen,
                                     const OSSL_PARAM params[])
{

    return akifascon128_internal_init(vctx, DECRYPTION, key, keylen, nonce, noncelen, params);
}

static int akifascon128_update(void *vctx, unsigned char *out, size_t *outl,
                               size_t outsize, const unsigned char *in, size_t inl)
{

    struct akif_ascon_ctx_st *ctx = vctx;

    if (ctx == NULL)
    {
        // handling the error
        ERR_raise(ERR_HANDLE(ctx), ASCON_NO_CTX_SET);
        return OSSL_RV_ERROR;
    }

    if (ctx->is_ongoing == false)
    {
        // handling the error
        ERR_raise(ERR_HANDLE(ctx), ASCON_NO_ONGOING_OPERATION);
        return OSSL_RV_ERROR;
    }

    if (ctx->direction == ENCRYPTION)
    {
        const uint8_t *plaintext = in;
        size_t plaintext_len = inl;
        uint8_t *ciphertext = out;
        size_t ciphertext_len;

        ciphertext_len = ascon_aead128_encrypt_update(ctx->internal_ctx, ciphertext, plaintext, plaintext_len);
        *outl = ciphertext_len;
        return OSSL_RV_SUCCESS;
    }

    else if (ctx->direction == DECRYPTION)

    {
        uint8_t *plaintext = out;
        size_t plaintext_len;
        const uint8_t *ciphertext = in;
        size_t ciphertext_len = inl;

        plaintext_len = ascon_aead128_decrypt_update(ctx->internal_ctx, plaintext, ciphertext, ciphertext_len);
        *outl = plaintext_len;
        return OSSL_RV_SUCCESS;
    }
    return OSSL_RV_ERROR;
}

/* PROVIDER'S FINAL FUNCTION*/

static int akifascon128_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{

    struct akif_ascon_ctx_st *ctx = vctx;

    if (ctx == NULL)
    {
        ERR_raise(ERR_HANDLE(ctx), ASCON_NO_CTX_SET);
        return OSSL_RV_ERROR;
    }

    if (ctx->is_ongoing == false)
    {
        ERR_raise(ERR_HANDLE(ctx), ASCON_NO_ONGOING_OPERATION);
        return OSSL_RV_ERROR;
    }

    if (ctx->direction == ENCRYPTION)
    {
        uint8_t *ciphertext = out;
        uint8_t *tag = ctx->tag;
        size_t tag_len = FIXED_TAG_LENGTH;
        size_t ret;

        ret = ascon_aead128_encrypt_final((ascon_aead_ctx_t *)ctx->internal_ctx, ciphertext, tag, tag_len);
        *outl = ret;
        ctx->is_tag_set = true;

        return OSSL_RV_SUCCESS;
    }
    else if (ctx->direction == DECRYPTION)
    {

        uint8_t *plaintext = out;
        bool is_tag_valid = false;
        size_t ret;

        if (ctx->is_tag_set)
        {
            const uint8_t *expected_tag = ctx->tag;
            size_t expected_tag_len = FIXED_TAG_LENGTH;

            ret = ascon_aead128_decrypt_final((ascon_aead_ctx_t *)ctx->internal_ctx, plaintext, &is_tag_valid, expected_tag, expected_tag_len);

            if (is_tag_valid)
            {
                *outl = ret;
                return OSSL_RV_SUCCESS;
            }
            else
            {
                return OSSL_RV_ERROR;
            }
        }
        else
        {
            ERR_raise(ERR_HANDLE(ctx), ASCON_NO_TAG_SET);
            return OSSL_RV_ERROR;
        }
    }

    *outl = 0;
    return OSSL_RV_SUCCESS;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *akifascon128_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        {"blocksize", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {"keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {"ivlen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {"aead", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {NULL, 0, NULL, 0, 0},
    };

    return table;
}

static int akifascon128_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (akif_ascon_params_parse(p->key))
        {
        case V_PARAM_blocksize:
            ok &= provnum_set_size_t(p, 1) >= 0;
            break;
        case V_PARAM_keylen:
            ok &= provnum_set_size_t(p, ASCON_AEAD128_KEY_LEN) >= 0;
            break;
        case V_PARAM_noncelen:
            ok &= provnum_set_size_t(p, ASCON_AEAD_NONCE_LEN) >= 0;
            break;
        case V_PARAM_aead:
            ok &= provnum_set_size_t(p, 1) >= 0;  // AEAD is supported
            break;
        }
    return ok;
}

static const OSSL_PARAM *akifascon128_gettable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0, NULL),
        OSSL_PARAM_END,
    };

    return table;
}

static int akifascon128_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct akif_ascon_ctx_st *ctx = vctx;
    int ok = 1;

#if 1
    OSSL_PARAM *p;

    for (p = params; p->key != NULL; p++)
        switch (akif_ascon_params_parse(p->key))
        {
        case V_PARAM_keylen:
            ok &= provnum_set_size_t(p, ASCON_AEAD128_KEY_LEN) >= 0;
            break;
        case V_PARAM_noncelen:
            ok &= provnum_set_size_t(p, ASCON_AEAD_NONCE_LEN) >= 0;
            break;
        case V_PARAM_taglen:
            ok &= provnum_set_size_t(p, ctx->tag_len) >= 0;
            break;
        case V_PARAM_tag:
            // check if p->data_type matches "octect string"
            // check that p->data (the given buffer) is not NULL
            if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
            {
                ok = 0;
                break;
            }

            // Check if the given buffer is big enough (p->data_size is big enough?)
            if (p->data_size < FIXED_TAG_LENGTH)
            {
                ok = 0;
                break;
            }

            // Check if ctx->is_tag_set is true
            if (!ctx->is_tag_set)
            {
                ERR_raise(ERR_HANDLE(ctx), ASCON_NO_TAG_SET);
                ok = 0;
                break;
            }
            // copy tag to destination
            memcpy(p->data, ctx->tag, FIXED_TAG_LENGTH);
            p->return_size = FIXED_TAG_LENGTH;
            ok &= 1;
            break;
        }

    return ok;
#else
    return !ok;
#endif
}

/* Parameters that libcrypto can send to this implementation */
static const OSSL_PARAM *akifascon128_settable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
        OSSL_PARAM_END,
    };

    return table;
}

static int akifascon128_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct akif_ascon_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (akif_ascon_params_parse(p->key))
        {
        case V_PARAM_taglen:
        {
            size_t tag_len = 0;
            if (!provnum_get_size_t(p, &tag_len))
            {
                ok = 0;
                break;
            }
            if (tag_len != FIXED_TAG_LENGTH)
            {
                ERR_raise(ERR_HANDLE(ctx), ASCON_ONLY_FIXED_TAG_LENGTH_SUPPORTED);
                ok = 0;
                break;
            }
            ctx->tag_len = tag_len;
            ok = 1;
        }
        break;
        case V_PARAM_tag:
        {
            if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
            {
                ok = 0;
                break;
            }

            // We only accept stricyl 16B tags here
            if (p->data_size != FIXED_TAG_LENGTH)
            {
                ERR_raise(ERR_HANDLE(ctx), ASCON_ONLY_FIXED_TAG_LENGTH_SUPPORTED);
                ok = 0;
                break;
            }
            memcpy(ctx->tag, p->data, FIXED_TAG_LENGTH);
            ctx->is_tag_set = 1;
        }
        }
    // #endif
    return ok;
}

/*********************************************************************
 *
 *  Setup
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
    {0, NULL}};

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
