/* CC0 license applied, see LICENCE.md */

#include "akif_ascon_aead128.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * Forward declarations to ensure we get signatures right.  All the
 * OSSL_FUNC_* types come from <openssl/core_dispatch.h>
 */
OSSL_FUNC_cipher_newctx_fn akifascon128_newctx;
OSSL_FUNC_cipher_encrypt_init_fn akifascon128_encrypt_init;
OSSL_FUNC_cipher_decrypt_init_fn akifascon128_decrypt_init;
OSSL_FUNC_cipher_update_fn akifascon128_update;
OSSL_FUNC_cipher_final_fn akifascon128_final;
OSSL_FUNC_cipher_dupctx_fn akifascon128_dupctx;
OSSL_FUNC_cipher_freectx_fn akifascon128_freectx;
OSSL_FUNC_cipher_get_params_fn akifascon128_get_params;
OSSL_FUNC_cipher_gettable_params_fn akifascon128_gettable_params;
OSSL_FUNC_cipher_set_ctx_params_fn akifascon128_set_ctx_params;
OSSL_FUNC_cipher_get_ctx_params_fn akifascon128_get_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn akifascon128_settable_ctx_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn akifascon128_gettable_ctx_params;
OSSL_FUNC_cipher_get_iv_length_fn akifascon128_get_iv_length;
OSSL_FUNC_cipher_get_tag_length_fn akifascon128_get_tag_length;

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

void *akifascon128_newctx(void *vprovctx)
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

void *akifascon128_dupctx(void *vctx)
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

void akifascon128_freectx(void *vctx)
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

int akifascon128_encrypt_init(void *vctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[])
{
    return akifascon128_internal_init(vctx, ENCRYPTION, key, keylen, nonce, noncelen, params);
}

int akifascon128_decrypt_init(void *vctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[])
{

    return akifascon128_internal_init(vctx, DECRYPTION, key, keylen, nonce, noncelen, params);
}

int akifascon128_update(void *vctx, unsigned char *out, size_t *outl,
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

int akifascon128_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
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
const OSSL_PARAM *akifascon128_gettable_params(void *provctx)
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

int akifascon128_get_params(OSSL_PARAM params[])
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

const OSSL_PARAM *akifascon128_gettable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        {OSSL_CIPHER_PARAM_KEYLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {OSSL_CIPHER_PARAM_AEAD_TAGLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
        {NULL, 0, NULL, 0, 0},
    };

    return table;
}

int akifascon128_get_ctx_params(void *vctx, OSSL_PARAM params[])
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
const OSSL_PARAM *akifascon128_settable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        {OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
        {OSSL_CIPHER_PARAM_AEAD_TAGLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0},
        {NULL, 0, NULL, 0, 0},
    };

    return table;
}

int akifascon128_set_ctx_params(void *vctx, const OSSL_PARAM params[])
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
            if (!provnum_get_size_t(&tag_len, p))
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

/* Added by Jack Barsa */
/* These helper functions tell OpenSSL the IV and tag sizes for Ascon AEAD */

size_t akifascon128_get_iv_length(void *vctx)
{
    /* Ascon uses a 128-bit (16-byte) IV */
    return ASCON_AEAD_NONCE_LEN;
}

size_t akifascon128_get_tag_length(void *vctx)
{
    /* Ascon authentication tag is also 16 bytes (128 bits) */
    return FIXED_TAG_LENGTH;
}

/*********************************************************************
 *
 *  Setup
 *
 *****/

typedef void (*funcptr_t)(void);

/* The Akif-Ascon dispatch table */
const OSSL_DISPATCH akifascon128_functions[] = {
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
    {OSSL_FUNC_CIPHER_GET_IV_LENGTH, (funcptr_t)akifascon128_get_iv_length},
    {OSSL_FUNC_CIPHER_GET_TAG_LENGTH, (funcptr_t)akifascon128_get_tag_length},
    {0, NULL}};
