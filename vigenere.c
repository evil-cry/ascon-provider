/* CC0 license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>

#include "prov/err.h"
#include "prov/num.h"
#include "v_params.h"

#include <ascon.h>

/*********************************************************************
 *
 *  Errors
 *
 *****/

/* The error reasons used here */
#define ASCON_NO_KEYLEN_SET          1
#define ASCON_ONGOING_OPERATION      2
#define ASCON_INCORRECT_KEYLEN       3
static const OSSL_ITEM reason_strings[] = {
    { ASCON_NO_KEYLEN_SET, "no key length has been set" },
    { ASCON_ONGOING_OPERATION, "an operation is underway" },
    { ASCON_INCORRECT_KEYLEN, "incorrect key length" },
    { 0, NULL }
};

/*********************************************************************
 *
 *  Provider context
 *
 *****/

struct provider_ctx_st {
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

    if ((ctx = malloc(sizeof(*ctx))) != NULL
        && (ctx->proverr_handle = proverr_new_handle(core, in)) != NULL) {
        ctx->core_handle = core;
    } else {
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
static OSSL_FUNC_provider_query_operation_fn ascon_prov_operation;
static OSSL_FUNC_provider_get_params_fn ascon_prov_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn ascon_prov_get_reason_strings;

static OSSL_FUNC_cipher_newctx_fn ascon_newctx;
static OSSL_FUNC_cipher_encrypt_init_fn akif_ascon_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn akif_ascon_decrypt_init;
static OSSL_FUNC_cipher_update_fn ascon_update;
static OSSL_FUNC_cipher_final_fn ascon_final;
static OSSL_FUNC_cipher_dupctx_fn ascon_dupctx;
static OSSL_FUNC_cipher_freectx_fn ascon_freectx;
static OSSL_FUNC_cipher_get_params_fn ascon_get_params;
static OSSL_FUNC_cipher_gettable_params_fn ascon_gettable_params;
static OSSL_FUNC_cipher_set_ctx_params_fn ascon_set_ctx_params;
static OSSL_FUNC_cipher_get_ctx_params_fn ascon_get_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn ascon_settable_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn ascon_gettable_ctx_params;

#define DEFAULT_KEYLENGTH 16    /* amount of bytes == 128 bits */
#define BLOCKSIZE 1             /* amount of bytes */

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

typedef enum direction_et {
    ENCRYPTION,
    DECRYPTION
} direction_t;

/*
 * The context used throughout all these functions.
 */
struct ascon_ctx_st {
    
    struct provider_ctx_st *provctx;
    
    // size_t keyl;                /* The configured length of the key */
   //size_t keysize;             /* Size of the key currently used */
   //size_t keypos;              /* The current position in the key */
   
   
    uint8_t *nonce;
   uint8_t *key;         /* A copy of the key */
   
    direction_t direction;       /* either encryption or decryption */
    int ongoing;                /* 1 = operation has started */
    void *internal_ctx;         /* a handle for the implementation internal context*/
};
#define ERR_HANDLE(ctx) ((ctx)->provctx->proverr_handle)

static void *ascon_newctx(void *vprovctx)
{
    struct ascon_ctx_st *ctx = malloc(sizeof(*ctx));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = vprovctx;
        //ctx->keyl = keylen();
    }
    return ctx;
}

#if 0
static void ascon_cleanctx(void *vctx)
{
    struct ascon_ctx_st *ctx = vctx;

    if (ctx == NULL)
        return;
    free(ctx->key);
    ctx->key = NULL;
    //ctx->keypos = 0;
    //ctx->enc = 0;
    ctx->ongoing = 0;
}
#endif

static void *ascon_dupctx(void *vctx)
{
    struct ascon_ctx_st *src = vctx;
    struct ascon_ctx_st *dst = NULL;

#if 0
    if (src == NULL
        || (dst = ascon_newctx(NULL)) == NULL)

    dst->provctx = src->provctx;
    dst->provctx->proverr_handle =
        proverr_dup_handle(src->provctx->proverr_handle);
    dst->keyl = src->keyl;

    if (src->key != NULL) {
        if ((dst->key = malloc(src->keyl)) == NULL) {
            ascon_freectx(dst);
            return NULL;
        }
        memcpy(dst->key, src->key, src->keyl);
    }

    dst->keypos = src->keypos;
    dst->enc = src->enc;
    dst->ongoing = src->ongoing;

    return dst;
#else
    // TO BE IMPLEMENTED
    return NULL;
#endif
}

static void ascon_freectx(void *vctx)
{
    struct ascon_ctx_st *ctx = vctx;

    ctx->provctx = NULL;
    // TODO: call ascon_cleanctx(ctx);
    free(ctx);
}

static int ascon_internal_init(void *vctx,
                              direction_t direction,
                              const unsigned char* key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;

    if (keylen != ASCON_AEAD128_KEY_LEN) {
        // TODO: handle the error
        return 0;
    }

    if (noncelen != ASCON_AEAD_NONCE_LEN) {
        // TODO: handle the error
        return 0;
    }

    if (key != NULL && nonce != NULL && ctx != NULL ) 
    
    {
        
        free(ctx->key);
        ctx->key = malloc(ASCON_AEAD128_KEY_LEN);
        memcpy(ctx->key, key, ASCON_AEAD128_KEY_LEN);
        // free and malloc for ctx->nonce
        free(ctx->nonce);
        ctx->nonce = malloc(ASCON_AEAD_NONCE_LEN);
	    memcpy(ctx->nonce, nonce, ASCON_AEAD_NONCE_LEN);
    }
    //ctx->keypos = 0; // remove structure
    ctx->ongoing = 0;
    ctx->direction = direction;
    
    // allocate and initialize ctx->internal_vctx (void*)
    // call and check return of libascon_whatever_init()
    if (ctx->direction == direction)
{
    // TODO: call ascon_aead128_init(...);
    return 0;
}
}


static int akif_ascon_encrypt_init(void *vctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[])
{
    return ascon_internal_init(vctx, ENCRYPTION, key, keylen, nonce, noncelen, params);
}

static int akif_ascon_decrypt_init(void *vctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[])
{
    return ascon_internal_init(vctx, DECRYPTION, key, keylen, nonce, noncelen, params);
}

static int ascon_update(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsize, const unsigned char *in, size_t inl)
{

    struct ascon_ctx_st *ctx = vctx;

    if (ctx->direction == ENCRYPTION)
    {
        // TODO: call ascon_aead128_encrypt_update(...) and check its return value (we noticed it cannot fail), do we need to keep track of the returned number of bytes?;
        return 0;
    }
    else if (ctx->direction == DECRYPTION)
    {
        // TODO: call ascon_aead128_decrypt_update(...) and check;
        return 0;
    }
    return 1;
}

static int ascon_final(void *vctx,
                       unsigned char *out, size_t *outl,
                       size_t outsize)
{

    struct ascon_ctx_st *ctx = vctx;

    if (ctx->direction == ENCRYPTION)
    {
        // TODO: call ascon_aead128_encrypt_final(...) and check the return value/output parameters;
        return 0;
    }
    else if(ctx->direction == DECRYPTION)
    {
        // TODO: call ascon_aead128_decrypt_final(...) and check;
        return 0;
    }
    //ciphertext = 0;
    ctx->ongoing = 0;
    return 1;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *ASCON_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "blocksize", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { "keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int ascon_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (vigenere_params_parse(p->key)) {
        case V_PARAM_blocksize:
            ok &= provnum_set_size_t(p, 1) >= 0;
            break;
        case V_PARAM_keylen:
            ok &= provnum_set_size_t(p, keylen()) >= 0;
            break;
        }
    return ok;
}

static const OSSL_PARAM *ascon_gettable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { S_PARAM_keylen, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}


static int ascon_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;
    int ok = 1;

    // TODO: to be implemented properly
#if 0
    if (ctx->keyl > 0) {
        OSSL_PARAM *p;

        for (p = params; p->key != NULL; p++)
            switch (vigenere_params_parse(p->key)) {
            case V_PARAM_keylen:
                ok &= provnum_set_size_t(p, ctx->keyl) >= 0;
                break;
            }
    }

    return ok;
#else
    return !ok; 
#endif
}

/* Parameters that libcrypto can send to this implementation */
static const OSSL_PARAM *ascon_settable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { S_PARAM_keylen, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int ascon_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;
    int ok = 1;

    // TODO: to be implemented properly
#if 0
    if (ctx->ongoing) {
        ERR_raise(ERR_HANDLE(ctx), ASCON_ONGOING_OPERATION);
        return 0;
    }

    for (p = params; p->key != NULL; p++)
        switch (vigenere_params_parse(p->key)) {
        case V_PARAM_keylen:
        {
            size_t keyl = 0;
            int res = provnum_get_size_t(&keyl, p) >= 0;

            ok &= res;
            if (res)
                ctx->keyl = keyl;
        }
        }
    return ok;
#else
    return !ok;
#endif
}


/*********************************************************************
 *
 *  Setup
 *
 *****/

typedef void (*funcptr_t)(void);

/* The Vigenere dispatch table */
static const OSSL_DISPATCH ascon_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)ascon_newctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)akif_ascon_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)akif_ascon_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)ascon_update },
    { OSSL_FUNC_CIPHER_FINAL, (funcptr_t)ascon_final },
    { OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)ascon_dupctx },
    { OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)ascon_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)ascon_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)ascon_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)ascon_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (funcptr_t)ascon_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)ascon_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
      (funcptr_t)ascon_settable_ctx_params },
    { 0, NULL }
};

/* The table of ciphers this provider offers */
static const OSSL_ALGORITHM ascon_ciphers[] = {
    { "vigenere:1.3.6.1.4.1.5168.4711.22087.1", "x.author='" AUTHOR "'",
      ascon_functions },
    { NULL, NULL, NULL }
};

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *ascon_prov_operation(void *vprovctx,
                                                     int operation_id,
                                                     int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
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

    for(p = params; p->key != NULL; p++)
        switch (vigenere_params_parse(p->key)) {
        case V_PARAM_version:
            *(const void **)p->data = VERSION;
            p->return_size = strlen(VERSION);
            break;
        case V_PARAM_buildinfo:
            if (BUILDTYPE[0] != '\0') {
                *(const void **)p->data = BUILDTYPE;
                p->return_size = strlen(BUILDTYPE);
            }
            break;
        case V_PARAM_author:
            if (AUTHOR[0] != '\0') {
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

/* The base dispatch table */
static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (funcptr_t)ascon_prov_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)ascon_prov_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
      (funcptr_t)ascon_prov_get_reason_strings },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
      (funcptr_t)ascon_prov_get_params },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **vprovctx)
{
    if ((*vprovctx = provider_ctx_new(core, in)) == NULL)
        return 0;
    *out = provider_functions;
    return 1;
}
