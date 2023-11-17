/* CC0 license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>

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
#define ASCON_NO_KEYLEN_SET          1
#define ASCON_ONGOING_OPERATION      2
#define NONCE_INCORRECT_KEYLEN       3
static const OSSL_ITEM reason_strings[] = {
    { ASCON_NO_KEYLEN_SET, "no key length has been set" },
    { ASCON_ONGOING_OPERATION, "an operation is underway" },
    //{ ASCON_INCORRECT_KEYLEN, "incorrect key length" },
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
static OSSL_FUNC_provider_query_operation_fn akif_ascon_prov_operation;
static OSSL_FUNC_provider_get_params_fn akif_ascon_prov_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn akif_ascon_prov_get_reason_strings;

static OSSL_FUNC_cipher_newctx_fn akif_ascon_newctx;
static OSSL_FUNC_cipher_encrypt_init_fn akif_ascon_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn akif_ascon_decrypt_init;
static OSSL_FUNC_cipher_update_fn akif_ascon_update;
static OSSL_FUNC_cipher_final_fn akif_ascon_final;
static OSSL_FUNC_cipher_dupctx_fn akif_ascon_dupctx;
static OSSL_FUNC_cipher_freectx_fn akif_ascon_freectx;
static OSSL_FUNC_cipher_get_params_fn akif_ascon_get_params;
static OSSL_FUNC_cipher_gettable_params_fn akif_ascon_gettable_params;
static OSSL_FUNC_cipher_set_ctx_params_fn akif_ascon_set_ctx_params;
static OSSL_FUNC_cipher_get_ctx_params_fn akif_ascon_get_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn akif_ascon_settable_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn akif_ascon_gettable_ctx_params;

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

typedef ascon_aead_ctx_t intctx_t;

/*
 * The context used throughout all these functions.
 */
struct akif_ascon_ctx_st {

    struct provider_ctx_st *provctx;

    uint8_t tag[FIXED_TAG_LENGTH];    //storing the tag with fixed length
    bool is_tag_set;             // wether a tag has been computed or set

    direction_t direction;      /* either encryption or decryption */
    bool is_ongoing;            /* true = operation has started */
    intctx_t *internal_ctx;     /* a handle for the implementation internal context*/
};
#define ERR_HANDLE(ctx) ((ctx)->provctx->proverr_handle)

static void *akif_ascon_newctx(void *vprovctx)
{
    struct akif_ascon_ctx_st *ctx = malloc(sizeof(*ctx));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = vprovctx;
        ctx->is_tag_set = false;
        ctx->is_ongoing = false;

        intctx_t *intctx = calloc(1, sizeof(*intctx));
        if (intctx != NULL) {
          ctx->internal_ctx = intctx;
        } else {
            // TODO: handle error
            return NULL;
        }
        //ctx->keyl = keylen();
    }
    return ctx;
}

static void akif_ascon_cleanctx(void *vctx)
{
    struct akif_ascon_ctx_st *ctx = vctx;

    if (ctx == NULL)
        return;
    ctx->is_tag_set = false;
    ctx->is_ongoing = false;
    memset(ctx->internal_ctx, 0, sizeof(*(ctx->internal_ctx)));
    memset(ctx->tag, 0, sizeof(ctx->tag));
}

static void *akif_ascon_dupctx(void *vctx)
{
    struct akif_ascon_ctx_st *src = vctx;
    struct akif_ascon_ctx_st *dst = NULL;

#if 0
    if (src == NULL
        || (dst = ascon_newctx(NULL)) == NULL)

    dst->provctx = src->provctx;
    dst->provctx->proverr_handle =
        proverr_dup_handle(src->provctx->proverr_handle);
    dst->keyl = src->keyl;

    if (src->key != NULL) {
        if ((dst->key = malloc(src->keyl)) == NULL) {
            akif_ascon_freectx(dst);
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

static void akif_ascon_freectx(void *vctx)
{
    struct akif_ascon_ctx_st *ctx = vctx;

    if (ctx == NULL)
        return;

    ctx->provctx = NULL;
    akif_ascon_cleanctx(ctx);
    free(ctx->internal_ctx);
    free(ctx);
}

/* MY INTERNAL INIT FUNCTION (glue)*/

static int akif_ascon_internal_init(void *vctx, direction_t direction,
                                    const unsigned char *key, size_t keylen,
                                    const unsigned char *nonce, size_t noncelen,
                                    const OSSL_PARAM params[]) {
  struct akif_ascon_ctx_st *ctx = vctx;

  assert(ctx != NULL);
  akif_ascon_cleanctx(ctx);

  if (key != NULL) {
    if (keylen != ASCON_AEAD128_KEY_LEN) {
      // TODO: handle the error
      //if (keylen == (size_t)-1 || keylen == 0) {
        ERR_raise(ERR_HANDLE(ctx), ASCON_NO_KEYLEN_SET);
        return OSSL_RV_ERROR;
      //}
    }
  }

  if (nonce != NULL) {
    if (noncelen != ASCON_AEAD_NONCE_LEN) {
      // TODO: handle the error
      //if (noncelen == (size_t)-1 || noncelen == 0) {
        ERR_raise(ERR_HANDLE(ctx), NONCE_INCORRECT_KEYLEN);
        return OSSL_RV_ERROR;
      //}
    }
  }

  ctx->direction = direction;

  // allocate and initialize ctx->internal_vctx (void*)
  // call and check return of libascon_whatever_init()
  if (key != NULL && nonce != NULL) {
    // TODO: call ascon_aead128_init(...);
    ascon_aead128_init(ctx->internal_ctx, key, nonce);
    ctx->is_ongoing = true;
    return OSSL_RV_SUCCESS;
  }
  return OSSL_RV_SUCCESS;
}

/* PROVIDER'S INIT FUNCTIONS */

static int akif_ascon_encrypt_init(void *vctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[])
{
    return akif_ascon_internal_init(vctx, ENCRYPTION, key, keylen, nonce, noncelen, params);
}

static int akif_ascon_decrypt_init(void *vctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[])
{
    /* calling  'internal init' based on the 'direction' */
    return akif_ascon_internal_init(vctx, DECRYPTION, key, keylen, nonce, noncelen, params);
}


/* PROVIDER'S UPDATE FUNCTION*/

static int akif_ascon_update(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsize, const unsigned char *in, size_t inl)
{

    struct akif_ascon_ctx_st *ctx = vctx;

    if (ctx->direction == ENCRYPTION)
    {
        // check if outsize is big enough
        const uint8_t *plaintext = in;
        size_t plaintext_len = inl;
        uint8_t *ciphertext = out;
        size_t ciphertext_len;
//ascon_aead_ctx_t *temp = (ascon_aead_ctx_t*)ctx->internal_ctx;
// TODO: call ascon_aead128_encrypt_update(...) and check its return value (we noticed it cannot fail), do we need to keep track of the returned number of bytes?;
        ciphertext_len = ascon_aead128_encrypt_update(ctx->internal_ctx, ciphertext, plaintext, plaintext_len);
        // check return
        *outl = ciphertext_len;
        return OSSL_RV_SUCCESS;
    }

    else if (ctx->direction == DECRYPTION)

    {
        uint8_t *plaintext = out;
        size_t plaintext_len;
        const uint8_t *ciphertext = in;
        size_t ciphertext_len = inl;

        // TODO: call ascon_aead128_decrypt_update(...) and check;
        plaintext_len = ascon_aead128_decrypt_update(ctx->internal_ctx, plaintext, ciphertext, ciphertext_len);
        // check the return value
        *outl = plaintext_len;
        return OSSL_RV_SUCCESS;

    }
    return OSSL_RV_ERROR;
}


/* PROVIDER'S FINAL FUNCTION*/


static int akif_ascon_final(void *cctx, unsigned char *out, size_t *outl,
                           size_t outsize)
{
#if 0
    struct ascon_ctx_st *ctx = vctx;

    if (ctx->direction == ENCRYPTION)
    {


        // TODO: call ascon_aead128_encrypt_final(...) and check the return value/output parameters;
        ascon_aead128_encrypt_final((ascon_aead_ctx_t*)ctx->internal_ctx, out, tag, outsize);
        return 0;
    }
    else if(ctx->direction == DECRYPTION)
    {
        size_t ret;
        bool is_tag_valid = true;
        //unsigned char *outl = (unsigned char *)malloc(sizeof(unsigned char));
        if (outl != NULL){
            *outl = is_tag_valid;
            //free(outl);
        }
        else {
            return 0;
        }
        // check if outsize is big enough
        // check that internal_ctx and out are not NULL
        // TODO: call ascon_aead128_decrypt_final(...) and check;
        ret = ascon_aead128_decrypt_final((ascon_aead_ctx_t*) ctx->internal_ctx ,out, &is_tag_valid,tag,outsize);
        return 0;
    }
    //ciphertext = 0;
    //ctx->ongoing = 0;
    }
#else
    *outl = 0;
    return OSSL_RV_SUCCESS;
#endif
}


/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *akif_ascon_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "blocksize", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { "keylen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { "ivlen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int akif_ascon_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (akif_ascon_params_parse(p->key)) {
        case V_PARAM_blocksize:
            ok &= provnum_set_size_t(p, 1) >= 0;
            break;
        case V_PARAM_keylen:
            ok &= provnum_set_size_t(p, ASCON_AEAD128_KEY_LEN) >= 0;
            break;
        case V_PARAM_noncelen:
            ok &= provnum_set_size_t(p, ASCON_AEAD_NONCE_LEN) >= 0;
            break;
        }
    return ok;
}

static const OSSL_PARAM *akif_ascon_gettable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { S_PARAM_keylen, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { S_PARAM_noncelen, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}


static int akif_ascon_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct ascon_ctx_st *ctx = vctx;
    int ok = 1;

    // TODO: to be implemented properly
#if 1
    OSSL_PARAM *p;

    for (p = params; p->key != NULL; p++)
      switch (akif_ascon_params_parse(p->key)) {
      case V_PARAM_keylen:
        ok &= provnum_set_size_t(p, ASCON_AEAD128_KEY_LEN) >= 0;
        break;
    case V_PARAM_noncelen:
        ok &= provnum_set_size_t(p, ASCON_AEAD_NONCE_LEN) >= 0;
        break;
      }

    return ok;
#else
    return !ok;
#endif
}

/* Parameters that libcrypto can send to this implementation */
static const OSSL_PARAM *akif_ascon_settable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        //{ S_PARAM_keylen, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int akif_ascon_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct akif_ascon_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;
    int ok = 1;

    // TODO: to be implemented properly
#if 0
    if (ctx->ongoing) {
        ERR_raise(ERR_HANDLE(ctx), AKIF_ASCON_ONGOING_OPERATION);
        return 0;
    }

    for (p = params; p->key != NULL; p++)
        switch (akif_ascon_params_parse(p->key)) {
        case V_PARAM_keylen:
        {
            size_t keyl = 0;
            int res = provnum_get_size_t(&keyl, p) >= 0;

            ok &= res;
            if (res)
                ctx->keyl = keyl;
        }
        }
#endif
    return ok;
}


/*********************************************************************
 *
 *  Setup
 *
 *****/

typedef void (*funcptr_t)(void);

/* The Akif-Ascon dispatch table */
static const OSSL_DISPATCH akif_ascon_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)akif_ascon_newctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)akif_ascon_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)akif_ascon_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)akif_ascon_update },
    { OSSL_FUNC_CIPHER_FINAL, (funcptr_t)akif_ascon_final },
    { OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)akif_ascon_dupctx },
    { OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)akif_ascon_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)akif_ascon_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)akif_ascon_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)akif_ascon_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,(funcptr_t)akif_ascon_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)akif_ascon_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,(funcptr_t)akif_ascon_settable_ctx_params },
    { 0, NULL }
};

/* The table of ciphers this provider offers */
static const OSSL_ALGORITHM akif_ascon_ciphers[] = {
    { "akifascon128", "x.author='" AUTHOR "'",
    akif_ascon_functions },
    { NULL, NULL, NULL }
};

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *akif_ascon_prov_operation(void *vprovctx,
                                                     int operation_id,
                                                     int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
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

    for(p = params; p->key != NULL; p++)
        switch (akif_ascon_params_parse(p->key)) {
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
static void akif_ascon_prov_teardown(void *vprovctx)
{
    provider_ctx_free(vprovctx);
}

/* The base dispatch table */
static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (funcptr_t)akif_ascon_prov_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)akif_ascon_prov_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
      (funcptr_t)akif_ascon_prov_get_reason_strings },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
      (funcptr_t)akif_ascon_prov_get_params },
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
    return OSSL_RV_SUCCESS;
}
