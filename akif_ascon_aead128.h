/* CC0 license applied, see LICENCE.md */

#ifndef ASCON_AEAD128_H
#define ASCON_AEAD128_H

#include "akif_ascon_cipher.h"

/*********************************************************************
 *
 *  ASCON-128 AEAD Function Declarations
 *
 *****/

/* OSSL_FUNC_cipher_* function pointers */
void *akifascon128_newctx(void *vprovctx);
int akifascon128_encrypt_init(void *vctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[]);
int akifascon128_decrypt_init(void *vctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *nonce, size_t noncelen,
                              const OSSL_PARAM params[]);
int akifascon128_update(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsize, const unsigned char *in, size_t inl);
int akifascon128_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize);
void *akifascon128_dupctx(void *vctx);
void akifascon128_freectx(void *vctx);
int akifascon128_get_params(OSSL_PARAM params[]);
const OSSL_PARAM *akifascon128_gettable_params(void *provctx);
int akifascon128_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
int akifascon128_get_ctx_params(void *vctx, OSSL_PARAM params[]);
const OSSL_PARAM *akifascon128_settable_ctx_params(void *cctx, void *provctx);
const OSSL_PARAM *akifascon128_gettable_ctx_params(void *cctx, void *provctx);
size_t akifascon128_get_iv_length(void *vctx);
size_t akifascon128_get_tag_length(void *vctx);

/* Dispatch table for ASCON-128 */
extern const OSSL_DISPATCH akifascon128_functions[];

#endif /* ASCON_AEAD128_H */
