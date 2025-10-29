/* CC0 license applied, see LICENCE.md */

#ifndef AKIF_ASCON_CIPHER_H
#define AKIF_ASCON_CIPHER_H

#include "akif_ascon_common.h"

/*********************************************************************
 *
 *  Cipher Common Definitions
 *
 *****/

typedef enum direction_et
{
    ENCRYPTION,
    DECRYPTION
} direction_t;

typedef ascon_aead_ctx_t intctx_t;

/* Base structure for AEAD cipher contexts */
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

/* Macro to access error handle from cipher context */
#define ERR_HANDLE(ctx) ((ctx)->provctx->proverr_handle)

#endif /* AKIF_ASCON_CIPHER_H */


