/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROV_CIPHER_ASCON_H
# define OSSL_PROV_CIPHER_ASCON_H

# include "ciphercommon_ascon.h"

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
struct ascon_ctx_st
{
    struct provider_ctx_st *provctx;

    uint8_t tag[FIXED_TAG_LENGTH]; /* storing the tag with fixed length */
    bool is_tag_set;               /* whether a tag has been computed or set */

    direction_t direction;  /* either encryption or decryption */
    bool is_ongoing;        /* true = operation has started */
    intctx_t *internal_ctx; /* a handle for the implementation internal context*/
    bool assoc_data_processed;  /* whether associated data has been processed */
    size_t tag_len;          /* tag length being used */
};

#endif /* OSSL_PROV_CIPHER_ASCON_H */

