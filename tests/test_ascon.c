/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/core.h>
# include <openssl/provider.h>
# include <openssl/core_names.h>
# include <openssl/params.h>

# include "test_common.h"

/* Compatibility: OSSL_CIPHER_PARAM_AEAD_AAD may not be defined in all OpenSSL versions */
# ifndef OSSL_CIPHER_PARAM_AEAD_AAD
#  define OSSL_CIPHER_PARAM_AEAD_AAD "aad"
# endif

# define FIXED_TAG_LENGTH 16
# define PROVIDER_NAME "ascon"
# define CIPHER_NAME "ascon128"

/* Test data */
static const unsigned char plaintext[] = "Ceasar's trove of junk and this is additional string";
static const unsigned char nonce[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};
static const unsigned char key[] =
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
     'Z', 'W', 'T', 'Q', 'N', 'K', 'H', 'B'};

/* Helper functions */

/* Gets the tag from ctx, and stores it at out.
 * - out points to a buffer of outsize bytes
 * - outl is updated with how many tag bytes were written at out
 *
 * RETURN
 * - 1 if success
 * - 0 otherwise
 */
static int get_tag_helper(EVP_CIPHER_CTX *ctx, uint8_t *out, size_t *outl, size_t outsize)
{
    OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, out, outsize);
    T(EVP_CIPHER_CTX_get_params(ctx, params));
    return 1;
}

/* Sets the expected tag inside ctx.
 * - in points to a buffer of inl bytes containing the expected tag obtained from the sender
 *
 * RETURN
 * - 1 if success
 * - 0 otherwise
 */
static int set_tag_helper(EVP_CIPHER_CTX *ctx, const uint8_t *in, size_t inl)
{
    OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, (void *)in, inl);
    T(EVP_CIPHER_CTX_set_params(ctx, params));
    return 1;
}

/* Test Functions */

/* Provider loading */
static int test_provider_load(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    EVP_CIPHER *c = NULL;
    OSSL_PROVIDER *prov = NULL;

    printf(cBLUE "Test 1: Provider loading" cNORM "\n");

    /* Verify cipher is not available before loading provider */
    T((c = EVP_CIPHER_fetch(libctx, CIPHER_NAME, NULL)) == NULL);
    ERR_clear_error();

    /* Load provider */
    T((prov = OSSL_PROVIDER_load(libctx, PROVIDER_NAME)) != NULL);
    printf(cGREEN "  Provider '%s' loaded successfully" cNORM "\n", PROVIDER_NAME);

    /* Verify cipher is now available */
    T((c = EVP_CIPHER_fetch(libctx, CIPHER_NAME, NULL)) != NULL);
    printf(cGREEN "  Algorithm '%s' available" cNORM "\n", CIPHER_NAME);

    EVP_CIPHER_free(c);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);

    return 1;
}

/* Basic encryption */
static int test_encryption(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    EVP_CIPHER *c = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    int outl = 0, outlf = 0;
    size_t ctlen = 0;
    unsigned char ciphertext[sizeof(plaintext) + FIXED_TAG_LENGTH];
    uint8_t computed_tag[FIXED_TAG_LENGTH] = {0};
    size_t computed_tag_len = FIXED_TAG_LENGTH;

    printf(cBLUE "Test 2: Basic encryption" cNORM "\n");

    T((prov = OSSL_PROVIDER_load(libctx, PROVIDER_NAME)) != NULL);
    T((c = EVP_CIPHER_fetch(libctx, CIPHER_NAME, NULL)) != NULL);
    T((ctx = EVP_CIPHER_CTX_new()) != NULL);

    /* Test initialization without key */
    printf("  Testing init without key\n");
    T(EVP_CipherInit(ctx, c, NULL, NULL, 1));

    /* Test encryption */
    printf("  Testing encryption with key and nonce\n");
    T(EVP_CipherInit(ctx, c, key, nonce, 1));
    T(EVP_CipherUpdate(ctx, ciphertext, &outl, plaintext, sizeof(plaintext)));
    ctlen += outl;
    printf("  CipherUpdate produced %d bytes\n", outl);

    T(EVP_CipherFinal(ctx, ciphertext + ctlen, &outlf));
    ctlen += outlf;
    printf("  CipherFinal produced %d bytes\n", outlf);

    /* Get authentication tag */
    T(get_tag_helper(ctx, computed_tag, &computed_tag_len, computed_tag_len));
    printf(cGREEN "  Encryption successful, tag generated" cNORM "\n");

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);

    return 1;
}

/* Basic decryption */
static int test_decryption(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    EVP_CIPHER *c = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    int outl = 0, outlf = 0;
    int outl2 = 0, outl2f = 0;
    size_t ctlen = 0;
    size_t ptlen = 0;
    unsigned char ciphertext[sizeof(plaintext) + FIXED_TAG_LENGTH];
    unsigned char plaintext2[sizeof(plaintext)];
    uint8_t computed_tag[FIXED_TAG_LENGTH] = {0};
    size_t computed_tag_len = FIXED_TAG_LENGTH;
    uint8_t expected_tag[FIXED_TAG_LENGTH] = {0};
    size_t expected_tag_len = FIXED_TAG_LENGTH;

    printf(cBLUE "Test 3: Basic decryption" cNORM "\n");

    T((prov = OSSL_PROVIDER_load(libctx, PROVIDER_NAME)) != NULL);
    T((c = EVP_CIPHER_fetch(libctx, CIPHER_NAME, NULL)) != NULL);
    T((ctx = EVP_CIPHER_CTX_new()) != NULL);

    /* Encrypt first */
    T(EVP_CipherInit(ctx, c, key, nonce, 1));
    T(EVP_CipherUpdate(ctx, ciphertext, &outl, plaintext, sizeof(plaintext)));
    ctlen += outl;
    T(EVP_CipherFinal(ctx, ciphertext + ctlen, &outlf));
    ctlen += outlf;
    T(get_tag_helper(ctx, computed_tag, &computed_tag_len, computed_tag_len));

    /* Now decrypt */
    printf("  Testing decryption\n");
    T(EVP_CipherInit(ctx, NULL, key, nonce, 0));
    T(EVP_CipherUpdate(ctx, plaintext2, &outl2, ciphertext, ctlen));
    ptlen = outl2;

    memcpy(expected_tag, computed_tag, FIXED_TAG_LENGTH);
    expected_tag_len = FIXED_TAG_LENGTH;
    T(set_tag_helper(ctx, expected_tag, expected_tag_len));
    T(EVP_CipherFinal(ctx, plaintext2 + outl2, &outl2f));
    ptlen += outl2f;

    /* Verify plaintext matches */
    int match = (sizeof(plaintext) == ptlen && 
                 memcmp(plaintext, plaintext2, sizeof(plaintext)) == 0);
    if (match) {
        printf(cGREEN "  Decryption successful, plaintext matches" cNORM "\n");
    } else {
        printf(cRED "  Decryption failed, plaintext mismatch" cNORM "\n");
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);

    return 1;
}

/* AAD (Associated Data) support */
static int test_aad_support(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    EVP_CIPHER *c = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    int outl = 0, outlf = 0;
    int outl2 = 0, outl2f = 0;
    size_t ctlen = 0;
    size_t ptlen = 0;
    unsigned char ciphertext[sizeof(plaintext) + FIXED_TAG_LENGTH];
    unsigned char plaintext2[sizeof(plaintext)];
    uint8_t computed_tag[FIXED_TAG_LENGTH] = {0};
    size_t computed_tag_len = FIXED_TAG_LENGTH;
    uint8_t expected_tag[FIXED_TAG_LENGTH] = {0};
    size_t expected_tag_len = FIXED_TAG_LENGTH;
    const unsigned char aad[] = "Additional authenticated data";

    printf(cBLUE "Test 4: AAD (Associated Data) support" cNORM "\n");

    T((prov = OSSL_PROVIDER_load(libctx, PROVIDER_NAME)) != NULL);
    T((c = EVP_CIPHER_fetch(libctx, CIPHER_NAME, NULL)) != NULL);
    T((ctx = EVP_CIPHER_CTX_new()) != NULL);

    /* Encrypt with AAD */
    printf("  Testing encryption with AAD\n");
    T(EVP_CipherInit(ctx, c, key, nonce, 1));

    /* Set AAD before encryption */
    OSSL_PARAM aad_params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
    aad_params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_AAD,
                                                       (void *)aad, sizeof(aad) - 1);
    T(EVP_CIPHER_CTX_set_params(ctx, aad_params));
    printf("  AAD set successfully\n");

    T(EVP_CipherUpdate(ctx, ciphertext, &outl, plaintext, sizeof(plaintext)));
    ctlen += outl;
    T(EVP_CipherFinal(ctx, ciphertext + ctlen, &outlf));
    ctlen += outlf;
    T(get_tag_helper(ctx, computed_tag, &computed_tag_len, computed_tag_len));

    /* Decrypt with matching AAD */
    printf("  Testing decryption with matching AAD\n");
    T(EVP_CipherInit(ctx, NULL, key, nonce, 0));

    /* Set same AAD for decryption */
    T(EVP_CIPHER_CTX_set_params(ctx, aad_params));

    T(EVP_CipherUpdate(ctx, plaintext2, &outl2, ciphertext, ctlen));
    ptlen = outl2;

    memcpy(expected_tag, computed_tag, FIXED_TAG_LENGTH);
    expected_tag_len = FIXED_TAG_LENGTH;
    T(set_tag_helper(ctx, expected_tag, expected_tag_len));
    T(EVP_CipherFinal(ctx, plaintext2 + outl2, &outl2f));
    ptlen += outl2f;

    /* Verify plaintext matches */
    int match = (sizeof(plaintext) == ptlen && 
                 memcmp(plaintext, plaintext2, sizeof(plaintext)) == 0);
    if (match) {
        printf(cGREEN "  AAD support verified, decryption successful" cNORM "\n");
    } else {
        printf(cRED "  AAD test failed, plaintext mismatch" cNORM "\n");
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);

    return 1;
}

/* Context duplication */
static int test_context_duplication(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    EVP_CIPHER *c = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *ctx2 = NULL;
    OSSL_PROVIDER *prov = NULL;
    int result = 1;

    printf(cBLUE "Test 5: Context duplication" cNORM "\n");

    T((prov = OSSL_PROVIDER_load(libctx, PROVIDER_NAME)) != NULL);
    T((c = EVP_CIPHER_fetch(libctx, CIPHER_NAME, NULL)) != NULL);
    T((ctx = EVP_CIPHER_CTX_new()) != NULL);
    T((ctx2 = EVP_CIPHER_CTX_new()) != NULL);

    /* Initialize original context */
    T(EVP_CipherInit(ctx, c, key, nonce, 1));

    /* Test context duplication */
    printf("  Testing context duplication\n");
    const EVP_CIPHER *cipher = EVP_CIPHER_CTX_cipher(ctx);
    if (EVP_CipherInit_ex(ctx2, cipher, NULL, NULL, NULL, -1) == 1) {
        if (EVP_CIPHER_CTX_copy(ctx2, ctx) == 1) {
            printf(cGREEN "  Context duplication successful" cNORM "\n");
        } else {
            printf(cRED "  Context copy failed" cNORM "\n");
            result = 0;
        }
    } else {
        printf(cRED "  Context initialization failed" cNORM "\n");
        result = 0;
    }

    EVP_CIPHER_CTX_free(ctx2);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);

    return result;
}

/* Full encryption/decryption roundtrip */
static int test_encryption_decryption_roundtrip(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    EVP_CIPHER *c = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    int outl = 0, outlf = 0;
    int outl2 = 0, outl2f = 0;
    size_t ctlen = 0;
    size_t ptlen = 0;
    unsigned char ciphertext[sizeof(plaintext) + FIXED_TAG_LENGTH];
    unsigned char plaintext2[sizeof(plaintext)];
    uint8_t computed_tag[FIXED_TAG_LENGTH] = {0};
    size_t computed_tag_len = FIXED_TAG_LENGTH;
    uint8_t expected_tag[FIXED_TAG_LENGTH] = {0};
    size_t expected_tag_len = FIXED_TAG_LENGTH;

    printf(cBLUE "Test 6: Full encryption/decryption roundtrip" cNORM "\n");

    T((prov = OSSL_PROVIDER_load(libctx, PROVIDER_NAME)) != NULL);
    T((c = EVP_CIPHER_fetch(libctx, CIPHER_NAME, NULL)) != NULL);
    T((ctx = EVP_CIPHER_CTX_new()) != NULL);

    /* Encrypt */
    printf("  Encrypting plaintext\n");
    T(EVP_CipherInit(ctx, c, key, nonce, 1));
    T(EVP_CipherUpdate(ctx, ciphertext, &outl, plaintext, sizeof(plaintext)));
    ctlen += outl;
    T(EVP_CipherFinal(ctx, ciphertext + ctlen, &outlf));
    ctlen += outlf;
    T(get_tag_helper(ctx, computed_tag, &computed_tag_len, computed_tag_len));

    printf("  Plaintext[%zu] = ", sizeof(plaintext));
    hexdump(plaintext, sizeof(plaintext));
    printf("  Ciphertext[%zu] = ", ctlen);
    hexdump(ciphertext, ctlen);

    /* Decrypt */
    printf("  Decrypting ciphertext\n");
    T(EVP_CipherInit(ctx, NULL, key, nonce, 0));
    T(EVP_CipherUpdate(ctx, plaintext2, &outl2, ciphertext, ctlen));
    ptlen = outl2;

    memcpy(expected_tag, computed_tag, FIXED_TAG_LENGTH);
    expected_tag_len = FIXED_TAG_LENGTH;
    T(set_tag_helper(ctx, expected_tag, expected_tag_len));
    T(EVP_CipherFinal(ctx, plaintext2 + outl2, &outl2f));
    ptlen += outl2f;

    printf("  Decrypted plaintext[%zu] = ", ptlen);
    hexdump(plaintext2, ptlen);

    /* Verify */
    int match = (sizeof(plaintext) == ptlen && 
                 memcmp(plaintext, plaintext2, sizeof(plaintext)) == 0);
    if (match) {
        printf(cGREEN "  Roundtrip test passed, plaintext matches" cNORM "\n");
    } else {
        printf(cRED "  Roundtrip test failed, plaintext mismatch" cNORM "\n");
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);

    return 1;
}

/* Main test runner */
int main(void)
{
    int failed = 0;
    int total = 6;

    printf(cBLUE "\n=== Running Ascon Provider Tests ===" cNORM "\n\n");

    if (!test_provider_load()) {
        printf(cRED "FAILED: test_provider_load" cNORM "\n");
        failed++;
    }

    if (!test_encryption()) {
        printf(cRED "FAILED: test_encryption" cNORM "\n");
        failed++;
    }

    if (!test_decryption()) {
        printf(cRED "FAILED: test_decryption" cNORM "\n");
        failed++;
    }

    if (!test_aad_support()) {
        printf(cRED "FAILED: test_aad_support" cNORM "\n");
        failed++;
    }

    if (!test_context_duplication()) {
        printf(cRED "FAILED: test_context_duplication" cNORM "\n");
        failed++;
    }

    if (!test_encryption_decryption_roundtrip()) {
        printf(cRED "FAILED: test_encryption_decryption_roundtrip" cNORM "\n");
        failed++;
    }

    printf(cBLUE "\n=== Test Results ===" cNORM "\n");
    printf("Total tests: %d\n", total);
    printf("Passed: %d\n", total - failed);
    printf("Failed: %d\n", failed);

    if (failed == 0) {
        printf(cGREEN "All tests passed!" cNORM "\n");
    } else {
        printf(cRED "Some tests failed!" cNORM "\n");
    }

    return (failed == 0) ? 0 : 1;
}

