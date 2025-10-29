/* CC0 license applied, see LICENCE.md */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "test_common.h"

#define FIXED_TAG_LENGTH 16

static const unsigned char plaintext[] = "Ceasar's trove of junk and this is additional string";
static const unsigned char nonce[] = {
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
};
static const unsigned char key[] =
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
     'Z', 'W', 'T', 'Q', 'N', 'K', 'H', 'B'};

/* Expected AEAD Tag value */
/*static const unsigned char exp_tag[FIXED_TAG_LENGTH] = {
    0xe7, 0x32, 0x97, 0x38, 0x69, 0x7e, 0x49, 0xbb,
    0x8b, 0x51, 0xf3, 0xdb, 0xc9, 0x43, 0xcf, 0x9f};*/

static unsigned char ciphertext[sizeof(plaintext)];
static unsigned char plaintext2[sizeof(plaintext)];

#define PROVIDER_NAME "akif_ascon"
#define CIPHER_NAME "akifascon128"

// gets the tag from ctx, and stores it at out.
// - out points to a buffer of outsize bytes
// - outl is updated with how many tag bytes were written at out
//
// RETURN
// - 1 if success
// - 0 otherwise

int get_tag_helper(EVP_CIPHER_CTX *ctx, uint8_t *out, size_t *outl, size_t outsize)
{

  OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
  params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, out, outsize);

  T(EVP_CIPHER_CTX_get_params(ctx, params));

  return 1;
}

// sets the expected tag inside ctx.
// - in points to a buffer of inl bytes containing the expected tag obtained from the sender
//
// RETURN
// - 1 if success
// - 0 otherwise

int set_tag_helper(EVP_CIPHER_CTX *ctx, const uint8_t *in, size_t inl)
{
  OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};

  params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, (void *)in, inl);

  T(EVP_CIPHER_CTX_set_params(ctx, params));

  // BIO_dump_fp(stdout, in, inl);

  return 1;
}

int main()
{
  OSSL_LIB_CTX *libctx = NULL;
  EVP_CIPHER *c = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  int outl = 0, outlf = 0;
  int outl2 = 0, outl2f = 0;
  OSSL_PROVIDER *prov = NULL;
  int test = 0;
  size_t ctlen = 0;
  size_t ptlen = 0;

  uint8_t computed_tag[FIXED_TAG_LENGTH] = {0};
  size_t computed_tag_len = FIXED_TAG_LENGTH;
  uint8_t expected_tag[2 * FIXED_TAG_LENGTH] = {0};
  size_t expected_tag_len = FIXED_TAG_LENGTH;

  printf(cBLUE "Trying to load %s provider" cNORM "\n", PROVIDER_NAME);
  T((c = EVP_CIPHER_fetch(libctx, CIPHER_NAME, NULL)) == NULL);
  ERR_clear_error();
  T((prov = OSSL_PROVIDER_load(libctx, PROVIDER_NAME)) != NULL);
  T((c = EVP_CIPHER_fetch(libctx, CIPHER_NAME, NULL)) != NULL);
  T((ctx = EVP_CIPHER_CTX_new()) != NULL);
  // EVP_CIPHER_free(c);         /* ctx holds on to the cipher */

  /* Test encryption */
  printf(cBLUE "Testing init without a key" cNORM "\n");
  T(EVP_CipherInit(ctx, c, NULL, NULL, 1));
  printf(cBLUE "Testing encryption" cNORM "\n");
  T(EVP_CipherInit(ctx, c, key, nonce, 1));
  T(EVP_CipherUpdate(ctx, ciphertext, &outl, plaintext, sizeof(plaintext)));
  ctlen += outl;
  printf(cBLUE "CipherUpdate produced" cNORM "%d bytes\n", outl);
  T(EVP_CipherFinal(ctx, ciphertext + ctlen, &outlf));
  ctlen += outlf;
  printf(cBLUE "CipherFinal produced" cNORM "%d bytes\n", outlf);
  T(get_tag_helper(ctx, computed_tag, &computed_tag_len, computed_tag_len));

  /* Test decryption */
  printf(cBLUE "Testing decryption" cNORM "\n");
  T(EVP_CipherInit(ctx, NULL, key, nonce, 0));
  T(EVP_CipherUpdate(ctx, plaintext2, &outl2, ciphertext, ctlen));
  ptlen = outl2;
  printf(cBLUE "CipherUpdate produced" cNORM "%d bytes\n", outl2);

  memcpy(expected_tag, computed_tag, FIXED_TAG_LENGTH);
  expected_tag_len = FIXED_TAG_LENGTH;
  T(set_tag_helper(ctx, expected_tag, expected_tag_len));
  T(EVP_CipherFinal(ctx, plaintext2 + outl2, &outl2f));
  ptlen += outl2f;
  printf(cBLUE "CipherFinal produced" cNORM "%d bytes\n", outl2f);

  printf("Plaintext[%zu]  = ", sizeof(plaintext));
  hexdump(plaintext, sizeof(plaintext));
  printf("Key[%zu]        = ", sizeof(key));
  hexdump(key, sizeof(key));
  printf("Ciphertext[%lu] = ", ctlen);
  hexdump(ciphertext, ctlen);
  printf("Plaintext2[%lu] = ", ptlen);
  hexdump(plaintext2, ptlen);

  /* Test context duplication using OpenSSL 3.0+ approach */
  printf(cBLUE "Testing context duplication" cNORM "\n");
  EVP_CIPHER_CTX *bogus = EVP_CIPHER_CTX_new();
  if (bogus != NULL) {
    // Initialize with the same cipher
    const EVP_CIPHER *cipher = EVP_CIPHER_CTX_cipher(ctx);
    if (EVP_CipherInit_ex(bogus, cipher, NULL, NULL, NULL, -1) == 1) {
      // Copy the context state
      if (EVP_CIPHER_CTX_copy(bogus, ctx) == 1) {
        printf(cGREEN "Context duplication successful" cNORM "\n");
      } else {
        printf(cRED "Context copy failed" cNORM "\n");
      }
    } else {
      printf(cRED "Context initialization failed" cNORM "\n");
    }
    EVP_CIPHER_CTX_free(bogus);
  } else {
    printf(cRED "Context allocation failed" cNORM "\n");
  }

  EVP_CIPHER_CTX_free(ctx);
  OSSL_PROVIDER_unload(prov);

  TEST_ASSERT(sizeof(plaintext) == outl2 + outl2f && memcmp(plaintext, plaintext2, sizeof(plaintext)) == 0);

  /* Exit code 0 == success */
  return !test;
}
