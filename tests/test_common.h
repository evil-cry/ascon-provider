/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

# include <stdio.h>
# include <openssl/err.h>

/* For controlled success */
# define T(e)                                    \
  if (!(e)) {                                   \
    ERR_print_errors_fp(stderr);                \
    OPENSSL_die(#e, __FILE__, __LINE__);        \
  }
/* For controlled failure */
# define TF(e)                                   \
  if ((e)) {                                    \
    ERR_print_errors_fp(stderr);                \
  } else {                                      \
    OPENSSL_die(#e, __FILE__, __LINE__);        \
  }
# define cRED    "\033[1;31m"
# define cDRED   "\033[0;31m"
# define cGREEN  "\033[1;32m"
# define cDGREEN "\033[0;32m"
# define cBLUE   "\033[1;34m"
# define cDBLUE  "\033[0;34m"
# define cNORM   "\033[m"
# define TEST_ASSERT(e)                                  \
  {                                                     \
    if (!(test = (e)))                                  \
      printf(cRED "  Test FAILED" cNORM "\n");          \
    else                                                \
      printf(cGREEN "  Test passed" cNORM "\n");        \
  }

void hexdump(const void *ptr, size_t len);
