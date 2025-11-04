/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROV_CIPHERCOMMON_ASCON_COMPAT_H
# define OSSL_PROV_CIPHERCOMMON_ASCON_COMPAT_H

/*
 * Compatibility layer for standalone builds outside OpenSSL source tree.
 * When building within OpenSSL, these definitions are not needed as
 * the actual OpenSSL headers provide the real implementations.
 */
# ifndef OPENSSL_INTERNAL_CRYPTLIB_H
#  define STANDALONE_BUILD 1
# else
#  define STANDALONE_BUILD 0
# endif

# if STANDALONE_BUILD

#  include <stdlib.h>
#  include <string.h>
#  include <openssl/crypto.h>

static inline int ossl_prov_is_running(void)
{
    return 1;
}

# else /* !STANDALONE_BUILD */
/*
 * Building within OpenSSL tree: use actual OpenSSL internal headers
 */

#  include "prov/providercommon.h"
#  include "internal/cryptlib.h"

# endif /* STANDALONE_BUILD */

#endif /* OSSL_PROV_CIPHERCOMMON_ASCON_COMPAT_H */

