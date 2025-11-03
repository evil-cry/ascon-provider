use strict;
use warnings;
use Test2::V0;

plan(1);

like(`openssl list -provider ascon -cipher-algorithms`,
     qr/ascon128 \@ ascon\n/,
     'ascon128 is listed');
