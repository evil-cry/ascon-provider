use strict;
use warnings;
use Test2::V0;

plan(1);

like(`openssl list -provider akif_ascon -cipher-algorithms`,
     qr/akifascon128 \@ akif_ascon\n/,
     'akifascon128 is listed');
