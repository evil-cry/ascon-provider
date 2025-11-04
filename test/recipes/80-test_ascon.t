#! /usr/bin/env perl
# 80-test_ascon.t
# Simple OpenSSL provider load test for Ascon

use strict;
use warnings;
use OpenSSL::Test;
use OpenSSL::Test::Utils;

setup("test_ascon");

plan tests => 2;

ok(run(app(["openssl", "version"])), "OpenSSL CLI is available");

ok(run(app(["openssl", "list", "-provider", "akif_ascon", "-cipher-algorithms"])),
   "Ascon provider loads successfully and lists ciphers");
