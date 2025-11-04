#! /usr/bin/env perl
#
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

package WrapOpenSSL;
use strict;
use warnings;

use File::Basename;
use File::Spec::Functions;

sub load {
    my ($class, $p) = @_;
    my $app  = $p->{app_prove};

    # turn on verbosity
    my $verbose = $ENV{CTEST_INTERACTIVE_DEBUG_MODE} || $app->verbose();
    $app->verbose( $verbose );

    print STDERR "$_=", $ENV{$_} // '', "\n"
        foreach qw(OPENSSL_MODULES OPENSSL_PROGRAM
                   OPENSSL_LIBRARY_DIR OPENSSL_RUNTIME_DIR
                   SOURCEDIR PERL5LIB);

    my $openssl_bindir = $ENV{OPENSSL_RUNTIME_DIR};
    my $openssl_libdir = $ENV{OPENSSL_LIBRARY_DIR};

    if ($openssl_libdir) {
        # Variants of library paths
        $ENV{$_} = join(':', $openssl_libdir, $ENV{$_} // ())
            foreach (
                     'LD_LIBRARY_PATH',    # Linux, ELF HP-UX
                     'DYLD_LIBRARY_PATH',  # MacOS X
                     'LIBPATH',            # AIX, OS/2
            );
        if ($verbose) {
            print STDERR "Added $openssl_libdir to:\n";
            print STDERR "  LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, LIBPATH\n";
        }
    }

    if ($openssl_bindir) {
        # Binary path, works the same everywhere
        my $pathsep = ($^O eq 'MSWin32' ? ';' : ':');
        $ENV{PATH} = join($pathsep, $openssl_bindir, $ENV{PATH});
        if ($verbose) {
            print STDERR "Added $openssl_bindir to:\n";
            print STDERR "  PATH\n";
        }
    }
    if ($verbose) {
        print STDERR "$_=", $ENV{$_} // '', "\n"
            foreach qw(LD_LIBRARY_PATH DYLD_LIBRARY_PATH LIBPATH PATH);
    }
}

1;
