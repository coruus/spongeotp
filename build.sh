#!/usr/bin/env sh
set -x
mkdir build
clang -o build/spongeotp_test -std=c11 -pedantic -Wextra -g spongeotp.c keccak-tiny/shakemac.c
