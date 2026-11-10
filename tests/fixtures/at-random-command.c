/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

#include <assert.h>
#include <stddef.h>
#include <sys/auxv.h>
#include <unistd.h>

int main(void) {
    const unsigned char *at_random = (const unsigned char *)getauxval(AT_RANDOM);
    assert(at_random != NULL);
    assert(write(STDOUT_FILENO, at_random, 16) == 16);
    return 0;
}
