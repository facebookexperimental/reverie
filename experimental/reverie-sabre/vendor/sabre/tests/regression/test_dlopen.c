/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

// RUN: %{cc} %s -o %t1 -ldl
// RUN: %{sbr} %{sbr-id} -- %t1 &> %t1.actual
// %t1 &> %t1.actual
// RUN: echo "-0.416147" > %t1.expected
// RUN: diff %t1.actual %t1.expected

#include <dlfcn.h>
#include <gnu/lib-names.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  void *handle;
  double (*cosine)(double);
  char *error;

  handle = dlopen(LIBM_SO, RTLD_LAZY);
  if (!handle) {
    fprintf(stderr, "%s\n", dlerror());
    exit(EXIT_FAILURE);
  }

  dlerror();

  cosine = (double (*)(double))dlsym(handle, "cos");

  error = dlerror();
  if (error != NULL) {
    fprintf(stderr, "%s\n", error);
    exit(EXIT_FAILURE);
  }

  printf("%f\n", (*cosine)(2.0));
  dlclose(handle);
  exit(EXIT_SUCCESS);
}
