/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * RUN: %{cc} -masm=intel -fPIC -pie -Wl,--export-dynamic %s -o %t1
 * RUN: %{process-vdso} %t1 %t1.processed
 */

#include <stdio.h>
#include <unistd.h>

void *__vdso_time() {
  void *ret;
  asm volatile("cmp DWORD PTR [rip+0x2],0x42 \n"
               "jmp end_time                 \n"
               ".quad 0x1                    \n"
               "nop                          \n"
               "nop                          \n"
               "nop                          \n"
               "nop                          \n"
               "end_time: nop"
               : "=g"(ret)::);
  return ret;
}

void *__vdso_clock_gettime() {
  void *ret;
  asm volatile("movq %0,[rip+0x2] \n"
               "jmp end           \n"
               ".quad 42          \n"
               "nop               \n"
               "nop               \n"
               "nop               \n"
               "nop               \n"
               "end: nop"
               : "=g"(ret)::);
  return ret;
}

int main(int argc, char **argv) {
  printf("%ld\n", (const long)__vdso_clock_gettime());
  return 0;
}
