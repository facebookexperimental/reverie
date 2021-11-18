/* must be compiled with -O */
/* demo how we can save return address from previous `callq xxx`
 * the byte code could be useful for us to generate temp trampoline
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>

__attribute__((noinline)) static void test1(void) {
  __asm__(
      "callq test2\n\t"
      "nop\n\t");
}

__attribute__((noinline, used)) static void test2(void) {
  __asm__(
      "push %rax\n\t"
      "movq 0x8(%rsp), %rax\n\t"
      "movq %rax, 0x65001010\n\t"
      "addq $0x8, %rsp\n\t"
      "nop");
}

__attribute__((noinline)) static void test3(void) {
  test1();
}

static void prepare_mmap(void) {
  void* addr = mmap(
      (void*)0x65000000UL,
      0x2000,
      PROT_READ | PROT_WRITE | PROT_EXEC,
      MAP_PRIVATE | MAP_ANONYMOUS,
      -1,
      0);
  if (addr != (void*)0x65000000UL)
    abort();
}

int main(int argc, char* argv[]) {
  unsigned long* ret = (unsigned long*)0x65001010UL;
  prepare_mmap();
  test3();
  printf("*ret = %lx, expected = %lx\n", *ret, (unsigned long)test1 + 5);
  if (*ret != (unsigned long)test1 + 5)
    abort();
  return 0;
}
