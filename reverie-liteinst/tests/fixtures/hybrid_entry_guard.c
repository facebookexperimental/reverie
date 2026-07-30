#include <stdio.h>
#include <sys/auxv.h>

int main(void) {
  const unsigned char *entry = (const unsigned char *)getauxval(AT_ENTRY);
  int still_guarded = entry == NULL || *entry == 0xcc;
  printf("entry-int3=%d\n", still_guarded);
  return still_guarded ? 20 : 0;
}
