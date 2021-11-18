#include <stdio.h>

int main(int argc, char* argv[]) {
  long* invalid_ptr = (long*)0x123;

  *invalid_ptr = 0x12345678l;

  return 0;
}
