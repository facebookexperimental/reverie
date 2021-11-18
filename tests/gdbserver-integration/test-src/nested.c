/* compile with clang.par nested.c -o nested -O0 -g -Wall */
#include <stdio.h>

int bar(int);
int baz(int, int);

int foo(int a, int b) {
  int x = a * a + b * b;
  return bar(x);
}

int bar(int x) {
  int y = x * (1 + x);
  return baz(x, y);
}

int baz(int a, int b) {
  return (a + b) * (a - b);
}

int main(int argc, char* argv[]) {
  printf("%d\n", foo(3, 4));
  return 0;
}
