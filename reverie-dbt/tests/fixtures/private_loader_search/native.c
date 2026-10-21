#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char** argv) {
  if (argc != 2)
    return 64;
  void* module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!module) {
    fprintf(stderr, "DLOPEN_ERROR=%s\n", dlerror());
    return 1;
  }
  int (*value)(void) = (int (*)(void))dlsym(module, "fixture_value");
  if (!value) {
    fprintf(stderr, "DLSYM_ERROR=%s\n", dlerror());
    return 2;
  }
  printf("LOADER_VALUE=%06d\n", value());
  return dlclose(module) != 0;
}
