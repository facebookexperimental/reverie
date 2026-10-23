/* With no argument: calls each getppid site twice and prints whether each
 * call reached the probe plugin (ROUTED) or ran natively (NATIVE), then the
 * code bytes of the long prefixed function, of the two short prefixed sites
 * and of the never-executed LOCK and overlong sites.
 *
 * With an argument N: calls only the cache-line-aligned short site N times,
 * for the statistics test. */
#include <stdio.h>
#include <stdlib.h>

long plain_getppid(void);
long prefixed_getppid(void);
long prefixed_short_getppid(void);
long aligned_short_getppid(void);
extern const unsigned char prefixed_getppid_code[];
extern const unsigned char prefixed_short_site[];
extern const unsigned char aligned_short_site[];
extern const unsigned char lock_site[];
extern const unsigned char overlong_site[];

static const char *route(long result) {
  return result == (1L << 30) ? "ROUTED" : "NATIVE";
}

static void bytes(const char *label, const unsigned char *b, int n) {
  printf("%s=", label);
  for (int k = 0; k < n; k++)
    printf("%02x", b[k]);
  printf("\n");
}

int main(int argc, char **argv) {
  if (argc > 1) {
    int calls = atoi(argv[1]);
    for (int k = 0; k < calls; k++)
      if (aligned_short_getppid() != (1L << 30))
        return 1;
    return 0;
  }
  for (int round = 0; round < 2; round++) {
    long plain = plain_getppid();
    long prefixed = prefixed_getppid();
    long prefixed_short = prefixed_short_getppid();
    long aligned_short = aligned_short_getppid();
    printf("plain=%s prefixed=%s prefixed_short=%s aligned_short=%s\n",
           route(plain), route(prefixed), route(prefixed_short),
           route(aligned_short));
  }
  bytes("prefixed_code", prefixed_getppid_code, 15);
  bytes("short_site", prefixed_short_site, 3);
  bytes("aligned_site", aligned_short_site, 4);
  bytes("lock_site", lock_site, 4);
  bytes("overlong_site", overlong_site, 16);
  return 0;
}
