/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* What the guest finds where its program break starts, before anything has
 * allocated: whether the page after its image is mapped, whether brk(0) is
 * the kernel's start_brk, and whether the break lies in a mapping. Natively,
 * none is mapped and brk(0) is start_brk. Raw syscalls and static buffers
 * only, so that nothing moves the break before it is looked at; an
 * observation that cannot be made fails the run, with nothing on standard
 * output, instead of reading as "no". With --stat-from-stdin or
 * --maps-from-stdin it runs only the stat or maps parser, on its standard
 * input, so tests can feed it malformed records. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char end;

static char text[1 << 20];

/* Exits nonzero, naming what failed: an observation the fixture could not
 * make must not read as an absence. */
static void fail(const char *what) {
  syscall(SYS_write, 2, what, strlen(what));
  syscall(SYS_write, 2, "\n", 1);
  syscall(SYS_exit_group, 2);
}

/* All of descriptor fd into `text`, or a failure: a read error, nothing at
 * all, a file that fills the buffer (it may be truncated), or one whose last
 * line has no newline (procfs ends every record with one). */
static void read_fd(int fd) {
  long total = 0;
  for (;;) {
    long n = syscall(SYS_read, fd, text + total, sizeof text - 1 - total);
    if (n < 0)
      fail("cannot read a procfs file");
    if (n == 0)
      break;
    total += n;
    if (total == (long)sizeof text - 1)
      fail("a procfs file fills the buffer and may be truncated");
  }
  text[total] = 0;
  if (total == 0)
    fail("a procfs file is empty");
  if (text[total - 1] != '\n')
    fail("a procfs file ends without a newline and may be truncated");
}

static void read_all(const char *path) {
  int fd = (int)syscall(SYS_open, path, O_RDONLY);
  if (fd < 0)
    fail("cannot open a procfs file");
  read_fd(fd);
  syscall(SYS_close, fd);
}

/* A whole unsigned decimal or hexadecimal token at `*at`, ending at `end`
 * (or the end of the line where `end` is 0), without overflow; the cursor
 * moves past it. */
static unsigned long token(char **at, int base, char end, const char *what) {
  char *after;
  errno = 0;
  if (**at < '0' || (base == 10 && **at > '9'))
    fail(what);
  unsigned long value = strtoul(*at, &after, base);
  if (after == *at || errno == ERANGE || (*after != end && !(end == 0 && *after == '\n')))
    fail(what);
  *at = after;
  return value;
}

/* Whether a line of the maps text in `text` covers address. Every line must
 * start with a well-formed, non-overflowing, increasing range. */
static int covered(unsigned long address) {
  int found = 0;
  for (char *line = text; *line;) {
    char *at = line;
    unsigned long low = token(&at, 16, '-', "a maps line does not start with a range");
    at++;
    unsigned long high = token(&at, 16, ' ', "a maps range has no well-formed end");
    if (high <= low)
      fail("a maps range does not increase");
    if (low <= address && address < high)
      found = 1;
    char *newline = strchr(at, '\n');
    if (!newline)
      fail("a maps line has no end");
    line = newline + 1;
  }
  return found;
}

static int mapped(unsigned long address) {
  read_all("/proc/self/maps");
  return covered(address);
}

/* Field 47 (start_brk) of the stat record in `text`: `text` must be exactly
 * one record, a single complete line, with at least the 52 fields Linux 5.x
 * and later print, none of them empty, and field 47 a whole number. A record
 * cut short anywhere, even just after field 47's digits, fails here rather
 * than yielding a prefix of the number. */
static unsigned long field_47(void) {
  /* One line first: the command may hold ')', so the last ')' is the
   * command's end only within a single record. */
  char *newline = strchr(text, '\n');
  if (!newline || newline[1] != 0)
    fail("a stat record is not one complete line");
  char *field = strrchr(text, ')');
  if (!field || field[1] != ' ')
    fail("a stat record has no command");
  /* Fields 3 onward follow the command, one space before each, and none is
   * empty. */
  int fields = 2;
  for (char *at = field + 1; at < newline; at++)
    if (*at == ' ') {
      if (at[1] == ' ' || at[1] == '\n')
        fail("a stat record has an empty field");
      fields++;
    }
  if (fields < 52)
    fail("a stat record has fewer than 52 fields");
  for (int number = 2; number < 47; number++)
    field = strchr(field + 1, ' ');
  char *at = field + 1;
  return token(&at, 10, ' ', "stat field 47 is not a whole number");
}

static unsigned long start_brk(void) {
  read_all("/proc/self/stat");
  return field_47();
}

static void say(const char *what, int yes) {
  syscall(SYS_write, 1, what, strlen(what));
  syscall(SYS_write, 1, yes ? " yes\n" : " no\n", yes ? 5 : 4);
}

int main(int argc, char **argv) {
  /* The parsers alone, on text from standard input, for the tests' negative
   * controls: a value or a failure, never the transcript below. */
  if (argc == 2 && strcmp(argv[1], "--stat-from-stdin") == 0) {
    read_fd(0);
    field_47();
    say("stat parsed:", 1);
    return 0;
  }
  if (argc == 2 && strcmp(argv[1], "--maps-from-stdin") == 0) {
    read_fd(0);
    covered(0);
    say("maps parsed:", 1);
    return 0;
  }
  unsigned long after_image = ((unsigned long)&end + 4095) & ~4095UL;
  unsigned long brk = (unsigned long)syscall(SYS_brk, 0);
  int page_mapped = mapped(after_image);
  int break_mapped = mapped(brk);
  unsigned long kernel_start = start_brk();
  say("page after the image mapped:", page_mapped);
  say("brk(0) is the kernel's start_brk:", brk == kernel_start);
  say("break in a mapping:", break_mapped);
  return 0;
}
