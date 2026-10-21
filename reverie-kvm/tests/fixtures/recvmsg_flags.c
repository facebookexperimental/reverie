#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int receive_case(int batch, int cloexec) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets))
    return 1;
  if (write(sockets[0], "hello", 5) != 5)
    return 2;
  char payload[16] = {0};
  struct iovec iov = {.iov_base = payload, .iov_len = sizeof(payload)};
  struct mmsghdr message = {
      .msg_hdr = {.msg_iov = &iov, .msg_iovlen = 1, .msg_flags = -1},
      .msg_len = 0xdeadbeef};
  int flags = MSG_DONTWAIT | cloexec;
  if (batch) {
    if (recvmmsg(sockets[1], &message, 1, flags, NULL) != 1 ||
        message.msg_len != 5)
      return 3;
  } else if (recvmsg(sockets[1], &message.msg_hdr, flags) != 5) {
    return 4;
  }
  if (memcmp(payload, "hello", 5) || message.msg_hdr.msg_controllen != 0)
    return 5;
  if (message.msg_hdr.msg_flags != cloexec) {
    fprintf(stderr, "%s requested=%#x returned=%#x\n",
            batch ? "recvmmsg" : "recvmsg", cloexec,
            message.msg_hdr.msg_flags);
    return 6;
  }
  if (close(sockets[0]) || close(sockets[1]))
    return 7;
  printf("%s flags=%08x\n", batch ? "recvmmsg" : "recvmsg", cloexec);
  return 0;
}

int main(void) {
  for (int batch = 0; batch != 2; ++batch) {
    int result = receive_case(batch, 0);
    if (result)
      return result;
    result = receive_case(batch, MSG_CMSG_CLOEXEC);
    if (result)
      return result;
  }
  return 0;
}
