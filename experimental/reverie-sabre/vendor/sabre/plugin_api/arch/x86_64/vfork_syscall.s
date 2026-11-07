/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: MIT
 */

  .file "vfork_syscall.s"
  .text
  .globl vfork_syscall
  .type vfork_syscall, @function

# long vfork_syscall();

vfork_syscall:

  # The reason for this pair of `pop rdi` and `push rdi` is quite subtle.
  # It might seem strange to pop before the push, but there is a good
  # reason for this. Stay a while and listen!
  #
  # There are several important things to remember here.
  #  1. The vforked child shares the same stack with the parent process
  #     and can modify the parent's stack.
  #  2. `%rdi` is not clobbered by the `syscall` instruction. (On x86-64,
  #     only `%rcx` and `%r11` are clobbered.)
  #  3. This function has no arguments and the top of the stack contains
  #     the return address. Thus, this `pop rdi` is storing the return
  #     address in `rdi`.
  #  4. When vfork is called, the parent process is paused and the child
  #     process continues on executing instructions. When the child
  #     process exits, this syscall returns for the parent process.
  #  5. Registers are NOT shared with the child process. The kernel
  #     simply saves/restores these whenever it does a context switch
  #     between the parent and child.
  #
  # When the child gets to the bottom of this function, the `ret`
  # instruction pops the return address off the stack for both itself and
  # the parent. Note that proper usage of vfork says that you shouldn't
  # return from the function where it was called. That's not true for
  # *this* function, but it is true for the caller of this function and
  # so the stack shouldn't get popped any further.
  #
  # Thus, this `pop rdi` saves the return address in `%rdi` and the `push
  # rdi` puts it back on the stack. In the child process, it puts it back
  # on the stack so that `ret` can pop it off again. In the parent
  # process, it puts it back because the child added it back, but then
  # subsequently popped it with the `ret`.
  #
  # glibc also does this in `vfork(3)`, but doesn't explain it very well.

  popq	%rdi

  # Adjust the arguments
  movq $58, %rax     # sc_no
  syscall            # syscall

  pushq	%rdi

  # This is an idempotent operation for the child process
  # but it is mandatory for the parent. When the child exits,
  # we might be outside of the plugin guard. This might be
  # the case because child and parent share memory. Here we
  # make sure we re-enter.
  pushq %rax
  call *enter_plugin@GOTPCREL(%rip)
  popq %rax

  ret # We are going back to the plugin.

  .size vfork_syscall, .-vfork_syscall
  .section .note.GNU-stack,"",@progbits
