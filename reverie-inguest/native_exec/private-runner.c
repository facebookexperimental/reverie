/* Ordinary GNU PIE with standard startup objects and a DT_NEEDED dependency
 * on the genuine explicit-init Detcore DSO. main NEVER returns to libc exit.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <sys/syscall.h>
#include "private-control.h"

struct KernelAction {
    uint64_t handler, flags, restorer, mask;
};
static _Thread_local volatile uint64_t runner_tls = UINT64_C(0x52554e4e4552544c);

static uint64_t parse_control(const char *value) {
    if (!value || value[0] != '0' || value[1] != 'x')
        private_native_terminal(82);
    uint64_t result = 0;
    for (unsigned i = 0; i < 16; ++i) {
        unsigned char c = (unsigned char)value[i + 2];
        unsigned digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else private_native_terminal(82);
        result = (result << 4) | digit;
    }
    if (value[18] != 0)
        private_native_terminal(82);
    return result;
}
static struct KernelAction current_action(void) {
    struct KernelAction action = {0};
    if (private_native_syscall(SYS_rt_sigaction, SIGSYS, 0,
                               (uint64_t)&action, 8, 0, 0))
        private_native_terminal(83);
    return action;
}

int main(int argc, char **argv) {
    if (argc != 2 || !argv || !argv[1])
        private_native_terminal(82);
    uint64_t address = parse_control(argv[1]);
    uint64_t located = *(volatile uint64_t *)(uintptr_t)EXEC_PRIVATE_LOCATOR_ADDR;
    if (address != EXEC_PRIVATE_CONTROL_ADDR || address != located)
        private_native_terminal(82);
    struct ExecPrivateControl *ctl = (void *)(uintptr_t)address;
    if (ctl->abi_version != EXEC_PRIVATE_ABI_VERSION ||
        ctl->byte_len != sizeof(*ctl) ||
        __atomic_load_n(&ctl->phase, __ATOMIC_ACQUIRE) != EXEC_PRIVATE_TOOL_LOADING ||
        ctl->runtime_ready != 0 || ctl->native_state != EXEC_PRIVATE_NATIVE_CAPTURED ||
        ctl->init_input != EXEC_PRIVATE_INPUT_ADDR ||
        ctl->init_input_len == 0 || ctl->init_input_len > EXEC_PRIVATE_PACKET_LIMIT ||
        ctl->init_input_fd != EXEC_PRIVATE_INIT_INPUT_FD)
        private_native_terminal(84);
    uint64_t fs = private_native_get_fs();
    if (fs == 0 || fs == ctl->guest_fs || fs != ctl->tool_fs ||
        runner_tls != UINT64_C(0x52554e4e4552544c))
        private_native_terminal(85);
    struct KernelAction before = current_action();
    if (before.handler != ctl->bootstrap_handler ||
        before.restorer != ctl->bootstrap_restorer ||
        !(before.flags & SA_SIGINFO) || !(before.flags & SA_ONSTACK) ||
        (before.flags & SA_NODEFER))
        private_native_terminal(86);
    __atomic_store_n(&ctl->phase, EXEC_PRIVATE_TOOL_INIT, __ATOMIC_RELEASE);

    /* This strong unresolved reference is intentional. Never replace it with
     * a success stub, old preload constructor, toy Tool or fake RPC reply.
     */
    int64_t result = detcore_liteinst_exec_initialize(ctl);
    if (result != 0 ||
        __atomic_load_n(&ctl->runtime_ready, __ATOMIC_ACQUIRE) != EXEC_PRIVATE_READY ||
        __atomic_load_n(&ctl->phase, __ATOMIC_ACQUIRE) != EXEC_PRIVATE_TOOL_INIT ||
        private_native_get_fs() != fs || ctl->tool_fs != fs ||
        runner_tls != UINT64_C(0x52554e4e4552544c))
        private_native_terminal(87);
    struct KernelAction after = current_action();
    uint64_t mask = 0;
    if (after.handler == 0 || after.handler == ctl->bootstrap_handler ||
        after.restorer != EXEC_PRIVATE_RESTORER_ENTRY ||
        !(after.flags & SA_SIGINFO) || !(after.flags & SA_ONSTACK) ||
        (after.flags & SA_NODEFER) ||
        private_native_syscall(SYS_rt_sigprocmask, SIG_SETMASK, 0,
                               (uint64_t)&mask, 8, 0, 0) ||
        (mask & (UINT64_C(1) << (SIGSYS - 1))))
        private_native_terminal(88);
    /* The genuine initializer, not this runner, publishes runtime_ready and
     * supplies the final reserved-signal-stripped guest_resume_mask.
     */
    if (ctl->guest_resume_mask & (UINT64_C(1) << (SIGSYS - 1)))
        private_native_terminal(88);
    private_runner_resume(ctl);
}
