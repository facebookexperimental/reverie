#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t saw_sigint;
static volatile sig_atomic_t saw_sigterm;
static volatile sig_atomic_t saw_sigchld;

static void record_signal(int signal_value)
{
    switch (signal_value) {
    case SIGINT:
        ++saw_sigint;
        break;
    case SIGTERM:
        ++saw_sigterm;
        break;
    case SIGCHLD:
        ++saw_sigchld;
        break;
    default:
        _exit(2);
    }
}

static void install_handler(int signal_value)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = record_signal;
    action.sa_flags = SA_RESTART;
    assert(sigemptyset(&action.sa_mask) == 0);
    assert(sigaction(signal_value, &action, NULL) == 0);
}

static void wait_for_child(void)
{
    int status;
    pid_t child = fork();

    assert(child >= 0);
    if (child == 0) {
        _exit(0);
    }

    while (waitpid(child, &status, 0) < 0) {
        assert(errno == EINTR);
    }
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void)
{
    struct sigaction default_action;
    struct sigaction observed;

    install_handler(SIGINT);
    install_handler(SIGTERM);

    memset(&observed, 0, sizeof(observed));
    assert(sigaction(SIGINT, NULL, &observed) == 0);
    assert(observed.sa_handler == record_signal);

    install_handler(SIGCHLD);
    wait_for_child();

    for (unsigned attempt = 0; saw_sigchld == 0 && attempt < 1000; ++attempt) {
        usleep(1000);
    }
    assert(saw_sigchld >= 1);

    memset(&default_action, 0, sizeof(default_action));
    default_action.sa_handler = SIG_DFL;
    assert(sigemptyset(&default_action.sa_mask) == 0);
    assert(sigaction(SIGCHLD, &default_action, NULL) == 0);
    wait_for_child();

    assert(raise(SIGINT) == 0);
    assert(raise(SIGTERM) == 0);

    assert(saw_sigint == 1);
    assert(saw_sigterm == 1);
    assert(saw_sigchld >= 1);
    puts("signal-forwarding: ok");
    return 0;
}
