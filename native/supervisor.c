/* Small Linux 4.9-compatible supervisor; credentials never enter argv or logs. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifndef CAPSULA_INTERFACE
#define CAPSULA_INTERFACE "wlan0"
#endif
#ifndef CAPSULA_PORT
#define CAPSULA_PORT "22"
#endif
#define RUN "/run/capsula-root"
#define SELF "/usr/lib/capsula-root/supervisor"
#define SERVER "/usr/lib/capsula-root/dropbearmulti"
static volatile sig_atomic_t stopping;
static void on_signal(int sig) { (void)sig; stopping = 1; }
static void pause_seconds(unsigned n) {
    while (n-- && !stopping) { struct timespec ts = {1, 0}; nanosleep(&ts, NULL); }
}

static unsigned long long start_time(pid_t pid) {
    char path[64], text[4096], *p, *end;
    snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    p = fgets(text, sizeof text, f); fclose(f);
    if (!p || !(p = strrchr(text, ')'))) return 0;
    p += 2;
    for (int field = 3; field < 22; field++) {
        p = strchr(p, ' '); if (!p) return 0; p++;
    }
    errno = 0;
    unsigned long long value = strtoull(p, &end, 10);
    return errno || p == end ? 0 : value;
}

static pid_t owner(void) {
    long pid; unsigned long long tick;
    FILE *f = fopen(RUN "/supervisor.pid", "r");
    if (!f) return -1;
    int ok = fscanf(f, "%ld %llu", &pid, &tick); fclose(f);
    if (ok != 2 || pid <= 1 || pid > 0x7fffffff || !tick || start_time((pid_t)pid) != tick) return -1;
    char path[64], exe[512];
    snprintf(path, sizeof path, "/proc/%ld/exe", pid);
    ssize_t n = readlink(path, exe, sizeof exe - 1);
    if (n < 0) return -1;
    exe[n] = 0;
    return strcmp(exe, SELF) ? -1 : (pid_t)pid;
}

static int stop_service(int lock) {
    if (!flock(lock, LOCK_EX | LOCK_NB)) { flock(lock, LOCK_UN); return 0; }
    if (errno != EWOULDBLOCK) return 1;
    pid_t pid = owner();
    if (pid < 0) { fputs("Supervisor is starting; retry stop.\n", stderr); return 1; }
    if (kill(pid, SIGTERM) && errno != ESRCH) return 1;
    for (int i = 0; i < 80; i++) {
        if (!flock(lock, LOCK_EX | LOCK_NB)) { flock(lock, LOCK_UN); return 0; }
        struct timespec ts = {0, 100000000}; nanosleep(&ts, NULL);
    }
    fputs("Supervisor did not stop in 8 seconds.\n", stderr); return 1;
}

static void supervise(int lock, int ready) {
    if (setsid() < 0) _exit(1);
    int nullfd = open("/dev/null", O_RDWR);
    if (nullfd < 0) _exit(1);
    for (int n = 0; n < 3; n++) if (dup2(nullfd, n) < 0) _exit(1);
    if (nullfd > 2) close(nullfd);
    chdir("/");
    openlog("capsula-root", LOG_PID, LOG_DAEMON);
    struct sigaction sa = {.sa_handler = on_signal};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL);
    signal(SIGHUP, SIG_IGN); signal(SIGPIPE, SIG_IGN);
    FILE *f = fopen(RUN "/supervisor.pid", "w");
    if (!f) _exit(1);
    fprintf(f, "%ld %llu\n", (long)getpid(), start_time(getpid()));
    if (fclose(f)) _exit(1);
    if (write(ready, "1", 1) != 1) _exit(1);
    close(ready);
    unsigned delay = 1;
    syslog(LOG_INFO, "Password SSH supervisor started on %s:%s", CAPSULA_INTERFACE, CAPSULA_PORT);
    while (!stopping && access("/data/capsula-root.disabled", F_OK)) {
        if (!if_nametoindex(CAPSULA_INTERFACE)) { pause_seconds(2); continue; }
        time_t began = time(NULL);
        pid_t child = fork();
        if (child == 0) {
            signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL);
            execl(SERVER, SERVER, "dropbear", "-F", "-r", "/etc/capsula-root/hostkey",
                  "-l", CAPSULA_INTERFACE, "-p", CAPSULA_PORT,
                  "-P", RUN "/dropbear.pid", (char *)NULL);
            _exit(127);
        }
        if (child < 0) { syslog(LOG_ERR, "fork failed"); pause_seconds(delay); continue; }
        int status;
        for (;;) {
            pid_t got = waitpid(child, &status, WNOHANG);
            if (got == child || (got < 0 && errno == ECHILD)) break;
            if (got < 0 && errno != EINTR) { stopping = 1; break; }
            if (!access("/data/capsula-root.disabled", F_OK)) stopping = 1;
            if (stopping) {
                kill(child, SIGTERM);
                for (int i = 0; i < 50; i++) {
                    if (waitpid(child, &status, WNOHANG) == child) { child = -1; break; }
                    struct timespec ts = {0, 100000000}; nanosleep(&ts, NULL);
                }
                if (child > 0) { kill(child, SIGKILL); while (waitpid(child, &status, 0) < 0 && errno == EINTR) {} }
                break;
            }
            pause_seconds(1);
        }
        unlink(RUN "/dropbear.pid");
        if (stopping) break;
        if (time(NULL) - began >= 60) delay = 1;
        syslog(LOG_WARNING, "SSH listener exited; retry in %u seconds", delay);
        pause_seconds(delay);
        delay = delay < 16 ? delay * 2 : 30;
    }
    unlink(RUN "/supervisor.pid");
    syslog(LOG_INFO, "Password SSH supervisor stopped");
    close(lock); closelog(); _exit(0);
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "identity")) {
        printf("%lu\n%lu\n", (unsigned long)getuid(), (unsigned long)getgid()); return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "uid")) {
        printf("%lu\n", (unsigned long)getuid()); return 0;
    }
    if (getuid() || argc != 2) return 2;
    int start = !strcmp(argv[1], "start"), stop = !strcmp(argv[1], "stop");
    int status = !strcmp(argv[1], "status"), restart = !strcmp(argv[1], "restart");
    if (!start && !stop && !status && !restart) return 2;
    umask(077);
    if (mkdir(RUN, 0700) && errno != EEXIST) return 1;
    int dir = open(RUN, O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (dir < 0 || fstat(dir, &st) || st.st_uid || (st.st_mode & 077)) return 1;
    int lock = openat(dir, "supervisor.lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    close(dir);
    if (lock < 0 || fstat(lock, &st) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode & 077)) return 1;
    if (stop || restart) { int result = stop_service(lock); if (stop || result) { close(lock); return result; } }
    if (!flock(lock, LOCK_EX | LOCK_NB)) {
        if (status) { puts("stopped"); close(lock); return 3; }
    } else {
        if (errno != EWOULDBLOCK) return 1;
        if (status) puts("running");
        close(lock); return 0;
    }
    int ready[2];
    if (pipe2(ready, O_CLOEXEC)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (!child) { close(ready[0]); supervise(lock, ready[1]); }
    close(ready[1]); close(lock);
    char result = 0;
    ssize_t n; do { n = read(ready[0], &result, 1); } while (n < 0 && errno == EINTR);
    close(ready[0]);
    return n == 1 && result == '1' ? 0 : 1;
}
