/*
 * Read-only Mach memory candidate scanner for chatlog-keeper.
 *
 * It does not decrypt databases and never writes to the target process.  The
 * Python caller validates every candidate against the user's local DB HMAC
 * before it can be cached.
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHUNK (8u * 1024u * 1024u)
#define OVERLAP 256u

struct process_identity {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    uint64_t start_sec;
    uint64_t start_usec;
    uid_t uid;
};

struct frozen_launch_path {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    uint64_t uid;
    uint64_t device;
    uint64_t inode;
    uint64_t file_type;
};

static int read_process_info(pid_t pid, struct proc_bsdinfo *out) {
    memset(out, 0, sizeof(*out));
    int info_len = proc_pidinfo(
        pid, PROC_PIDTBSDINFO, 0, out, (int)sizeof(*out));
    return info_len == (int)sizeof(*out) && out->pbi_pid == (uint32_t)pid;
}

static int read_identity(pid_t pid, struct process_identity *out) {
    memset(out, 0, sizeof(*out));
    struct proc_bsdinfo info;
    if (!read_process_info(pid, &info)) return 0;
    int path_len = proc_pidpath(pid, out->path, sizeof(out->path));
    if (path_len <= 0 || (size_t)path_len >= sizeof(out->path)) return 0;
    out->start_sec = info.pbi_start_tvsec;
    out->start_usec = info.pbi_start_tvusec;
    out->uid = info.pbi_uid;
    return 1;
}

static int same_identity(
    const struct process_identity *left,
    const struct process_identity *right) {
    return left->start_sec == right->start_sec &&
           left->start_usec == right->start_usec &&
           left->uid == right->uid &&
           !strcmp(left->path, right->path);
}

static int snapshot_identity(pid_t pid, struct process_identity *out) {
    struct process_identity first;
    struct process_identity second;
    if (!read_identity(pid, &first) || !read_identity(pid, &second) ||
        !same_identity(&first, &second)) {
        return 0;
    }
    *out = second;
    return 1;
}

static int parse_u64(const char *raw, uint64_t *out) {
    if (!raw || !*raw) return 0;
    for (const unsigned char *cursor = (const unsigned char *)raw;
         *cursor; ++cursor) {
        if (!isdigit(*cursor)) return 0;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(raw, &end, 10);
    if (errno == ERANGE || !end || *end) return 0;
    *out = (uint64_t)parsed;
    return 1;
}

static int parse_pid(const char *raw, pid_t *out) {
    uint64_t parsed = 0;
    if (!parse_u64(raw, &parsed)) return 0;
    pid_t candidate = (pid_t)parsed;
    if (candidate <= 1 || (uint64_t)candidate != parsed) return 0;
    *out = candidate;
    return 1;
}

static int hex_value(unsigned char value) {
    if (value >= '0' && value <= '9') return (int)(value - '0');
    if (value >= 'a' && value <= 'f') return (int)(value - 'a') + 10;
    if (value >= 'A' && value <= 'F') return (int)(value - 'A') + 10;
    return -1;
}

static int decode_path(const char *raw, char *out, size_t out_size) {
    size_t raw_len = strlen(raw);
    if (!raw_len || (raw_len % 2) || raw_len / 2 >= out_size) return 0;
    for (size_t i = 0; i < raw_len / 2; ++i) {
        int high = hex_value((unsigned char)raw[2 * i]);
        int low = hex_value((unsigned char)raw[2 * i + 1]);
        if (high < 0 || low < 0) return 0;
        out[i] = (char)((high << 4) | low);
        if (!out[i]) return 0;
    }
    out[raw_len / 2] = '\0';
    return 1;
}

static int parse_frozen_launch_path(
    char **argv,
    size_t first,
    struct frozen_launch_path *out) {
    memset(out, 0, sizeof(*out));
    return decode_path(argv[first], out->path, sizeof(out->path)) &&
           out->path[0] == '/' &&
           parse_u64(argv[first + 1], &out->uid) &&
           parse_u64(argv[first + 2], &out->device) &&
           parse_u64(argv[first + 3], &out->inode) && out->inode > 0 &&
           parse_u64(argv[first + 4], &out->file_type);
}

static int frozen_launch_path_matches(
    const struct frozen_launch_path *expected,
    mode_t required_type,
    int required_permissions) {
    struct stat info;
    char canonical[PROC_PIDPATHINFO_MAXSIZE];
    memset(&info, 0, sizeof(info));
    if (expected->uid != (uint64_t)geteuid() ||
        expected->file_type != (uint64_t)required_type ||
        realpath(expected->path, canonical) == NULL ||
        strcmp(expected->path, canonical) != 0 ||
        lstat(expected->path, &info) != 0 || S_ISLNK(info.st_mode) ||
        (info.st_mode & S_IFMT) != required_type ||
        (uint64_t)info.st_uid != expected->uid ||
        (uint64_t)info.st_dev != expected->device ||
        (uint64_t)info.st_ino != expected->inode ||
        (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return 0;
    }
    return required_permissions < 0 ||
           (info.st_mode & 07777) == (mode_t)required_permissions;
}

static void emit_identity(const struct process_identity *identity) {
    printf("IDENTITY:%llu:%llu:",
           (unsigned long long)identity->start_sec,
           (unsigned long long)identity->start_usec);
    const unsigned char *path = (const unsigned char *)identity->path;
    for (size_t i = 0; path[i]; ++i) printf("%02x", path[i]);
    fputc('\n', stdout);
}

static int identity_matches(
    pid_t pid,
    const struct process_identity *expected) {
    struct process_identity current;
    return snapshot_identity(pid, &current) && same_identity(&current, expected);
}

static int owner_process_alive(pid_t expected_parent) {
    return expected_parent > 1 && getppid() == expected_parent;
}

static int pid_may_be_alive(pid_t pid) {
    errno = 0;
    return kill(pid, 0) == 0 || errno == EPERM;
}

static int printable(unsigned char c) { return c >= 0x20 && c <= 0x7e; }

static void emit_hex(const char *kind, const unsigned char *p, size_t n) {
    fputs(kind, stdout);
    fputc(':', stdout);
    for (size_t i = 0; i < n; ++i) fprintf(stdout, "%02x", p[i]);
    fputc('\n', stdout);
}

static void scan_qq(const unsigned char *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        if (!printable(p[i])) {
            ++i;
            continue;
        }
        size_t j = i;
        while (j < n && printable(p[j])) ++j;
        size_t len = j - i;
        if ((len == 16 || len == 32) && j < n && p[j] == 0 &&
            (i == 0 || p[i - 1] == 0)) {
            emit_hex("QQ", p + i, len);
        }
        i = j + (j < n ? 1 : 0);
    }
}

static int hexch(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static void scan_wechat(const unsigned char *p, size_t n) {
    for (size_t i = 0; i + 67 < n; ++i) {
        if (p[i] != 'x' || p[i + 1] != '\'') continue;
        size_t j = i + 2;
        while (j < n && hexch(p[j]) && j - (i + 2) <= 192) ++j;
        size_t len = j - (i + 2);
        if (len >= 64 && j < n && p[j] == '\'') {
            /* The first 64 hex chars are the 32-byte master-key candidate. */
            unsigned char key[32];
            for (size_t k = 0; k < 32; ++k) {
                unsigned int v = 0;
                sscanf((const char *)(p + i + 2 + 2 * k), "%2x", &v);
                key[k] = (unsigned char)v;
            }
            emit_hex("WX", key, sizeof(key));
        }
    }
}

#define WATCH_MAX_GENERATIONS 16
#define WATCH_CLEANUP_GRACE_MS 35000u
#define WATCH_TERM_GRACE_MS 5000u

struct watched_generation {
    pid_t pid;
    struct process_identity identity;
    uint64_t term_sent_ms;
};

static volatile sig_atomic_t watch_interrupted = 0;

static void interrupt_watch(int signal_number) {
    (void)signal_number;
    watch_interrupted = 1;
}

static int emit_watch_marker(const char *marker) {
    return fputs(marker, stdout) != EOF && fflush(stdout) == 0;
}

static uint64_t monotonic_ms(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * 1000u + (uint64_t)value.tv_nsec / 1000000u;
}

static int trusted_open_tool(void) {
    struct stat info;
    return lstat("/usr/bin/open", &info) == 0 && S_ISREG(info.st_mode) &&
           info.st_uid == 0 && !(info.st_mode & (S_IWGRP | S_IWOTH));
}

static int exact_path_generations(
    const char *path,
    struct watched_generation *out,
    size_t capacity,
    size_t *out_count) {
    *out_count = 0;
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (bytes <= 0 || bytes > (int)(1024u * 1024u * 16u)) return 0;
    bytes += (int)(256u * sizeof(pid_t));
    pid_t *pids = calloc(1, (size_t)bytes);
    if (!pids) return 0;
    int used = proc_listpids(PROC_ALL_PIDS, 0, pids, bytes);
    if (used < 0 || used >= bytes) {
        free(pids);
        return 0;
    }
    size_t count = (size_t)used / sizeof(pid_t);
    const char *target_name = strrchr(path, '/');
    target_name = target_name ? target_name + 1 : path;
    for (size_t index = 0; index < count; ++index) {
        pid_t pid = pids[index];
        struct proc_bsdinfo info;
        struct process_identity identity;
        if (pid <= 1) continue;
        if (!read_process_info(pid, &info) || info.pbi_uid != geteuid()) continue;
        if (!snapshot_identity(pid, &identity)) {
            if (pid_may_be_alive(pid) &&
                (!strcmp(info.pbi_name, target_name) ||
                 !strcmp(info.pbi_comm, target_name))) {
                free(pids);
                return 0;
            }
            continue;
        }
        if (identity.uid != geteuid() || strcmp(identity.path, path)) continue;
        if (*out_count >= capacity) {
            free(pids);
            return 0;
        }
        out[*out_count].pid = pid;
        out[*out_count].identity = identity;
        out[*out_count].term_sent_ms = 0;
        ++*out_count;
    }
    free(pids);
    return 1;
}

static int remember_generation(
    struct watched_generation *known,
    size_t *known_count,
    const struct watched_generation *candidate) {
    for (size_t index = 0; index < *known_count; ++index) {
        if (known[index].pid != candidate->pid) continue;
        /* PID reuse is never folded into the generation we armed for. */
        return same_identity(&known[index].identity, &candidate->identity);
    }
    if (*known_count >= WATCH_MAX_GENERATIONS) return 0;
    known[*known_count] = *candidate;
    ++*known_count;
    return 1;
}

static int open_child_finished(pid_t open_pid, int *finished) {
    if (*finished) return 1;
    int status = 0;
    pid_t result = waitpid(open_pid, &status, WNOHANG);
    if (result == 0) return 1;
    if (result != open_pid) return 0;
    *finished = 1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int cleanup_watched_target(
    const char *path,
    pid_t open_pid,
    struct watched_generation *known,
    size_t *known_count) {
    uint64_t started = monotonic_ms();
    uint64_t deadline = started + WATCH_CLEANUP_GRACE_MS;
    uint64_t quiet_since = 0;
    int open_finished = 0;
    while (monotonic_ms() <= deadline) {
        if (!open_child_finished(open_pid, &open_finished)) return 0;
        struct watched_generation current[WATCH_MAX_GENERATIONS];
        size_t current_count = 0;
        if (!exact_path_generations(
                path, current, WATCH_MAX_GENERATIONS, &current_count)) {
            usleep(100000);
            continue;
        }
        for (size_t index = 0; index < current_count; ++index) {
            if (!remember_generation(known, known_count, &current[index])) {
                return 0;
            }
        }
        uint64_t now = monotonic_ms();
        int any_same = 0;
        for (size_t index = 0; index < *known_count; ++index) {
            if (!identity_matches(known[index].pid, &known[index].identity)) {
                continue;
            }
            any_same = 1;
            int signal_number = SIGTERM;
            if (known[index].term_sent_ms != 0 &&
                now - known[index].term_sent_ms >= WATCH_TERM_GRACE_MS) {
                signal_number = SIGKILL;
            }
            if (known[index].term_sent_ms == 0 || signal_number == SIGKILL) {
                /* Revalidate immediately before every signal. */
                if (!identity_matches(
                        known[index].pid, &known[index].identity)) {
                    continue;
                }
                if (kill(known[index].pid, signal_number) != 0 &&
                    errno != ESRCH) {
                    return 0;
                }
                if (known[index].term_sent_ms == 0) {
                    known[index].term_sent_ms = now;
                }
            }
        }
        if (open_finished && current_count == 0 && !any_same) {
            if (quiet_since == 0) quiet_since = now;
            if (now - quiet_since >= 1000u) return 1;
        } else {
            quiet_since = 0;
        }
        usleep(100000);
    }
    return 0;
}

static int wait_for_launch_command(pid_t owner_pid) {
    while (owner_process_alive(owner_pid) && !watch_interrupted) {
        struct pollfd control = {STDIN_FILENO, POLLIN | POLLHUP, 0};
        int ready = poll(&control, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return 0;
        if (control.revents & (POLLHUP | POLLERR | POLLNVAL)) return 0;
        if (control.revents & POLLIN) {
            unsigned char command = 0;
            ssize_t read_count = read(STDIN_FILENO, &command, 1);
            return read_count == 1 && command == 'L';
        }
    }
    return 0;
}

static int watch_launch_main(int argc, char **argv) {
    if (argc != 13 && argc != 23) return 2;
    pid_t owner_pid = 0;
    if (!parse_pid(argv[2], &owner_pid)) return 2;
    struct frozen_launch_path target;
    struct frozen_launch_path app;
    struct frozen_launch_path capture_library;
    struct frozen_launch_path capture_fifo;
    if (!parse_frozen_launch_path(argv, 3, &target) ||
        !parse_frozen_launch_path(argv, 8, &app)) {
        return 2;
    }
    int capture = argc == 23;
    if (capture &&
        (!parse_frozen_launch_path(argv, 13, &capture_library) ||
         !parse_frozen_launch_path(argv, 18, &capture_fifo))) {
        return 2;
    }
    if (!owner_process_alive(owner_pid) || !trusted_open_tool()) return 6;
    if (!frozen_launch_path_matches(&target, S_IFREG, -1) ||
        !frozen_launch_path_matches(&app, S_IFDIR, 0700) ||
        (capture &&
         (!frozen_launch_path_matches(&capture_library, S_IFREG, 0700) ||
          !frozen_launch_path_matches(&capture_fifo, S_IFIFO, 0600)))) {
        return 7;
    }
    struct watched_generation baseline[WATCH_MAX_GENERATIONS];
    size_t baseline_count = 0;
    if (!exact_path_generations(
            target.path, baseline, WATCH_MAX_GENERATIONS, &baseline_count) ||
        baseline_count != 0) {
        fprintf(stderr, "watch_baseline_not_empty\n");
        return 7;
    }
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR ||
        signal(SIGTERM, interrupt_watch) == SIG_ERR ||
        signal(SIGINT, interrupt_watch) == SIG_ERR ||
        !emit_watch_marker("WATCH_ARMED\n")) {
        return 6;
    }
    if (!wait_for_launch_command(owner_pid)) return 6;
    if (!owner_process_alive(owner_pid) || watch_interrupted) return 6;
    if (!exact_path_generations(
            target.path, baseline, WATCH_MAX_GENERATIONS, &baseline_count) ||
        baseline_count != 0) {
        return 7;
    }

    /* The LaunchServices child must not inherit the owner-control pipe. */
    for (int descriptor = 0; descriptor <= 2; ++descriptor) {
        int flags = fcntl(descriptor, F_GETFD);
        if (flags >= 0) (void)fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC);
    }
    char library_env[PROC_PIDPATHINFO_MAXSIZE + 64];
    char fifo_env[PROC_PIDPATHINFO_MAXSIZE + 64];
    char *open_argv[9];
    size_t arg_index = 0;
    open_argv[arg_index++] = "/usr/bin/open";
    open_argv[arg_index++] = "-n";
    if (capture) {
        if (snprintf(
                library_env, sizeof(library_env),
                "DYLD_INSERT_LIBRARIES=%s", capture_library.path) >=
                (int)sizeof(library_env) ||
            snprintf(
                fifo_env, sizeof(fifo_env),
                "CHATLOG_KEEPER_WECHAT_KEY_FIFO=%s", capture_fifo.path) >=
                (int)sizeof(fifo_env)) {
            return 2;
        }
        open_argv[arg_index++] = "--env";
        open_argv[arg_index++] = library_env;
        open_argv[arg_index++] = "--env";
        open_argv[arg_index++] = fifo_env;
    }
    open_argv[arg_index++] = app.path;
    open_argv[arg_index] = NULL;
    char *open_envp[] = {NULL};
    if (!frozen_launch_path_matches(&target, S_IFREG, -1) ||
        !frozen_launch_path_matches(&app, S_IFDIR, 0700) ||
        (capture &&
         (!frozen_launch_path_matches(&capture_library, S_IFREG, 0700) ||
          !frozen_launch_path_matches(&capture_fifo, S_IFIFO, 0600)))) {
        return 7;
    }
    pid_t open_pid = 0;
    int spawn_result = posix_spawn(
        &open_pid, "/usr/bin/open", NULL, NULL, open_argv, open_envp);
    if (spawn_result != 0 || open_pid <= 1) return 7;

    struct watched_generation known[WATCH_MAX_GENERATIONS];
    size_t known_count = 0;
    if (!emit_watch_marker("WATCH_LAUNCHED\n")) {
        /* The owner can disappear after launch authorization but before it
         * observes this marker.  The client may already be starting, so a
         * broken status pipe must enter the same exact-generation cleanup
         * path as any other loss of owner/control, without an early exit. */
        watch_interrupted = 1;
    }
    while (owner_process_alive(owner_pid) && !watch_interrupted) {
        struct watched_generation current[WATCH_MAX_GENERATIONS];
        size_t current_count = 0;
        if (exact_path_generations(
                target.path, current, WATCH_MAX_GENERATIONS, &current_count)) {
            for (size_t index = 0; index < current_count; ++index) {
                if (!remember_generation(known, &known_count, &current[index])) {
                    watch_interrupted = 1;
                    break;
                }
            }
        }
        struct pollfd control = {STDIN_FILENO, POLLIN | POLLHUP, 0};
        int ready = poll(&control, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || control.revents & (POLLHUP | POLLERR | POLLNVAL)) {
            watch_interrupted = 1;
            break;
        }
        if (control.revents & POLLIN) {
            unsigned char command = 0;
            ssize_t read_count = read(STDIN_FILENO, &command, 1);
            if (read_count != 1 || command != 'C') watch_interrupted = 1;
            break;
        }
    }
    int cleaned = cleanup_watched_target(
        target.path, open_pid, known, &known_count);
    if (!cleaned) fprintf(stderr, "watch_cleanup_failed\n");
    return cleaned ? 0 : 7;
}

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "watch-launch")) {
        return watch_launch_main(argc, argv);
    }
    if (argc == 3 && !strcmp(argv[1], "identity")) {
        pid_t identity_pid = 0;
        struct process_identity identity;
        if (!parse_pid(argv[2], &identity_pid) ||
            !snapshot_identity(identity_pid, &identity)) {
            fprintf(stderr, "process_identity_unavailable\n");
            return 5;
        }
        emit_identity(&identity);
        return 0;
    }
    if (argc != 7 || (strcmp(argv[1], "qq") && strcmp(argv[1], "wechat"))) {
        fprintf(stderr,
                "usage: macos-memory-scan <qq|wechat> <pid> "
                "<start-sec> <start-usec> <path-hex> <owner-pid>\n");
        return 2;
    }
    pid_t pid = 0;
    if (!parse_pid(argv[2], &pid)) return 2;

    struct process_identity expected;
    memset(&expected, 0, sizeof(expected));
    if (!parse_u64(argv[3], &expected.start_sec) ||
        !parse_u64(argv[4], &expected.start_usec) ||
        expected.start_usec >= 1000000 ||
        !decode_path(argv[5], expected.path, sizeof(expected.path))) {
        fprintf(stderr, "invalid_process_identity\n");
        return 2;
    }
    expected.uid = geteuid();
    pid_t owner_pid = 0;
    if (!parse_pid(argv[6], &owner_pid) || !owner_process_alive(owner_pid)) {
        fprintf(stderr, "owner_process_lost\n");
        return 6;
    }
    if (!identity_matches(pid, &expected)) {
        fprintf(stderr, "process_identity_mismatch\n");
        return 5;
    }

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid:%d\n", kr);
        return 3;
    }
    if (!identity_matches(pid, &expected)) {
        mach_port_deallocate(mach_task_self(), task);
        fprintf(stderr, "process_identity_mismatch\n");
        return 5;
    }

    unsigned char *buf = malloc(CHUNK + OVERLAP);
    if (!buf) return 4;
    mach_vm_address_t address = 0;
    int owner_lost = 0;
    int target_lost = 0;
    while (1) {
        if (!owner_process_alive(owner_pid)) {
            owner_lost = 1;
            break;
        }
        if (!identity_matches(pid, &expected)) {
            target_lost = 1;
            break;
        }
        mach_vm_size_t region_size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name = MACH_PORT_NULL;
        kr = mach_vm_region(
            task, &address, &region_size, VM_REGION_BASIC_INFO_64,
            (vm_region_info_t)&info, &count, &object_name);
        if (kr != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && region_size > 0) {
            mach_vm_size_t offset = 0;
            size_t carry = 0;
            while (offset < region_size) {
                if (!owner_process_alive(owner_pid)) {
                    owner_lost = 1;
                    break;
                }
                if (!identity_matches(pid, &expected)) {
                    target_lost = 1;
                    break;
                }
                mach_vm_size_t want = region_size - offset;
                if (want > CHUNK) want = CHUNK;
                mach_vm_size_t got = 0;
                kr = mach_vm_read_overwrite(
                    task, address + offset, want,
                    (mach_vm_address_t)(buf + carry), &got);
                if (kr != KERN_SUCCESS || got == 0) break;
                size_t total = carry + (size_t)got;
                if (!strcmp(argv[1], "qq")) scan_qq(buf, total);
                else scan_wechat(buf, total);
                carry = total < OVERLAP ? total : OVERLAP;
                memmove(buf, buf + total - carry, carry);
                offset += got;
            }
            if (owner_lost || target_lost) break;
        }
        if (object_name != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object_name);
        mach_vm_address_t next = address + region_size;
        if (next <= address) break;
        address = next;
    }
    free(buf);
    mach_port_deallocate(mach_task_self(), task);
    if (owner_lost) {
        fprintf(stderr, "owner_process_lost\n");
        return 6;
    }
    if (target_lost) {
        fprintf(stderr, "process_identity_mismatch\n");
        return 5;
    }
    if (!identity_matches(pid, &expected)) {
        fprintf(stderr, "process_identity_mismatch\n");
        return 5;
    }
    return 0;
}
