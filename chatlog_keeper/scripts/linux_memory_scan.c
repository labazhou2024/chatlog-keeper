/*
 * Read-only Linux memory candidate scanner for chatlog-keeper.
 *
 * It does not decrypt databases and never writes to the target process.
 * process_vm_readv is the primary path; ptrace PEEKDATA is a same-uid
 * fallback for a child the Python caller spawned. Every printed candidate
 * still has to pass the caller's local DB HMAC oracle.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHUNK (8u * 1024u * 1024u)
#define MAX_REGION (200u * 1024u * 1024u)

static int parse_args(
    int argc,
    char **argv,
    pid_t *pid,
    const char **kind,
    int *timeout) {
    *pid = 0;
    *kind = NULL;
    *timeout = 120;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc) {
            *pid = (pid_t)atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--kind") && i + 1 < argc) {
            *kind = argv[++i];
        } else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) {
            *timeout = atoi(argv[++i]);
        } else {
            return 0;
        }
    }
    return *pid > 0 && *kind != NULL &&
           (!strcmp(*kind, "wechat") || !strcmp(*kind, "qq")) &&
           *timeout > 0;
}

static int is_candidate_region(const char *line, unsigned long *start, unsigned long *end) {
    char perms[8];
    unsigned long offset;
    unsigned int dev_maj, dev_min;
    unsigned long inode;
    char path[256];
    path[0] = 0;
    if (sscanf(
            line,
            "%lx-%lx %7s %lx %x:%x %lu %255s",
            start,
            end,
            perms,
            &offset,
            &dev_maj,
            &dev_min,
            &inode,
            path) < 7) {
        return 0;
    }
    if (perms[0] != 'r') return 0;
    if (*end <= *start || (*end - *start) >= MAX_REGION) return 0;
    if (!strcmp(path, "[vvar]") || !strcmp(path, "[vdso]") ||
        !strcmp(path, "[vsyscall]")) {
        return 0;
    }
    if (path[0] != 0 && path[0] != '[') return 0;
    return 1;
}

static ssize_t read_remote(
    pid_t pid,
    unsigned long address,
    void *buf,
    size_t size,
    int *attached) {
    struct iovec local = {buf, size};
    struct iovec remote = {(void *)address, size};
    ssize_t got = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (got >= 0) return got;
    if (errno != EPERM && errno != EACCES) return -1;
    if (!*attached) {
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) return -1;
        int status = 0;
        if (waitpid(pid, &status, 0) != pid) return -1;
        *attached = 1;
    }
    size_t offset = 0;
    unsigned char *out = buf;
    while (offset + sizeof(long) <= size) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(address + offset), NULL);
        if (word == -1 && errno != 0) break;
        memcpy(out + offset, &word, sizeof(long));
        offset += sizeof(long);
    }
    return (ssize_t)offset;
}

static int is_printable(unsigned char c) {
    return c >= 0x20 && c <= 0x7e;
}

static void emit_wechat(const unsigned char *chunk, size_t n) {
    for (size_t i = 0; i + 67 < n; ++i) {
        if (chunk[i] != 'x' || chunk[i + 1] != '\'') continue;
        size_t j = i + 2;
        while (j < n && j < i + 2 + 192 && isxdigit(chunk[j])) j++;
        if (j < n && chunk[j] == '\'' && (j - (i + 2)) >= 64) {
            fputs("HEX:", stdout);
            fwrite(chunk + i + 2, 1, 64, stdout);
            fputc('\n', stdout);
        }
    }
}

static void emit_qq(const unsigned char *chunk, size_t n) {
    size_t i = 0;
    while (i < n) {
        if (!is_printable(chunk[i])) {
            i++;
            continue;
        }
        size_t j = i;
        while (j < n && is_printable(chunk[j])) j++;
        if (j < n && chunk[j] == 0 && (j - i == 16 || j - i == 32)) {
            fputs("ASCII:", stdout);
            fwrite(chunk + i, 1, j - i, stdout);
            fputc('\n', stdout);
        }
        i = j + 1;
    }
}

int main(int argc, char **argv) {
    pid_t pid = 0;
    const char *kind = NULL;
    int timeout = 120;
    if (!parse_args(argc, argv, &pid, &kind, &timeout)) {
        fprintf(stderr, "usage: linux_memory_scan --pid PID --kind wechat|qq [--timeout S]\n");
        return 2;
    }

    char maps_path[64];
    if (snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid) >= (int)sizeof(maps_path)) {
        return 1;
    }
    FILE *maps = fopen(maps_path, "r");
    if (maps == NULL) {
        return errno == EACCES || errno == EPERM ? 3 : 1;
    }

    unsigned char *buf = malloc(CHUNK);
    if (buf == NULL) {
        fclose(maps);
        return 1;
    }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int attached = 0;
    char line[512];
    int wechat = !strcmp(kind, "wechat");
    while (fgets(line, sizeof(line), maps) != NULL) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - start.tv_sec) >= timeout) break;
        unsigned long start_addr = 0;
        unsigned long end_addr = 0;
        if (!is_candidate_region(line, &start_addr, &end_addr)) continue;
        unsigned long addr = start_addr;
        while (addr < end_addr) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            if ((now.tv_sec - start.tv_sec) >= timeout) break;
            size_t want = (size_t)(end_addr - addr);
            if (want > CHUNK) want = CHUNK;
            ssize_t got = read_remote(pid, addr, buf, want, &attached);
            if (got <= 0) break;
            if (wechat) emit_wechat(buf, (size_t)got);
            else emit_qq(buf, (size_t)got);
            if ((size_t)got < want) break;
            addr += (unsigned long)got;
        }
    }
    free(buf);
    fclose(maps);
    if (attached) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }
    return 0;
}
