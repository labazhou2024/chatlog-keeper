/*
 * Read-only Mach memory candidate scanner for chatlog-keeper.
 *
 * It does not decrypt databases and never writes to the target process.  The
 * Python caller validates every candidate against the user's local DB HMAC
 * before it can be cached.
 */
#include <ctype.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>

#define CHUNK (8u * 1024u * 1024u)
#define OVERLAP 256u

struct process_identity {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    uint64_t start_sec;
    uint64_t start_usec;
};

static int read_identity(pid_t pid, struct process_identity *out) {
    struct proc_bsdinfo info;
    memset(out, 0, sizeof(*out));
    memset(&info, 0, sizeof(info));
    int path_len = proc_pidpath(pid, out->path, sizeof(out->path));
    if (path_len <= 0 || (size_t)path_len >= sizeof(out->path)) return 0;
    int info_len = proc_pidinfo(
        pid, PROC_PIDTBSDINFO, 0, &info, (int)sizeof(info));
    if (info_len != (int)sizeof(info) || info.pbi_pid != (uint32_t)pid) return 0;
    out->start_sec = info.pbi_start_tvsec;
    out->start_usec = info.pbi_start_tvusec;
    return 1;
}

static int same_identity(
    const struct process_identity *left,
    const struct process_identity *right) {
    return left->start_sec == right->start_sec &&
           left->start_usec == right->start_usec &&
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
    char *end = NULL;
    unsigned long long parsed = strtoull(raw, &end, 10);
    if (!end || *end) return 0;
    *out = (uint64_t)parsed;
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

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "identity")) {
        char *identity_end = NULL;
        long identity_pid = strtol(argv[2], &identity_end, 10);
        struct process_identity identity;
        if (!identity_end || *identity_end || identity_pid <= 0 ||
            !snapshot_identity((pid_t)identity_pid, &identity)) {
            fprintf(stderr, "process_identity_unavailable\n");
            return 5;
        }
        emit_identity(&identity);
        return 0;
    }
    if (argc != 6 || (strcmp(argv[1], "qq") && strcmp(argv[1], "wechat"))) {
        fprintf(stderr,
                "usage: macos-memory-scan <qq|wechat> <pid> "
                "<start-sec> <start-usec> <path-hex>\n");
        return 2;
    }
    char *end = NULL;
    long parsed = strtol(argv[2], &end, 10);
    if (!end || *end || parsed <= 0) return 2;

    struct process_identity expected;
    memset(&expected, 0, sizeof(expected));
    if (!parse_u64(argv[3], &expected.start_sec) ||
        !parse_u64(argv[4], &expected.start_usec) ||
        expected.start_usec >= 1000000 ||
        !decode_path(argv[5], expected.path, sizeof(expected.path))) {
        fprintf(stderr, "invalid_process_identity\n");
        return 2;
    }
    pid_t pid = (pid_t)parsed;
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
    while (1) {
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
        }
        if (object_name != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object_name);
        mach_vm_address_t next = address + region_size;
        if (next <= address) break;
        address = next;
    }
    free(buf);
    mach_port_deallocate(mach_task_self(), task);
    if (!identity_matches(pid, &expected)) {
        fprintf(stderr, "process_identity_mismatch\n");
        return 5;
    }
    return 0;
}
