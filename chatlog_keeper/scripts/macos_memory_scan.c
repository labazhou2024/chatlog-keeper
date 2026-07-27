/*
 * Read-only Mach memory candidate scanner for chatlog-keeper.
 *
 * It does not decrypt databases and never writes to the target process.  The
 * Python caller validates every candidate against the user's local DB HMAC
 * before it can be cached.
 */
#include <ctype.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK (8u * 1024u * 1024u)
#define OVERLAP 256u

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
    if (argc != 3 || (strcmp(argv[1], "qq") && strcmp(argv[1], "wechat"))) {
        fprintf(stderr, "usage: macos-memory-scan <qq|wechat> <pid>\n");
        return 2;
    }
    char *end = NULL;
    long parsed = strtol(argv[2], &end, 10);
    if (!end || *end || parsed <= 0) return 2;

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), (pid_t)parsed, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid:%d\n", kr);
        return 3;
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
    return 0;
}
