/*
 * Startup-time WeChat key candidate capture for macOS.
 *
 * This library is loaded only into chatlog-keeper's private, ad-hoc-signed
 * WeChat copy. It interposes CommonCrypto's PBKDF2 boundary before app code runs,
 * copies only bounded 32-byte password candidates, and forwards them through
 * a caller-created FIFO. Key-free WXS1 status frames share that FIFO with WXK1
 * candidates, so load/resolve/match/write failures are visible without
 * exposing candidate bytes.
 */
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CommonCrypto/CommonCryptor.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CAPTURE_ENV "CHATLOG_KEEPER_WECHAT_KEY_FIFO"
#define CAPTURE_MAGIC "WXK1"
#define STATUS_MAGIC "WXS1"
#define STATUS_RECORD_BYTES 16u
#define WECHAT_MASTER_KEY_BYTES 32u
#define WECHAT_SALT_BYTES 16u
#define WECHAT_KDF_ROUNDS 256000u
#ifndef COMMON_CRYPTO_IMAGE_PATH
#define COMMON_CRYPTO_IMAGE_PATH "/usr/lib/system/libcommonCrypto.dylib"
#endif

typedef int (*pbkdf_fn)(
    CCPBKDFAlgorithm,
    const char *,
    size_t,
    const uint8_t *,
    size_t,
    CCPseudoRandomAlgorithm,
    uint,
    uint8_t *,
    size_t);

static int capture_pbkdf(
    CCPBKDFAlgorithm,
    const char *,
    size_t,
    const uint8_t *,
    size_t,
    CCPseudoRandomAlgorithm,
    uint,
    uint8_t *,
    size_t);

static pthread_once_t original_once = PTHREAD_ONCE_INIT;
static pbkdf_fn original_pbkdf = NULL;
static int emit_status(unsigned char event, uint32_t detail);
static volatile uint32_t candidate_count = 0;
static volatile uint32_t status_flags = 0;

enum capture_status {
    STATUS_CONSTRUCTOR = 1,
    STATUS_LOAD = 2,
    STATUS_RESOLVE_ATTEMPT = 3,
    STATUS_RESOLVE_OK = 4,
    STATUS_RESOLVE_FAILED = 5,
    STATUS_CALL = 6,
    STATUS_MATCH = 7,
    STATUS_WRITE_OK = 8,
    STATUS_WRITE_FAILED = 9,
};

static void emit_status_once(unsigned char event, uint32_t detail) {
    if (event == 0 || event > 31) return;
    uint32_t bit = (uint32_t)1u << (event - 1u);
    if ((__sync_fetch_and_or(&status_flags, bit) & bit) == 0)
        (void)emit_status(event, detail);
}

static void *common_crypto_symbol_address(void) {
    uint32_t image_count = _dyld_image_count();
    for (uint32_t index = 0; index < image_count; ++index) {
        const char *name = _dyld_get_image_name(index);
        if (name == NULL || strcmp(name, COMMON_CRYPTO_IMAGE_PATH) != 0)
            continue;
        const struct mach_header *header = _dyld_get_image_header(index);
        if (header == NULL) return NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        NSSymbol export = NSLookupSymbolInImage(
            header,
            "_CCKeyDerivationPBKDF",
            NSLOOKUPSYMBOLINIMAGE_OPTION_BIND |
                NSLOOKUPSYMBOLINIMAGE_OPTION_RETURN_ON_ERROR);
        void *symbol = export == NULL ? NULL : NSAddressOfSymbol(export);
#pragma clang diagnostic pop
        Dl_info owner = {0};
        if (symbol == NULL || symbol == (void *)(uintptr_t)&capture_pbkdf ||
            dladdr(symbol, &owner) == 0 || owner.dli_fname == NULL ||
            strcmp(owner.dli_fname, COMMON_CRYPTO_IMAGE_PATH) != 0) {
            return NULL;
        }
        return symbol;
    }
    return NULL;
}

static void resolve_original_once(void) {
    /*
     * In a DYLD_INSERT_LIBRARIES process, a broad lookup can resolve this
     * CommonCrypto export back to the replacement or to another interposer.
     * Resolve only through the concrete system image and require dladdr() to
     * prove that the final address belongs to that image.  Resolve once so
     * concurrent startup KDF calls cannot race the forwarding target.  There
     * is deliberately no RTLD_NEXT fallback.
     */
    void *symbol = common_crypto_symbol_address();
    if (symbol != NULL) {
        memcpy(&original_pbkdf, &symbol, sizeof(original_pbkdf));
        emit_status_once(STATUS_RESOLVE_OK, 1);
    } else {
        emit_status_once(STATUS_RESOLVE_FAILED, 1);
    }
}

static pbkdf_fn resolve_original(void) {
    emit_status_once(STATUS_RESOLVE_ATTEMPT, 0);
    if (pthread_once(&original_once, resolve_original_once) != 0 ||
        original_pbkdf == NULL) {
        _exit(127);
    }
    return original_pbkdf;
}

/* Details are fixed outcome classes or counters; no pointer/path/key bytes. */
static int emit_status(unsigned char event, uint32_t detail) {
    const char *path = getenv(CAPTURE_ENV);
    if (path == NULL || path[0] != '/') return 0;

    int fd = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;

    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISFIFO(info.st_mode) ||
        info.st_uid != getuid() || (info.st_mode & 0777) != 0600) {
        close(fd);
        return 0;
    }

    unsigned char record[STATUS_RECORD_BYTES] = {0};
    memcpy(record, STATUS_MAGIC, 4);
    record[4] = event;
    memcpy(record + 5, &detail, sizeof(detail));
    ssize_t written;
    do {
        written = write(fd, record, sizeof(record));
    } while (written < 0 && errno == EINTR);
    close(fd);
    return written == (ssize_t)sizeof(record);
}

static void emit_candidate(const char *password) {
    const char *path = getenv(CAPTURE_ENV);
    if (path == NULL || path[0] != '/') return;
    if (__sync_fetch_and_add(&candidate_count, 1) >= 1024u) return;

    int fd = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        emit_status_once(STATUS_WRITE_FAILED, 1);
        return;
    }

    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISFIFO(info.st_mode) ||
        info.st_uid != getuid() || (info.st_mode & 0777) != 0600) {
        close(fd);
        emit_status_once(STATUS_WRITE_FAILED, 2);
        return;
    }

    unsigned char record[4 + WECHAT_MASTER_KEY_BYTES];
    memcpy(record, CAPTURE_MAGIC, 4);
    memcpy(record + 4, password, WECHAT_MASTER_KEY_BYTES);
    ssize_t written;
    do {
        written = write(fd, record, sizeof(record));
    } while (written < 0 && errno == EINTR);
    close(fd);
    emit_status_once(
        written == (ssize_t)sizeof(record) ? STATUS_WRITE_OK : STATUS_WRITE_FAILED,
        written == (ssize_t)sizeof(record) ? 0u : 3u);
}

static int capture_pbkdf(
    CCPBKDFAlgorithm algorithm,
    const char *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    CCPseudoRandomAlgorithm prf,
    uint rounds,
    uint8_t *derived_key,
    size_t derived_key_len) {
    emit_status_once(STATUS_CALL, 0);
    int matches = algorithm == kCCPBKDF2 && password != NULL && salt != NULL &&
                  derived_key != NULL && password_len == WECHAT_MASTER_KEY_BYTES &&
                  salt_len == WECHAT_SALT_BYTES && prf == kCCPRFHmacAlgSHA512 &&
                  rounds == WECHAT_KDF_ROUNDS &&
                  derived_key_len == WECHAT_MASTER_KEY_BYTES;
    if (matches) {
        emit_status_once(STATUS_MATCH, 1u);
        emit_candidate(password);
    }

    pbkdf_fn original = resolve_original();
    return original(
        algorithm,
        password,
        password_len,
        salt,
        salt_len,
        prf,
        rounds,
        derived_key,
        derived_key_len);
}

__attribute__((constructor)) static void capture_constructor(void) {
    emit_status_once(STATUS_CONSTRUCTOR, 0);
    const char *path = getenv(CAPTURE_ENV);
    emit_status_once(STATUS_LOAD, path != NULL && path[0] == '/' ? 1u : 0u);
}

#define DYLD_INTERPOSE(replacement, replacee)                                  \
    __attribute__((used)) static struct {                                      \
        const void *replacement;                                               \
        const void *replacee;                                                  \
    } _interpose_##replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&replacement,                                 \
        (const void *)(uintptr_t)&replacee                                     \
    }

DYLD_INTERPOSE(capture_pbkdf, CCKeyDerivationPBKDF);
