/*
 * Startup-time WeChat key candidate capture for macOS.
 *
 * This library is loaded only into chatlog-keeper's private, ad-hoc-signed
 * WeChat copy.  It interposes CommonCrypto's PBKDF2 boundary before any app
 * code runs, copies only the narrowly-shaped WeChat database password
 * candidate, and forwards it through a caller-created FIFO.  The Python caller
 * still HMAC-verifies every candidate against the user's local message DB
 * before it can be cached.
 */
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CommonCrypto/CommonCryptor.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CAPTURE_ENV "CHATLOG_KEEPER_WECHAT_KEY_FIFO"
#define CAPTURE_MAGIC "WXK1"
#define WECHAT_MASTER_KEY_BYTES 32u
#define WECHAT_SALT_BYTES 16u
#define WECHAT_KDF_ROUNDS 256000u

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

static pbkdf_fn resolve_original(void) {
    static pbkdf_fn original = NULL;
    if (original != NULL) return original;
    void *symbol = dlsym(RTLD_NEXT, "CCKeyDerivationPBKDF");
    if (symbol != NULL) memcpy(&original, &symbol, sizeof(original));
    return original;
}

static void emit_candidate(const char *password) {
    const char *path = getenv(CAPTURE_ENV);
    if (path == NULL || path[0] != '/') return;

    int fd = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return;

    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISFIFO(info.st_mode) ||
        info.st_uid != getuid() || (info.st_mode & 0777) != 0600) {
        close(fd);
        return;
    }

    unsigned char record[4 + WECHAT_MASTER_KEY_BYTES];
    memcpy(record, CAPTURE_MAGIC, 4);
    memcpy(record + 4, password, WECHAT_MASTER_KEY_BYTES);
    ssize_t written;
    do {
        written = write(fd, record, sizeof(record));
    } while (written < 0 && errno == EINTR);
    (void)written;
    close(fd);
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
    if (algorithm == kCCPBKDF2 && password != NULL && salt != NULL &&
        derived_key != NULL && password_len == WECHAT_MASTER_KEY_BYTES &&
        salt_len == WECHAT_SALT_BYTES && prf == kCCPRFHmacAlgSHA512 &&
        rounds == WECHAT_KDF_ROUNDS &&
        derived_key_len == WECHAT_MASTER_KEY_BYTES) {
        emit_candidate(password);
    }

    pbkdf_fn original = resolve_original();
    if (original == NULL) return kCCParamError;
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

#define DYLD_INTERPOSE(replacement, replacee)                                  \
    __attribute__((used)) static struct {                                      \
        const void *replacement;                                               \
        const void *replacee;                                                  \
    } _interpose_##replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&replacement,                                 \
        (const void *)(uintptr_t)&replacee                                     \
    }

DYLD_INTERPOSE(capture_pbkdf, CCKeyDerivationPBKDF);
