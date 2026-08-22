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
#include <mach-o/dyld.h>
#include <pthread.h>
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

static void *common_crypto_symbol_address(void) {
    static const char image_suffix[] = "/usr/lib/system/libcommonCrypto.dylib";
    uint32_t image_count = _dyld_image_count();
    for (uint32_t index = 0; index < image_count; ++index) {
        const char *name = _dyld_get_image_name(index);
        if (name == NULL) continue;
        size_t name_len = strlen(name);
        size_t suffix_len = sizeof(image_suffix) - 1;
        if (name_len < suffix_len ||
            strcmp(name + name_len - suffix_len, image_suffix) != 0) {
            continue;
        }
        const struct mach_header *header = _dyld_get_image_header(index);
        if (header == NULL) return NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        NSSymbol symbol = NSLookupSymbolInImage(
            header,
            "_CCKeyDerivationPBKDF",
            NSLOOKUPSYMBOLINIMAGE_OPTION_BIND |
                NSLOOKUPSYMBOLINIMAGE_OPTION_RETURN_ON_ERROR);
        void *address = symbol == NULL ? NULL : NSAddressOfSymbol(symbol);
#pragma clang diagnostic pop
        return address;
    }
    return NULL;
}

static void resolve_original_once(void) {
    /*
     * In a DYLD_INSERT_LIBRARIES process on current macOS, RTLD_NEXT can still
     * resolve this interposed CommonCrypto export back to the replacement.  An
     * unchecked forward then recurses until the target crashes.  Prefer the
     * symbol exported by the concrete shared-cache image and retain Apple's
     * documented RTLD_NEXT lookup only as a guarded fallback.  Resolve once so
     * concurrent startup KDF calls cannot race the forwarding target.
     */
    void *symbol = common_crypto_symbol_address();
    if (symbol == NULL) {
        symbol = dlsym(RTLD_NEXT, "CCKeyDerivationPBKDF");
    }
    if (symbol != NULL) memcpy(&original_pbkdf, &symbol, sizeof(original_pbkdf));
    if (original_pbkdf == capture_pbkdf) original_pbkdf = NULL;
}

static pbkdf_fn resolve_original(void) {
    if (pthread_once(&original_once, resolve_original_once) != 0) return NULL;
    return original_pbkdf;
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
