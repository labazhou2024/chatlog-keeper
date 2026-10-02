/*
 * Startup-time WeChat key candidate capture for official Linux clients.
 *
 * Loaded only into a child WeChat process that chatlog-keeper launched.
 * It observes sqlite3_key / sqlite3_key_v2 and OpenSSL PBKDF2 when those
 * symbols are dynamically resolved, copies only the narrow 32-byte WeChat
 * 4.x candidate shape, and forwards it through a caller-created FIFO.
 * The Python caller HMAC-verifies every candidate before it can be cached.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
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

typedef struct sqlite3 sqlite3;
typedef int (*sqlite3_key_fn)(sqlite3 *, const void *, int);
typedef int (*sqlite3_key_v2_fn)(sqlite3 *, const char *, const void *, int);
typedef int (*pbkdf_fn)(
    const char *,
    int,
    const unsigned char *,
    int,
    int,
    const void *,
    int,
    unsigned char *);

static pthread_once_t sqlite_once = PTHREAD_ONCE_INIT;
static pthread_once_t pbkdf_once = PTHREAD_ONCE_INIT;
static sqlite3_key_fn original_sqlite3_key = NULL;
static sqlite3_key_v2_fn original_sqlite3_key_v2 = NULL;
static pbkdf_fn original_pbkdf = NULL;

static void emit_candidate(const void *key, int nkey) {
    if (key == NULL || nkey != (int)WECHAT_MASTER_KEY_BYTES) return;
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
    memcpy(record + 4, key, WECHAT_MASTER_KEY_BYTES);
    ssize_t written;
    do {
        written = write(fd, record, sizeof(record));
    } while (written < 0 && errno == EINTR);
    (void)written;
    close(fd);
}

static void resolve_sqlite_once(void) {
    original_sqlite3_key = (sqlite3_key_fn)dlsym(RTLD_NEXT, "sqlite3_key");
    original_sqlite3_key_v2 = (sqlite3_key_v2_fn)dlsym(RTLD_NEXT, "sqlite3_key_v2");
}

static void resolve_pbkdf_once(void) {
    original_pbkdf = (pbkdf_fn)dlsym(RTLD_NEXT, "PKCS5_PBKDF2_HMAC");
}

int sqlite3_key(sqlite3 *db, const void *pKey, int nKey) {
    emit_candidate(pKey, nKey);
    if (pthread_once(&sqlite_once, resolve_sqlite_once) != 0 ||
        original_sqlite3_key == NULL) {
        return 1;
    }
    return original_sqlite3_key(db, pKey, nKey);
}

int sqlite3_key_v2(sqlite3 *db, const char *zDb, const void *pKey, int nKey) {
    emit_candidate(pKey, nKey);
    if (pthread_once(&sqlite_once, resolve_sqlite_once) != 0 ||
        original_sqlite3_key_v2 == NULL) {
        return 1;
    }
    return original_sqlite3_key_v2(db, zDb, pKey, nKey);
}

int PKCS5_PBKDF2_HMAC(
    const char *pass,
    int passlen,
    const unsigned char *salt,
    int saltlen,
    int iter,
    const void *digest,
    int keylen,
    unsigned char *out) {
    if (pass != NULL && salt != NULL && out != NULL &&
        passlen == (int)WECHAT_MASTER_KEY_BYTES &&
        saltlen == (int)WECHAT_SALT_BYTES &&
        (unsigned int)iter == WECHAT_KDF_ROUNDS &&
        keylen == (int)WECHAT_MASTER_KEY_BYTES) {
        emit_candidate(pass, passlen);
    }
    if (pthread_once(&pbkdf_once, resolve_pbkdf_once) != 0 ||
        original_pbkdf == NULL) {
        return 0;
    }
    return original_pbkdf(pass, passlen, salt, saltlen, iter, digest, keylen, out);
}
