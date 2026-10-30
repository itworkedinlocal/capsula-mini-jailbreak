/* Host helper: plaintext arrives only through stdin, never argv or a file. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#define explicit_bzero(p,n) SecureZeroMemory((p),(n))
#else
#include <sys/random.h>
#endif
#include "sha512-crypt.c"

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) return 2;
    unsigned char password[514], random[8];
#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) == -1) return 1;
#endif
    size_t length = fread(password, 1, sizeof(password) - 1, stdin);
    if (ferror(stdin) || !length || length > 512) return 1;
    for (size_t i = 0; i < length; i++)
        if (!password[i] || password[i] == '\r' || password[i] == '\n') return 1;
    password[length] = 0;
#ifdef _WIN32
    if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return 1;
#else
    size_t done = 0;
    while (done < sizeof(random)) {
        ssize_t n = getrandom(random + done, sizeof(random) - done, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 1;
        done += (size_t)n;
    }
#endif
    char salt[64] = "$6$rounds=100000$";
    size_t offset = strlen(salt);
    for (size_t i = 0; i < sizeof(random); i++)
        snprintf(salt + offset + 2 * i, 3, "%02x", random[i]);
    strcat(salt, "$");
    char output[128];
    char *hash = capsula_sha512_crypt((char *)password, salt, output);
    explicit_bzero(password, sizeof(password));
    if (!hash || strncmp(hash, salt, strlen(salt))) return 1;
    puts(hash);
    return 0;
}
