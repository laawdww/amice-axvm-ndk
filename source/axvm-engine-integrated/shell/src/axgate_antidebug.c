#include "axgate_antidebug.h"
#include "axgate_aes.h"

#include <fcntl.h>
#include <errno.h>
#include <string.h>

/*
 * 关键字与路径 XOR 存放，避免 /proc 与 TracerPid 明文进入 .rodata。
 * key = 0x5A
 */
static void xor_dec(char *out, const uint8_t *enc, size_t n, uint8_t key)
{
    for (size_t i = 0; i < n; ++i) {
        out[i] = (char)(enc[i] ^ key);
    }
    out[n] = '\0';
}

static int maps_has_needle(const axgate_apis_t *api, const uint8_t *path_enc, size_t path_n,
                           const uint8_t *need_enc, size_t need_n)
{
    char path[24];
    char needle[16];
    xor_dec(path, path_enc, path_n, 0x5Au);
    xor_dec(needle, need_enc, need_n, 0x5Au);

    int fd = api->open(path, O_RDONLY | O_CLOEXEC);
    axgate_secure_wipe(path, sizeof(path));
    if (fd < 0) {
        axgate_secure_wipe(needle, sizeof(needle));
        return -1; /* unreadable */
    }

    char buf[512];
    int hit = 0;
    for (;;) {
        long n = api->read(fd, buf, sizeof(buf) - 1);
        if (n <= 0) {
            break;
        }
        buf[n] = '\0';
        if (strstr(buf, needle)) {
            hit = 1;
            break;
        }
    }
    api->close(fd);
    axgate_secure_wipe(needle, sizeof(needle));
    axgate_secure_wipe(buf, sizeof(buf));
    return hit;
}

axgate_status_t axgate_antidebug_check(const axgate_apis_t *api)
{
    /* "/proc/self/status" */
    static const uint8_t path_enc[] = {
        0x75,0x2a,0x28,0x35,0x39,0x75,0x29,0x3f,0x36,0x3c,0x75,0x29,0x2e,0x3b,0x2e,0x2f,0x29
    };
    /* "TracerPid:\t" */
    static const uint8_t key_enc[] = {
        0x0e,0x28,0x3b,0x39,0x3f,0x28,0x0a,0x33,0x3e,0x60,0x50
    };
    /* "/proc/self/maps" */
    static const uint8_t maps_enc[] = {
        0x75,0x2a,0x28,0x35,0x39,0x75,0x29,0x3f,0x36,0x3c,0x75,0x37,0x3b,0x2a,0x29
    };
    /* "frida" */
    static const uint8_t frida_enc[] = { 0x3c,0x28,0x33,0x3e,0x3b };
    /* "gadget" */
    static const uint8_t gadget_enc[] = { 0x3d,0x3b,0x3e,0x3d,0x3f,0x2e };

    if (!api || !api->open || !api->read || !api->close) {
        return AXGATE_ERR_DEBUG; /* fail-closed without IAT */
    }

    char path[24];
    char needle[16];
    xor_dec(path, path_enc, sizeof(path_enc), 0x5Au);
    xor_dec(needle, key_enc, sizeof(key_enc), 0x5Au);

    int fd = api->open(path, O_RDONLY | O_CLOEXEC);
    axgate_secure_wipe(path, sizeof(path));
    if (fd < 0) {
        axgate_secure_wipe(needle, sizeof(needle));
        return AXGATE_ERR_DEBUG; /* fail-closed */
    }

    char buf[512];
    long n = api->read(fd, buf, sizeof(buf) - 1);
    api->close(fd);
    if (n <= 0) {
        axgate_secure_wipe(needle, sizeof(needle));
        return AXGATE_ERR_DEBUG;
    }
    buf[n] = '\0';

    char *p = strstr(buf, needle);
    axgate_secure_wipe(needle, sizeof(needle));
    if (!p) {
        axgate_secure_wipe(buf, sizeof(buf));
        return AXGATE_ERR_DEBUG;
    }
    p += 11; /* strlen("TracerPid:\t") */
    while (*p == ' ' || *p == '\t') {
        ++p;
    }
    long pid = 0;
    while (*p >= '0' && *p <= '9') {
        pid = pid * 10 + (*p - '0');
        ++p;
    }
    axgate_secure_wipe(buf, sizeof(buf));
    if (pid != 0) {
        return AXGATE_ERR_DEBUG;
    }

    int fr = maps_has_needle(api, maps_enc, sizeof(maps_enc), frida_enc, sizeof(frida_enc));
    int gd = maps_has_needle(api, maps_enc, sizeof(maps_enc), gadget_enc, sizeof(gadget_enc));
    if (fr == 1 || gd == 1) {
        return AXGATE_ERR_DEBUG;
    }

    if (api->ptrace) {
        (void)api->ptrace(0 /* PTRACE_TRACEME */, 0, 0, 0);
    }
    return AXGATE_OK;
}
