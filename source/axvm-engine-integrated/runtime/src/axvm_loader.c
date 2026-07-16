#include "axvm_pack.h"
#include "axvm.h"
#include "axvm_bytecode.h"
#include "axvm_dynseed.h"
#include "axvm_got_crypt.h"
#include "axvm_crypt.h"
#include "axvm_stext.h"
#include "axvm_integrity.h"
#include "axvm_hmac.h"

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "axvm_log.h"

#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>

void axvm_crypt_set_key(const uint8_t *seed, size_t n);
void axvm_crypt_set_variant(uint8_t variant);
void axvm_crypt_decrypt(uint8_t *buf, size_t len, uint32_t func_id);

#define AXVM_MAX_MODULES 16
#define AXVM_MAX_FUNCS   128
#define AXVM_STUB_DISPATCH_OFF 64 /* v1 default; v2 pack uses stub_meta */

static int axvm_load_pack_from_file(const char *path, void *load_base);
static size_t readable_map_len(const void *addr, size_t want);

static size_t pack_rec_stride(const axvm_pack_hdr_t *hdr)
{
    if (hdr->version >= AXVM_PACK_VERSION_V2) {
        return AXVM_REC_SIZE_V2;
    }
    return AXVM_REC_SIZE_V1;
}

static const axvm_func_rec_t *pack_rec_at(const axvm_pack_hdr_t *hdr,
                                          const uint8_t *pack, uint32_t idx)
{
    return (const axvm_func_rec_t *)(pack + hdr->table_off + idx * pack_rec_stride(hdr));
}

static uint32_t pack_rec_stub_meta(const axvm_pack_hdr_t *hdr, const axvm_func_rec_t *r)
{
    if (hdr->version < AXVM_PACK_VERSION_V2) {
        return 0;
    }
    const uint8_t *p = (const uint8_t *)r;
    uint32_t meta;
    memcpy(&meta, p + 72, sizeof(meta));
    return meta;
}

static uint32_t rec_stub_dispatch_off(const axvm_pack_hdr_t *hdr, const axvm_func_rec_t *r)
{
    uint32_t meta = pack_rec_stub_meta(hdr, r);
    if (meta == 0) {
        return AXVM_STUB_DISPATCH_OFF;
    }
    uint32_t off = (meta >> 16) & 0xFFu;
    if (off < 16u || off > 240u) {
        return AXVM_STUB_DISPATCH_OFF;
    }
    return off;
}

typedef struct axvm_func_slot {
    uint32_t    func_id;
    uint32_t    entry_pc;
    uint8_t    *bytecode;
    size_t      bc_size;
    void       *load_base;
    axvm_ctx_t *ctx;
    char        name[48];
} axvm_func_slot_t;

typedef struct axvm_module {
    void            *load_base;
    const uint8_t   *pack;
    size_t           pack_size;
    void            *stub_exec;
    uint64_t         stub_map_vaddr;
    uint8_t         *pack_owned;
    axvm_func_slot_t funcs[AXVM_MAX_FUNCS];
    uint32_t         func_count;
    uint32_t         pack_flags;
    uint32_t         stext_unlocked;
    int              used;
} axvm_module_t;

static axvm_module_t g_modules[AXVM_MAX_MODULES];
static uint32_t      g_module_count;
static int           g_stext_unlock_total;
static int           g_stext_prepatch_total;
static int           g_dynsym_patched_total;
static pthread_mutex_t g_ctx_create_mu = PTHREAD_MUTEX_INITIALIZER;
static const uint8_t g_axpk_manifest_label[] = "AXPK-MANIFEST-V1";
static void        *g_registered_dispatch;

void axvm_register_dispatch(void *dispatch_fn)
{
    g_registered_dispatch = dispatch_fn;
}

#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
/* 在扫描派生 pack magic 之前，先从文件尾探测 AXDS（AXDS 位于 pack 之后）。 */
static void ensure_dynseed_probe_tail(const uint8_t *buf, size_t len)
{
    if (axvm_dynseed_master_is_real() || !buf || len < sizeof(axvm_dynseed_block_t)) {
        return;
    }
    size_t scan = len;
    if (scan > 65536u) {
        scan = 65536u;
    }
    size_t base = len - scan;
    axvm_dynseed_scan_tail_and_set(buf + base, scan);
}
#else
static void ensure_dynseed_probe_tail(const uint8_t *buf, size_t len)
{
    (void)buf;
    (void)len;
}
#endif

static int pack_magic_matches(uint32_t magic)
{
    if (magic == AXPK_MAGIC) {
        return 1;
    }
#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    if (axvm_dynseed_master_is_real() && magic == axvm_dynseed_pack_magic()) {
        return 1;
    }
#endif
    return 0;
}

static uint32_t pack_manifest_mac32(const uint8_t *p, size_t len)
{
    if (!p || len < sizeof(axvm_pack_hdr_t)) {
        return 0;
    }
    const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)p;
    size_t pack_len = (size_t)hdr->blob_off + (size_t)hdr->blob_size;
    if (pack_len < sizeof(axvm_pack_hdr_t) || pack_len > len) {
        return 0;
    }

    uint8_t key[AXVM_SHA256_DIGEST];
    uint8_t mac[AXVM_SHA256_DIGEST];
    uint8_t *canon = (uint8_t *)malloc(pack_len);
    if (!canon) {
        return 0;
    }
    memcpy(canon, p, pack_len);

    axvm_pack_hdr_t *wh = (axvm_pack_hdr_t *)canon;
    wh->checksum = 0;
    wh->file_off = 0; /* file_off 为注入阶段回填，不参与 MAC */
    wh->flags &= ~AXPK_FLAG_WIPED; /* prepatch 可能清除此位 */

    axvm_hmac_sha256(hdr->key_seed, sizeof(hdr->key_seed),
                     g_axpk_manifest_label, sizeof(g_axpk_manifest_label) - 1u, key);
    axvm_hmac_sha256(key, sizeof(key), canon, pack_len, mac);

    uint32_t out = ((uint32_t)mac[0]) |
                   ((uint32_t)mac[1] << 8) |
                   ((uint32_t)mac[2] << 16) |
                   ((uint32_t)mac[3] << 24);
    volatile uint8_t *wk = key;
    volatile uint8_t *wm = mac;
    volatile uint8_t *wc = canon;
    for (size_t i = 0; i < sizeof(key); ++i) {
        wk[i] = 0;
    }
    for (size_t i = 0; i < sizeof(mac); ++i) {
        wm[i] = 0;
    }
    for (size_t i = 0; i < pack_len; ++i) {
        wc[i] = 0;
    }
    free(canon);
    return out;
}

static int pack_valid(const uint8_t *p, size_t len)
{
    if (!p || len < sizeof(axvm_pack_hdr_t)) {
        return 0;
    }
    const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)p;
			if (!pack_magic_matches(hdr->magic)) {
				return 0;
			}
			if (hdr->version != AXVM_PACK_VERSION &&
				hdr->version != AXVM_PACK_VERSION_L1 &&
				hdr->version != AXVM_PACK_VERSION_V2) {
				return 0;
			}
			if (hdr->func_count == 0 || hdr->func_count > AXVM_MAX_FUNCS) {
				return 0;
			}
			if (hdr->table_off < sizeof(axvm_pack_hdr_t) || hdr->table_off >= len) {
				return 0;
			}
			if (hdr->blob_off >= len || hdr->blob_off < hdr->table_off) {
				return 0;
			}
			size_t table_bytes = (size_t)hdr->func_count * pack_rec_stride(hdr);
			if (hdr->table_off + table_bytes > hdr->blob_off) {
				return 0;
			}
			if (hdr->blob_off + hdr->blob_size > len) {
				return 0;
			}
			/*
			 * 模块 Z：manifest MAC（新增）。checksum==0 兼容历史包；
			 * 非零时必须通过 HMAC 校验，防止 pack table/blob 被离线篡改。
			 */
			if (hdr->checksum != 0) {
				uint32_t mac = pack_manifest_mac32(p, len);
				if (mac == 0 || mac != hdr->checksum) {
					/* decoy 故意错 MAC；真包失败由上层 PACK: FAIL 体现 */
					return 0;
				}
			}
			return 1;
		}

static int pack_export_name_trusted(const char *name)
{
    if (!name || name[0] == '\0') {
        return 0;
    }
    /* axpack decoy 块：_axdecoy_N，不得当作真 pack 加载 */
    if (name[0] == '_' &&
        strncmp(name, "_axdecoy_", 9) == 0) {
        return 0;
    }
    return 1;
}

static int pack_name_sane(const axvm_pack_hdr_t *hdr, const uint8_t *pack, size_t len)
{
    (void)len;
    if (hdr->func_count == 0) {
        return 0;
    }
    const axvm_func_rec_t *r =
        (const axvm_func_rec_t *)(pack + hdr->table_off);
    if (r[0].name[0] == '\0') {
        return 0;
    }
    if (!pack_export_name_trusted(r[0].name)) {
        return 0;
    }
    for (int i = 0; i < 39 && r[0].name[i] != '\0'; ++i) {
        char c = r[0].name[i];
        if ((c < 'a' || c > 'z') &&
            (c < 'A' || c > 'Z') &&
            (c < '0' || c > '9') &&
            c != '_') {
            return 0;
        }
    }
    return 1;
}

static int pack_trusted(const uint8_t *p, size_t len)
{
    if (!pack_valid(p, len)) {
        return 0;
    }
    const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)p;
    return pack_name_sane(hdr, p, len);
}

static int path_is_scan_target(const char *path)
{
    if (path && path[0]) {
        if (strstr(path, "libaxvm.so") != NULL) {
            return 0;
        }
        if (strstr(path, "/system/") != NULL ||
            strstr(path, "/apex/") != NULL ||
            strstr(path, "/vendor/") != NULL) {
            return 0;
        }
    }
    return 1;
}

static int pack_already_loaded(const uint8_t *pack)
{
    for (uint32_t m = 0; m < g_module_count; ++m) {
        if (g_modules[m].used && g_modules[m].pack == pack) {
            return 1;
        }
    }
    return 0;
}

static void *stub_target(axvm_module_t *mod, const axvm_func_rec_t *r);
static int write_jump(void *from, void *to);
static int write_stub_call(void *from, void *to);
static int write_bl_to(void *from, void *to);
static int elf_vaddr_to_file_off(const uint8_t *elf, size_t elf_len, uint64_t vaddr,
                                 uint64_t *out_off);
static int text_entry_is_patched(const void *entry);
static int patch_dynsym_exports(axvm_module_t *mod);
static int patch_victim_entries(axvm_module_t *mod);
#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
static int load_dynseed_from_file(const char *path);
#endif
static int mprotect_text_writable(void *page, size_t len);
static int mprotect_text_executable(void *page, size_t len);

static int patch_got_slot(uintptr_t got_addr, void *target)
{
    long page_sz = sysconf(_SC_PAGESIZE);
    if (page_sz <= 0) {
        return 0;
    }
    uintptr_t page = got_addr & ~((uintptr_t)page_sz - 1u);

    if (mprotect((void *)page, (size_t)page_sz, PROT_READ | PROT_WRITE) != 0) {
        return 0;
    }
    *(void **)(got_addr) = target;
    __builtin___clear_cache((char *)(uintptr_t)got_addr,
                            (char *)(uintptr_t)(got_addr + sizeof(void *)));
    if (mprotect((void *)page, (size_t)page_sz, PROT_READ | PROT_EXEC) != 0) {
        return 0;
    }
    return 1;
}

static void patch_module_gots(axvm_module_t *mod)
{
    if (!mod || !mod->load_base || !mod->pack || !mod->stub_exec) {
        return;
    }
    const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)mod->pack;
    void *dispatch = g_registered_dispatch;
    if (!dispatch) {
        dispatch = (void *)(uintptr_t)axvm_dispatch_ex;
        void *resolved = dlsym(RTLD_DEFAULT, "axvm_dispatch_ex");
        if (resolved) {
            dispatch = resolved;
        }
    }
    axvm_got_crypt_bind_dispatch(dispatch);

    for (uint32_t i = 0; i < hdr->func_count; ++i) {
        const axvm_func_rec_t *r = pack_rec_at(hdr, mod->pack, i);
        if (r->stub_off == 0) {
            continue;
        }
        void *stub = stub_target(mod, r);
        if (!stub) {
            continue;
        }
        uint32_t disp_off = rec_stub_dispatch_off(hdr, r);
        void *slot = (void *)((uintptr_t)stub + disp_off);
        long page_sz = sysconf(_SC_PAGESIZE);
        if (page_sz <= 0) {
            continue;
        }
		uintptr_t page = (uintptr_t)slot & ~((uintptr_t)page_sz - 1u);
		uintptr_t end_page = ((uintptr_t)slot + 16u + (uintptr_t)page_sz - 1u) &
							 ~((uintptr_t)page_sz - 1u);
		size_t prot_len = (size_t)(end_page - page);
		if (!mprotect_text_writable((void *)page, prot_len)) {
			AXVM_LOGE( "stub mprotect fail %s", r->name);
			continue;
		}
        int n;
        /* Prefer direct BL to dispatch: got_gate absolute MOVZ/BLR has been
         * implicated in single-SO stack overflows when PLT/GOT pages shift. */
        n = write_bl_to(slot, dispatch);
        if (n != 4) {
#if defined(AXVM_GOT_CRYPT) && AXVM_GOT_CRYPT
            if (axvm_got_crypt_enabled()) {
                n = write_stub_call(slot, (void *)(uintptr_t)axvm_got_gate);
            } else
#endif
            {
                n = write_stub_call(slot, dispatch);
            }
        } else {
            /* Keep remaining slot bytes as NOP so fall-through hits epilogue. */
            uint32_t nop = 0xD503201Fu;
            for (int pi = 4; pi < 16; pi += 4) {
                memcpy((uint8_t *)slot + pi, &nop, 4);
            }
            n = 16;
        }
        __builtin___clear_cache((char *)slot, (char *)slot + (size_t)n);
		(void)mprotect_text_executable((void *)page, prot_len);
        AXVM_LOGI("stub dispatch %s slot=%p -> %p (%d)",
                            r->name, slot, dispatch, n);
    }
}

#if defined(AXVM_STEXT) && AXVM_STEXT
static void stext_lazy_unlock_module(axvm_module_t *mod)
{
    if (!mod || !mod->load_base || !(mod->pack_flags & AXPK_FLAG_WIPED)) {
        return;
    }
    if (!axvm_dynseed_master_is_real()) {
        return;
    }
    const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)mod->pack;
    uint32_t n = hdr->func_count;
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        page = 4096;
    }

    for (uint32_t i = 0; i < n; ++i) {
        const axvm_func_rec_t *r = pack_rec_at(hdr, mod->pack, i);
        if (r->orig_vaddr == 0 || r->orig_size <= 4) {
            continue;
        }
        uint8_t *entry = (uint8_t *)mod->load_base + r->orig_vaddr;
        size_t plen = axvm_stext_patch_len(entry);
        if (plen >= (size_t)r->orig_size) {
            continue;
        }
        uint8_t *tail = entry + plen;
        size_t tail_len = (size_t)r->orig_size - plen;

        uintptr_t page_base = (uintptr_t)tail & ~((uintptr_t)page - 1u);
        uintptr_t page_end =
            ((uintptr_t)tail + tail_len + (uintptr_t)page - 1u) & ~((uintptr_t)page - 1u);
        size_t prot_len = page_end - page_base;
        if (prot_len == 0) {
            continue;
        }
        if (!mprotect_text_writable((void *)page_base, prot_len)) {
            continue;
        }
        if (axvm_stext_decrypt_runtime(tail, tail_len, r->func_id) > 0) {
            mod->stext_unlocked++;
            g_stext_unlock_total++;
        }
        (void)mprotect_text_executable((void *)page_base, prot_len);
        __builtin___clear_cache((char *)tail, (char *)tail + tail_len);
    }
}
#endif

void axvm_module_load(const uint8_t *pack, size_t len, void *load_base)
{
    axvm_module_load_ex(pack, len, load_base, NULL, 0, 0);
#if defined(AXVM_SO_INTEGRITY) && AXVM_SO_INTEGRITY
    axvm_integrity_register(pack, len, load_base);
#endif
}

void axvm_module_load_ex(const uint8_t *pack, size_t len, void *load_base,
                         void *stub_exec, uint64_t stub_map_vaddr, int pack_owned)
{
    if (!pack_trusted(pack, len) || g_module_count >= AXVM_MAX_MODULES) {
        return;
    }
    if (pack_already_loaded(pack)) {
        return;
    }

#if defined(__ANDROID__)
#include <android/log.h>
#endif

    const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)pack;
    axvm_crypt_set_key(hdr->key_seed, sizeof(hdr->key_seed));
#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    if (axvm_dynseed_master_is_real()) {
        uint8_t mp[32];
        axvm_dynseed_get_master_plain(mp);
        uint8_t sub[4];
        axvm_dynseed_master_subkey(mp, AXVM_DYNSEED_PURPOSE_CRYPT, sub, sizeof(sub));
        axvm_crypt_set_variant((uint8_t)(sub[0] & 3u));
#if defined(__ANDROID__)
        __android_log_print(ANDROID_LOG_ERROR, "AXVM",
                            "module crypt var=%u master=%02x%02x%02x%02x apk_bind=%d",
                            (unsigned)(sub[0] & 3u), mp[0], mp[1], mp[2], mp[3],
                            axvm_dynseed_apk_bind_required());
#endif
        volatile uint8_t *w = mp;
        for (size_t i = 0; i < sizeof(mp); ++i) {
            w[i] = 0;
        }
    }
#endif

    axvm_module_t *mod = &g_modules[g_module_count++];
    memset(mod, 0, sizeof(*mod));
    mod->load_base = load_base;
    mod->pack = pack;
    mod->pack_size = len;
    mod->pack_flags = hdr->flags;
    mod->stub_exec = stub_exec;
    mod->stub_map_vaddr = stub_map_vaddr;
    if (pack_owned) {
        mod->pack_owned = (uint8_t *)pack;
    }
    mod->used = 1;

    const uint8_t *blob = pack + hdr->blob_off;

    uint32_t n = hdr->func_count;
    if (n > AXVM_MAX_FUNCS) {
        n = AXVM_MAX_FUNCS;
    }

    for (uint32_t i = 0; i < n; ++i) {
        const axvm_func_rec_t *r = pack_rec_at(hdr, pack, i);
        if (r->bc_size == 0 || r->blob_off + r->bc_size > hdr->blob_size) {
            continue;
        }
        axvm_func_slot_t *sl = &mod->funcs[mod->func_count];
        memset(sl, 0, sizeof(*sl));
        sl->func_id = r->func_id;
        sl->entry_pc = r->entry_pc;
        sl->bc_size = r->bc_size;
        sl->load_base = mod->load_base;
        sl->bytecode = (uint8_t *)malloc(r->bc_size);
        if (!sl->bytecode) {
            continue;
        }
        memcpy(sl->bytecode, blob + r->blob_off, r->bc_size);
        if (hdr->flags & AXPK_FLAG_ENCRYPTED) {
            const axvm_bc_header_t *bh = (const axvm_bc_header_t *)sl->bytecode;
            size_t off = bh->code_off;
            if (off < sl->bc_size) {
                axvm_crypt_decrypt(sl->bytecode + off, sl->bc_size - off, r->func_id);
                axvm_bc_header_t *wh = (axvm_bc_header_t *)sl->bytecode;
                wh->checksum = axvm_bc_checksum(sl->bytecode, sl->bc_size);
            }
        }
        strncpy(sl->name, r->name, sizeof(sl->name) - 1);

        mod->func_count++;
    }

    if (mod->stub_exec) {
        patch_module_gots(mod);
    }

#if defined(AXVM_STEXT) && AXVM_STEXT
    /*
     * disk-ready packs leave wipe tails as plaintext NOPs (no stext crypt).
     * Decrypting them XOR-corrupts adjacent entries that share a page.
     * Only unlock when the first protected entry is not already a jump.
     */
    {
        const axvm_func_rec_t *r0 = pack_rec_at(hdr, pack, 0);
        int disk_ready_jumps = r0 && r0->orig_vaddr != 0 &&
            text_entry_is_patched((const void *)((uintptr_t)load_base +
                                                 (uintptr_t)r0->orig_vaddr));
        if (!disk_ready_jumps) {
            stext_lazy_unlock_module(mod);
        }
    }
#endif
}

static axvm_func_slot_t *find_func(uint32_t func_id)
{
    for (uint32_t m = 0; m < g_module_count; ++m) {
        axvm_module_t *mod = &g_modules[m];
        if (!mod->used) {
            continue;
        }
        for (uint32_t i = 0; i < mod->func_count; ++i) {
            if (mod->funcs[i].func_id == func_id) {
                return &mod->funcs[i];
            }
        }
    }
    return NULL;
}

__attribute__((visibility("default")))
uint64_t axvm_dispatch_ex(uint32_t func_id,
                          uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
    static int s_depth;
    if (s_depth > 64) {
        AXVM_LOGE("dispatch recurse depth=%d id=%u", s_depth, func_id);
        return 0;
    }
    s_depth++;
    uint64_t ret = 0;
    axvm_func_slot_t *fn = find_func(func_id);
    if (!fn || !fn->bytecode) {
        AXVM_LOGE("dispatch miss id=%u", func_id);
        goto out;
    }

    if (!fn->ctx) {
        pthread_mutex_lock(&g_ctx_create_mu);
        if (!fn->ctx) {
            if (!axvm_bc_validate(fn->bytecode, fn->bc_size)) {
                const axvm_bc_header_t *bh = (const axvm_bc_header_t *)fn->bytecode;
                AXVM_LOGE("bc invalid id=%u len=%zu ver=%x off=%u csz=%u chk=%x calc=%x",
                          func_id, fn->bc_size, bh->version, bh->code_off, bh->code_size,
                          bh->checksum, axvm_bc_checksum(fn->bytecode, fn->bc_size));
            }
            axvm_status_t cst = axvm_ctx_create(&fn->ctx, fn->bytecode, fn->bc_size);
            if (cst != AXVM_OK) {
                pthread_mutex_unlock(&g_ctx_create_mu);
                AXVM_LOGE("ctx create fail id=%u st=%d", func_id, (int)cst);
                goto out;
            }
            fn->ctx->module_load_base = (uint64_t)(uintptr_t)fn->load_base;
        }
        pthread_mutex_unlock(&g_ctx_create_mu);
    }

    uint64_t args[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
    axvm_status_t gst = axvm_bridge_enter(fn->ctx);
    if (gst != AXVM_OK) {
        AXVM_LOGE("bridge enter fail id=%u st=%d", func_id, (int)gst);
        goto out;
    }
    axvm_ctx_bind_args(fn->ctx, args, 8);
    ret = axvm_invoke(fn->ctx, fn->entry_pc);
out:
    s_depth--;
    return ret;
}

static int load_pack_from_mapped_segment(void *load_base,
                                         const uint8_t *candidate,
                                         size_t remain)
{
    if (!load_base || !pack_trusted(candidate, remain)) {
        return 0;
    }
    const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)candidate;
    size_t pack_bytes = (size_t)((hdr->blob_off + hdr->blob_size + 15u) & ~15u);
    if (pack_bytes == 0 || pack_bytes > remain) {
        return 0;
    }

    /*
     * Do NOT MAP_FIXED-replace the pack/stub PT_LOAD. Extending a private
     * mapping into the RX→RW hole can cover pages that PLT ADRP still uses
     * as GOT (e.g. 0x28000), so libc calls branch into stub noise and
     * stack-overflow. Patch stubs in place on the original file mapping.
     */

    void *stub_exec = NULL;
    uint64_t stub_map_vaddr = 0;
    if (remain > pack_bytes) {
        stub_exec = (void *)(candidate + pack_bytes);
        /*
         * stub_target() receives the pack mapping VA and adds pack_bytes to
         * recover the first stub VA.  The file-tail fallback uses the same
         * convention, so keep the PHDR path aligned with it.
         */
        stub_map_vaddr = (uint64_t)((uintptr_t)candidate - (uintptr_t)load_base);
    }

    axvm_module_load_ex(candidate, pack_bytes, load_base,
                        stub_exec, stub_map_vaddr, 0);
    if (g_module_count == 0) {
        return 0;
    }

    axvm_module_t *mod = &g_modules[g_module_count - 1];
    if (stub_exec) {
        patch_dynsym_exports(mod);
        patch_victim_entries(mod);
    }
    return 1;
}

static int scan_phdr_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    int *found = (int *)data;

    const Elf64_Phdr *phdr = info->dlpi_phdr;
    Elf64_Addr base = info->dlpi_addr;

    if (!phdr) {
        return 0;
    }
    if (info->dlpi_name && info->dlpi_name[0] && !path_is_scan_target(info->dlpi_name)) {
        return 0;
    }
#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
	if (info->dlpi_name && info->dlpi_name[0]) {
		load_dynseed_from_file(info->dlpi_name);
	}
#endif

	for (int i = 0; i < info->dlpi_phnum; ++i) {
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }
        if ((phdr[i].p_flags & PF_X) == 0) {
            continue;
        }
        if (phdr[i].p_filesz < sizeof(axvm_pack_hdr_t)) {
            continue;
        }

        const uint8_t *seg = (const uint8_t *)(uintptr_t)(base + phdr[i].p_vaddr);
        size_t seg_len = (size_t)phdr[i].p_filesz;
        size_t mapped_len = readable_map_len(seg, seg_len);
        if (mapped_len < sizeof(axvm_pack_hdr_t)) {
            continue;
        }
        seg_len = mapped_len;

        const uint8_t *best = NULL;
        size_t best_total = 0;
		for (size_t off = 0; off + sizeof(axvm_pack_hdr_t) <= seg_len; off += 4) {
			const uint8_t *candidate = seg + off;
			size_t remain = seg_len - off;
			if (!pack_magic_matches(*(const uint32_t *)candidate)) {
				continue;
			}
			if (pack_trusted(candidate, remain)) {
				const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)candidate;
				best_total = (size_t)((hdr->blob_off + hdr->blob_size + 15u) & ~15u);
                best = candidate;
            }
        }
        if (best) {
            (void)best_total;
            load_pack_from_mapped_segment((void *)(uintptr_t)base, best,
                                          (size_t)(seg + seg_len - best));
            AXVM_LOGI( "phdr pack %s@%p base=%p",
                                info->dlpi_name ? info->dlpi_name : "?",
                                best, (void *)(uintptr_t)base);
            if (found) {
                *found = 1;
            }
        }
    }
    if ((!found || !*found) && info->dlpi_name && info->dlpi_name[0]) {
        if (axvm_load_pack_from_file(info->dlpi_name, (void *)(uintptr_t)base)) {
            AXVM_LOGI( "phdr file pack %s base=%p",
                                info->dlpi_name, (void *)(uintptr_t)base);
            if (found) {
                *found = 1;
            }
        }
    }
    return 0;
}

static size_t readable_map_len(const void *addr, size_t want)
{
    if (!addr || want == 0) {
        return 0;
    }
	FILE *fp = fopen("/proc/self/maps", "r");
	if (!fp) {
		return 0;
	}
    uintptr_t a = (uintptr_t)addr;
    char line[512];
    size_t out = 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0, end = 0;
        char perm[8] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perm) < 3) {
            continue;
        }
        if (perm[0] != 'r') {
            continue;
        }
        if ((uintptr_t)start <= a && a < (uintptr_t)end) {
            size_t avail = (size_t)((uintptr_t)end - a);
            out = avail < want ? avail : want;
            break;
        }
    }
    fclose(fp);
    return out;
}

static void scan_maps_fallback(int *found)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0, end = 0, off = 0;
        char perm[8] = {0};
        char path[256] = {0};

        if (sscanf(line, "%lx-%lx %4s %lx %*s %*s %255[^\n]",
                   &start, &end, perm, &off, path) < 4) {
            continue;
        }
        if (perm[2] != 'x') {
            continue;
        }
        if (!path_is_scan_target(path)) {
            continue;
        }
#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
        if (path[0]) {
            load_dynseed_from_file(path);
        }
#endif

        size_t map_len = (size_t)(end - start);
        if (map_len < sizeof(axvm_pack_hdr_t)) {
            continue;
        }

        const uint8_t *base = (const uint8_t *)(uintptr_t)start;
        void *load_base = (void *)(uintptr_t)(start - off);

        const uint8_t *best = NULL;
        size_t best_total = 0;
		for (size_t i = 0; i + sizeof(axvm_pack_hdr_t) <= map_len; i += 4) {
			const uint8_t *candidate = base + i;
			size_t remain = map_len - i;
			if (!pack_magic_matches(*(const uint32_t *)candidate)) {
				continue;
			}
			if (pack_trusted(candidate, remain)) {
				const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)candidate;
				best_total = (size_t)((hdr->blob_off + hdr->blob_size + 15u) & ~15u);
                best = candidate;
            }
        }
        if (best) {
            (void)best_total;
            load_pack_from_mapped_segment(load_base, best,
                                          (size_t)(base + map_len - best));
            AXVM_LOGI( "maps pack %s@%p base=%p",
                                path, best, load_base);
            if (found) {
                *found = 1;
            }
        }
    }
    fclose(fp);
}

void axvm_scan_proc_maps(void)
{
    /* 已通过 register_symbol / module_load 登记时，勿再全进程 4 字节步进扫描（主线程可卡 10s+） */
    if (g_module_count > 0) {
        AXVM_LOGI("scan skip modules=%u (already loaded)", g_module_count);
        return;
    }
    int found = 0;
    dl_iterate_phdr(scan_phdr_cb, &found);
    if (!found) {
        scan_maps_fallback(&found);
    }
    AXVM_LOGI( "scan done found=%d modules=%u",
                        found, g_module_count);
}

static uint64_t axvm_pack_map_vaddr(void *load_base)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)load_base;
    if (eh->e_ident[EI_MAG0] != ELFMAG0 || eh->e_phoff == 0) {
        return 0;
    }
    const Elf64_Phdr *ph = (const Elf64_Phdr *)((const uint8_t *)load_base + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD || (ph[i].p_flags & PF_X) == 0) {
            continue;
        }
        uint64_t end = ph[i].p_vaddr + ph[i].p_filesz;
        return (end + 15u) & ~15u;
    }
	return 0;
}

static uint64_t axvm_file_off_to_vaddr(int fd, uint64_t file_off)
{
	Elf64_Ehdr eh;
	if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh)) {
		return 0;
	}
	if (eh.e_ident[EI_MAG0] != ELFMAG0 || eh.e_phoff == 0 ||
		eh.e_phnum == 0 || eh.e_phentsize != sizeof(Elf64_Phdr)) {
		return 0;
	}
	size_t ph_bytes = (size_t)eh.e_phnum * sizeof(Elf64_Phdr);
	Elf64_Phdr *ph = (Elf64_Phdr *)malloc(ph_bytes);
	if (!ph) {
		return 0;
	}
	uint64_t out = 0;
	if (pread(fd, ph, ph_bytes, (off_t)eh.e_phoff) == (ssize_t)ph_bytes) {
		for (int i = 0; i < eh.e_phnum; ++i) {
			if (ph[i].p_type != PT_LOAD || ph[i].p_filesz == 0) {
				continue;
			}
			uint64_t start = ph[i].p_offset;
			uint64_t end = ph[i].p_offset + ph[i].p_filesz;
			if (file_off >= start && file_off < end) {
				out = ph[i].p_vaddr + (file_off - start);
				break;
			}
		}
	}
	free(ph);
	return out;
}

/* VMPacker 风格 3 指令 token 跳板（12 字节） */
static int write_token_trampoline(void *from, uint64_t func_vaddr, void *entry, uint32_t func_id)
{
    uint32_t token = func_id & 0xFFFu;
    uint32_t lo16 = token & 0xFFFFu;
    uint32_t hi16 = (token >> 16) & 0xFFFFu;
    uint32_t ins[3];
    ins[0] = 0x52800010u | (lo16 << 5);
    ins[1] = 0x72A00010u | (hi16 << 5);
    int64_t off = (int64_t)(uintptr_t)entry - (int64_t)(func_vaddr + 8u);
    if (off % 4 != 0 || off < -134217728 || off > 134217724) {
        return 0;
    }
    uint32_t imm26 = (uint32_t)(off / 4) & 0x03FFFFFFu;
    ins[2] = 0x14000000u | imm26;
    memcpy(from, ins, sizeof(ins));
    return 12;
}

/* Prefer RWX while patching: .text pages often share the PLT; a RW-only
 * window faults on the next PLT call (SEGV_ACCERR / execute non-exec). */
static int mprotect_text_writable(void *page, size_t len)
{
    if (mprotect(page, len, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        return 1;
    }
    return mprotect(page, len, PROT_READ | PROT_WRITE) == 0;
}

static int mprotect_text_executable(void *page, size_t len)
{
    return mprotect(page, len, PROT_READ | PROT_EXEC) == 0;
}

static int write_jump(void *from, void *to)
{
    int64_t off = (int64_t)(uintptr_t)to - (int64_t)(uintptr_t)from;
    if (off % 4 == 0 && off >= -134217728 && off <= 134217724) {
        uint32_t imm26 = (uint32_t)(off / 4) & 0x03FFFFFFu;
        uint32_t ins = 0x14000000u | imm26;
        memcpy(from, &ins, 4);
        return 4;
    }

    uint64_t addr = (uint64_t)(uintptr_t)to;
    uint32_t ins[4];
    ins[0] = 0xD2800000u | (((uint32_t)(addr & 0xFFFFu)) << 5) | 16u;
    ins[1] = 0xF2A00000u | (((uint32_t)((addr >> 16) & 0xFFFFu)) << 5) | 16u | (1u << 21);
    ins[2] = 0xF2C00000u | (((uint32_t)((addr >> 32) & 0xFFFFu)) << 5) | 16u | (2u << 21);
    ins[3] = 0xD63F0200u; /* BLR x16 */
    memcpy(from, ins, 16);
    return 16;
}

/* Stub epilogue must run — never patch a bare B into the dispatch slot. */
static int write_stub_call(void *from, void *to)
{
    uint64_t addr = (uint64_t)(uintptr_t)to;
    uint32_t ins[4];
    ins[0] = 0xD2800000u | (((uint32_t)(addr & 0xFFFFu)) << 5) | 16u;
    ins[1] = 0xF2A00000u | (((uint32_t)((addr >> 16) & 0xFFFFu)) << 5) | 16u | (1u << 21);
    ins[2] = 0xF2C00000u | (((uint32_t)((addr >> 32) & 0xFFFFu)) << 5) | 16u | (2u << 21);
    ins[3] = 0xD63F0200u; /* BLR x16 */
    memcpy(from, ins, 16);
    return 16;
}

/* 模块 P：BL 到 got_gate，避免在 stub 可执行区嵌入明文 dispatch 指针 */
static int write_bl_to(void *from, void *to)
{
    int64_t off = (int64_t)(uintptr_t)to - (int64_t)(uintptr_t)from;
    if (off % 4 != 0 || off < -67108864 || off > 67108860) {
        return 0;
    }
    uint32_t imm26 = (uint32_t)(off / 4) & 0x03FFFFFFu;
    uint32_t ins = 0x94000000u | imm26;
    memcpy(from, &ins, 4);
    return 4;
}

static int elf_vaddr_to_file_off(const uint8_t *elf, size_t elf_len, uint64_t vaddr,
                                 uint64_t *out_off)
{
    if (!elf || elf_len < sizeof(Elf64_Ehdr) || !out_off) {
        return 0;
    }
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)elf;
    if (eh->e_ident[EI_MAG0] != ELFMAG0 || eh->e_phoff == 0 ||
        eh->e_phnum == 0 || eh->e_phentsize < sizeof(Elf64_Phdr)) {
        return 0;
    }
    if ((size_t)eh->e_phoff + (size_t)eh->e_phnum * eh->e_phentsize > elf_len) {
        return 0;
    }
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(elf + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD || ph[i].p_filesz == 0) {
            continue;
        }
        if (vaddr < ph[i].p_vaddr || vaddr >= ph[i].p_vaddr + ph[i].p_filesz) {
            continue;
        }
        uint64_t delta = vaddr - ph[i].p_vaddr;
        if (ph[i].p_offset + delta > elf_len) {
            return 0;
        }
        *out_off = ph[i].p_offset + delta;
        return 1;
    }
    return 0;
}

static int text_entry_is_patched(const void *entry)
{
    if (!entry) {
        return 0;
    }
    uint32_t w0;
    memcpy(&w0, entry, sizeof(w0));
    if ((w0 & 0xFC000000u) == 0x14000000u) {
        return 1;
    }
    if (w0 == 0x58000050u) {
        uint32_t w1;
        memcpy(&w1, (const uint8_t *)entry + 4, sizeof(w1));
        if (w1 == 0xD61F0200u) {
            return 1;
        }
    }
    return 0;
}

static int patch_text_jump(void *load_base, uint64_t from_vaddr, void *to)
{
    void *from = (void *)((uintptr_t)load_base + (uintptr_t)from_vaddr);
    long page_sz = sysconf(_SC_PAGESIZE);
    if (page_sz <= 0) {
        return 0;
    }
        uintptr_t page = (uintptr_t)from & ~((uintptr_t)page_sz - 1u);
        if (!mprotect_text_writable((void *)page, (size_t)page_sz)) {
            AXVM_LOGE( "text mprotect fail vaddr=0x%llx",
                            (unsigned long long)from_vaddr);
            return 0;
        }

    int n = write_jump(from, to);
    __builtin___clear_cache((char *)from, (char *)from + (size_t)n);
    (void)mprotect_text_executable((void *)page, (size_t)page_sz);
    AXVM_LOGI( "text patch vaddr=0x%llx -> %p (%d bytes)",
                        (unsigned long long)from_vaddr, to, n);
    return n > 0;
}

static uint32_t rec_orig_size(const axvm_pack_hdr_t *hdr, const axvm_func_rec_t *r)
{
    if (hdr->version >= AXVM_PACK_VERSION) {
        return r->orig_size;
    }
    return 16;
}

static void *map_stub_region(void *load_base, uint64_t map_vaddr, size_t map_sz)
{
    void *hint = (void *)((uintptr_t)load_base + (uintptr_t)map_vaddr);
    void *stub = mmap(hint, map_sz, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stub != MAP_FAILED && stub == hint) {
        return stub;
    }
    if (stub != MAP_FAILED) {
        munmap(stub, map_sz);
    }
    stub = mmap(hint, map_sz, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (stub != MAP_FAILED) {
        return stub;
    }
    stub = mmap(NULL, map_sz, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return stub;
}

static int mprotect_rw(void *addr, size_t len)
{
    long page_sz = sysconf(_SC_PAGESIZE);
    if (page_sz <= 0 || len == 0) {
        return 0;
    }
    uintptr_t start = (uintptr_t)addr & ~((uintptr_t)page_sz - 1u);
    uintptr_t end = ((uintptr_t)addr + len + (uintptr_t)page_sz - 1u) &
                    ~((uintptr_t)page_sz - 1u);
    return mprotect((void *)start, (size_t)(end - start), PROT_READ | PROT_WRITE) == 0;
}

static int mprotect_ro(void *addr, size_t len)
{
    long page_sz = sysconf(_SC_PAGESIZE);
    if (page_sz <= 0 || len == 0) {
        return 0;
    }
    uintptr_t start = (uintptr_t)addr & ~((uintptr_t)page_sz - 1u);
    uintptr_t end = ((uintptr_t)addr + len + (uintptr_t)page_sz - 1u) &
                    ~((uintptr_t)page_sz - 1u);
    return mprotect((void *)start, (size_t)(end - start), PROT_READ) == 0;
}

static void *stub_target(axvm_module_t *mod, const axvm_func_rec_t *r)
{
    if (!mod->stub_exec || r->stub_off == 0 || !mod->pack) {
        return NULL;
    }
    const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)mod->pack;
    size_t pack_bytes = (size_t)((hdr->blob_off + hdr->blob_size + 15u) & ~15u);
    uint64_t stub_base_va = mod->stub_map_vaddr + (uint64_t)pack_bytes;
    if (r->stub_off < stub_base_va) {
        return NULL;
    }
    return (void *)((uintptr_t)mod->stub_exec +
                    (uintptr_t)(r->stub_off - stub_base_va));
}

static int patch_dynsym_exports(axvm_module_t *mod)
{
#if defined(__ANDROID__)
    (void)mod;
    return 0;
#else
    if (!mod || !mod->load_base || !mod->pack) {
        return 0;
    }
    const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)mod->pack;

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)mod->load_base;
    if (eh->e_ident[EI_MAG0] != ELFMAG0 || eh->e_phoff == 0) {
        return 0;
    }
    const Elf64_Phdr *ph = (const Elf64_Phdr *)((const uint8_t *)mod->load_base + eh->e_phoff);
    const Elf64_Dyn *dyn = NULL;
    size_t dyn_cnt = 0;

    for (int i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_DYNAMIC) {
            continue;
        }
        dyn = (const Elf64_Dyn *)((const uint8_t *)mod->load_base + ph[i].p_vaddr);
        if (ph[i].p_memsz >= sizeof(Elf64_Dyn)) {
            dyn_cnt = (size_t)(ph[i].p_memsz / sizeof(Elf64_Dyn));
        }
        break;
    }
    if (!dyn) {
        return 0;
    }

    Elf64_Addr symtab = 0;
    Elf64_Addr strtab = 0;
    Elf64_Addr hash = 0;
    size_t syment = sizeof(Elf64_Sym);
    size_t nchain = 0;

    for (size_t i = 0; i < dyn_cnt && dyn[i].d_tag != DT_NULL; ++i) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:
            symtab = dyn[i].d_un.d_ptr;
            break;
        case DT_STRTAB:
            strtab = dyn[i].d_un.d_ptr;
            break;
        case DT_HASH:
            hash = dyn[i].d_un.d_ptr;
            break;
        case DT_SYMENT:
            syment = (size_t)dyn[i].d_un.d_val;
            break;
        default:
            break;
        }
    }
    if (!symtab || !strtab || syment < sizeof(Elf64_Sym)) {
        return 0;
    }
    if (hash) {
        const uint32_t *hb = (const uint32_t *)((uintptr_t)mod->load_base + hash);
        nchain = hb[1];
    }
    if (nchain == 0 || nchain > 65536u) {
        nchain = 4096;
    }

    Elf64_Sym *sym = (Elf64_Sym *)((uintptr_t)mod->load_base + symtab);
    const char *str = (const char *)((uintptr_t)mod->load_base + strtab);
    int patched = 0;

    for (uint32_t fi = 0; fi < hdr->func_count; ++fi) {
        const axvm_func_rec_t *r = pack_rec_at(hdr, mod->pack, fi);
        if (r->stub_off == 0 || r->name[0] == '\0') {
            continue;
        }
        for (size_t si = 0; si < nchain; ++si) {
            Elf64_Sym *s = (Elf64_Sym *)((uint8_t *)sym + si * syment);
            if (ELF64_ST_TYPE(s->st_info) != STT_FUNC || s->st_name == 0) {
                continue;
            }
            if (strcmp(str + s->st_name, r->name) != 0) {
                continue;
            }
            if (s->st_value == (Elf64_Addr)r->stub_off) {
                patched++;
                g_dynsym_patched_total++;
                break;
            }
            void *tgt = stub_target(mod, r);
            if (!tgt) {
                break;
            }
            Elf64_Addr new_val =
                (Elf64_Addr)((uintptr_t)tgt - (uintptr_t)mod->load_base);
            if (!mprotect_rw(s, sizeof(Elf64_Sym))) {
                AXVM_LOGE( "dynsym mprotect fail %s",
                                    r->name);
                break;
            }
            s->st_value = new_val;
            s->st_size = 96;
#if !defined(__ANDROID__)
            if (s->st_name != 0) {
                size_t noff = (size_t)s->st_name;
                char *str_mut = (char *)((uintptr_t)mod->load_base + strtab);
                if (mprotect_rw(str_mut + noff, 64)) {
                    for (size_t sl = 0; sl < 64u && str_mut[noff + sl] != '\0'; ++sl) {
                        str_mut[noff + sl] = 0;
                    }
                    mprotect_ro(str_mut + noff, 64);
                }
                s->st_name = 0;
                s->st_info = ELF64_ST_INFO(STB_LOCAL, STT_FUNC);
            }
#endif
            mprotect_ro(s, sizeof(Elf64_Sym));
            AXVM_LOGI( "dynsym %s -> %p (st_value=0x%llx)",
                                r->name, tgt, (unsigned long long)new_val);
            patched++;
            g_dynsym_patched_total++;
            break;
        }
    }
    return patched;
#endif
}

static int patch_victim_entries(axvm_module_t *mod)
{
    if (!mod || !mod->load_base || !mod->pack || !mod->stub_exec) {
        return 0;
    }
    const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)mod->pack;

    uint32_t n = hdr->func_count;
    if (n == 0) {
        return 0;
    }

    uint64_t *vaddrs = (uint64_t *)calloc(n, sizeof(uint64_t));
    uint32_t *order = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!vaddrs || !order) {
        free(vaddrs);
        free(order);
        return 0;
    }
    for (uint32_t i = 0; i < n; ++i) {
        vaddrs[i] = pack_rec_at(hdr, mod->pack, i)->orig_vaddr;
        order[i] = i;
    }
    for (uint32_t i = 0; i + 1 < n; ++i) {
        for (uint32_t j = i + 1; j < n; ++j) {
            if (vaddrs[i] > vaddrs[j]) {
                uint64_t tv = vaddrs[i];
                vaddrs[i] = vaddrs[j];
                vaddrs[j] = tv;
                uint32_t ti = order[i];
                order[i] = order[j];
                order[j] = ti;
            }
        }
    }

    int patched = 0;
    void *token_entry = NULL;
    if (hdr->flags & AXPK_FLAG_TOKEN) {
        token_entry = dlsym(RTLD_DEFAULT, "axvm_entry_token");
        if (!token_entry) {
            AXVM_LOGW( "token entry: axvm_entry_token missing");
        }
    }
    for (uint32_t k = 0; k < n; ++k) {
        const axvm_func_rec_t *r = pack_rec_at(hdr, mod->pack, order[k]);
        if (r->stub_off == 0 || r->orig_vaddr == 0) {
            continue;
        }
        size_t room = 16;
        uint32_t orig_sz = rec_orig_size(hdr, r);
        if (orig_sz > 0 && orig_sz < room) {
            room = orig_sz;
        }
        if (k + 1 < n) {
            uint64_t gap = vaddrs[k + 1] - r->orig_vaddr;
            if (gap > 0 && gap < room) {
                room = (size_t)gap;
            }
        }
        if (room < 4) {
            continue;
        }
        void *from = (void *)((uintptr_t)mod->load_base + (uintptr_t)r->orig_vaddr);
        void *to = stub_target(mod, r);
        if (!to && !(hdr->flags & AXPK_FLAG_TOKEN)) {
            continue;
        }
        if (text_entry_is_patched(from)) {
            patched++;
            continue;
        }
        long page_sz = sysconf(_SC_PAGESIZE);
        if (page_sz <= 0) {
            continue;
        }
        uintptr_t page = (uintptr_t)from & ~((uintptr_t)page_sz - 1u);
        if (!mprotect_text_writable((void *)page, (size_t)page_sz)) {
            AXVM_LOGW(
                                "text mprotect skip %s (use dynsym redirect)",
                                r->name);
            continue;
        }

        int nwrite = 0;
        if ((hdr->flags & AXPK_FLAG_TOKEN) && token_entry && room >= 12) {
            nwrite = write_token_trampoline(from, (uint64_t)(uintptr_t)from, token_entry,
                                            r->func_id);
            if (nwrite > 0) {
                __builtin___clear_cache((char *)from, (char *)from + (size_t)nwrite);
            }
        }
        if (nwrite <= 0) {
            if (!to) {
                (void)mprotect_text_executable((void *)page, (size_t)page_sz);
                continue;
            }
            int64_t off = (int64_t)(uintptr_t)to - (int64_t)(uintptr_t)from;
            nwrite = 16;
            if (off % 4 == 0 && off >= -134217728 && off <= 134217724 && room >= 4) {
                uint32_t imm26 = (uint32_t)(off / 4) & 0x03FFFFFFu;
                uint32_t ins = 0x14000000u | imm26;
                memcpy(from, &ins, 4);
                nwrite = 4;
                __builtin___clear_cache((char *)from, (char *)from + 4);
            } else if (room >= 16) {
                nwrite = write_jump(from, to);
                __builtin___clear_cache((char *)from, (char *)from + (size_t)nwrite);
            } else {
                (void)mprotect_text_executable((void *)page, (size_t)page_sz);
                continue;
            }
        }
        (void)mprotect_text_executable((void *)page, (size_t)page_sz);
        AXVM_LOGI( "text patch %s vaddr=0x%llx -> %s (%d)",
                            r->name, (unsigned long long)r->orig_vaddr,
                            (hdr->flags & AXPK_FLAG_TOKEN) && token_entry ? "token" : "stub",
                            nwrite);
        patched++;
    }

    free(vaddrs);
    free(order);
    return patched;
}

static uint64_t axvm_find_pack_file_off(int fd, const struct stat *st)
{
    if (!st || st->st_size < (off_t)sizeof(axvm_pack_hdr_t)) {
        return 0;
    }

    size_t scan = (size_t)st->st_size;
    if (scan > 65536u) {
        scan = 65536u;
    }
    uint8_t *buf = (uint8_t *)malloc(scan);
    if (!buf) {
        return 0;
    }
    off_t base = (off_t)st->st_size - (off_t)scan;
    if (base < 0) {
        base = 0;
        scan = (size_t)st->st_size;
    }
    ssize_t n = pread(fd, buf, scan, base);
    if (n < (ssize_t)sizeof(axvm_pack_hdr_t)) {
        free(buf);
        return 0;
    }
    ensure_dynseed_probe_tail(buf, (size_t)n);
    uint64_t found = 0;
    for (ssize_t i = 0; i <= n - (ssize_t)sizeof(axvm_pack_hdr_t); i += 4) {
        if (!pack_magic_matches(*(const uint32_t *)(buf + i))) {
            continue;
        }
        size_t remain = (size_t)(n - i);
        if (!pack_trusted(buf + i, remain)) {
            continue;
        }
        found = (uint64_t)base + (uint64_t)i;
    }
    free(buf);
    return found;
}

static int axvm_load_pack_from_file(const char *path, void *load_base)
{
    if (!path || !path[0] || !load_base) {
        return 0;
    }

	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return 0;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return 0;
    }

    uint64_t pack_off = axvm_find_pack_file_off(fd, &st);
	if (pack_off == 0) {
		AXVM_LOGE( "pack magic not found in %s size=%lld",
							path, (long long)st.st_size);
		close(fd);
		return 0;
	}
	uint64_t map_vaddr = axvm_file_off_to_vaddr(fd, pack_off);
	if (map_vaddr == 0) {
		map_vaddr = axvm_pack_map_vaddr(load_base);
	}
	if (map_vaddr == 0) {
		close(fd);
		return 0;
	}

	size_t tail_len = (size_t)((uint64_t)st.st_size - pack_off);
    if (tail_len < sizeof(axvm_pack_hdr_t)) {
        close(fd);
        return 0;
    }

    uint8_t *tail = (uint8_t *)malloc(tail_len);
    if (!tail) {
        close(fd);
        return 0;
    }
    if (pread(fd, tail, tail_len, (off_t)pack_off) < (ssize_t)sizeof(axvm_pack_hdr_t)) {
        free(tail);
        close(fd);
        return 0;
    }
    close(fd);

    /* 模块 M：EOF 中的 AXDS 动态种子块（pack 之后、随 stub 一并落盘）。 */
    if (axvm_dynseed_scan_and_set(tail, tail_len)) {
        AXVM_LOGI( "dynseed master loaded from %s", path);
    }

    if (!pack_trusted(tail, tail_len)) {
        AXVM_LOGE( "pack untrusted off=0x%llx len=%zu",
                            (unsigned long long)pack_off, tail_len);
        free(tail);
        return 0;
    }

    const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)tail;
    size_t pack_bytes = (size_t)((hdr->blob_off + hdr->blob_size + 15u) & ~15u);
    if (pack_bytes > tail_len) {
        free(tail);
        return 0;
    }
    size_t stub_len = tail_len - pack_bytes;
    if (stub_len == 0) {
        AXVM_LOGE( "empty stub tail pack_bytes=%zu tail=%zu",
                            pack_bytes, tail_len);
        free(tail);
        return 0;
    }

    long page_sz = sysconf(_SC_PAGESIZE);
    if (page_sz <= 0) {
        free(tail);
        return 0;
    }
	size_t map_sz = (stub_len + (size_t)page_sz - 1u) & ~((size_t)page_sz - 1u);
	map_sz += (size_t)page_sz;
    void *stub_exec = map_stub_region(load_base, map_vaddr, map_sz);
    if (stub_exec == MAP_FAILED) {
        free(tail);
        return 0;
    }
    memcpy(stub_exec, tail + pack_bytes, stub_len);
    if (mprotect(stub_exec, map_sz, PROT_READ | PROT_EXEC) != 0) {
        munmap(stub_exec, map_sz);
        free(tail);
        return 0;
    }

    axvm_module_load_ex(tail, pack_bytes, load_base, stub_exec, map_vaddr, 1);
    axvm_module_t *mod = &g_modules[g_module_count - 1];
    patch_dynsym_exports(mod);
    patch_victim_entries(mod);
#if defined(AXVM_SO_INTEGRITY) && AXVM_SO_INTEGRITY
    /* 模块 I：全部合法运行时 patch 完成后再 arm，避免 TEXT 误报 */
    axvm_integrity_register(tail, pack_bytes, load_base);
#endif

    AXVM_LOGI( "file pack %s pack=%zu stub=%zu base=%p",
                        path, pack_bytes, stub_len, load_base);
    return 1;
}

static int try_load_pack_at(void *load_base, const uint8_t *candidate, size_t remain)
{
    /*
     * Must use the mapped-segment path (stub_exec + patch_victim_entries).
     * Plain axvm_module_load() registers bytecode but leaves disk-ready stubs
     * unwired; scan_proc_maps then skips because g_module_count > 0.
     */
    return load_pack_from_mapped_segment(load_base, candidate, remain);
}

static int scan_loaded_segments(void *load_base, const char *tag)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)load_base;
    if (eh->e_ident[EI_MAG0] != ELFMAG0 || eh->e_phoff == 0) {
        return 0;
    }
    const Elf64_Phdr *ph = (const Elf64_Phdr *)((const uint8_t *)load_base + eh->e_phoff);

    for (int i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD || (ph[i].p_flags & PF_X) == 0) {
            continue;
		}
		const uint8_t *seg = (const uint8_t *)load_base + ph[i].p_vaddr;
		size_t seg_len = (size_t)ph[i].p_filesz;
		size_t mapped_len = readable_map_len(seg, seg_len);
		if (mapped_len < sizeof(axvm_pack_hdr_t)) {
			continue;
		}
		seg_len = mapped_len;
		for (size_t off = 0; off + sizeof(axvm_pack_hdr_t) <= seg_len; off += 4) {
			if (!pack_magic_matches(*(const uint32_t *)(seg + off))) {
				continue;
			}
			if (try_load_pack_at(load_base, seg + off, seg_len - off)) {
				AXVM_LOGI( "%s pack in phdr base=%p",
									tag, load_base);
				return 1;
            }
        }
    }
    return 0;
}

#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
/*
 * 从 SO 文件尾（EOF 追加区）单独补读并登记 AXDS MasterSeed。
 * 当内存 PT_LOAD 段扫描已命中 pack 时会提前返回，而 AXDS 位于文件尾、
 * 不在任何 PT_LOAD 段内，故须从文件补读，避免退化为合成 MasterSeed。
 */
static int load_dynseed_from_file(const char *path)
{
    if (!path || !path[0]) {
        return 0;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return 0;
    }
    uint64_t pack_off = axvm_find_pack_file_off(fd, &st);
    if (pack_off == 0) {
        close(fd);
        return 0;
    }
    size_t tail_len = (size_t)((uint64_t)st.st_size - pack_off);
    uint8_t *tail = (uint8_t *)malloc(tail_len);
    if (!tail) {
        close(fd);
        return 0;
    }
    int ok = 0;
    if (pread(fd, tail, tail_len, (off_t)pack_off) == (ssize_t)tail_len) {
        ok = axvm_dynseed_scan_and_set(tail, tail_len);
    }
    free(tail);
    close(fd);
    return ok;
}
#endif

void axvm_register_symbol(void *symbol)
{
    Dl_info info;
    if (!symbol || dladdr(symbol, &info) == 0 || !info.dli_fbase) {
        AXVM_LOGE( "register_symbol: dladdr failed");
        return;
    }

#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    /* AXDS is past PT_LOAD; load master before decrypting the pack blob. */
    if (info.dli_fname && info.dli_fname[0] &&
        load_dynseed_from_file(info.dli_fname)) {
        AXVM_LOGI("dynseed master loaded (register) from %s", info.dli_fname);
    }
#endif

    if (scan_loaded_segments(info.dli_fbase, "register")) {
        return;
    }

    if (info.dli_fname && axvm_load_pack_from_file(info.dli_fname, info.dli_fbase)) {
        AXVM_LOGI( "register file %s base=%p",
                            info.dli_fname, info.dli_fbase);
        return;
    }

    AXVM_LOGE( "register_symbol: no pack in %s",
                        info.dli_fname ? info.dli_fname : "?");
}

int axvm_loader_got_leak_probe(void)
{
    for (uint32_t m = 0; m < g_module_count; ++m) {
        axvm_module_t *mod = &g_modules[m];
        if (!mod->used || !mod->pack || !mod->stub_exec) {
            continue;
        }
        const axvm_pack_hdr_t *hdr = (const axvm_pack_hdr_t *)mod->pack;
        for (uint32_t i = 0; i < hdr->func_count; ++i) {
            const axvm_func_rec_t *r = pack_rec_at(hdr, mod->pack, i);
            if (r->stub_off == 0) {
                continue;
            }
            void *stub = stub_target(mod, r);
            if (!stub) {
                continue;
            }
            uint32_t disp_off = rec_stub_dispatch_off(hdr, r);
            const void *slot =
                (const void *)((uintptr_t)stub + disp_off);
            return axvm_got_crypt_probe_stub_leak(slot);
        }
    }
    return -1;
}

int axvm_loader_stext_wiped_count(void)
{
    int n = 0;
    for (uint32_t m = 0; m < g_module_count; ++m) {
        if (g_modules[m].used && (g_modules[m].pack_flags & AXPK_FLAG_WIPED)) {
            n++;
        }
    }
    return n;
}

int axvm_loader_stext_unlock_total(void)
{
    return g_stext_unlock_total + g_stext_prepatch_total;
}

int axvm_loader_dynsym_strip_probe(void)
{
#if defined(__ANDROID__)
    /* Android 保留 dynsym 名称供 dlsym；以已重定向导出数作为 strip 探针。 */
    if (g_dynsym_patched_total > 0) {
        return g_dynsym_patched_total;
    }
#endif
    int stripped = 0;
    for (uint32_t m = 0; m < g_module_count; ++m) {
        axvm_module_t *mod = &g_modules[m];
        if (!mod->used || !mod->load_base) {
            continue;
        }
        const Elf64_Ehdr *eh = (const Elf64_Ehdr *)mod->load_base;
        if (eh->e_ident[EI_MAG0] != ELFMAG0 || eh->e_phoff == 0 || eh->e_phnum == 0) {
            continue;
        }
        if ((size_t)eh->e_phoff + (size_t)eh->e_phnum * eh->e_phentsize >
            (size_t)eh->e_ehsize + 0x1000u) {
            continue;
        }
        const Elf64_Phdr *ph = (const Elf64_Phdr *)((const uint8_t *)mod->load_base + eh->e_phoff);
        const Elf64_Dyn *dyn = NULL;
        size_t dyn_cnt = 0;
        size_t dyn_memsz = 0;
        for (int i = 0; i < eh->e_phnum; ++i) {
            if (ph[i].p_type != PT_DYNAMIC) {
                continue;
            }
            dyn = (const Elf64_Dyn *)((const uint8_t *)mod->load_base + ph[i].p_vaddr);
            dyn_memsz = (size_t)ph[i].p_memsz;
            if (dyn_memsz >= sizeof(Elf64_Dyn)) {
                dyn_cnt = dyn_memsz / sizeof(Elf64_Dyn);
            }
            break;
        }
        if (!dyn || dyn_cnt == 0) {
            continue;
        }
        Elf64_Addr symtab = 0;
        size_t syment = sizeof(Elf64_Sym);
        size_t nchain = 256;
        for (size_t i = 0; i < dyn_cnt && dyn[i].d_tag != DT_NULL; ++i) {
            if (dyn[i].d_tag == DT_SYMTAB) {
                symtab = dyn[i].d_un.d_ptr;
            }
            if (dyn[i].d_tag == DT_SYMENT) {
                syment = (size_t)dyn[i].d_un.d_val;
                if (syment < sizeof(Elf64_Sym)) {
                    syment = sizeof(Elf64_Sym);
                }
            }
            if (dyn[i].d_tag == DT_HASH) {
                const uint32_t *hb =
                    (const uint32_t *)((uintptr_t)mod->load_base + dyn[i].d_un.d_ptr);
                if (hb && hb[1] > 0 && hb[1] <= 4096u) {
                    nchain = hb[1];
                }
            }
        }
        if (!symtab || syment == 0) {
            continue;
        }
        if (nchain > 4096u) {
            nchain = 4096u;
        }
        const Elf64_Sym *sym = (const Elf64_Sym *)((uintptr_t)mod->load_base + symtab);
        for (size_t si = 0; si < nchain; ++si) {
            const Elf64_Sym *s = (const Elf64_Sym *)((const uint8_t *)sym + si * syment);
            if (ELF64_ST_TYPE(s->st_info) == STT_FUNC && s->st_name == 0 && s->st_value != 0) {
                stripped++;
            }
        }
    }
    return stripped;
}

static uint64_t pack_off_in_buf(const uint8_t *buf, size_t len)
{
    if (!buf || len < sizeof(axvm_pack_hdr_t)) {
        return 0;
    }
    ensure_dynseed_probe_tail(buf, len);
    size_t scan = len;
    if (scan > 65536u) {
        scan = 65536u;
    }
    uint64_t base = (uint64_t)len - (uint64_t)scan;
    uint64_t found = 0;
    for (size_t i = 0; i + sizeof(axvm_pack_hdr_t) <= scan; i += 4) {
        if (!pack_magic_matches(*(const uint32_t *)(buf + base + i))) {
            continue;
        }
        size_t remain = len - (size_t)(base + (uint64_t)i);
        if (!pack_trusted(buf + base + i, remain)) {
            continue;
        }
        found = base + (uint64_t)i;
    }
    return found;
}

static int prepatch_stext_in_file(uint8_t *file, size_t file_len, axvm_pack_hdr_t *hdr)
{
#if !defined(AXVM_STEXT) || !AXVM_STEXT
    (void)file;
    (void)file_len;
    (void)hdr;
    return 0;
#else
    if (!file || !hdr || !(hdr->flags & AXPK_FLAG_WIPED)) {
        return 0;
    }
    if (!axvm_dynseed_master_is_real()) {
        return 0;
    }
    const uint8_t *pack_base = (const uint8_t *)hdr;
    uint32_t n = hdr->func_count;
    int unlocked = 0;
    for (uint32_t i = 0; i < n; ++i) {
        const axvm_func_rec_t *r = pack_rec_at(hdr, pack_base, i);
        if (r->orig_vaddr == 0 || r->orig_size <= 4) {
            continue;
        }
        uint64_t entry_off = 0;
        if (!elf_vaddr_to_file_off(file, file_len, r->orig_vaddr, &entry_off)) {
            continue;
        }
        size_t plen = axvm_stext_patch_len(file + entry_off);
        if (plen >= (size_t)r->orig_size) {
            continue;
        }
        size_t tail_off = (size_t)entry_off + plen;
        size_t tail_len = (size_t)r->orig_size - plen;
        if (tail_off + tail_len > file_len) {
            continue;
        }
        if (axvm_stext_decrypt_file_range(file, tail_off, tail_len, r->func_id) > 0) {
            unlocked++;
        }
    }
    if (unlocked > 0) {
        hdr->flags &= ~AXPK_FLAG_WIPED;
        g_stext_prepatch_total += unlocked;
    }
    return unlocked;
#endif
}

#define AXNW_MAGIC   0x574E5841u /* 'AXNW' */
#define AXNW_VERSION 1u

static const uint8_t *find_axnw_block(const uint8_t *buf, size_t len)
{
    if (!buf || len < 16) {
        return NULL;
    }
    size_t scan = len;
    if (scan > 65536u) {
        scan = 65536u;
    }
    size_t base = len - scan;
    const uint8_t *found = NULL;
    for (size_t i = 0; i + 16 <= scan; i += 4) {
        const uint8_t *p = buf + base + i;
        uint32_t magic;
        uint32_t ver;
        uint32_t cnt;
        memcpy(&magic, p, sizeof(magic));
        if (magic != AXNW_MAGIC) {
            continue;
        }
        memcpy(&ver, p + 4, sizeof(ver));
        if (ver != AXNW_VERSION) {
            continue;
        }
        memcpy(&cnt, p + 8, sizeof(cnt));
        if (cnt == 0 || cnt > 4096u) {
            continue;
        }
        size_t need = 16u + (size_t)cnt * 16u;
        if (base + i + need > len) {
            continue;
        }
        found = p;
    }
    return found;
}

static int prepatch_native_wipe_in_file(uint8_t *file, size_t file_len)
{
#if !defined(AXVM_STEXT) || !AXVM_STEXT
    (void)file;
    (void)file_len;
    return 0;
#else
    if (!file || !axvm_dynseed_master_is_real()) {
        return 0;
    }
    const uint8_t *blk = find_axnw_block(file, file_len);
    if (!blk) {
        return 0;
    }
    uint32_t cnt;
    memcpy(&cnt, blk + 8, sizeof(cnt));
    int unlocked = 0;
    for (uint32_t i = 0; i < cnt; ++i) {
        const uint8_t *e = blk + 16 + (size_t)i * 16u;
        uint64_t vaddr;
        uint32_t size;
        uint32_t func_id;
        memcpy(&vaddr, e, sizeof(vaddr));
        memcpy(&size, e + 8, sizeof(size));
        memcpy(&func_id, e + 12, sizeof(func_id));
        if (vaddr == 0 || size < 4) {
            continue;
        }
        uint64_t body_off = 0;
        if (!elf_vaddr_to_file_off(file, file_len, vaddr, &body_off)) {
            continue;
        }
        if (body_off + (uint64_t)size > file_len) {
            continue;
        }
        if (axvm_stext_decrypt_file_range(file, (size_t)body_off, (size_t)size, func_id) > 0) {
            unlocked++;
        }
    }
    return unlocked;
#endif
}

static int prepatch_text_jumps_in_file(uint8_t *file, size_t file_len,
                                       const axvm_pack_hdr_t *hdr)
{
    if (!file || !hdr) {
        return 0;
    }
    const uint8_t *pack_base = (const uint8_t *)hdr;
    uint32_t n = hdr->func_count;
    if (n == 0) {
        return 0;
    }

    uint64_t *vaddrs = (uint64_t *)calloc(n, sizeof(uint64_t));
    uint32_t *order = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!vaddrs || !order) {
        free(vaddrs);
        free(order);
        return 0;
    }
    for (uint32_t i = 0; i < n; ++i) {
        vaddrs[i] = pack_rec_at(hdr, pack_base, i)->orig_vaddr;
        order[i] = i;
    }
    for (uint32_t i = 0; i + 1 < n; ++i) {
        for (uint32_t j = i + 1; j < n; ++j) {
            if (vaddrs[i] > vaddrs[j]) {
                uint64_t tv = vaddrs[i];
                vaddrs[i] = vaddrs[j];
                vaddrs[j] = tv;
                uint32_t ti = order[i];
                order[i] = order[j];
                order[j] = ti;
            }
        }
    }

    int patched = 0;
    for (uint32_t k = 0; k < n; ++k) {
        const axvm_func_rec_t *r = pack_rec_at(hdr, pack_base, order[k]);
        if (r->stub_off == 0 || r->orig_vaddr == 0) {
            continue;
        }
        uint64_t from_off = 0;
        if (!elf_vaddr_to_file_off(file, file_len, r->orig_vaddr, &from_off)) {
            continue;
        }
        if (text_entry_is_patched(file + from_off)) {
            patched++;
            continue;
        }
        size_t room = 16;
        uint32_t orig_sz = rec_orig_size(hdr, r);
        if (orig_sz > 0 && orig_sz < room) {
            room = orig_sz;
        }
        if (k + 1 < n) {
            uint64_t gap = vaddrs[k + 1] - r->orig_vaddr;
            if (gap > 0 && gap < room) {
                room = (size_t)gap;
            }
        }
        if (room < 4) {
            continue;
        }
        int64_t off = (int64_t)r->stub_off - (int64_t)r->orig_vaddr;
        if (off % 4 == 0 && off >= -134217728 && off <= 134217724 && room >= 4) {
            uint32_t imm26 = (uint32_t)(off / 4) & 0x03FFFFFFu;
            uint32_t ins = 0x14000000u | imm26;
            memcpy(file + from_off, &ins, 4);
            patched++;
        }
    }
    free(vaddrs);
    free(order);
    return patched;
}

static int prepatch_dynsym_in_file(uint8_t *file, size_t file_len,
                                   const axvm_pack_hdr_t *hdr)
{
    if (!file || !hdr || file_len < sizeof(Elf64_Ehdr)) {
        return 0;
    }
    const uint8_t *pack_base = (const uint8_t *)hdr;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)file;
    if (eh->e_ident[EI_MAG0] != ELFMAG0 || eh->e_phoff == 0) {
        return 0;
    }
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(file + eh->e_phoff);
    const Elf64_Dyn *dyn = NULL;
    size_t dyn_cnt = 0;
    for (int i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_DYNAMIC) {
            continue;
        }
        if (ph[i].p_offset + ph[i].p_filesz > file_len) {
            return 0;
        }
        dyn = (const Elf64_Dyn *)(file + ph[i].p_offset);
        if (ph[i].p_filesz >= sizeof(Elf64_Dyn)) {
            dyn_cnt = (size_t)(ph[i].p_filesz / sizeof(Elf64_Dyn));
        }
        break;
    }
    if (!dyn) {
        return 0;
    }

    Elf64_Addr symtab = 0;
    Elf64_Addr strtab = 0;
    Elf64_Addr hash = 0;
    size_t syment = sizeof(Elf64_Sym);
    size_t nchain = 0;
    for (size_t i = 0; i < dyn_cnt && dyn[i].d_tag != DT_NULL; ++i) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:
            symtab = dyn[i].d_un.d_ptr;
            break;
        case DT_STRTAB:
            strtab = dyn[i].d_un.d_ptr;
            break;
        case DT_HASH:
            hash = dyn[i].d_un.d_ptr;
            break;
        case DT_SYMENT:
            syment = (size_t)dyn[i].d_un.d_val;
            break;
        default:
            break;
        }
    }
    if (!symtab || !strtab || syment < sizeof(Elf64_Sym)) {
        return 0;
    }
    if (hash) {
        uint64_t hash_off = 0;
        if (elf_vaddr_to_file_off(file, file_len, hash, &hash_off) &&
            hash_off + 8 <= file_len) {
            const uint32_t *hb = (const uint32_t *)(file + hash_off);
            nchain = hb[1];
        }
    }
    if (nchain == 0 || nchain > 65536u) {
        nchain = 4096;
    }

    uint64_t symtab_off = 0;
    uint64_t strtab_off = 0;
    if (!elf_vaddr_to_file_off(file, file_len, symtab, &symtab_off) ||
        !elf_vaddr_to_file_off(file, file_len, strtab, &strtab_off)) {
        return 0;
    }

    int patched = 0;
    for (uint32_t fi = 0; fi < hdr->func_count; ++fi) {
        const axvm_func_rec_t *r = pack_rec_at(hdr, pack_base, fi);
        if (r->stub_off == 0 || r->name[0] == '\0') {
            continue;
        }
        for (size_t si = 0; si < nchain; ++si) {
            uint64_t soff = symtab_off + si * syment;
            if (soff + sizeof(Elf64_Sym) > file_len) {
                break;
            }
            Elf64_Sym *s = (Elf64_Sym *)(file + soff);
            if (ELF64_ST_TYPE(s->st_info) != STT_FUNC || s->st_name == 0) {
                continue;
            }
            uint64_t name_off = 0;
            if (!elf_vaddr_to_file_off(file, file_len, strtab + s->st_name, &name_off)) {
                continue;
            }
            if (strcmp((const char *)(file + name_off), r->name) != 0) {
                continue;
            }
            if (s->st_value == (Elf64_Addr)r->stub_off) {
                patched++;
                break;
            }
            s->st_value = (Elf64_Addr)r->stub_off;
            s->st_size = 96;
            patched++;
            break;
        }
    }
    return patched;
}

int axvm_prepatch_so_file(const char *path)
{
    if (!path || !path[0]) {
        return 0;
    }
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        __android_log_print(ANDROID_LOG_ERROR, "AXVM", "prepatch open fail %s errno=%d", path, errno);
        return 0;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return 0;
    }
    size_t file_len = (size_t)st.st_size;
    uint8_t *file = (uint8_t *)mmap(NULL, file_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (file == MAP_FAILED) {
        __android_log_print(ANDROID_LOG_ERROR, "AXVM", "prepatch mmap fail %s errno=%d", path, errno);
        return 0;
    }

#if defined(AXVM_DYNAMIC_SEED) && AXVM_DYNAMIC_SEED
    axvm_dynseed_reset_for_prepatch();
    size_t axds_scan = file_len;
    if (axds_scan > 65536u) {
        axds_scan = 65536u;
    }
    if (!axvm_dynseed_scan_tail_and_set(file + file_len - axds_scan, axds_scan)) {
        __android_log_print(ANDROID_LOG_ERROR, "AXVM", "prepatch: AXDS not found in %s", path);
        munmap(file, file_len);
        return 0;
    }
    size_t axds_off = file_len - sizeof(axvm_dynseed_block_t);
    __android_log_print(ANDROID_LOG_ERROR, "AXVM",
                        "prepatch axds ok off=0x%zx bind=%d real=%d magic=0x%08X size=%zu",
                        axds_off,
                        axvm_dynseed_apk_bind_required(),
                        axvm_dynseed_master_is_real(),
                        axvm_dynseed_pack_magic(),
                        file_len);
#endif

    uint64_t pack_off = pack_off_in_buf(file, file_len);
    if (pack_off == 0 || pack_off + sizeof(axvm_pack_hdr_t) > file_len) {
        __android_log_print(ANDROID_LOG_ERROR, "AXVM", "prepatch: pack not found in %s", path);
        munmap(file, file_len);
        return 0;
    }
    size_t tail_len = file_len - (size_t)pack_off;
    if (!pack_trusted(file + pack_off, tail_len)) {
        __android_log_print(ANDROID_LOG_ERROR, "AXVM", "prepatch: pack untrusted %s", path);
        munmap(file, file_len);
        return 0;
    }

    axvm_pack_hdr_t *hdr = (axvm_pack_hdr_t *)(file + pack_off);
    int stext_n = prepatch_stext_in_file(file, file_len, hdr);
    int native_n = prepatch_native_wipe_in_file(file, file_len);
    uint32_t flags = hdr->flags;
    msync(file, file_len, MS_SYNC);
    munmap(file, file_len);

    AXVM_LOGI(
                        "prepatch %s stext=%d native=%d flags=0x%x (dynsym/text at runtime)",
                        path, stext_n, native_n, flags);
    return 1;
}
