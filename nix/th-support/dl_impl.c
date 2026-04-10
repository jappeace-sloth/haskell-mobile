#include <stddef.h>
#include <string.h>
#include <elf.h>
#include <stdint.h>
#include <unistd.h>

/* Minimal stderr diagnostic (avoids stdio dependency) */
static void diag(const char *msg) {
    write(2, msg, strlen(msg));
}
/* Use hex output to avoid __aeabi_idiv references from decimal division.
 * On ARM32, val % 10 and val / 10 generate __aeabi_idiv calls which pull
 * in division helpers that can break static binary TLS initialization. */
static void diag_hex(const char *label, unsigned long val) {
    char buf[20];
    const char *hex = "0123456789abcdef";
    int i = 19;
    buf[i] = 0;
    if (val == 0) { buf[--i] = '0'; }
    else { while (val > 0 && i > 0) { buf[--i] = hex[val & 0xf]; val >>= 4; } }
    buf[--i] = 'x'; buf[--i] = '0';
    diag(label);
    diag(buf + i);
    diag("\n");
}

/*
 * Minimal dlopen/dlsym for a statically linked Android binary.
 *
 * dlopen: returns a fake non-NULL handle (the binary itself).
 * dlsym:  walks the .dynsym table (populated by --export-dynamic)
 *         to find symbols by name.
 *
 * Works for both aarch64 (ELF64) and armv7a (ELF32).
 * Handles both SysV hash (DT_HASH) and GNU hash (DT_GNU_HASH)
 * for determining the symbol count.
 *
 * Requires: -Wl,--export-dynamic at link time.
 */

/* Architecture-independent ELF types (Bionic lacks ElfW() macro). */
#if __SIZEOF_POINTER__ == 8
typedef Elf64_Dyn ElfDyn;
typedef Elf64_Sym ElfSym;
typedef Elf64_Addr ElfAddr;
#else
typedef Elf32_Dyn ElfDyn;
typedef Elf32_Sym ElfSym;
typedef Elf32_Addr ElfAddr;
#endif

/* _DYNAMIC is provided by the linker when --export-dynamic is used. */
extern ElfDyn _DYNAMIC[] __attribute__((weak));

static ElfSym     *g_symtab  = NULL;
static const char *g_strtab  = NULL;
static uint32_t    g_strsz   = 0;     /* string table size (DT_STRSZ) */
static uint32_t    g_nsyms   = 0;
static int         g_inited  = 0;

/* Compute nsyms from GNU hash table.
 * GNU hash layout: nbuckets, symoffset, bloom_size, bloom_shift,
 *                  bloom[bloom_size], buckets[nbuckets], chains[...]
 * The maximum symbol index is the highest bucket value plus the chain
 * length for that bucket. */
static uint32_t gnu_hash_nsyms(const uint32_t *gnu_hash) {
    uint32_t nbuckets   = gnu_hash[0];
    uint32_t symoffset  = gnu_hash[1];
    uint32_t bloom_size = gnu_hash[2];
    /* bloom_shift = gnu_hash[3] */
#if __SIZEOF_POINTER__ == 8
    const uint32_t *buckets = gnu_hash + 4 + bloom_size * 2; /* 64-bit bloom words */
#else
    const uint32_t *buckets = gnu_hash + 4 + bloom_size;     /* 32-bit bloom words */
#endif
    const uint32_t *chains  = buckets + nbuckets;

    /* Find the highest occupied bucket */
    uint32_t max_idx = 0;
    uint32_t i;
    for (i = 0; i < nbuckets; i++) {
        if (buckets[i] > max_idx)
            max_idx = buckets[i];
    }
    if (max_idx < symoffset) return symoffset; /* all buckets empty */

    /* Follow chain from max_idx until the stop bit (LSB set) */
    const uint32_t *chain_entry = chains + (max_idx - symoffset);
    while (!(*chain_entry & 1)) {
        max_idx++;
        chain_entry++;
    }
    return max_idx + 1;
}

static void init_symtab(void) {
    ElfDyn *d;
    const uint32_t *gnu_hash_ptr = NULL;
    g_inited = 1;
    diag("dl_impl: init_symtab called\n");
    if (!_DYNAMIC) { diag("dl_impl: _DYNAMIC is NULL!\n"); return; }
    for (d = _DYNAMIC; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_SYMTAB:
            g_symtab = (ElfSym *)(uintptr_t)d->d_un.d_ptr;
            break;
        case DT_STRTAB:
            g_strtab = (const char *)(uintptr_t)d->d_un.d_ptr;
            break;
        case DT_STRSZ:
            g_strsz = (uint32_t)d->d_un.d_val;
            break;
        case DT_HASH: {
            /* SysV hash table: uint32_t nbuckets, nchain.
             * nchain == total number of symbols in .dynsym. */
            uint32_t *h = (uint32_t *)(uintptr_t)d->d_un.d_ptr;
            g_nsyms = h[1];
            break;
        }
        case DT_GNU_HASH:
            gnu_hash_ptr = (const uint32_t *)(uintptr_t)d->d_un.d_ptr;
            break;
        }
    }
    /* If SysV hash wasn't present, try GNU hash */
    if (g_nsyms == 0 && gnu_hash_ptr) {
        diag("dl_impl: using DT_GNU_HASH fallback\n");
        g_nsyms = gnu_hash_nsyms(gnu_hash_ptr);
    }
    diag_hex("dl_impl: g_nsyms = ", g_nsyms);
    diag_hex("dl_impl: g_strsz = ", g_strsz);
    diag_hex("dl_impl: g_symtab = ", (unsigned long)g_symtab);
    diag_hex("dl_impl: g_strtab = ", (unsigned long)g_strtab);
}

void *dlopen(const char *filename, int flags) {
    (void)filename; (void)flags;
    return (void *)(uintptr_t)1;  /* fake non-NULL handle */
}

char *dlerror(void) { return NULL; }

void *dlsym(void *handle, const char *symbol) {
    uint32_t i;
    (void)handle;
    if (!g_inited) init_symtab();
    if (!g_symtab || !g_strtab) return NULL;
    for (i = 0; i < g_nsyms; i++) {
        /* Bounds check: skip entries with out-of-range st_name */
        if (g_strsz > 0 && g_symtab[i].st_name >= g_strsz) continue;
        if (g_symtab[i].st_shndx != SHN_UNDEF &&
            g_symtab[i].st_name  != 0 &&
            strcmp(g_strtab + g_symtab[i].st_name, symbol) == 0) {
            return (void *)(uintptr_t)g_symtab[i].st_value;
        }
    }
    return NULL;
}

int dlclose(void *handle) { (void)handle; return 0; }

void *dlvsym(void *handle, const char *s, const char *v) {
    (void)v;
    return dlsym(handle, s);
}

int dladdr(const void *addr, void *info) {
    (void)addr; (void)info;
    return 0;
}

/*
 * ARM EABI integer division helpers.
 * GHC's LLVM backend emits __aeabi_idiv calls for ARM32 code.
 * The Android NDK's compiler-rt omits these (assumes hardware divide).
 * Defined here (in dl_impl.c) so they're part of dl_impl.o and exported
 * via --export-dynamic, making them available to the RTS linker via dlsym.
 * Pure C software division — no hardware divide instructions.
 */
#if defined(__arm__) || defined(__thumb__)

unsigned __aeabi_uidiv(unsigned numerator, unsigned denominator) {
    if (denominator == 0) return 0;
    unsigned quotient = 0;
    unsigned bit = 1;
    while (denominator <= numerator && !(denominator & (1u << 31))) {
        denominator <<= 1;
        bit <<= 1;
    }
    while (bit) {
        if (numerator >= denominator) {
            numerator -= denominator;
            quotient |= bit;
        }
        denominator >>= 1;
        bit >>= 1;
    }
    return quotient;
}

int __aeabi_idiv(int numerator, int denominator) {
    int negative = 0;
    if (numerator < 0) { numerator = -numerator; negative = !negative; }
    if (denominator < 0) { denominator = -denominator; negative = !negative; }
    unsigned result = __aeabi_uidiv((unsigned)numerator, (unsigned)denominator);
    return negative ? -(int)result : (int)result;
}

typedef struct { int quot; int rem; } __aeabi_idivmod_result_t;
__aeabi_idivmod_result_t __aeabi_idivmod(int numerator, int denominator) {
    int quot = __aeabi_idiv(numerator, denominator);
    int rem = numerator - quot * denominator;
    return (__aeabi_idivmod_result_t){quot, rem};
}

typedef struct { unsigned quot; unsigned rem; } __aeabi_uidivmod_result_t;
__aeabi_uidivmod_result_t __aeabi_uidivmod(unsigned numerator,
                                           unsigned denominator) {
    unsigned quot = __aeabi_uidiv(numerator, denominator);
    unsigned rem = numerator - quot * denominator;
    return (__aeabi_uidivmod_result_t){quot, rem};
}

#endif /* __arm__ || __thumb__ */
