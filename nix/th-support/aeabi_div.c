/*
 * ARM EABI integer division helpers for static iserv-proxy-interpreter.
 *
 * GHC's LLVM backend targets armv7-a which lacks hardware integer divide,
 * so it emits calls to __aeabi_idiv etc.  Android's NDK compiler-rt omits
 * these functions because Android API 21+ effectively requires Cortex-A7
 * or above, which has the IDIV extension.
 *
 * When the RTS linker loads TH .o files that use integer division, it
 * tries to resolve __aeabi_idiv via dlsym and fails.  This causes the
 * entire boot package loading to fail, cascading into missing Haskell
 * symbols.
 *
 * Fix: provide the division functions using Thumb-2 SDIV/UDIV hardware
 * instructions.  This file MUST be compiled with -march=armv7-a+idiv
 * (or equivalent) to ensure the assembler accepts sdiv/udiv.
 *
 * Only compiled for ARM32 targets.
 */

#if defined(__arm__) || defined(__thumb__)

/* Use hardware divide instructions (available on Cortex-A7 and above). */

int __aeabi_idiv(int numerator, int denominator) {
    int result;
    __asm__ volatile("sdiv %0, %1, %2"
                     : "=r"(result)
                     : "r"(numerator), "r"(denominator));
    return result;
}

unsigned __aeabi_uidiv(unsigned numerator, unsigned denominator) {
    unsigned result;
    __asm__ volatile("udiv %0, %1, %2"
                     : "=r"(result)
                     : "r"(numerator), "r"(denominator));
    return result;
}

/*
 * __aeabi_idivmod: signed division + modulo.
 * ARM EABI calling convention: returns quotient in r0, remainder in r1.
 * We use a struct return which GCC/Clang map to r0+r1 for small structs.
 */
typedef struct { int quot; int rem; } __aeabi_idivmod_result_t;
__aeabi_idivmod_result_t __aeabi_idivmod(int numerator, int denominator) {
    int quot;
    __asm__ volatile("sdiv %0, %1, %2"
                     : "=r"(quot) : "r"(numerator), "r"(denominator));
    int rem = numerator - quot * denominator;
    return (__aeabi_idivmod_result_t){quot, rem};
}

typedef struct { unsigned quot; unsigned rem; } __aeabi_uidivmod_result_t;
__aeabi_uidivmod_result_t __aeabi_uidivmod(unsigned numerator,
                                           unsigned denominator) {
    unsigned quot;
    __asm__ volatile("udiv %0, %1, %2"
                     : "=r"(quot) : "r"(numerator), "r"(denominator));
    unsigned rem = numerator - quot * denominator;
    return (__aeabi_uidivmod_result_t){quot, rem};
}

#endif /* __arm__ || __thumb__ */
