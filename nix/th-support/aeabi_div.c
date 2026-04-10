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
 * Fix: provide the division functions as pure C software implementations.
 * No inline assembly needed — avoids hardware divide instruction issues
 * under QEMU user-mode emulation.
 *
 * Only compiled for ARM32 targets.
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

/*
 * __aeabi_idivmod: signed division + modulo.
 * ARM EABI: quotient in r0, remainder in r1.
 * Small struct return maps to r0+r1 on ARM.
 */
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
