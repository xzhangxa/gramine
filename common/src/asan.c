/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include "api.h"
#include "asan.h"
#include "assert.h"

#ifndef ASAN
#error This code should be compiled only with ASAN defined.
#endif

#define RETURN_ADDR() (__builtin_extract_return_addr(__builtin_return_address(0)))

/* See `callbacks.h` */
#if defined(IN_SHIM)
#define ABORT_NAME "shim_abort"
#elif defined(IN_PAL)
#define ABORT_NAME "pal_abort"
#else
#define ABORT_NAME "abort"
#endif

__attribute_no_sanitize_address
void asan_poison_region(uintptr_t addr, size_t size, uint8_t value) {
    assert((addr & ASAN_SHADOW_MASK) == 0);
    size = ALIGN_UP(size, ASAN_SHADOW_ALIGN);
    uint8_t* shadow_ptr = (uint8_t*)ASAN_MEM_TO_SHADOW(addr);
    size_t shadow_size = size >> ASAN_SHADOW_SHIFT;

    _real_memset(shadow_ptr, value, shadow_size);
}

__attribute_no_sanitize_address
void asan_unpoison_region(uintptr_t addr, size_t size) {
    assert((addr & ASAN_SHADOW_MASK) == 0);
    uint8_t* shadow_ptr = (uint8_t*)ASAN_MEM_TO_SHADOW(addr);
    size_t shadow_size = size >> ASAN_SHADOW_SHIFT;
    size_t right_part_size = size & ASAN_SHADOW_MASK;

    _real_memset(shadow_ptr, 0, shadow_size);
    if (right_part_size)
        *(shadow_ptr + shadow_size) = right_part_size;
}

/* Check if a single byte is poisoned */
__attribute_no_sanitize_address
static bool asan_check(uintptr_t addr) {
    uint8_t val = *(uint8_t*)ASAN_MEM_TO_SHADOW(addr);
    return val && ((val >= 0x80) || val <= (uint8_t)(addr & ASAN_SHADOW_MASK));
}

static int asan_buf_write_all(const char* str, size_t size, void* arg) {
    __UNUSED(arg);
    log_error("asan: %.*s", (int)size, str);
    return 0;
}

/* Find the exact bad address, and attempt to classify the bug */
__attribute_no_sanitize_address
static void asan_find_problem(uintptr_t addr, size_t size, uintptr_t* out_bad_addr,
                              const char** out_bug_type) {
    uintptr_t bad_addr;
    for (bad_addr = addr; bad_addr < addr + size; bad_addr++)
        if (asan_check(bad_addr))
            break;

    assert(asan_check(bad_addr));

    uint8_t* shadow_ptr = (uint8_t*)ASAN_MEM_TO_SHADOW(bad_addr);
    /* If this is a partial right redzone, check the next byte */
    if (*shadow_ptr < 0x80)
        shadow_ptr++;

    const char* bug_type;

    switch (*shadow_ptr) {
        case ASAN_POISON_HEAP_LEFT_REDZONE:
            bug_type = "heap-buffer-overflow";
            break;
        case ASAN_POISON_HEAP_AFTER_FREE:
            bug_type = "heap-use-after-free";
            break;
        default:
            bug_type = "unknown-crash";
            break;
    }

    *out_bad_addr = bad_addr;
    *out_bug_type = bug_type;
}

/* Dump shadow memory around the bad address */
__attribute_no_sanitize_address
static void asan_dump(uintptr_t bad_addr) {
    const unsigned int width = 16;
    const unsigned int lines = 4;

    struct print_buf buf = INIT_PRINT_BUF(asan_buf_write_all);

    uintptr_t bad_shadow = ASAN_MEM_TO_SHADOW(bad_addr);
    uintptr_t report_start = bad_shadow - bad_shadow % width - width * lines;
    uintptr_t report_end = report_start + width * (lines * 2 + 1);
    for (uintptr_t line = report_start; line < report_end; line += width) {
        buf_printf(&buf, "%p ", (void*)ASAN_SHADOW_TO_MEM(line));
        for (uintptr_t shadow = line; shadow < line + width; shadow++) {
            uint8_t val = *(uint8_t*)shadow;
            if (shadow == bad_shadow) {
                buf_printf(&buf, "[%02x]", val);
            } else if (shadow == bad_shadow + 1) {
                buf_printf(&buf, "%02x", val);
            } else {
                buf_printf(&buf, " %02x", val);
            }
        }
        buf_flush(&buf);
    }
    log_error("asan:");
    log_error("asan: shadow byte legend (1 shadow byte = %d application bytes):",
              ASAN_SHADOW_ALIGN);
    log_error("asan: %22s 00", "addressable:");
    log_error("asan: %22s %02x..%02x", "partially addressable:", 1, ASAN_SHADOW_ALIGN - 1);
    log_error("asan: %22s %02x", "heap left redzone:", ASAN_POISON_HEAP_LEFT_REDZONE);
    log_error("asan: %22s %02x", "freed heap region:", ASAN_POISON_HEAP_AFTER_FREE);
}

/* Display full report for the user */
__attribute_no_sanitize_address
static void asan_report(void* ip_addr, uintptr_t addr, size_t size, bool is_load) {
    uintptr_t bad_addr;
    const char* bug_type;
    asan_find_problem(addr, size, &bad_addr, &bug_type);

    log_error("asan: %s while trying to %s %lu byte%s at 0x%lx", bug_type,
              is_load ? "load" : "store", size, (size > 1 ? "s" : ""), addr);
    log_error("asan: the bad address is %p (%lu from beginning of access)", (void*)bad_addr,
              bad_addr - addr);
    log_error("asan: IP = %p (for a full traceback, use GDB with a breakpoint at \"%s\")", ip_addr,
              ABORT_NAME);
    log_error("asan:");

    asan_dump(bad_addr);
}

/* Check a longer region */
__attribute_no_sanitize_address
static bool asan_check_region(uintptr_t addr, size_t size) {
    if (size == 0)
        return false;

    uintptr_t start = addr;
    uintptr_t end = addr + size;

    /* First, check if first and last byte are accessible */
    if (asan_check(start))
        return true;
    if (size > 1 && asan_check(end - 1))
        return true;

    /* Then, check all shadow bytes between start and end (it's enough if they're non-zero) */
    if (size > ASAN_SHADOW_ALIGN) {
        uintptr_t start_shadow = ASAN_MEM_TO_SHADOW(start);
        uintptr_t end_shadow = ASAN_MEM_TO_SHADOW(end - 1);
        for (uintptr_t shadow = start_shadow + 1; shadow < end_shadow; shadow++) {
            if (*(uint8_t*)shadow != 0)
                return true;
        }
    }

    return false;
}

#define ASAN_LOAD(addr, size)                                          \
    do {                                                               \
        if (asan_check_region(addr, size)) {                           \
            asan_report(RETURN_ADDR(), addr, size, /*is_load=*/true);  \
            abort();                                                   \
        }                                                              \
    } while(0)

#define ASAN_STORE(addr, size)                                         \
    do {                                                               \
        if (asan_check_region(addr, size)) {                           \
            asan_report(RETURN_ADDR(), addr, size, /*is_load=*/false); \
            abort();                                                   \
        }                                                              \
    } while(0)

#define DEFINE_ASAN_LOAD_STORE_CALLBACKS(size)                     \
    void __asan_load##size(uintptr_t addr) {                       \
        ASAN_LOAD(addr, size);                                     \
    }                                                              \
    void __asan_store##size(uintptr_t addr) {                      \
        ASAN_STORE(addr, size);                                    \
    }                                                              \
    void __asan_report_load##size(uintptr_t addr) {                \
        asan_report(RETURN_ADDR(), addr, size, /*is_load=*/true);  \
        abort();                                                   \
    }                                                              \
    void __asan_report_store##size(uintptr_t addr) {               \
        asan_report(RETURN_ADDR(), addr, size, /*is_load=*/false); \
        abort();                                                   \
    }

DEFINE_ASAN_LOAD_STORE_CALLBACKS(1)
DEFINE_ASAN_LOAD_STORE_CALLBACKS(2)
DEFINE_ASAN_LOAD_STORE_CALLBACKS(4)
DEFINE_ASAN_LOAD_STORE_CALLBACKS(8)
DEFINE_ASAN_LOAD_STORE_CALLBACKS(16)

void __asan_loadN(uintptr_t addr, size_t size) {
    ASAN_LOAD(addr, size);
}

void __asan_storeN(uintptr_t addr, size_t size) {
    ASAN_STORE(addr, size);
}

void __asan_report_load_n(uintptr_t addr, size_t size) {
    asan_report(RETURN_ADDR(), addr, size, /*is_load=*/true);
    abort();
}

void __asan_report_store_n(uintptr_t addr, size_t size) {
    asan_report(RETURN_ADDR(), addr, size, /*is_load=*/false);
    abort();
}

void __asan_handle_no_return(void) {}

void __asan_init(void) {}
void __asan_version_mismatch_check_v8(void) {}

#define DEFINE_ASAN_SET_SHADOW(name, value)                         \
    void __asan_set_shadow_ ## name (uintptr_t addr, size_t size) { \
        _real_memset((void*)addr, value, size);                     \
    }

DEFINE_ASAN_SET_SHADOW(00, 0)
DEFINE_ASAN_SET_SHADOW(f1, 0xf1)
DEFINE_ASAN_SET_SHADOW(f2, 0xf2)
DEFINE_ASAN_SET_SHADOW(f3, 0xf3)
DEFINE_ASAN_SET_SHADOW(f5, 0xf5)
DEFINE_ASAN_SET_SHADOW(f8, 0xf8)

/* Callbacks required by the compiler */

__attribute__((alias("memcpy")))
void* __asan_memcpy(void*, const void*, size_t size);
__attribute__((alias("memset")))
void* __asan_memset(void*, int, size_t);
__attribute__((alias("memmove")))
void* __asan_memmove(void*, const void*, size_t);

/* ASan-aware overrides for standard functions */

void* memcpy(void* dst, const void* src, size_t size) {
    ASAN_LOAD((uintptr_t)src, size);
    ASAN_STORE((uintptr_t)dst, size);
    return _real_memcpy(dst, src, size);
}

void* memset(void* s, int c, size_t n) {
    ASAN_STORE((uintptr_t)s, n);
    return _real_memset(s, c, n);
}

void* memmove(void* dest, const void* src, size_t n) {
    ASAN_LOAD((uintptr_t)src, n);
    ASAN_STORE((uintptr_t)dest, n);
    return _real_memmove(dest, src, n);
}

int memcmp(const void* lhs, const void* rhs, size_t count) {
    ASAN_LOAD((uintptr_t)lhs, count);
    ASAN_LOAD((uintptr_t)rhs, count);
    return _real_memcmp(lhs, rhs, count);
}
