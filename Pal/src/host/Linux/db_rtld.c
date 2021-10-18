/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University  */
/* Copyright (C) 2021 Intel Labs */

/*
 * This file contains host-specific code related to linking and reporting ELFs to debugger.
 *
 * Overview of ELF files used in this host:
 * - libpal.so - used as main executable, so it doesn't need to be reported separately
 * - vDSO - virtual library loaded by host Linux, doesn't need to be reported
 * - LibOS, application, libc... - reported through DkDebugMap*
 */

#include "api.h"
#include "cpu.h"
#include "debug_map.h"
#include "elf/elf.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_rtld.h"

uintptr_t g_vdso_start = 0;
uintptr_t g_vdso_end = 0;

bool is_in_vdso(uintptr_t addr) {
    return (g_vdso_start || g_vdso_end) && g_vdso_start <= addr && addr < g_vdso_end;
}

void _DkDebugMapAdd(const char* name, void* addr) {
    int ret = debug_map_add(name, addr);
    if (ret < 0)
        log_error("debug_map_add(%s, %p) failed: %d", name, addr, ret);
}

void _DkDebugMapRemove(void* addr) {
    int ret = debug_map_remove(addr);
    if (ret < 0)
        log_error("debug_map_remove(%p) failed: %d", addr, ret);
}

/* populate g_vdso_start/g_vdso_end and g_linux_state.vdso_clock_gettime based on vDSO */
int setup_vdso(ElfW(Addr) base_addr) {
    int ret;

    const ElfW(Ehdr)* header = (void*)base_addr;
    const ElfW(Phdr)* phdr = (void*)(base_addr + header->e_phoff);

    int pt_loads_count = 0;

    /* iterate through vDSO's program headers to populate g_vdso_start/g_vdso_end addresses */
    for (const ElfW(Phdr)* ph = phdr; ph < &phdr[header->e_phnum]; ph++) {
        if (ph->p_type == PT_LOAD) {
            g_vdso_start = (uintptr_t)base_addr;
            g_vdso_end = ALIGN_UP(g_vdso_start + (size_t)ph->p_memsz, PAGE_SIZE);
            pt_loads_count++;
        }
    }

    if (pt_loads_count != 1) {
        log_warning("The VDSO has %d PT_LOAD segments, but only 1 was expected.", pt_loads_count);
        g_vdso_start = 0;
        g_vdso_end = 0;
        return -PAL_ERROR_DENIED;
    }

    const char* string_table = NULL;
    ElfW(Sym)* symbol_table  = NULL;
    int symbol_table_cnt     = 0;

    ret = find_string_and_symbol_tables(base_addr, base_addr, &string_table, &symbol_table,
                                        &symbol_table_cnt);
    if (ret < 0) {
        log_warning("The VDSO unexpectedly doesn't have string table or symbol table.");
        return 0;
    }

    /* iterate through the symbol table and find where clock_gettime vDSO func is located */
    for (int i = 0; i < symbol_table_cnt; i++) {
        const char* symbol_name = string_table + symbol_table[i].st_name;
        if (!strcmp("__vdso_clock_gettime", symbol_name)) {
            g_linux_state.vdso_clock_gettime = (void*)(base_addr + symbol_table[i].st_value);
            break;
        }
    }

    return 0;
}
