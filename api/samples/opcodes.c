/* ******************************************************************************
 * Copyright (c) 2015-2018 Google, Inc.  All rights reserved.
 * ******************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Code Manipulation API Sample:
 * opcodes.c
 *
 * Reports the dynamic count of the total number of instructions executed
 * broken down by opcode.
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drx.h"

#include <stdlib.h> /* qsort */
#include <string.h>

#ifdef WINDOWS
#    define DISPLAY_STRING(msg) dr_messagebox(msg)
#else
#    define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
#endif

#define NULL_TERMINATE(buf) (buf)[(sizeof((buf)) / sizeof((buf)[0])) - 1] = '\0'

/* We keep a separate execution count per opcode.
 *
 * XXX: our counters are racy on ARM.  We use DRX_COUNTER_LOCK to make them atomic
 * (at a perf cost) on x86.
 *
 * XXX: we're using 32-bit counters.  64-bit counters are more challenging: they're
 * harder to make atomic on 32-bit x86, and drx does not yet support them on ARM.
 */
enum {
#ifdef X86
    ISA_X86_32,
    ISA_X86_64,
#elif defined(ARM)
    ISA_ARM_A32,
    ISA_ARM_THUMB,
#elif defined(AARCH64)
    ISA_ARM_A64,
#endif
    NUM_ISA_MODE,
};

/* These are used to define regions of interest. In practice they correspond to
 * unnalocated hint instructions that are treated as NOPs. */
#ifdef X86
    #define __START_TRACE_INSTR "\x66\x0f\x1f\x04\x25\x24\x00\x00\x00"
    #define __STOP_TRACE_INSTR "\x66\x0f\x1f\x04\x25\x42\x00\x00\x00"
    // #define __START_TRACE() { asm volatile ("nopw 0x24"); }
    // #define  __STOP_TRACE() { asm volatile ("nopw 0x42"); }
#elif defined(ARM) || defined(AARCH64)
    #define __START_TRACE_INSTR "\x5f\x25\x03\xd5"
    #define __STOP_TRACE_INSTR "\x7f\x25\x03\xd5"
    // #define __START_TRACE() { asm volatile ("hint 0x2a"); }
    // #define __STOP_TRACE() { asm volatile ("hint 0x2b"); }
#else
    #error invalid target
#endif

#define __START_TRACE_INSTR_SIZE (sizeof(__START_TRACE_INSTR)-1)
#define __STOP_TRACE_INSTR_SIZE (sizeof( __STOP_TRACE_INSTR)-1)

// Count inside the region of interest. Start paused by default.
static bool count_enabled = false;

typedef enum {
    OP_TYPE_OTHER,

    OP_TYPE_SIMD_LOAD,
    OP_TYPE_SCALAR_LOAD,

    OP_TYPE_SIMD_STORE,
    OP_TYPE_SCALAR_STORE,

    OP_TYPE_SIMD_REGISTER,
    OP_TYPE_SCALAR_REGISTER,

    OP_TYPE_SIMD_FLOAT,
    OP_TYPE_SCALAR_FLOAT,

    OP_TYPE_SIMD_INTEGER,
    OP_TYPE_SCALAR_INTEGER,

    OP_TYPE_BRANCH,

    NUM_OP_TYPES
} op_type_t;

static const char *op_type_names[NUM_OP_TYPES] = {
    "OTHER",

    "SIMD_LOAD",
    "SCALAR_LOAD",

    "SIMD_STORE",
    "SCALAR_STORE",

    "SIMD_REGISTER",
    "SCALAR_REGISTER",

    "SIMD_FLOAT",
    "SCALAR_FLOAT",

    "SIMD_INTEGER",
    "SCALAR_INTEGER",

    "BRANCH",
};

static uint64 total_bytes_read;
static uint64 total_bytes_write;
static uint64 op_type_count[NUM_OP_TYPES];
static uint64 op_reads[NUM_ISA_MODE][OP_LAST + 1];
static uint64 op_writes[NUM_ISA_MODE][OP_LAST + 1];
static uint64 op_memory[4]; // 0-LD / 1-ST / 2-LD&ST / 3-None
static uint64 count[NUM_ISA_MODE][OP_LAST + 1];

#define NUM_COUNT sizeof(count[0]) / sizeof(count[0][0])
/* We only display the top 15 counts.  This sample could be extended to
 * write all the counts to a file.
 *
 * XXX: DynamoRIO uses a separate stack for better transparency. DynamoRIO stack
 * has limited size, so we should keep NUM_COUNT_SHOW small to avoid the message
 * buffer (char msg[NUM_COUNT_SHOW*80]) in event_exit() overflowing the stack.
 * It won't work on Windows either if the output is too large.
 */
#define NUM_COUNT_SHOW 100

static void
event_exit(void);
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data);

static void update_op_type_count(void *drcontext, instrlist_t *bb, instr_t *instr,
                                 instr_t *ins, int num_reads_mem, int num_writes_mem) {
    bool added = false;

    // To avoid calling drx_insert all the time.
    #define increment_counter(op_type, cnt) \
        drx_insert_counter_update(drcontext,bb,instr,SPILL_SLOT_MAX+1, \
                IF_AARCHXX_(SPILL_SLOT_MAX+1) \
                &op_type_count[(op_type)],(cnt),DRX_COUNTER_64BIT); \
            added = true;

    bool is_simd = instr_is_simd(ins);

    // x86 can read and write memory in the same instruction.
    if (num_reads_mem > 0 || num_writes_mem > 0) {
        // mov/integer/float
        if (is_simd) {
            // simd load or simd instruction that reads memory.
            if (num_reads_mem > 0) {
                increment_counter(OP_TYPE_SIMD_LOAD, num_reads_mem);
            }
            // simd store or simd instruction that reads memory.
            if (num_writes_mem > 0) {
                increment_counter(OP_TYPE_SIMD_STORE, num_writes_mem);
            }
        }
        else {
            // scalar load or scalar instruction that writes memory.
            if (num_reads_mem > 0) {
                increment_counter(OP_TYPE_SCALAR_LOAD, num_reads_mem);
            }
            // scalar store or scalar instruction that writes memory.
            if (num_writes_mem > 0) {
                increment_counter(OP_TYPE_SCALAR_STORE, num_writes_mem);
            }
        }
    }
    else if (instr_is_ldst(ins)) {
        if (is_simd) {
            // simd register instruction
            increment_counter(OP_TYPE_SIMD_REGISTER, 1);
        }
        else {
            // scalar register instruction
            increment_counter(OP_TYPE_SCALAR_REGISTER, 1);
        }
    }
    // x86 can read/write memory and compute in the same instruction.
    if (instr_is_integer(ins)) {
        if (is_simd) {
            increment_counter(OP_TYPE_SIMD_INTEGER, 1);
        }
        else {
            increment_counter(OP_TYPE_SCALAR_INTEGER, 1);
        }
    }
    else if (instr_is_float(ins)) {
        if (is_simd) {
            increment_counter(OP_TYPE_SIMD_FLOAT, 1);
        }
        else {
            increment_counter(OP_TYPE_SCALAR_FLOAT, 1);
        }
    }

    // x86 can increment a variable and branch on the same instruction.
    if (instr_is_branch(ins)) {
        increment_counter(OP_TYPE_BRANCH, 1);
    }

    if (!added) {
        increment_counter(OP_TYPE_OTHER, 1);
    }

    #undef increment_counter
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    int i, j;
    for (j = 0; j < NUM_ISA_MODE; j++) {
      for (i = 0; i <= OP_LAST; i++) {
        op_reads[j][i] = 0;
        op_writes[j][i] = 0;
        count[j][i] = 0;
      }
    }
    op_memory[0] = 0;
    op_memory[1] = 0;
    op_memory[2] = 0;
    op_memory[3] = 0;

    total_bytes_read = 0;
    total_bytes_write = 0;

    for (i = 0; i < NUM_OP_TYPES; ++i) {
        op_type_count[i] = 0;
    }

    dr_set_client_name("DynamoRIO Sample Client 'opcodes'",
                       "http://dynamorio.org/issues");
    if (!drmgr_init())
        DR_ASSERT(false);
    drx_init();

    /* Register events: */
    dr_register_exit_event(event_exit);
    if (!drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL))
        DR_ASSERT(false);

    /* Make it easy to tell from the log file which client executed. */
    dr_log(NULL, DR_LOG_ALL, 1, "Client 'opcodes' initializing\n");
#ifdef SHOW_RESULTS
    /* Also give notification to stderr. */
    if (dr_is_notify_on()) {
#    ifdef WINDOWS
        /* Ask for best-effort printing to cmd window.  Must be called at init. */
        dr_enable_console_printing();
#    endif
        dr_fprintf(STDERR, "Client opcodes is running\n");
    }
#endif
}

#ifdef SHOW_RESULTS
/* We use cur_isa to iterate each ISA counters in event_exit, so there will be
 * no race on accessing it in compare_counts.
 */
static uint cur_isa;
static int
compare_counts(const void *a_in, const void *b_in)
{
    const uint a = *(const uint *)a_in;
    const uint b = *(const uint *)b_in;
    if (count[cur_isa][a] > count[cur_isa][b])
        return 1;
    if (count[cur_isa][a] < count[cur_isa][b])
        return -1;
    return 0;
}

static const char *
get_isa_mode_name(uint isa_mode)
{
#    ifdef X86
    return (isa_mode == ISA_X86_32) ? "32-bit X86" : "64-bit AMD64";
#    elif defined(ARM)
    return (isa_mode == ISA_ARM_A32) ? "32-bit ARM" : "32-bit Thumb";
#    elif defined(AARCH64)
    return "64-bit AArch64";
#    else
    return "unknown";
#    endif
}
#endif

static void
event_exit(void)
{
  printf("Showing results\n");
#ifdef SHOW_RESULTS
    int i;
    /* First, sort the counts */
    uint indices[NUM_COUNT];
    for (cur_isa = 0; cur_isa < NUM_ISA_MODE; cur_isa++) {
        for (i = 0; i <= OP_LAST; i++) indices[i] = i;
        qsort(indices, NUM_COUNT, sizeof(indices[0]), compare_counts);

        printf("Top %d opcode execution counts in %s mode:\n",
            NUM_COUNT_SHOW, get_isa_mode_name(cur_isa));
        for (i = OP_LAST; i >= OP_LAST - 1 - NUM_COUNT_SHOW; i--) {
            if (count[cur_isa][indices[i]] != 0) {
                printf("  %9lu : %-15s %lu %lu\n",
                    count[cur_isa][indices[i]],
                    decode_opcode_name(indices[i]),
                    op_reads[cur_isa][indices[i]],
                    op_writes[cur_isa][indices[i]]);
            }
        }
        printf("\n");

        printf("Instruction mix:\n");
        for (i = 0; i < NUM_OP_TYPES; ++i) {
            printf("\t%s: %ld\n", op_type_names[i], op_type_count[i]);
        }

        printf("\n");
        printf("Total bytes read: %ld\n", total_bytes_read);
        printf("Total bytes written: %ld\n", total_bytes_write);
        printf("\n");

        printf("Memory Instructions (disambiguation)\n"
               "\tRegister  %ld\n"
               "\tMem.Read  %ld\n"
               "\tMem.Write %ld\n"
               "\tMem.R/W   %ld\n",op_memory[3],op_memory[0],op_memory[1],op_memory[2]);
        
        fflush(stdout);
    }
#endif /* SHOW_RESULTS */
    if (!drmgr_unregister_bb_insertion_event(event_app_instruction))
        DR_ASSERT(false);
    drx_exit();
    drmgr_exit();
}

static uint
get_count_isa_idx(void *drcontext)
{
    switch (dr_get_isa_mode(drcontext)) {
#ifdef X86
    case DR_ISA_X86: return ISA_X86_32;
    case DR_ISA_AMD64: return ISA_X86_64;
#elif defined(ARM)
    case DR_ISA_ARM_A32: return ISA_ARM_A32; break;
    case DR_ISA_ARM_THUMB: return ISA_ARM_THUMB;
#elif defined(AARCH64)
    case DR_ISA_ARM_A64: return ISA_ARM_A64;
#endif
    default: DR_ASSERT(false); /* NYI */
    }
    return 0;
}

/* This is called separately for each instruction in the block. */
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    drmgr_disable_auto_predication(drcontext, bb);
    if (drmgr_is_first_instr(drcontext, instr)) {
        instr_t *ins;
        uint isa_idx = get_count_isa_idx(drcontext);

        /* Normally looking ahead should be performed in the analysis event, but
         * here that would require storing the counts into an array passed in
         * user_data.  We avoid that overhead by cheating drmgr's model a little
         * bit and looking forward.  An alternative approach would be to insert
         * each counter before its respective instruction and have an
         * instru2instru pass that pulls the increments together to reduce
         * overhead.
         */
        for (ins = instrlist_first_app(bb); ins != NULL; ins = instr_get_next_app(ins)) {
            byte *const ins_raw = instr_get_raw_bits(ins);
            int const ins_size = instr_length(drcontext, ins);

            if (ins_size == __START_TRACE_INSTR_SIZE &&
                memcmp(__START_TRACE_INSTR, ins_raw, __START_TRACE_INSTR_SIZE) == 0) { 
                count_enabled = true; 
                fprintf(stderr, "Client opcodes: Start counting instructions\n");
                continue; 
            }
            else if (ins_size == __STOP_TRACE_INSTR_SIZE && 
                     memcmp( __STOP_TRACE_INSTR, ins_raw,  __STOP_TRACE_INSTR_SIZE) == 0) { 
                count_enabled = false;
                fprintf(stderr, "Client opcodes: Stop counting instructions\n");
                continue;
            }

            if (!count_enabled) {
                continue;
            }

            /* We insert all increments sequentially up front so that drx can
             * optimize the spills and restores.
             */
            drx_insert_counter_update(drcontext, bb, instr,
                                      /* We're using drmgr, so these slots
                                       * here won't be used: drreg's slots will be.
                                       */
                                      SPILL_SLOT_MAX + 1,
                                      IF_AARCHXX_(SPILL_SLOT_MAX + 1)
                                      &count[isa_idx][instr_get_opcode(ins)],
                                      1,
                                      /* DRX_COUNTER_LOCK is not yet supported on ARM */
                                      DRX_COUNTER_64BIT); // DRX_COUNTER_64BIT | IF_X86_ELSE(DRX_COUNTER_LOCK, 0)
            uint num_mem_reads = 0;
            uint num_bytes_read = 0;
            if (instr_reads_memory(ins)) {
              int a;
              opnd_t curop;
              for (a = 0; a < instr_num_srcs(ins); a++) {
                  curop = instr_get_src(ins, a);
                  if (opnd_is_memory_reference(curop)) {
                      num_bytes_read += opnd_size_in_bytes(opnd_get_size(curop));
                      ++num_mem_reads;
                  }
              }
              drx_insert_counter_update(
                  drcontext,bb,instr,SPILL_SLOT_MAX+1,IF_AARCHXX_(SPILL_SLOT_MAX+1)
                  &op_reads[isa_idx][instr_get_opcode(ins)],num_bytes_read,DRX_COUNTER_64BIT);
            }
            uint num_mem_writes = 0;
            uint num_bytes_write = 0;
            if (instr_writes_memory(ins)) {
              int a;
              opnd_t curop;
              for (a = 0; a < instr_num_dsts(ins); a++) {
                  curop = instr_get_dst(ins, a);
                  if (opnd_is_memory_reference(curop)) {
                    num_bytes_write += opnd_size_in_bytes(opnd_get_size(curop));
                    ++num_mem_writes;
                  }
              }
            }

            drx_insert_counter_update(
                drcontext,bb,instr,SPILL_SLOT_MAX+1,IF_AARCHXX_(SPILL_SLOT_MAX+1)
                &total_bytes_read,num_bytes_read,DRX_COUNTER_64BIT);

            drx_insert_counter_update(
                drcontext,bb,instr,SPILL_SLOT_MAX+1,IF_AARCHXX_(SPILL_SLOT_MAX+1)
                &total_bytes_write,num_bytes_write,DRX_COUNTER_64BIT);

            update_op_type_count(drcontext, bb, instr, ins, num_mem_reads, num_mem_writes);

            drx_insert_counter_update(
                drcontext,bb,instr,SPILL_SLOT_MAX+1,IF_AARCHXX_(SPILL_SLOT_MAX+1)
                &op_memory[3],1,DRX_COUNTER_64BIT);

            if (num_bytes_read==0 && num_bytes_write==0) {
              drx_insert_counter_update(
                  drcontext,bb,instr,SPILL_SLOT_MAX+1,IF_AARCHXX_(SPILL_SLOT_MAX+1)
                  &op_memory[3],1,DRX_COUNTER_64BIT);
            } else if (num_bytes_read>0 && num_bytes_write>0) {
              drx_insert_counter_update(
                  drcontext,bb,instr,SPILL_SLOT_MAX+1,IF_AARCHXX_(SPILL_SLOT_MAX+1)
                  &op_memory[2],1,DRX_COUNTER_64BIT);
            } else if (num_bytes_read>0) {
              drx_insert_counter_update(
                  drcontext,bb,instr,SPILL_SLOT_MAX+1,IF_AARCHXX_(SPILL_SLOT_MAX+1)
                  &op_memory[0],1,DRX_COUNTER_64BIT);
            } else if (num_bytes_write>0) {
              drx_insert_counter_update(
                  drcontext,bb,instr,SPILL_SLOT_MAX+1,IF_AARCHXX_(SPILL_SLOT_MAX+1)
                  &op_memory[1],1,DRX_COUNTER_64BIT);
            }
        }
    }
    return DR_EMIT_DEFAULT;
}
