/* **********************************************************
 * Copyright (c) 2011-2021 Google, Inc.  All rights reserved.
 * Copyright (c) 2000-2010 VMware, Inc.  All rights reserved.
 * **********************************************************/

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

/* Copyright (c) 2003-2007 Determina Corp. */
/* Copyright (c) 2001-2003 Massachusetts Institute of Technology */
/* Copyright (c) 2000-2001 Hewlett-Packard Company */

#include "../globals.h"
#include "arch.h"
#include "instr.h"
#include "decode.h"
#include "decode_private.h"
#include "instr_create_shared.h"

#ifdef X64
/*
 * Each instruction stores whether it should be interpreted in 32-bit
 * (x86) or 64-bit (x64) mode.  This routine sets the mode for \p instr.
 */
void
instr_set_x86_mode(instr_t *instr, bool x86)
{
    if (x86)
        instr->flags |= INSTR_X86_MODE;
    else
        instr->flags &= ~INSTR_X86_MODE;
}

/*
 * Each instruction stores whether it should be interpreted in 32-bit
 * (x86) or 64-bit (x64) mode.  This routine returns the mode for \p instr.
 */
bool
instr_get_x86_mode(instr_t *instr)
{
    return TEST(INSTR_X86_MODE, instr->flags);
}
#endif

bool
instr_set_isa_mode(instr_t *instr, dr_isa_mode_t mode)
{
#ifdef X64
    if (mode == DR_ISA_IA32)
        instr_set_x86_mode(instr, true);
    else if (mode == DR_ISA_AMD64)
        instr_set_x86_mode(instr, false);
    else
        return false;
#else
    if (mode != DR_ISA_IA32)
        return false;
#endif
    return true;
}

dr_isa_mode_t
instr_get_isa_mode(instr_t *instr)
{
#ifdef X64
    return TEST(INSTR_X86_MODE, instr->flags) ? DR_ISA_IA32 : DR_ISA_AMD64;
#else
    return DR_ISA_IA32;
#endif
}

int
instr_length_arch(dcontext_t *dcontext, instr_t *instr)
{
    /* hardcode length for cti */
    switch (instr_get_opcode(instr)) {
    case OP_jmp:
    case OP_call:
        /* XXX i#1315: we should support 2-byte immeds => length 3 */
        return 5;
    case OP_jb:
    case OP_jnb:
    case OP_jbe:
    case OP_jnbe:
    case OP_jl:
    case OP_jnl:
    case OP_jle:
    case OP_jnle:
    case OP_jo:
    case OP_jno:
    case OP_jp:
    case OP_jnp:
    case OP_js:
    case OP_jns:
    case OP_jz:
    case OP_jnz:
        /* XXX i#1315: we should support 2-byte immeds => length 4+ */
        return 6 +
            ((TEST(PREFIX_JCC_TAKEN, instr_get_prefixes(instr)) ||
              TEST(PREFIX_JCC_NOT_TAKEN, instr_get_prefixes(instr)))
                 ? 1
                 : 0);
    case OP_jb_short:
    case OP_jnb_short:
    case OP_jbe_short:
    case OP_jnbe_short:
    case OP_jl_short:
    case OP_jnl_short:
    case OP_jle_short:
    case OP_jnle_short:
    case OP_jo_short:
    case OP_jno_short:
    case OP_jp_short:
    case OP_jnp_short:
    case OP_js_short:
    case OP_jns_short:
    case OP_jz_short:
    case OP_jnz_short:
        return 2 +
            ((TEST(PREFIX_JCC_TAKEN, instr_get_prefixes(instr)) ||
              TEST(PREFIX_JCC_NOT_TAKEN, instr_get_prefixes(instr)))
                 ? 1
                 : 0);
        /* alternative names (e.g., OP_jae_short) are equivalent,
         * so don't need to list them */
    case OP_jmp_short: return 2;
    case OP_jecxz:
    case OP_loop:
    case OP_loope:
    case OP_loopne:
        if (opnd_get_reg(instr_get_src(instr, 1)) !=
            REG_XCX IF_X64(&&!instr_get_x86_mode(instr)))
            return 3; /* need addr prefix */
        else
            return 2;
    case OP_LABEL: return 0;
    case OP_xbegin:
        /* XXX i#1315: we should support 2-byte immeds => length 4 */
        return 6;
    default: return -1;
    }
}

bool
opc_is_not_a_real_memory_load(int opc)
{
    /* lea has a mem_ref source operand, but doesn't actually read */
    if (opc == OP_lea)
        return true;
    /* The multi-byte nop has a mem/reg source operand, but it does not read. */
    if (opc == OP_nop_modrm)
        return true;
    return false;
}

/* Returns whether ordinal is within the count of memory references
 * (i.e., the caller should iterate, incrementing ordinal by one,
 * until it returns false).
 * If it returns true, sets *selected to whether this memory
 * reference actually goes through (i.e., whether it is enabled in
 * the mask).
 * If *selected is true, returns the scaled index in *result.
 *
 * On a fault, any completed memory loads have their corresponding
 * mask bits cleared, so we shouldn't have to do anything special
 * to support faults of VSIB accesses.
 */
static bool
instr_compute_VSIB_index(bool *selected OUT, app_pc *result OUT, bool *is_write OUT,
                         instr_t *instr, int ordinal, priv_mcontext_t *mc, size_t mc_size,
                         dr_mcontext_flags_t mc_flags)
{
    CLIENT_ASSERT(selected != NULL && result != NULL && mc != NULL,
                  "vsib address computation: invalid args");
    CLIENT_ASSERT(TEST(DR_MC_MULTIMEDIA, mc_flags),
                  "dr_mcontext_t.flags must include DR_MC_MULTIMEDIA");
    opnd_t src0 = instr_get_src(instr, 0);
    /* We detect whether the instruction is EVEX by looking at its potential mask operand.
     */
    bool is_evex = opnd_is_reg(src0) && reg_is_opmask(opnd_get_reg(src0));
    int opc = instr_get_opcode(instr);
    opnd_size_t index_size = OPSZ_NA;
    opnd_size_t mem_size = OPSZ_NA;
    switch (opc) {
    case OP_vgatherdpd:
        index_size = OPSZ_4;
        mem_size = OPSZ_8;
        *is_write = false;
        break;
    case OP_vgatherqpd:
        index_size = OPSZ_8;
        mem_size = OPSZ_8;
        *is_write = false;
        break;
    case OP_vgatherdps:
        index_size = OPSZ_4;
        mem_size = OPSZ_4;
        *is_write = false;
        break;
    case OP_vgatherqps:
        index_size = OPSZ_8;
        mem_size = OPSZ_4;
        *is_write = false;
        break;
    case OP_vpgatherdd:
        index_size = OPSZ_4;
        mem_size = OPSZ_4;
        *is_write = false;
        break;
    case OP_vpgatherqd:
        index_size = OPSZ_8;
        mem_size = OPSZ_4;
        *is_write = false;
        break;
    case OP_vpgatherdq:
        index_size = OPSZ_4;
        mem_size = OPSZ_8;
        *is_write = false;
        break;
    case OP_vpgatherqq:
        index_size = OPSZ_8;
        mem_size = OPSZ_8;
        *is_write = false;
        break;
    case OP_vscatterdpd:
        index_size = OPSZ_4;
        mem_size = OPSZ_8;
        *is_write = true;
        break;
    case OP_vscatterqpd:
        index_size = OPSZ_8;
        mem_size = OPSZ_8;
        *is_write = true;
        break;
    case OP_vscatterdps:
        index_size = OPSZ_4;
        mem_size = OPSZ_4;
        *is_write = true;
        break;
    case OP_vscatterqps:
        index_size = OPSZ_8;
        mem_size = OPSZ_4;
        *is_write = true;
        break;
    case OP_vpscatterdd:
        index_size = OPSZ_4;
        mem_size = OPSZ_4;
        *is_write = true;
        break;
    case OP_vpscatterqd:
        index_size = OPSZ_8;
        mem_size = OPSZ_4;
        *is_write = true;
        break;
    case OP_vpscatterdq:
        index_size = OPSZ_4;
        mem_size = OPSZ_8;
        *is_write = true;
        break;
    case OP_vpscatterqq:
        index_size = OPSZ_8;
        mem_size = OPSZ_8;
        *is_write = true;
        break;
    default: CLIENT_ASSERT(false, "non-VSIB opcode passed in"); return false;
    }
    opnd_t memop;
    reg_id_t mask_reg;
    if (is_evex) {
        /* We assume that all EVEX VSIB-using instructions have the VSIB memop as the 2nd
         * source and the (EVEX-)mask register as the 1st source for gather reads, and the
         * VSIB memop as the first destination for scatter writes.
         */
        if (*is_write)
            memop = instr_get_dst(instr, 0);
        else
            memop = instr_get_src(instr, 1);
        mask_reg = opnd_get_reg(instr_get_src(instr, 0));
    } else {
        /* We assume that all VEX VSIB-using instructions have the VSIB memop as the 1st
         * source and the mask register as the 2nd source. There are no VEX encoded AVX
         * scatter instructions.
         */
        memop = instr_get_src(instr, 0);
        mask_reg = opnd_get_reg(instr_get_src(instr, 1));
    }
    int scale = opnd_get_scale(memop);
    int index_reg_start;
    int mask_reg_start;
    uint64 index_addr;
    reg_id_t index_reg = opnd_get_index(memop);
    if (reg_get_size(index_reg) == OPSZ_64) {
        CLIENT_ASSERT(mc_size >= offsetof(dr_mcontext_t, simd) +
                              MCXT_NUM_SIMD_SSE_AVX_SLOTS * ZMM_REG_SIZE,
                      "Incompatible client, invalid dr_mcontext_t.size.");
        index_reg_start = DR_REG_START_ZMM;
    } else if (reg_get_size(index_reg) == OPSZ_32) {
        CLIENT_ASSERT(
            mc_size >= offsetof(dr_mcontext_t, simd) +
                    /* With regards to backward compatibility, ymm size slots were already
                     * there, and this is what we need to make the version check for.
                     */
                    MCXT_NUM_SIMD_SSE_AVX_SLOTS * YMM_REG_SIZE,
            "Incompatible client, invalid dr_mcontext_t.size.");
        index_reg_start = DR_REG_START_YMM;
    } else {
        CLIENT_ASSERT(mc_size >= offsetof(dr_mcontext_t, simd) +
                              MCXT_NUM_SIMD_SSE_AVX_SLOTS * YMM_REG_SIZE,
                      "Incompatible client, invalid dr_mcontext_t.size.");
        index_reg_start = DR_REG_START_XMM;
    }
    /* Size check for upper 16 AVX-512 registers, requiring updated dr_mcontext_t simd
     * size.
     */
    CLIENT_ASSERT(index_reg - index_reg_start < MCXT_NUM_SIMD_SSE_AVX_SLOTS ||
                      mc_size >= offsetof(dr_mcontext_t, simd) +
                              MCXT_NUM_SIMD_SSE_AVX_SLOTS * ZMM_REG_SIZE,
                  "Incompatible client, invalid dr_mcontext_t.size.");
    if (is_evex)
        mask_reg_start = DR_REG_START_OPMASK;
    else
        mask_reg_start = index_reg_start;

    LOG(THREAD_GET, LOG_ALL, 4,
        "%s: ordinal=%d: index size=%s, mem size=%s, index reg=%s\n", __FUNCTION__,
        ordinal, size_names[index_size], size_names[mem_size], reg_names[index_reg]);

    if (index_size == OPSZ_4) {
        int mask;
        if (ordinal >= (int)opnd_size_in_bytes(reg_get_size(index_reg)) /
                (int)opnd_size_in_bytes(mem_size))
            return false;
        if (is_evex) {
            mask = (mc->opmask[mask_reg - mask_reg_start] >> ordinal) & 0x1;
            if (mask == 0) { /* mask bit not set */
                *selected = false;
                return true;
            }
        } else {
            mask = (int)mc->simd[mask_reg - mask_reg_start].u32[ordinal];
            if (mask >= 0) { /* top bit not set */
                *selected = false;
                return true;
            }
        }
        *selected = true;
        index_addr = mc->simd[index_reg - index_reg_start].u32[ordinal];
    } else if (index_size == OPSZ_8) {
        int mask;
        /* For qword indices, the number of ordinals is not dependent on the mem_size,
         * therefore we can divide by opnd_size_in_bytes(index_size).
         */
        if (ordinal >= (int)opnd_size_in_bytes(reg_get_size(index_reg)) /
                (int)opnd_size_in_bytes(index_size))
            return false;
        if (is_evex) {
            mask = (mc->opmask[mask_reg - mask_reg_start] >> ordinal) & 0x1;
            if (mask == 0) { /* mask bit not set */
                *selected = false;
                return true;
            }
        } else {
            /* just top half */
            mask = (int)mc->simd[mask_reg - mask_reg_start].u32[ordinal * 2 + 1];
            if (mask >= 0) { /* top bit not set */
                *selected = false;
                return true;
            }
        }
        *selected = true;
#ifdef X64
        index_addr = mc->simd[index_reg - index_reg_start].reg[ordinal];
#else
        index_addr =
            (((uint64)mc->simd[index_reg - index_reg_start].u32[ordinal * 2 + 1]) << 32) |
            mc->simd[index_reg - index_reg_start].u32[ordinal * 2];
#endif
    } else
        return false;

    LOG(THREAD_GET, LOG_ALL, 4, "%s: ordinal=%d: " PFX "*%d=" PFX "\n", __FUNCTION__,
        ordinal, index_addr, scale, index_addr * scale);

    index_addr *= scale;
#ifdef X64
    *result = (app_pc)index_addr;
#else
    *result = (app_pc)(uint)index_addr; /* truncated */
#endif
    return true;
}

bool
instr_compute_address_VSIB(instr_t *instr, priv_mcontext_t *mc, size_t mc_size,
                           dr_mcontext_flags_t mc_flags, opnd_t curop, uint index,
                           OUT bool *have_addr, OUT app_pc *addr, OUT bool *write)
{
    /* We assume that any instr w/ a VSIB opnd has no other
     * memory reference (and the VSIB is a source)!  Else we'll
     * have to be more careful w/ memcount, as we have multiple
     * iters in the VSIB.
     */
    bool selected = false;
    /* XXX: b/c we have no iterator state we have to repeat the
     * full iteration on each call
     */
    uint vsib_idx = 0;
    bool is_write = false;
    *have_addr = true;
    while (instr_compute_VSIB_index(&selected, addr, &is_write, instr, vsib_idx, mc,
                                    mc_size, mc_flags) &&
           (!selected || vsib_idx < index)) {
        vsib_idx++;
        selected = false;
    }
    if (selected && vsib_idx == index) {
        *write = is_write;
        if (addr != NULL) {
            /* Add in seg, base, and disp */
            *addr = opnd_compute_address_helper(curop, mc, (ptr_int_t)*addr);
        }
        return true;
    } else
        return false;
}

/* return the branch type of the (branch) inst */
uint
instr_branch_type(instr_t *cti_instr)
{
    switch (instr_get_opcode(cti_instr)) {
    case OP_call: return LINK_DIRECT | LINK_CALL; /* unconditional */
    case OP_jmp_short:
    case OP_jmp: return LINK_DIRECT | LINK_JMP; /* unconditional */
    case OP_ret: return LINK_INDIRECT | LINK_RETURN;
    case OP_jmp_ind: return LINK_INDIRECT | LINK_JMP;
    case OP_call_ind: return LINK_INDIRECT | LINK_CALL;
    case OP_jb_short:
    case OP_jnb_short:
    case OP_jbe_short:
    case OP_jnbe_short:
    case OP_jl_short:
    case OP_jnl_short:
    case OP_jle_short:
    case OP_jnle_short:
    case OP_jo_short:
    case OP_jno_short:
    case OP_jp_short:
    case OP_jnp_short:
    case OP_js_short:
    case OP_jns_short:
    case OP_jz_short:
    case OP_jnz_short:
        /* alternative names (e.g., OP_jae_short) are equivalent,
         * so don't need to list them */
    case OP_jecxz:
    case OP_loop:
    case OP_loope:
    case OP_loopne:
    case OP_jb:
    case OP_jnb:
    case OP_jbe:
    case OP_jnbe:
    case OP_jl:
    case OP_jnl:
    case OP_jle:
    case OP_jnle:
    case OP_jo:
    case OP_jno:
    case OP_jp:
    case OP_jnp:
    case OP_js:
    case OP_jns:
    case OP_jz:
    case OP_jnz: return LINK_DIRECT | LINK_JMP; /* conditional */
    case OP_jmp_far:
        /* far direct is treated as indirect (i#823) */
        return LINK_INDIRECT | LINK_JMP | LINK_FAR;
    case OP_jmp_far_ind: return LINK_INDIRECT | LINK_JMP | LINK_FAR;
    case OP_call_far:
        /* far direct is treated as indirect (i#823) */
        return LINK_INDIRECT | LINK_CALL | LINK_FAR;
    case OP_call_far_ind: return LINK_INDIRECT | LINK_CALL | LINK_FAR;
    case OP_ret_far:
    case OP_iret: return LINK_INDIRECT | LINK_RETURN | LINK_FAR;
    default:
        LOG(THREAD_GET, LOG_ALL, 0, "branch_type: unknown opcode: %d\n",
            instr_get_opcode(cti_instr));
        CLIENT_ASSERT(false, "instr_branch_type: unknown opcode");
    }

    return LINK_INDIRECT;
}

bool
instr_is_mov(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_mov_st || opc == OP_mov_ld || opc == OP_mov_imm ||
            opc == OP_mov_seg || opc == OP_mov_priv);
}

bool
instr_is_call_arch(instr_t *instr)
{
    int opc = instr->opcode; /* caller ensures opcode is valid */
    return (opc == OP_call || opc == OP_call_far || opc == OP_call_ind ||
            opc == OP_call_far_ind);
}

bool
instr_is_call_direct(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_call || opc == OP_call_far);
}

bool
instr_is_near_call_direct(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_call);
}

bool
instr_is_call_indirect(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_call_ind || opc == OP_call_far_ind);
}

bool
instr_is_return(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_ret || opc == OP_ret_far || opc == OP_iret);
}

/*** WARNING!  The following rely on ordering of opcodes! ***/

bool
opc_is_cbr_arch(int opc)
{
    return ((opc >= OP_jo && opc <= OP_jnle) ||
            (opc >= OP_jo_short && opc <= OP_jnle_short) ||
            (opc >= OP_loopne && opc <= OP_jecxz));
}

bool
instr_is_cbr_arch(instr_t *instr) /* conditional branch */
{
    int opc = instr->opcode; /* caller ensures opcode is valid */
    return opc_is_cbr_arch(opc);
}

bool
instr_is_mbr_arch(instr_t *instr) /* multi-way branch */
{
    int opc = instr->opcode; /* caller ensures opcode is valid */
    return (opc == OP_jmp_ind || opc == OP_call_ind || opc == OP_ret ||
            opc == OP_jmp_far_ind || opc == OP_call_far_ind || opc == OP_ret_far ||
            opc == OP_iret);
}

bool
instr_is_jump_mem(instr_t *instr)
{
    return instr_get_opcode(instr) == OP_jmp_ind &&
        opnd_is_memory_reference(instr_get_target(instr));
}

bool
instr_is_far_cti(instr_t *instr) /* target address has a segment and offset */
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_jmp_far || opc == OP_call_far || opc == OP_jmp_far_ind ||
            opc == OP_call_far_ind || opc == OP_ret_far || opc == OP_iret);
}

bool
instr_is_far_abs_cti(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_jmp_far || opc == OP_call_far);
}

bool
instr_is_ubr_arch(instr_t *instr) /* unconditional branch */
{
    int opc = instr->opcode; /* caller ensures opcode is valid */
    return (opc == OP_jmp || opc == OP_jmp_short || opc == OP_jmp_far);
}

bool
instr_is_near_ubr(instr_t *instr) /* unconditional branch */
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_jmp || opc == OP_jmp_short);
}

/* This routine does NOT decode the cti of instr if the raw bits are valid,
 * since all short ctis have single-byte opcodes and so just grabbing the first
 * byte can tell if instr is a cti short
 */
bool
instr_is_cti_short(instr_t *instr)
{
    int opc;
    if (instr_opcode_valid(instr)) /* 1st choice: set opcode */
        opc = instr_get_opcode(instr);
    else if (instr_raw_bits_valid(instr)) { /* 2nd choice: 1st byte */
        /* get raw opcode
         * FIXME: figure out which callers really rely on us not
         * up-decoding here -- if nobody then just do the
         * instr_get_opcode() and get rid of all this
         */
        opc = (int)*(instr_get_raw_bits(instr));
        return (opc == RAW_OPCODE_jmp_short ||
                (opc >= RAW_OPCODE_jcc_short_start && opc <= RAW_OPCODE_jcc_short_end) ||
                (opc >= RAW_OPCODE_loop_start && opc <= RAW_OPCODE_loop_end));
    } else /* ok, fine, decode opcode */
        opc = instr_get_opcode(instr);
    return (opc == OP_jmp_short || (opc >= OP_jo_short && opc <= OP_jnle_short) ||
            (opc >= OP_loopne && opc <= OP_jecxz));
}

bool
instr_is_cti_loop(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    /* only looking for loop* and jecxz */
    return (opc >= OP_loopne && opc <= OP_jecxz);
}

/* Checks whether instr is a jecxz/loop* that was originally an app instruction.
 * All such app instructions are mangled into a jecxz/loop*,jmp_short,jmp sequence.
 * If pc != NULL, pc is expected to point the the beginning of the encoding of
 * instr, and the following instructions are assumed to be encoded in sequence
 * after instr.
 * Otherwise, the encoding is expected to be found in instr's allocated bits.
 * This routine does NOT decode instr to the opcode level.
 * The caller should remangle any short-rewrite cti before calling this routine.
 */
bool
instr_is_cti_short_rewrite(instr_t *instr, byte *pc)
{
    /* ASSUMPTION: all app jecxz/loop* are converted to the pattern
     * (jecxz/loop*,jmp_short,jmp), and all jecxz/loop* generated by DynamoRIO
     * DO NOT MATCH THAT PATTERN.
     *
     * For clients, I belive we're robust in the presence of a client adding a
     * pattern that matches ours exactly: decode_fragment() won't think it's an
     * exit cti if it's in a fine-grained fragment where we have Linkstubs.  Since
     * bb building marks as non-coarse if a client adds any cti at all (meta or
     * not), we're protected there.  The other uses of remangle are in perscache,
     * which is only for coarse once again (coarse in general has a hard time
     * finding exit ctis: case 8711/PR 213146), and instr_expand(), which shouldn't
     * be used in the presence of clients w/ bb hooks.
     * Note that we now help clients make jecxz/loop transformations that look
     * just like ours: instr_convert_short_meta_jmp_to_long() (PR 266292).
     */
    if (pc == NULL) {
        if (!instr_has_allocated_bits(instr))
            return false;
        pc = instr_get_raw_bits(instr);
        if (*pc == ADDR_PREFIX_OPCODE) {
            pc++;
            if (instr->length != CTI_SHORT_REWRITE_LENGTH + 1)
                return false;
        } else if (instr->length != CTI_SHORT_REWRITE_LENGTH)
            return false;
    } else {
        if (*pc == ADDR_PREFIX_OPCODE)
            pc++;
    }
    if (instr_opcode_valid(instr)) {
        int opc = instr_get_opcode(instr);
        if (opc < OP_loopne || opc > OP_jecxz)
            return false;
    } else {
        /* don't require decoding to opcode level */
        int raw_opc = (int)*(pc);
        if (raw_opc < RAW_OPCODE_loop_start || raw_opc > RAW_OPCODE_loop_end)
            return false;
    }
    /* now check remaining undecoded bytes */
    if (*(pc + 2) != decode_first_opcode_byte(OP_jmp_short))
        return false;
    if (*(pc + 4) != decode_first_opcode_byte(OP_jmp))
        return false;
    return true;
}

bool
instr_is_interrupt(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_int || opc == OP_int3 || opc == OP_into);
}

bool
instr_is_syscall(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    /* FIXME: Intel processors treat "syscall" as invalid in 32-bit mode;
     * do we need to treat it specially? */
    if (opc == OP_sysenter || opc == OP_syscall)
        return true;
    if (opc == OP_int) {
        int num = instr_get_interrupt_number(instr);
#ifdef WINDOWS
        return ((byte)num == 0x2e);
#else
#    ifdef VMX86_SERVER
        return ((byte)num == 0x80 || (byte)num == VMKUW_SYSCALL_GATEWAY);
#    elif defined(MACOS)
        return ((byte)num == 0x80 || /* BSD syscall */
                (byte)num == 0x81 || /* Mach syscall */
                (byte)num == 0x82);  /* Mach machine-dependent syscall */
#    else
        return ((byte)num == 0x80);
#    endif
#endif
    }
#ifdef WINDOWS
    /* PR 240258 (WOW64): consider this a syscall */
    if (instr_is_wow64_syscall(instr))
        return true;
#endif
    return false;
}

#ifdef WINDOWS
DR_API
bool
instr_is_wow64_syscall(instr_t *instr)
{
#    ifdef STANDALONE_DECODER
    /* We don't have get_os_version(), etc., and we assume this routine is not needed */
    return false;
#    else
    /* For x64 DR we assume we're controlling the wow64 code too and thus
     * a wow64 "syscall" is just an indirect call (xref i#821, i#49)
     */
    if (IF_X64_ELSE(true, !is_wow64_process(NT_CURRENT_PROCESS)))
        return false;
    CLIENT_ASSERT(get_syscall_method() == SYSCALL_METHOD_WOW64,
                  "wow64 system call inconsistency");
    if (get_os_version() < WINDOWS_VERSION_10) {
        opnd_t tgt;
        if (instr_get_opcode(instr) != OP_call_ind)
            return false;
        tgt = instr_get_target(instr);
        return (opnd_is_far_base_disp(tgt) && opnd_get_segment(tgt) == SEG_FS &&
                opnd_get_base(tgt) == REG_NULL && opnd_get_index(tgt) == REG_NULL &&
                opnd_get_disp(tgt) == WOW64_TIB_OFFSET);
    } else {
        /* It's much simpler to have a syscall gateway instruction where
         * does_syscall_ret_to_callsite() is true: so we require that the
         * instr passed here has its translation set.  This also gets the
         * syscall # into the same bb to help static analysis.
         */
        opnd_t tgt;
        app_pc xl8;
        uint imm;
        byte opbyte;
        /* We can't just compare to wow64_syscall_call_tgt b/c there are copies
         * in {ntdll,kernelbase,kernel32,user32,gdi32}!Wow64SystemServiceCall.
         * They are all identical and we could perform a hardcoded pattern match,
         * but that is fragile across updates (it broke in 1511 and again in 1607).
         * Instead we just look for "mov edx,imm; call edx; ret" and we assume
         * that will never happen in regular code.
         * XXX: should we instead consider treating the far jmp as the syscall, and
         * putting in hooks on the return paths in wow64cpu!RunSimulatedCode()
         * (might be tricky b/c we'd have to decode 64-bit code), or changing
         * the return addr?
         */
#        ifdef DEBUG
        /* We still pattern match in debug to provide a sanity check */
        static const byte WOW64_SYSSVC[] = {
            0x64, 0x8b, 0x15, 0x30, 0x00, 0x00, 0x00, /* mov edx,dword ptr fs:[30h] */
            /* The offset here varies across updates so we do do not check it */
            0x8b, 0x92, /* mov edx,dword ptr [edx+254h] */
        };
        static const byte WOW64_SYSSVC_1609[] = {
            0xff, 0x25, /* + offs for "jmp dword ptr [ntdll!Wow64Transition]" */
        };
        byte tgt_code[sizeof(WOW64_SYSSVC)];
#        endif
        if (instr_get_opcode(instr) != OP_call_ind)
            return false;
        tgt = instr_get_target(instr);
        if (!opnd_is_reg(tgt) || opnd_get_reg(tgt) != DR_REG_EDX)
            return false;
        xl8 = get_app_instr_xl8(instr);
        if (xl8 == NULL)
            return false;
        if (/* Is the "call edx" followed by a "ret"? */
            d_r_safe_read(xl8 + CTI_IND1_LENGTH, sizeof(opbyte), &opbyte) &&
            (opbyte == RET_NOIMM_OPCODE || opbyte == RET_IMM_OPCODE) &&
            /* Is the "call edx" preceded by a "mov imm into edx"? */
            d_r_safe_read(xl8 - sizeof(imm) - 1, sizeof(opbyte), &opbyte) &&
            opbyte == MOV_IMM_EDX_OPCODE) {
            /* Slightly worried: let's at least have some kind of marker a user
             * could see to make it easier to diagnose problems.
             * It's a tradeoff: less likely to break in a future update, but
             * more likely to mess up an app with unusual code.
             * We could also check whether in a system dll but we'd need to
             * cache the bounds of multiple libs.
             */
            ASSERT_CURIOSITY(
                d_r_safe_read(xl8 - sizeof(imm), sizeof(imm), &imm) &&
                    (d_r_safe_read((app_pc)(ptr_uint_t)imm, sizeof(tgt_code), tgt_code) &&
                     memcmp(tgt_code, WOW64_SYSSVC, sizeof(tgt_code)) == 0) ||
                (d_r_safe_read((app_pc)(ptr_uint_t)imm, sizeof(WOW64_SYSSVC_1609),
                               tgt_code) &&
                 memcmp(tgt_code, WOW64_SYSSVC_1609, sizeof(WOW64_SYSSVC_1609)) == 0));
            return true;
        } else
            return false;
    }
#    endif /* STANDALONE_DECODER */
}
#endif

/* looks for mov_imm and mov_st and xor w/ src==dst,
 * returns the constant they set their dst to
 */
bool
instr_is_mov_constant(instr_t *instr, ptr_int_t *value)
{
    int opc = instr_get_opcode(instr);
    if (opc == OP_xor) {
        if (opnd_same(instr_get_src(instr, 0), instr_get_dst(instr, 0))) {
            *value = 0;
            return true;
        } else
            return false;
    } else if (opc == OP_mov_imm || opc == OP_mov_st) {
        opnd_t op = instr_get_src(instr, 0);
        if (opnd_is_immed_int(op)) {
            *value = opnd_get_immed_int(op);
            return true;
        } else
            return false;
    }
    return false;
}

bool
instr_is_prefetch(instr_t *instr)
{
    int opcode = instr_get_opcode(instr);

    if (opcode == OP_prefetchnta || opcode == OP_prefetcht0 || opcode == OP_prefetcht1 ||
        opcode == OP_prefetcht2 || opcode == OP_prefetch || opcode == OP_prefetchw)
        return true;

    return false;
}

bool
instr_is_string_op(instr_t *instr)
{
    uint opc = instr_get_opcode(instr);
    return (opc == OP_ins || opc == OP_outs || opc == OP_movs || opc == OP_stos ||
            opc == OP_lods || opc == OP_cmps || opc == OP_scas);
}

bool
instr_is_rep_string_op(instr_t *instr)
{
    uint opc = instr_get_opcode(instr);
    return (opc == OP_rep_ins || opc == OP_rep_outs || opc == OP_rep_movs ||
            opc == OP_rep_stos || opc == OP_rep_lods || opc == OP_rep_cmps ||
            opc == OP_repne_cmps || opc == OP_rep_scas || opc == OP_repne_scas);
}

bool
instr_is_floating_ex(instr_t *instr, dr_fp_type_t *type OUT)
{
    int opc = instr_get_opcode(instr);

    switch (opc) {
    case OP_fnclex:
    case OP_fninit:
    case OP_fxsave32:
    case OP_fxrstor32:
    case OP_fxsave64:
    case OP_fxrstor64:
    case OP_ldmxcsr:
    case OP_stmxcsr:
    case OP_fldenv:
    case OP_fldcw:
    case OP_fnstenv:
    case OP_fnstcw:
    case OP_frstor:
    case OP_fnsave:
    case OP_fnstsw:
    case OP_xsave32:
    case OP_xrstor32:
    case OP_xsaveopt32:
    case OP_xsavec32:
    case OP_xsave64:
    case OP_xrstor64:
    case OP_xsaveopt64:
    case OP_xsavec64:
    case OP_vldmxcsr:
    case OP_vstmxcsr:
    case OP_fwait: {
        if (type != NULL)
            *type = DR_FP_STATE;
        return true;
    }

    case OP_fld:
    case OP_fst:
    case OP_fstp:
    case OP_fild:
    case OP_movntps:
    case OP_movntpd:
    case OP_movups:
    case OP_movss:
    case OP_movupd:
    case OP_movsd:
    case OP_movlps:
    case OP_movlpd:
    case OP_movhps:
    case OP_movhpd:
    case OP_movaps:
    case OP_movapd:
    case OP_movsldup:
    case OP_movshdup:
    case OP_movddup:
    case OP_vmovss:
    case OP_vmovsd:
    case OP_vmovups:
    case OP_vmovupd:
    case OP_vmovlps:
    case OP_vmovsldup:
    case OP_vmovlpd:
    case OP_vmovddup:
    case OP_vmovhps:
    case OP_vmovshdup:
    case OP_vmovhpd:
    case OP_vmovaps:
    case OP_vmovapd:
    case OP_vmovntps:
    case OP_vmovntpd:
    case OP_unpcklps:
    case OP_unpcklpd:
    case OP_unpckhps:
    case OP_unpckhpd:
    case OP_vunpcklps:
    case OP_vunpcklpd:
    case OP_vunpckhps:
    case OP_vunpckhpd:
    case OP_extractps:
    case OP_insertps:
    case OP_vextractps:
    case OP_vinsertps:
    case OP_vinsertf128:
    case OP_vextractf128:
    case OP_vbroadcastss:
    case OP_vbroadcastsd:
    case OP_vbroadcastf128:
    case OP_vperm2f128:
    case OP_vpermilpd:
    case OP_vpermilps:
    case OP_vmaskmovps:
    case OP_vmaskmovpd:
    case OP_shufps:
    case OP_shufpd:
    case OP_vshufps:
    case OP_vshufpd: {
        if (type != NULL)
            *type = DR_FP_MOVE;
        return true;
    }

    case OP_fist:
    case OP_fistp:
    case OP_fbld:
    case OP_fbstp:
    case OP_fisttp:
    case OP_cvtpi2ps:
    case OP_cvtsi2ss:
    case OP_cvtpi2pd:
    case OP_cvtsi2sd:
    case OP_cvttps2pi:
    case OP_cvttss2si:
    case OP_cvttpd2pi:
    case OP_cvttsd2si:
    case OP_cvtps2pi:
    case OP_cvtss2si:
    case OP_cvtpd2pi:
    case OP_cvtsd2si:
    case OP_cvtps2pd:
    case OP_cvtss2sd:
    case OP_cvtpd2ps:
    case OP_cvtsd2ss:
    case OP_cvtdq2ps:
    case OP_cvttps2dq:
    case OP_cvtps2dq:
    case OP_cvtdq2pd:
    case OP_cvttpd2dq:
    case OP_cvtpd2dq:
    case OP_vcvtsi2ss:
    case OP_vcvtsi2sd:
    case OP_vcvttss2si:
    case OP_vcvttsd2si:
    case OP_vcvtss2si:
    case OP_vcvtsd2si:
    case OP_vcvtps2pd:
    case OP_vcvtss2sd:
    case OP_vcvtpd2ps:
    case OP_vcvtsd2ss:
    case OP_vcvtdq2ps:
    case OP_vcvttps2dq:
    case OP_vcvtps2dq:
    case OP_vcvtdq2pd:
    case OP_vcvttpd2dq:
    case OP_vcvtpd2dq:
    case OP_vcvtph2ps:
    case OP_vcvtps2ph: {
        if (type != NULL)
            *type = DR_FP_CONVERT;
        return true;
    }

    case OP_ucomiss:
    case OP_ucomisd:
    case OP_comiss:
    case OP_comisd:
    case OP_movmskps:
    case OP_movmskpd:
    case OP_sqrtps:
    case OP_sqrtss:
    case OP_sqrtpd:
    case OP_sqrtsd:
    case OP_rsqrtps:
    case OP_rsqrtss:
    case OP_rcpps:
    case OP_rcpss:
    case OP_andps:
    case OP_andpd:
    case OP_andnps:
    case OP_andnpd:
    case OP_orps:
    case OP_orpd:
    case OP_xorps:
    case OP_xorpd:
    case OP_addps:
    case OP_addss:
    case OP_addpd:
    case OP_addsd:
    case OP_mulps:
    case OP_mulss:
    case OP_mulpd:
    case OP_mulsd:
    case OP_subps:
    case OP_subss:
    case OP_subpd:
    case OP_subsd:
    case OP_minps:
    case OP_minss:
    case OP_minpd:
    case OP_minsd:
    case OP_divps:
    case OP_divss:
    case OP_divpd:
    case OP_divsd:
    case OP_maxps:
    case OP_maxss:
    case OP_maxpd:
    case OP_maxsd:
    case OP_cmpps:
    case OP_cmpss:
    case OP_cmppd:
    case OP_cmpsd:

    case OP_fadd:
    case OP_fmul:
    case OP_fcom:
    case OP_fcomp:
    case OP_fsub:
    case OP_fsubr:
    case OP_fdiv:
    case OP_fdivr:
    case OP_fiadd:
    case OP_fimul:
    case OP_ficom:
    case OP_ficomp:
    case OP_fisub:
    case OP_fisubr:
    case OP_fidiv:
    case OP_fidivr:
    case OP_fxch:
    case OP_fnop:
    case OP_fchs:
    case OP_fabs:
    case OP_ftst:
    case OP_fxam:
    case OP_fld1:
    case OP_fldl2t:
    case OP_fldl2e:
    case OP_fldpi:
    case OP_fldlg2:
    case OP_fldln2:
    case OP_fldz:
    case OP_f2xm1:
    case OP_fyl2x:
    case OP_fptan:
    case OP_fpatan:
    case OP_fxtract:
    case OP_fprem1:
    case OP_fdecstp:
    case OP_fincstp:
    case OP_fprem:
    case OP_fyl2xp1:
    case OP_fsqrt:
    case OP_fsincos:
    case OP_frndint:
    case OP_fscale:
    case OP_fsin:
    case OP_fcos:
    case OP_fcmovb:
    case OP_fcmove:
    case OP_fcmovbe:
    case OP_fcmovu:
    case OP_fucompp:
    case OP_fcmovnb:
    case OP_fcmovne:
    case OP_fcmovnbe:
    case OP_fcmovnu:
    case OP_fucomi:
    case OP_fcomi:
    case OP_ffree:
    case OP_fucom:
    case OP_fucomp:
    case OP_faddp:
    case OP_fmulp:
    case OP_fcompp:
    case OP_fsubrp:
    case OP_fsubp:
    case OP_fdivrp:
    case OP_fdivp:
    case OP_fucomip:
    case OP_fcomip:
    case OP_ffreep:

    /* SSE3/3D-Now!/SSE4 */
    case OP_haddpd:
    case OP_haddps:
    case OP_hsubpd:
    case OP_hsubps:
    case OP_addsubpd:
    case OP_addsubps:
    case OP_femms:
    case OP_movntss:
    case OP_movntsd:
    case OP_blendvps:
    case OP_blendvpd:
    case OP_roundps:
    case OP_roundpd:
    case OP_roundss:
    case OP_roundsd:
    case OP_blendps:
    case OP_blendpd:
    case OP_dpps:
    case OP_dppd:

    /* AVX */
    case OP_vucomiss:
    case OP_vucomisd:
    case OP_vcomiss:
    case OP_vcomisd:
    case OP_vmovmskps:
    case OP_vmovmskpd:
    case OP_vsqrtps:
    case OP_vsqrtss:
    case OP_vsqrtpd:
    case OP_vsqrtsd:
    case OP_vrsqrtps:
    case OP_vrsqrtss:
    case OP_vrcpps:
    case OP_vrcpss:
    case OP_vandps:
    case OP_vandpd:
    case OP_vandnps:
    case OP_vandnpd:
    case OP_vorps:
    case OP_vorpd:
    case OP_vxorps:
    case OP_vxorpd:
    case OP_vaddps:
    case OP_vaddss:
    case OP_vaddpd:
    case OP_vaddsd:
    case OP_vmulps:
    case OP_vmulss:
    case OP_vmulpd:
    case OP_vmulsd:
    case OP_vsubps:
    case OP_vsubss:
    case OP_vsubpd:
    case OP_vsubsd:
    case OP_vminps:
    case OP_vminss:
    case OP_vminpd:
    case OP_vminsd:
    case OP_vdivps:
    case OP_vdivss:
    case OP_vdivpd:
    case OP_vdivsd:
    case OP_vmaxps:
    case OP_vmaxss:
    case OP_vmaxpd:
    case OP_vmaxsd:
    case OP_vcmpps:
    case OP_vcmpss:
    case OP_vcmppd:
    case OP_vcmpsd:
    case OP_vhaddpd:
    case OP_vhaddps:
    case OP_vhsubpd:
    case OP_vhsubps:
    case OP_vaddsubpd:
    case OP_vaddsubps:
    case OP_vblendvps:
    case OP_vblendvpd:
    case OP_vroundps:
    case OP_vroundpd:
    case OP_vroundss:
    case OP_vroundsd:
    case OP_vblendps:
    case OP_vblendpd:
    case OP_vdpps:
    case OP_vdppd:
    case OP_vtestps:
    case OP_vtestpd:

    /* FMA */
    case OP_vfmadd132ps:
    case OP_vfmadd132pd:
    case OP_vfmadd213ps:
    case OP_vfmadd213pd:
    case OP_vfmadd231ps:
    case OP_vfmadd231pd:
    case OP_vfmadd132ss:
    case OP_vfmadd132sd:
    case OP_vfmadd213ss:
    case OP_vfmadd213sd:
    case OP_vfmadd231ss:
    case OP_vfmadd231sd:
    case OP_vfmaddsub132ps:
    case OP_vfmaddsub132pd:
    case OP_vfmaddsub213ps:
    case OP_vfmaddsub213pd:
    case OP_vfmaddsub231ps:
    case OP_vfmaddsub231pd:
    case OP_vfmsubadd132ps:
    case OP_vfmsubadd132pd:
    case OP_vfmsubadd213ps:
    case OP_vfmsubadd213pd:
    case OP_vfmsubadd231ps:
    case OP_vfmsubadd231pd:
    case OP_vfmsub132ps:
    case OP_vfmsub132pd:
    case OP_vfmsub213ps:
    case OP_vfmsub213pd:
    case OP_vfmsub231ps:
    case OP_vfmsub231pd:
    case OP_vfmsub132ss:
    case OP_vfmsub132sd:
    case OP_vfmsub213ss:
    case OP_vfmsub213sd:
    case OP_vfmsub231ss:
    case OP_vfmsub231sd:
    case OP_vfnmadd132ps:
    case OP_vfnmadd132pd:
    case OP_vfnmadd213ps:
    case OP_vfnmadd213pd:
    case OP_vfnmadd231ps:
    case OP_vfnmadd231pd:
    case OP_vfnmadd132ss:
    case OP_vfnmadd132sd:
    case OP_vfnmadd213ss:
    case OP_vfnmadd213sd:
    case OP_vfnmadd231ss:
    case OP_vfnmadd231sd:
    case OP_vfnmsub132ps:
    case OP_vfnmsub132pd:
    case OP_vfnmsub213ps:
    case OP_vfnmsub213pd:
    case OP_vfnmsub231ps:
    case OP_vfnmsub231pd:
    case OP_vfnmsub132ss:
    case OP_vfnmsub132sd:
    case OP_vfnmsub213ss:
    case OP_vfnmsub213sd:
    case OP_vfnmsub231ss:
    case OP_vfnmsub231sd: {
        if (type != NULL)
            *type = DR_FP_MATH;
        return true;
    }

    default: return false;
    }
}

bool
instr_can_set_single_step(instr_t *instr)
{
    return (instr_get_opcode(instr) == OP_popf || instr_get_opcode(instr) == OP_iret);
}

bool
instr_may_write_zmm_or_opmask_register(instr_t *instr)
{
    if (instr_get_prefix_flag(instr, PREFIX_EVEX))
        return true;

    for (int i = 0; i < instr_num_dsts(instr); ++i) {
        opnd_t dst = instr_get_dst(instr, i);
        if (opnd_is_reg(dst)) {
            if (reg_is_strictly_zmm(opnd_get_reg(dst)) ||
                reg_is_opmask(opnd_get_reg(dst)))
                return true;
        }
    }
    return false;
}

bool
instr_is_floating(instr_t *instr)
{
    return instr_is_floating_ex(instr, NULL);
}

bool
instr_saves_float_pc(instr_t *instr)
{
    int op = instr_get_opcode(instr);
    return (op == OP_fnsave || op == OP_fnstenv || op == OP_fxsave32 ||
            op == OP_xsave32 || op == OP_xsaveopt32 || op == OP_xsavec32 ||
            op == OP_xsavec64 || op == OP_fxsave64 || op == OP_xsave64 ||
            op == OP_xsaveopt64);
}

static bool
opcode_is_mmx(int op)
{
    switch (op) {
    case OP_emms:
    case OP_movd:
    case OP_movq:
    case OP_packssdw:
    case OP_packsswb:
    case OP_packuswb:
    case OP_paddb:
    case OP_paddw:
    case OP_paddd:
    case OP_paddsb:
    case OP_paddsw:
    case OP_paddusb:
    case OP_paddusw:
    case OP_pand:
    case OP_pandn:
    case OP_por:
    case OP_pxor:
    case OP_pcmpeqb:
    case OP_pcmpeqw:
    case OP_pcmpeqd:
    case OP_pcmpgtb:
    case OP_pcmpgtw:
    case OP_pcmpgtd:
    case OP_pmaddwd:
    case OP_pmulhw:
    case OP_pmullw:
    case OP_psllw:
    case OP_pslld:
    case OP_psllq:
    case OP_psrad:
    case OP_psraw:
    case OP_psrlw:
    case OP_psrld:
    case OP_psrlq:
    case OP_psubb:
    case OP_psubw:
    case OP_psubd:
    case OP_psubsb:
    case OP_psubsw:
    case OP_psubusb:
    case OP_psubusw:
    case OP_punpckhbw:
    case OP_punpckhwd:
    case OP_punpckhdq:
    case OP_punpcklbw:
    case OP_punpckldq:
    case OP_punpcklwd: return true;
    default: return false;
    }
}

static bool
opcode_is_opmask(int op)
{
    switch (op) {
    case OP_kmovw:
    case OP_kmovb:
    case OP_kmovq:
    case OP_kmovd:
    case OP_kandw:
    case OP_kandb:
    case OP_kandq:
    case OP_kandd:
    case OP_kandnw:
    case OP_kandnb:
    case OP_kandnq:
    case OP_kandnd:
    case OP_kunpckbw:
    case OP_kunpckwd:
    case OP_kunpckdq:
    case OP_knotw:
    case OP_knotb:
    case OP_knotq:
    case OP_knotd:
    case OP_korw:
    case OP_korb:
    case OP_korq:
    case OP_kord:
    case OP_kxnorw:
    case OP_kxnorb:
    case OP_kxnorq:
    case OP_kxnord:
    case OP_kxorw:
    case OP_kxorb:
    case OP_kxorq:
    case OP_kxord:
    case OP_kaddw:
    case OP_kaddb:
    case OP_kaddq:
    case OP_kaddd:
    case OP_kortestw:
    case OP_kortestb:
    case OP_kortestq:
    case OP_kortestd:
    case OP_kshiftlw:
    case OP_kshiftlb:
    case OP_kshiftlq:
    case OP_kshiftld:
    case OP_kshiftrw:
    case OP_kshiftrb:
    case OP_kshiftrq:
    case OP_kshiftrd:
    case OP_ktestw:
    case OP_ktestb:
    case OP_ktestq:
    case OP_ktestd: return true;
    default: return false;
    }
}

static bool
opcode_is_sse(int op)
{
    switch (op) {
    case OP_addps:
    case OP_addss:
    case OP_andnps:
    case OP_andps:
    case OP_cmpps:
    case OP_cmpss:
    case OP_comiss:
    case OP_cvtpi2ps:
    case OP_cvtps2pi:
    case OP_cvtsi2ss:
    case OP_cvtss2si:
    case OP_cvttps2pi:
    case OP_cvttss2si:
    case OP_divps:
    case OP_divss:
    case OP_ldmxcsr:
    case OP_maskmovq:
    case OP_maxps:
    case OP_maxss:
    case OP_minps:
    case OP_minss:
    case OP_movaps:
    case OP_movhps: /* == OP_movlhps */
    case OP_movlps: /* == OP_movhlps */
    case OP_movmskps:
    case OP_movntps:
    case OP_movntq:
    case OP_movss:
    case OP_movups:
    case OP_mulps:
    case OP_mulss:
    case OP_nop_modrm:
    case OP_orps:
    case OP_pavgb:
    case OP_pavgw:
    case OP_pextrw:
    case OP_pinsrw:
    case OP_pmaxsw:
    case OP_pmaxub:
    case OP_pminsw:
    case OP_pminub:
    case OP_pmovmskb:
    case OP_pmulhuw:
    case OP_prefetchnta:
    case OP_prefetcht0:
    case OP_prefetcht1:
    case OP_prefetcht2:
    case OP_psadbw:
    case OP_pshufw:
    case OP_rcpps:
    case OP_rcpss:
    case OP_rsqrtps:
    case OP_rsqrtss:
    case OP_sfence:
    case OP_shufps:
    case OP_sqrtps:
    case OP_sqrtss:
    case OP_stmxcsr:
    case OP_subps:
    case OP_subss:
    case OP_ucomiss:
    case OP_unpckhps:
    case OP_unpcklps:
    case OP_xorps: return true;
    default: return false;
    }
}

static bool
opcode_is_new_in_sse2(int op)
{
    switch (op) {
    case OP_addpd:
    case OP_addsd:
    case OP_andnpd:
    case OP_andpd:
    case OP_clflush: /* has own cpuid bit */
    case OP_cmppd:
    case OP_cmpsd:
    case OP_comisd:
    case OP_cvtdq2pd:
    case OP_cvtdq2ps:
    case OP_cvtpd2dq:
    case OP_cvtpd2pi:
    case OP_cvtpd2ps:
    case OP_cvtpi2pd:
    case OP_cvtps2dq:
    case OP_cvtps2pd:
    case OP_cvtsd2si:
    case OP_cvtsd2ss:
    case OP_cvtsi2sd:
    case OP_cvtss2sd:
    case OP_cvttpd2dq:
    case OP_cvttpd2pi:
    case OP_cvttps2dq:
    case OP_cvttsd2si:
    case OP_divpd:
    case OP_divsd:
    case OP_maskmovdqu:
    case OP_maxpd:
    case OP_maxsd:
    case OP_minpd:
    case OP_minsd:
    case OP_movapd:
    case OP_movdq2q:
    case OP_movdqa:
    case OP_movdqu:
    case OP_movhpd:
    case OP_movlpd:
    case OP_movmskpd:
    case OP_movntdq:
    case OP_movntpd:
    case OP_movnti:
    case OP_movq2dq:
    case OP_movsd:
    case OP_movupd:
    case OP_mulpd:
    case OP_mulsd:
    case OP_orpd:
    case OP_paddq:
    case OP_pmuludq:
    case OP_pshufd:
    case OP_pshufhw:
    case OP_pshuflw:
    case OP_pslldq:
    case OP_psrldq:
    case OP_psubq:
    case OP_punpckhqdq:
    case OP_punpcklqdq:
    case OP_shufpd:
    case OP_sqrtpd:
    case OP_sqrtsd:
    case OP_subpd:
    case OP_subsd:
    case OP_ucomisd:
    case OP_unpckhpd:
    case OP_unpcklpd:
    case OP_xorpd: return true;
    default: return false;
    }
}

static bool
opcode_is_widened_in_sse2(int op)
{
    switch (op) {
    case OP_pavgb:
    case OP_pavgw:
    case OP_pextrw:
    case OP_pinsrw:
    case OP_pmaxsw:
    case OP_pmaxub:
    case OP_pminsw:
    case OP_pminub:
    case OP_pmovmskb:
    case OP_pmulhuw:
    case OP_psadbw: return true;
    default: return opcode_is_mmx(op) && op != OP_emms;
    }
}

static bool
instr_has_xmm_opnd(instr_t *instr)
{
    int i;
    opnd_t opnd;
    CLIENT_ASSERT(instr_operands_valid(instr), "instr_shrink_to_16_bits: invalid opnds");
    for (i = 0; i < instr_num_dsts(instr); i++) {
        opnd = instr_get_dst(instr, i);
        if (opnd_is_reg(opnd) && reg_is_xmm(opnd_get_reg(opnd)))
            return true;
    }
    for (i = 0; i < instr_num_srcs(instr); i++) {
        opnd = instr_get_src(instr, i);
        if (opnd_is_reg(opnd) && reg_is_xmm(opnd_get_reg(opnd)))
            return true;
    }
    return false;
}

bool
instr_is_mmx(instr_t *instr)
{
    int op = instr_get_opcode(instr);
    if (opcode_is_mmx(op)) {
        /* SSE2 extends SSE and MMX integer opcodes */
        if (opcode_is_widened_in_sse2(op))
            return !instr_has_xmm_opnd(instr);
        return true;
    }
    return false;
}

// static bool
// instr_has_ymm_opnd(instr_t *instr)
// {
//     int i;
//     opnd_t opnd;
//     CLIENT_ASSERT(instr_operands_valid(instr), "instr_shrink_to_16_bits: invalid opnds");
//     for (i = 0; i < instr_num_dsts(instr); i++) {
//         opnd = instr_get_dst(instr, i);
//         if (opnd_is_reg(opnd) && reg_is_strictly_ymm(opnd_get_reg(opnd)))
//             return true;
//     }
//     for (i = 0; i < instr_num_srcs(instr); i++) {
//         opnd = instr_get_src(instr, i);
//         if (opnd_is_reg(opnd) && reg_is_strictly_ymm(opnd_get_reg(opnd)))
//             return true;
//     }
//     return false;
// }

// static bool
// instr_has_zmm_opnd(instr_t *instr)
// {
//     int i;
//     opnd_t opnd;
//     CLIENT_ASSERT(instr_operands_valid(instr), "instr_shrink_to_16_bits: invalid opnds");
//     for (i = 0; i < instr_num_dsts(instr); i++) {
//         opnd = instr_get_dst(instr, i);
//         if (opnd_is_reg(opnd) && reg_is_strictly_zmm(opnd_get_reg(opnd)))
//             return true;
//     }
//     for (i = 0; i < instr_num_srcs(instr); i++) {
//         opnd = instr_get_src(instr, i);
//         if (opnd_is_reg(opnd) && reg_is_strictly_zmm(opnd_get_reg(opnd)))
//             return true;
//     }
//     return false;
// }

bool
instr_is_opmask(instr_t *instr)
{
    int op = instr_get_opcode(instr);
    return opcode_is_opmask(op);
}

bool
instr_is_sse(instr_t *instr)
{
    int op = instr_get_opcode(instr);
    if (opcode_is_sse(op)) {
        /* SSE2 extends SSE and MMX integer opcodes */
        if (opcode_is_widened_in_sse2(op))
            return !instr_has_xmm_opnd(instr);
        return true;
    }
    return false;
}

bool
instr_is_sse2(instr_t *instr)
{
    int op = instr_get_opcode(instr);
    if (opcode_is_new_in_sse2(op))
        return true;
    /* SSE2 extends SSE and MMX integer opcodes */
    if (opcode_is_widened_in_sse2(op))
        return instr_has_xmm_opnd(instr);
    return false;
}

bool
instr_is_sse_or_sse2(instr_t *instr)
{
    return instr_is_sse(instr) || instr_is_sse2(instr);
}

bool
instr_is_sse3(instr_t *instr)
{
    int op = instr_get_opcode(instr);
    /* We rely on the enum order here.  We include OP_monitor and OP_mwait. */
    return (op >= OP_fisttp && op <= OP_movddup);
}

bool
instr_is_3DNow(instr_t *instr)
{
    int op = instr_get_opcode(instr);
    /* We rely on the enum order here. */
    return (op >= OP_femms && op <= OP_pswapd) || op == OP_prefetch || op == OP_prefetchw;
}

bool
instr_is_ssse3(instr_t *instr)
{
    int op = instr_get_opcode(instr);
    /* We rely on the enum order here. */
    return (op >= OP_pshufb && op <= OP_palignr);
}

bool
instr_is_sse41(instr_t *instr)
{
    int op = instr_get_opcode(instr);
    /* We rely on the enum order here. */
    return (op >= OP_pblendvb && op <= OP_mpsadbw && op != OP_pcmpgtq && op != OP_crc32);
}

bool
instr_is_sse42(instr_t *instr)
{
    int op = instr_get_opcode(instr);
    /* We rely on the enum order here. */
    return (op >= OP_pcmpestrm && op <= OP_pcmpistri) || op == OP_pcmpgtq ||
        op == OP_crc32 || op == OP_popcnt;
}

bool
instr_is_sse4A(instr_t *instr)
{
    int op = instr_get_opcode(instr);
    /* We rely on the enum order here. */
    return (op >= OP_popcnt && op <= OP_lzcnt);
}

bool
instr_is_mov_imm_to_tos(instr_t *instr)
{
    return instr_opcode_valid(instr) && instr_get_opcode(instr) == OP_mov_st &&
        (opnd_is_immed(instr_get_src(instr, 0)) ||
         opnd_is_near_instr(instr_get_src(instr, 0))) &&
        opnd_is_near_base_disp(instr_get_dst(instr, 0)) &&
        opnd_get_base(instr_get_dst(instr, 0)) == REG_ESP &&
        opnd_get_index(instr_get_dst(instr, 0)) == REG_NULL &&
        opnd_get_disp(instr_get_dst(instr, 0)) == 0;
}

/* Returns true iff instr is an "undefined" instruction (ud2) */
bool
instr_is_undefined(instr_t *instr)
{
    return (instr_opcode_valid(instr) &&
            (instr_get_opcode(instr) == OP_ud2a || instr_get_opcode(instr) == OP_ud2b));
}

DR_API
/* Given a cbr, change the opcode (and potentially branch hint
 * prefixes) to that of the inverted branch condition.
 */
void
instr_invert_cbr(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    CLIENT_ASSERT(instr_is_cbr(instr), "instr_invert_cbr: instr not a cbr");
    if (instr_is_cti_short_rewrite(instr, NULL)) {
        /* these all look like this:
                     jcxz cx_zero
                     jmp-short cx_nonzero
            cx_zero: jmp foo
            cx_nonzero:
         */
        uint disp1_pos = 1, disp2_pos = 3;
        if (instr_get_raw_byte(instr, 0) == ADDR_PREFIX_OPCODE) {
            disp1_pos++;
            disp2_pos++;
        }
        if (instr_get_raw_byte(instr, disp1_pos) == 2) {
            CLIENT_ASSERT(instr_get_raw_byte(instr, disp2_pos) == 5,
                          "instr_invert_cbr: cti_short_rewrite is corrupted");
            /* swap targets of the short jumps: */
            instr_set_raw_byte(instr, disp1_pos, (byte)7); /* target cx_nonzero */
            instr_set_raw_byte(instr, disp2_pos, (byte)0); /* target next inst, cx_zero */
            /* with inverted logic we don't need jmp-short but we keep it in
             * case we get inverted again */
        } else {
            /* re-invert */
            CLIENT_ASSERT(instr_get_raw_byte(instr, disp1_pos) == 7 &&
                              instr_get_raw_byte(instr, disp2_pos) == 0,
                          "instr_invert_cbr: cti_short_rewrite is corrupted");
            instr_set_raw_byte(instr, disp1_pos, (byte)2);
            instr_set_raw_byte(instr, disp2_pos, (byte)5);
        }
    } else if ((opc >= OP_jo && opc <= OP_jnle) ||
               (opc >= OP_jo_short && opc <= OP_jnle_short)) {
        switch (opc) {
        case OP_jb: opc = OP_jnb; break;
        case OP_jnb: opc = OP_jb; break;
        case OP_jbe: opc = OP_jnbe; break;
        case OP_jnbe: opc = OP_jbe; break;
        case OP_jl: opc = OP_jnl; break;
        case OP_jnl: opc = OP_jl; break;
        case OP_jle: opc = OP_jnle; break;
        case OP_jnle: opc = OP_jle; break;
        case OP_jo: opc = OP_jno; break;
        case OP_jno: opc = OP_jo; break;
        case OP_jp: opc = OP_jnp; break;
        case OP_jnp: opc = OP_jp; break;
        case OP_js: opc = OP_jns; break;
        case OP_jns: opc = OP_js; break;
        case OP_jz: opc = OP_jnz; break;
        case OP_jnz: opc = OP_jz; break;
        case OP_jb_short: opc = OP_jnb_short; break;
        case OP_jnb_short: opc = OP_jb_short; break;
        case OP_jbe_short: opc = OP_jnbe_short; break;
        case OP_jnbe_short: opc = OP_jbe_short; break;
        case OP_jl_short: opc = OP_jnl_short; break;
        case OP_jnl_short: opc = OP_jl_short; break;
        case OP_jle_short: opc = OP_jnle_short; break;
        case OP_jnle_short: opc = OP_jle_short; break;
        case OP_jo_short: opc = OP_jno_short; break;
        case OP_jno_short: opc = OP_jo_short; break;
        case OP_jp_short: opc = OP_jnp_short; break;
        case OP_jnp_short: opc = OP_jp_short; break;
        case OP_js_short: opc = OP_jns_short; break;
        case OP_jns_short: opc = OP_js_short; break;
        case OP_jz_short: opc = OP_jnz_short; break;
        case OP_jnz_short: opc = OP_jz_short; break;
        default: CLIENT_ASSERT(false, "instr_invert_cbr: unknown opcode"); break;
        }
        instr_set_opcode(instr, opc);
        /* reverse any branch hint */
        if (TEST(PREFIX_JCC_TAKEN, instr_get_prefixes(instr))) {
            instr->prefixes &= ~PREFIX_JCC_TAKEN;
            instr->prefixes |= PREFIX_JCC_NOT_TAKEN;
        } else if (TEST(PREFIX_JCC_NOT_TAKEN, instr_get_prefixes(instr))) {
            instr->prefixes &= ~PREFIX_JCC_NOT_TAKEN;
            instr->prefixes |= PREFIX_JCC_TAKEN;
        }
    } else
        CLIENT_ASSERT(false, "instr_invert_cbr: unknown opcode");
}

/* Given a machine state, returns whether or not the cbr instr would be taken
 * if the state is before execution (pre == true) or after (pre == false).
 */
bool
instr_cbr_taken(instr_t *instr, priv_mcontext_t *mcontext, bool pre)
{
    CLIENT_ASSERT(instr_is_cbr(instr), "instr_cbr_taken: instr not a cbr");
    if (instr_is_cti_loop(instr)) {
        uint opc = instr_get_opcode(instr);
        switch (opc) {
        case OP_loop: return (mcontext->xcx != (pre ? 1U : 0U));
        case OP_loope:
            return (TEST(EFLAGS_ZF, mcontext->xflags) &&
                    mcontext->xcx != (pre ? 1U : 0U));
        case OP_loopne:
            return (!TEST(EFLAGS_ZF, mcontext->xflags) &&
                    mcontext->xcx != (pre ? 1U : 0U));
        case OP_jecxz: return (mcontext->xcx == 0U);
        default: CLIENT_ASSERT(false, "instr_cbr_taken: unknown opcode"); return false;
        }
    }
    return instr_jcc_taken(instr, mcontext->xflags);
}

/* Given eflags, returns whether or not the conditional branch opc would be taken */
static bool
opc_jcc_taken(int opc, reg_t eflags)
{
    switch (opc) {
    case OP_jo:
    case OP_jo_short: return TEST(EFLAGS_OF, eflags);
    case OP_jno:
    case OP_jno_short: return !TEST(EFLAGS_OF, eflags);
    case OP_jb:
    case OP_jb_short: return TEST(EFLAGS_CF, eflags);
    case OP_jnb:
    case OP_jnb_short: return !TEST(EFLAGS_CF, eflags);
    case OP_jz:
    case OP_jz_short: return TEST(EFLAGS_ZF, eflags);
    case OP_jnz:
    case OP_jnz_short: return !TEST(EFLAGS_ZF, eflags);
    case OP_jbe:
    case OP_jbe_short: return TESTANY(EFLAGS_CF | EFLAGS_ZF, eflags);
    case OP_jnbe:
    case OP_jnbe_short: return !TESTANY(EFLAGS_CF | EFLAGS_ZF, eflags);
    case OP_js:
    case OP_js_short: return TEST(EFLAGS_SF, eflags);
    case OP_jns:
    case OP_jns_short: return !TEST(EFLAGS_SF, eflags);
    case OP_jp:
    case OP_jp_short: return TEST(EFLAGS_PF, eflags);
    case OP_jnp:
    case OP_jnp_short: return !TEST(EFLAGS_PF, eflags);
    case OP_jl:
    case OP_jl_short: return (TEST(EFLAGS_SF, eflags) != TEST(EFLAGS_OF, eflags));
    case OP_jnl:
    case OP_jnl_short: return (TEST(EFLAGS_SF, eflags) == TEST(EFLAGS_OF, eflags));
    case OP_jle:
    case OP_jle_short:
        return (TEST(EFLAGS_ZF, eflags) ||
                TEST(EFLAGS_SF, eflags) != TEST(EFLAGS_OF, eflags));
    case OP_jnle:
    case OP_jnle_short:
        return (!TEST(EFLAGS_ZF, eflags) &&
                TEST(EFLAGS_SF, eflags) == TEST(EFLAGS_OF, eflags));
    default: CLIENT_ASSERT(false, "instr_jcc_taken: unknown opcode"); return false;
    }
}

/* Given eflags, returns whether or not the conditional branch instr would be taken */
bool
instr_jcc_taken(instr_t *instr, reg_t eflags)
{
    int opc = instr_get_opcode(instr);
    CLIENT_ASSERT(instr_is_cbr(instr) && !instr_is_cti_loop(instr),
                  "instr_jcc_taken: instr not a non-jecxz/loop-cbr");
    return opc_jcc_taken(opc, eflags);
}

DR_API
/* Converts a cmovcc opcode \p cmovcc_opcode to the OP_jcc opcode that
 * tests the same bits in eflags.
 */
int
instr_cmovcc_to_jcc(int cmovcc_opcode)
{
    int jcc_opc = OP_INVALID;
    if (cmovcc_opcode >= OP_cmovo && cmovcc_opcode <= OP_cmovnle) {
        jcc_opc = cmovcc_opcode - OP_cmovo + OP_jo;
    } else {
        switch (cmovcc_opcode) {
        case OP_fcmovb: jcc_opc = OP_jb; break;
        case OP_fcmove: jcc_opc = OP_jz; break;
        case OP_fcmovbe: jcc_opc = OP_jbe; break;
        case OP_fcmovu: jcc_opc = OP_jp; break;
        case OP_fcmovnb: jcc_opc = OP_jnb; break;
        case OP_fcmovne: jcc_opc = OP_jnz; break;
        case OP_fcmovnbe: jcc_opc = OP_jnbe; break;
        case OP_fcmovnu: jcc_opc = OP_jnp; break;
        default: CLIENT_ASSERT(false, "invalid cmovcc opcode"); return OP_INVALID;
        }
    }
    return jcc_opc;
}

DR_API
/* Given \p eflags, returns whether or not the conditional move
 * instruction \p instr would execute the move.  The conditional move
 * can be an OP_cmovcc or an OP_fcmovcc instruction.
 */
bool
instr_cmovcc_triggered(instr_t *instr, reg_t eflags)
{
    int opc = instr_get_opcode(instr);
    int jcc_opc = instr_cmovcc_to_jcc(opc);
    return opc_jcc_taken(jcc_opc, eflags);
}

DR_API
dr_pred_trigger_t
instr_predicate_triggered(instr_t *instr, dr_mcontext_t *mc)
{
    dr_pred_type_t pred = instr_get_predicate(instr);
    if (pred == DR_PRED_NONE)
        return DR_PRED_TRIGGER_NOPRED;
    else if (pred == DR_PRED_COMPLEX) {
#ifndef STANDALONE_DECODER /* no safe_read there */
        int opc = instr_get_opcode(instr);
        if (opc == OP_bsf || opc == OP_bsr) {
            /* The src can't involve a multimedia reg or VSIB */
            opnd_t src = instr_get_src(instr, 0);
            CLIENT_ASSERT(instr_num_srcs(instr) == 1, "invalid predicate/instr combo");
            if (opnd_is_immed_int(src)) {
                return (opnd_get_immed_int(src) != 0) ? DR_PRED_TRIGGER_MATCH
                                                      : DR_PRED_TRIGGER_MISMATCH;
            } else if (opnd_is_reg(src)) {
                return (reg_get_value(opnd_get_reg(src), mc) != 0)
                    ? DR_PRED_TRIGGER_MATCH
                    : DR_PRED_TRIGGER_MISMATCH;
            } else if (opnd_is_memory_reference(src)) {
                ptr_int_t val;
                if (!d_r_safe_read(opnd_compute_address(src, mc),
                                   MIN(opnd_get_size(src), sizeof(val)), &val))
                    return false;
                return (val != 0) ? DR_PRED_TRIGGER_MATCH : DR_PRED_TRIGGER_MISMATCH;
            } else
                CLIENT_ASSERT(false, "invalid predicate/instr combo");
        }
        /* XXX: add other opcodes: OP_getsec, OP_xend, OP_*maskmov* */
#endif
        return DR_PRED_TRIGGER_UNKNOWN;
    } else if (pred >= DR_PRED_O && pred <= DR_PRED_NLE) {
        /* We rely on DR_PRED_ having the same ordering as the OP_jcc opcodes */
        int jcc_opc = pred - DR_PRED_O + OP_jo;
        return opc_jcc_taken(jcc_opc, mc->xflags) ? DR_PRED_TRIGGER_MATCH
                                                  : DR_PRED_TRIGGER_MISMATCH;
    }
    return DR_PRED_TRIGGER_INVALID;
}

bool
instr_predicate_reads_srcs(dr_pred_type_t pred)
{
    /* All complex instances so far read srcs. */
    return pred == DR_PRED_COMPLEX;
}

bool
instr_predicate_writes_eflags(dr_pred_type_t pred)
{
    /* Only OP_bsf and OP_bsr are conditional and write eflags, and they do
     * the eflags write unconditionally.
     */
    return pred == DR_PRED_COMPLEX;
}

bool
instr_predicate_is_cond(dr_pred_type_t pred)
{
    return pred != DR_PRED_NONE;
}

bool
reg_is_gpr(reg_id_t reg)
{
    return (reg >= REG_RAX && reg <= REG_DIL);
}

bool
reg_is_segment(reg_id_t reg)
{
    return (reg >= SEG_ES && reg <= SEG_GS);
}

bool
reg_is_stack(reg_id_t reg)
{
    return (reg == REG_RSP);
}

bool
reg_is_simd(reg_id_t reg)
{
    return reg_is_strictly_xmm(reg) || reg_is_strictly_ymm(reg) ||
        reg_is_strictly_zmm(reg) || reg_is_mmx(reg);
}

bool
reg_is_vector_simd(reg_id_t reg)
{
    return reg_is_strictly_xmm(reg) || reg_is_strictly_ymm(reg) ||
        reg_is_strictly_zmm(reg);
}

bool
reg_is_opmask(reg_id_t reg)
{
    return (reg >= DR_REG_START_OPMASK && reg <= DR_REG_STOP_OPMASK);
}

bool
reg_is_bnd(reg_id_t reg)
{
    return (reg >= DR_REG_START_BND && reg <= DR_REG_STOP_BND);
}

bool
reg_is_strictly_zmm(reg_id_t reg)
{
    return (reg >= DR_REG_START_ZMM && reg <= DR_REG_STOP_ZMM);
}

bool
reg_is_ymm(reg_id_t reg)
{
    return reg_is_strictly_ymm(reg);
}

bool
reg_is_strictly_ymm(reg_id_t reg)
{
    return (reg >= DR_REG_START_YMM && reg <= DR_REG_STOP_YMM);
}

bool
reg_is_xmm(reg_id_t reg)
{
    /* This function is deprecated and the only one out of the x86
     * reg_is_ set of functions that calls its wider sibling.
     */
    return (reg_is_strictly_xmm(reg) || reg_is_strictly_ymm(reg));
}

bool
reg_is_strictly_xmm(reg_id_t reg)
{
    return (reg >= DR_REG_START_XMM && reg <= DR_REG_STOP_XMM);
}

bool
reg_is_mmx(reg_id_t reg)
{
    return (reg >= DR_REG_START_MMX && reg <= DR_REG_STOP_MMX);
}

bool
reg_is_fp(reg_id_t reg)
{
    return (reg >= DR_REG_START_FLOAT && reg <= DR_REG_STOP_FLOAT);
}

bool
opnd_same_sizes_ok(opnd_size_t s1, opnd_size_t s2, bool is_reg)
{
    opnd_size_t s1_default, s2_default;
    decode_info_t di;
    if (s1 == s2)
        return true;
    /* This routine is used for variable sizes in INSTR_CREATE macros so we
     * check whether the default size matches.  If we need to do more
     * then we'll have to hook into encode's size resolution to resolve all
     * operands with each other's constraints at the instr level before coming here.
     */
    IF_X86_64(di.x86_mode = false);
    di.prefixes = 0;
    s1_default = resolve_variable_size(&di, s1, is_reg);
    s2_default = resolve_variable_size(&di, s2, is_reg);
    return (s1_default == s2_default);
}

instr_t *
instr_create_popa(void *drcontext)
{
    dcontext_t *dcontext = (dcontext_t *)drcontext;
    instr_t *in = instr_build(dcontext, OP_popa, 8, 2);
    instr_set_dst(in, 0, opnd_create_reg(REG_ESP));
    instr_set_dst(in, 1, opnd_create_reg(REG_EAX));
    instr_set_dst(in, 2, opnd_create_reg(REG_EBX));
    instr_set_dst(in, 3, opnd_create_reg(REG_ECX));
    instr_set_dst(in, 4, opnd_create_reg(REG_EDX));
    instr_set_dst(in, 5, opnd_create_reg(REG_EBP));
    instr_set_dst(in, 6, opnd_create_reg(REG_ESI));
    instr_set_dst(in, 7, opnd_create_reg(REG_EDI));
    instr_set_src(in, 0, opnd_create_reg(REG_ESP));
    instr_set_src(in, 1, opnd_create_base_disp(REG_ESP, REG_NULL, 0, 0, OPSZ_32_short16));
    return in;
}

instr_t *
instr_create_pusha(void *drcontext)
{
    dcontext_t *dcontext = (dcontext_t *)drcontext;
    instr_t *in = instr_build(dcontext, OP_pusha, 2, 8);
    instr_set_dst(in, 0, opnd_create_reg(REG_ESP));
    instr_set_dst(in, 1,
                  opnd_create_base_disp(REG_ESP, REG_NULL, 0, -32, OPSZ_32_short16));
    instr_set_src(in, 0, opnd_create_reg(REG_ESP));
    instr_set_src(in, 1, opnd_create_reg(REG_EAX));
    instr_set_src(in, 2, opnd_create_reg(REG_EBX));
    instr_set_src(in, 3, opnd_create_reg(REG_ECX));
    instr_set_src(in, 4, opnd_create_reg(REG_EDX));
    instr_set_src(in, 5, opnd_create_reg(REG_EBP));
    instr_set_src(in, 6, opnd_create_reg(REG_ESI));
    instr_set_src(in, 7, opnd_create_reg(REG_EDI));
    return in;
}

instr_t *
instr_create_nbyte_nop(dcontext_t *dcontext, uint num_bytes, bool raw)
{
    CLIENT_ASSERT(num_bytes != 0, "instr_create_nbyte_nop: 0 bytes passed");
    CLIENT_ASSERT(num_bytes <= 3, "instr_create_nbyte_nop: > 3 bytes not supported");
    /* INSTR_CREATE_nop*byte creates nop according to dcontext->x86_mode.
     * In x86_to_x64, we want to create x64 nop, but dcontext may be in x86 mode.
     * As a workaround, we call INSTR_CREATE_RAW_nop*byte here if in x86_to_x64.
     */
    if (raw IF_X64(|| DYNAMO_OPTION(x86_to_x64))) {
        switch (num_bytes) {
        case 1: return INSTR_CREATE_RAW_nop1byte(dcontext);
        case 2: return INSTR_CREATE_RAW_nop2byte(dcontext);
        case 3: return INSTR_CREATE_RAW_nop3byte(dcontext);
        }
    } else {
        switch (num_bytes) {
        case 1: return INSTR_CREATE_nop1byte(dcontext);
        case 2: return INSTR_CREATE_nop2byte(dcontext);
        case 3: return INSTR_CREATE_nop3byte(dcontext);
        }
    }
    CLIENT_ASSERT(false, "instr_create_nbyte_nop: invalid parameters");
    return NULL;
}

/* Borrowed from optimize.c, prob. belongs here anyways, could make it more
 * specific to the ones we create above, but know it works as is FIXME */
/* return true if this instr is a nop, does not check for all types of nops
 * since there are many, these seem to be the most common */
bool
instr_is_nop(instr_t *inst)
{
    /* XXX: could check raw bits for 0x90 to avoid the decoding if raw */
    int opcode = instr_get_opcode(inst);
    if (opcode == OP_nop || opcode == OP_nop_modrm)
        return true;
    if ((opcode == OP_mov_ld || opcode == OP_mov_st) &&
        opnd_same(instr_get_src(inst, 0), instr_get_dst(inst, 0))
        /* for 64-bit, targeting a 32-bit register zeroes the top bits => not a nop! */
        IF_X64(&&(instr_get_x86_mode(inst) || !opnd_is_reg(instr_get_dst(inst, 0)) ||
                  reg_get_size(opnd_get_reg(instr_get_dst(inst, 0))) != OPSZ_4)))
        return true;
    if (opcode == OP_xchg &&
        opnd_same(instr_get_dst(inst, 0), instr_get_dst(inst, 1))
        /* for 64-bit, targeting a 32-bit register zeroes the top bits => not a nop! */
        IF_X64(&&(instr_get_x86_mode(inst) ||
                  opnd_get_size(instr_get_dst(inst, 0)) != OPSZ_4)))
        return true;
    if (opcode == OP_lea &&
        opnd_is_base_disp(instr_get_src(inst, 0)) /* x64: rel, abs aren't base-disp */ &&
        opnd_get_disp(instr_get_src(inst, 0)) == 0 &&
        ((opnd_get_base(instr_get_src(inst, 0)) == opnd_get_reg(instr_get_dst(inst, 0)) &&
          opnd_get_index(instr_get_src(inst, 0)) == REG_NULL) ||
         (opnd_get_index(instr_get_src(inst, 0)) ==
              opnd_get_reg(instr_get_dst(inst, 0)) &&
          opnd_get_base(instr_get_src(inst, 0)) == REG_NULL &&
          opnd_get_scale(instr_get_src(inst, 0)) == 1)))
        return true;
    return false;
}

DR_API
bool
instr_is_exclusive_load(instr_t *instr)
{
    return false;
}

DR_API
bool
instr_is_exclusive_store(instr_t *instr)
{
    return false;
}

DR_API
bool
instr_is_scatter(instr_t *instr)
{
    switch (instr_get_opcode(instr)) {
    case OP_vpscatterdd:
    case OP_vscatterdpd:
    case OP_vscatterdps:
    case OP_vpscatterdq:
    case OP_vpscatterqd:
    case OP_vscatterqpd:
    case OP_vscatterqps:
    case OP_vpscatterqq: return true;
    default: return false;
    }
}

DR_API
bool
instr_is_gather(instr_t *instr)
{
    switch (instr_get_opcode(instr)) {
    case OP_vpgatherdd:
    case OP_vgatherdpd:
    case OP_vgatherdps:
    case OP_vpgatherdq:
    case OP_vpgatherqd:
    case OP_vgatherqpd:
    case OP_vgatherqps:
    case OP_vpgatherqq: return true;
    default: return false;
    }
}

// TODO: CONVERT (cvt)
static bool
instr_is_scalar_mov(instr_t *instr) {
    switch (instr_get_opcode(instr)) {
        /* point ld & st at eAX & al instrs, they save 1 byte (no modrm),
            * hopefully time taken considering them doesn't offset that */
        case /*  55 */ OP_mov_ld: /**< IA-32/AMD64 mov_ld opcode. */
        case /*  56 */ OP_mov_st: /**< IA-32/AMD64 mov_st opcode. */
        /* PR 250397: store of immed is mov_st not mov_imm even though can be immed->reg
        * which we address by sharing part of the mov_st template chain */
        case /*  57 */ OP_mov_imm:  /**< IA-32/AMD64 mov_imm opcode. */
        case /*  58 */ OP_mov_seg:  /**< IA-32/AMD64 mov_seg opcode. */
        case /*  59 */ OP_mov_priv: /**< IA-32/AMD64 mov_priv opcode. */

        case /*  62 */ OP_xchg:  /**< IA-32/AMD64 xchg opcode. */

        case /* 110 */ OP_cmovo:   /**< IA-32/AMD64 cmovo opcode. */
        case /* 111 */ OP_cmovno:  /**< IA-32/AMD64 cmovno opcode. */
        case /* 112 */ OP_cmovb:   /**< IA-32/AMD64 cmovb opcode. */
        case /* 113 */ OP_cmovnb:  /**< IA-32/AMD64 cmovnb opcode. */
        case /* 114 */ OP_cmovz:   /**< IA-32/AMD64 cmovz opcode. */
        case /* 115 */ OP_cmovnz:  /**< IA-32/AMD64 cmovnz opcode. */
        case /* 116 */ OP_cmovbe:  /**< IA-32/AMD64 cmovbe opcode. */
        case /* 117 */ OP_cmovnbe: /**< IA-32/AMD64 cmovnbe opcode. */
        case /* 118 */ OP_cmovs:   /**< IA-32/AMD64 cmovs opcode. */
        case /* 119 */ OP_cmovns:  /**< IA-32/AMD64 cmovns opcode. */
        case /* 120 */ OP_cmovp:   /**< IA-32/AMD64 cmovp opcode. */
        case /* 121 */ OP_cmovnp:  /**< IA-32/AMD64 cmovnp opcode. */
        case /* 122 */ OP_cmovl:   /**< IA-32/AMD64 cmovl opcode. */
        case /* 123 */ OP_cmovnl:  /**< IA-32/AMD64 cmovnl opcode. */
        case /* 124 */ OP_cmovle:  /**< IA-32/AMD64 cmovle opcode. */
        case /* 125 */ OP_cmovnle: /**< IA-32/AMD64 cmovnle opcode. */

        case /* 168 */ OP_seto:   /**< IA-32/AMD64 seto opcode. */
        case /* 169 */ OP_setno:  /**< IA-32/AMD64 setno opcode. */
        case /* 170 */ OP_setb:   /**< IA-32/AMD64 setb opcode. */
        case /* 171 */ OP_setnb:  /**< IA-32/AMD64 setnb opcode. */
        case /* 172 */ OP_setz:   /**< IA-32/AMD64 setz opcode. */
        case /* 173 */ OP_setnz:  /**< IA-32/AMD64 setnz opcode. */
        case /* 174 */ OP_setbe:  /**< IA-32/AMD64 setbe opcode. */
        case /* 175 */ OP_setnbe: /**< IA-32/AMD64 setnbe opcode. */
        case /* 176 */ OP_sets:   /**< IA-32/AMD64 sets opcode. */
        case /* 177 */ OP_setns:  /**< IA-32/AMD64 setns opcode. */
        case /* 178 */ OP_setp:   /**< IA-32/AMD64 setp opcode. */
        case /* 179 */ OP_setnp:  /**< IA-32/AMD64 setnp opcode. */
        case /* 180 */ OP_setl:   /**< IA-32/AMD64 setl opcode. */
        case /* 181 */ OP_setnl:  /**< IA-32/AMD64 setnl opcode. */
        case /* 182 */ OP_setle:  /**< IA-32/AMD64 setle opcode. */
        case /* 183 */ OP_setnle: /**< IA-32/AMD64 setnle opcode. */

        case /* 190 */ OP_cmpxchg:    /**< IA-32/AMD64 cmpxchg opcode. */

        case /* 193 */ OP_lfs:        /**< IA-32/AMD64 lfs opcode. */
        case /* 194 */ OP_lgs:        /**< IA-32/AMD64 lgs opcode. */

        case /* 195 */ OP_movzx:      /**< IA-32/AMD64 movzx opcode. */
        case /* 200 */ OP_movsx:      /**< IA-32/AMD64 movsx opcode. */
        case /* 202 */ OP_movnti:     /**< IA-32/AMD64 movnti opcode. */
        case /* 203 */ OP_pinsrw:     /**< IA-32/AMD64 pinsrw opcode. */
        case /* 204 */ OP_pextrw:     /**< IA-32/AMD64 pextrw opcode. */

        case /* 387 */ OP_movs:       /**< IA-32/AMD64 movs opcode. */
        case /* 388 */ OP_rep_movs:   /**< IA-32/AMD64 rep_movs opcode. */
        case /* 389 */ OP_stos:       /**< IA-32/AMD64 stos opcode. */
        case /* 390 */ OP_rep_stos:   /**< IA-32/AMD64 rep_stos opcode. */
        case /* 391 */ OP_lods:       /**< IA-32/AMD64 lods opcode. */
        case /* 392 */ OP_rep_lods:   /**< IA-32/AMD64 rep_lods opcode. */

        case /* 407 */ OP_fld:     /**< IA-32/AMD64 fld opcode. */
        case /* 408 */ OP_fst:     /**< IA-32/AMD64 fst opcode. */
        case /* 409 */ OP_fstp:    /**< IA-32/AMD64 fstp opcode. */
        case /* 422 */ OP_fild:    /**< IA-32/AMD64 fild opcode. */
        case /* 423 */ OP_fist:    /**< IA-32/AMD64 fist opcode. */
        case /* 424 */ OP_fistp:   /**< IA-32/AMD64 fistp opcode. */

        case /* 430 */ OP_fxch:     /**< IA-32/AMD64 fxch opcode. */
        case /* 447 */ OP_fxtract:  /**< IA-32/AMD64 fxtract opcode. */
        case /* 459 */ OP_fcmovb:   /**< IA-32/AMD64 fcmovb opcode. */
        case /* 460 */ OP_fcmove:   /**< IA-32/AMD64 fcmove opcode. */
        case /* 461 */ OP_fcmovbe:  /**< IA-32/AMD64 fcmovbe opcode. */
        case /* 462 */ OP_fcmovu:   /**< IA-32/AMD64 fcmovu opcode. */
        case /* 463 */ OP_fucompp:  /**< IA-32/AMD64 fucompp opcode. */
        case /* 464 */ OP_fcmovnb:  /**< IA-32/AMD64 fcmovnb opcode. */
        case /* 465 */ OP_fcmovne:  /**< IA-32/AMD64 fcmovne opcode. */
        case /* 466 */ OP_fcmovnbe: /**< IA-32/AMD64 fcmovnbe opcode. */
        case /* 467 */ OP_fcmovnu:  /**< IA-32/AMD64 fcmovnu opcode. */

        /* x64 */
        case /* 597 */ OP_movsxd: /**< IA-32/AMD64 movsxd opcode. */

        /* AMD TBM */
        case /* 1041 */ OP_bextr:   /**< IA-32/AMD64 bextr opcode. */
        case /* 1042 */ OP_blcfill: /**< IA-32/AMD64 blcfill opcode. */
        case /* 1043 */ OP_blci:    /**< IA-32/AMD64 blci opcode. */
        case /* 1044 */ OP_blcic:   /**< IA-32/AMD64 blcic opcode. */
        case /* 1045 */ OP_blcmsk:  /**< IA-32/AMD64 blcmsk opcode. */
        case /* 1046 */ OP_blcs:    /**< IA-32/AMD64 blcs opcode. */
        case /* 1047 */ OP_blsfill: /**< IA-32/AMD64 blsfill opcode. */
        case /* 1048 */ OP_blsic:   /**< IA-32/AMD64 blsic opcode. */
        case /* 1049 */ OP_t1mskc:  /**< IA-32/AMD64 t1mskc opcode. */
        case /* 1050 */ OP_tzmsk:   /**< IA-32/AMD64 tzmsk opcode. */

        /* Intel BMI1 */
        /* (includes non-immed form of OP_bextr) */
        case /* 1056 */ OP_blsr:   /**< IA-32/AMD64 blsr opcode. */
        case /* 1057 */ OP_blsmsk: /**< IA-32/AMD64 blsmsk opcode. */
        case /* 1058 */ OP_blsi:   /**< IA-32/AMD64 blsi opcode. */

        /* Intel BMI2 */
        case /* 1060 */ OP_bzhi: /**< IA-32/AMD64 bzhi opcode. */
        case /* 1061 */ OP_pext: /**< IA-32/AMD64 pext opcode. */
        case /* 1062 */ OP_pdep: /**< IA-32/AMD64 pdep opcode. */

        // TODO: SIMD?
        case /* 140 */ OP_movd:       /**< IA-32/AMD64 movd opcode. */
        case /* 141 */ OP_movq:       /**< IA-32/AMD64 movq opcode. */
        case /* 142 */ OP_movdqu:     /**< IA-32/AMD64 movdqu opcode. */
        case /* 143 */ OP_movdqa:     /**< IA-32/AMD64 movdqa opcode. */

        case /* 226 */ OP_movntq:     /**< IA-32/AMD64 movntq opcode. */
        case /* 227 */ OP_movntdq:    /**< IA-32/AMD64 movntdq opcode. */
        case /* 242 */ OP_maskmovq:   /**< IA-32/AMD64 maskmovq opcode. */
        case /* 243 */ OP_maskmovdqu: /**< IA-32/AMD64 maskmovdqu opcode. */

        case /* 294 */ OP_movss:     /**< IA-32/AMD64 movss opcode. */

        case /* 296 */ OP_movsd:     /**< IA-32/AMD64 movsd opcode. */

        /* SSE4 (incl AMD (SSE4A) and Intel-specific (SSE4.1, SSE4.2) extensions */
        case /* 540 */ OP_movntss:    /**< IA-32/AMD64 movntss opcode. */
        case /* 541 */ OP_movntsd:    /**< IA-32/AMD64 movntsd opcode. */
        case /* 542 */ OP_extrq:      /**< IA-32/AMD64 extrq opcode. */
        case /* 543 */ OP_insertq:    /**< IA-32/AMD64 insertq opcode. */
        
        case /* 557 */ OP_movntdqa:   /**< IA-32/AMD64 movntdqa opcode. */

        /* AVX */
        case /* 636 */ OP_vmovss:           /**< IA-32/AMD64 vmovss opcode. */
        case /* 637 */ OP_vmovsd:           /**< IA-32/AMD64 vmovsd opcode. */
        
        case /* 641 */ OP_vmovsldup:        /**< IA-32/AMD64 vmovsldup opcode. */

        case /* 643 */ OP_vmovddup:         /**< IA-32/AMD64 vmovddup opcode. */

        case /* 649 */ OP_vmovshdup:        /**< IA-32/AMD64 vmovshdup opcode. */

        case /* 728 */ OP_vmovd:            /**< IA-32/AMD64 vmovd opcode. */

        case /* 735 */ OP_vmovq:            /**< IA-32/AMD64 vmovq opcode. */

        case /* 767 */ OP_vmovntdq:         /**< IA-32/AMD64 vmovntdq opcode. */

        case /* 782 */ OP_vmaskmovdqu:      /**< IA-32/AMD64 vmaskmovdqu opcode. */

        case /* 792 */ OP_vmovdqu:          /**< IA-32/AMD64 vmovdqu opcode. */
        case /* 793 */ OP_vmovdqa:          /**< IA-32/AMD64 vmovdqa opcode. */

        case /* 800 */ OP_vlddqu:           /**< IA-32/AMD64 vlddqu opcode. */

        case /* 829 */ OP_vmovntdqa:        /**< IA-32/AMD64 vmovntdqa opcode. */

        /* FMA */
        case /* 953 */ OP_movq2dq: /**< IA-32/AMD64 movq2dq opcode. */
        case /* 954 */ OP_movdq2q: /**< IA-32/AMD64 movdq2q opcode. */ return true;

        default: return false;
    }
}

static bool
instr_is_simd_mov(instr_t *instr) {
    switch (instr_get_opcode(instr)) {
        case /* 102 */ OP_movntps:   /**< IA-32/AMD64 movntps opcode. */
        case /* 103 */ OP_movntpd:   /**< IA-32/AMD64 movntpd opcode. */

        case /* 126 */ OP_punpcklbw:  /**< IA-32/AMD64 punpcklbw opcode. */
        case /* 127 */ OP_punpcklwd:  /**< IA-32/AMD64 punpcklwd opcode. */
        case /* 128 */ OP_punpckldq:  /**< IA-32/AMD64 punpckldq opcode. */
        case /* 129 */ OP_packsswb:   /**< IA-32/AMD64 packsswb opcode. */

        case /* 133 */ OP_packuswb:   /**< IA-32/AMD64 packuswb opcode. */
        case /* 134 */ OP_punpckhbw:  /**< IA-32/AMD64 punpckhbw opcode. */
        case /* 135 */ OP_punpckhwd:  /**< IA-32/AMD64 punpckhwd opcode. */
        case /* 136 */ OP_punpckhdq:  /**< IA-32/AMD64 punpckhdq opcode. */
        case /* 137 */ OP_packssdw:   /**< IA-32/AMD64 packssdw opcode. */
        case /* 138 */ OP_punpcklqdq: /**< IA-32/AMD64 punpcklqdq opcode. */
        case /* 139 */ OP_punpckhqdq: /**< IA-32/AMD64 punpckhqdq opcode. */

        case /* 144 */ OP_pshufw:     /**< IA-32/AMD64 pshufw opcode. */
        case /* 145 */ OP_pshufd:     /**< IA-32/AMD64 pshufd opcode. */
        case /* 146 */ OP_pshufhw:    /**< IA-32/AMD64 pshufhw opcode. */
        case /* 147 */ OP_pshuflw:    /**< IA-32/AMD64 pshuflw opcode. */

        case /* 211 */ OP_pmovmskb:   /**< IA-32/AMD64 pmovmskb opcode. */

        case /* 293 */ OP_movups:    /**< IA-32/AMD64 movups opcode. */

        case /* 295 */ OP_movupd:    /**< IA-32/AMD64 movupd opcode. */

        case /* 297 */ OP_movlps:    /**< IA-32/AMD64 movlps opcode. */
        case /* 298 */ OP_movlpd:    /**< IA-32/AMD64 movlpd opcode. */
        case /* 299 */ OP_unpcklps:  /**< IA-32/AMD64 unpcklps opcode. */
        case /* 300 */ OP_unpcklpd:  /**< IA-32/AMD64 unpcklpd opcode. */
        case /* 301 */ OP_unpckhps:  /**< IA-32/AMD64 unpckhps opcode. */
        case /* 302 */ OP_unpckhpd:  /**< IA-32/AMD64 unpckhpd opcode. */
        case /* 303 */ OP_movhps:    /**< IA-32/AMD64 movhps opcode. */
        case /* 304 */ OP_movhpd:    /**< IA-32/AMD64 movhpd opcode. */
        case /* 305 */ OP_movaps:    /**< IA-32/AMD64 movaps opcode. */
        case /* 306 */ OP_movapd:    /**< IA-32/AMD64 movapd opcode. */
        case /* 323 */ OP_movmskps:  /**< IA-32/AMD64 movmskps opcode. */
        case /* 324 */ OP_movmskpd:  /**< IA-32/AMD64 movmskpd opcode. */

        /* SSE3 instructions */
        case /* 484 */ OP_fisttp:   /**< IA-32/AMD64 fisttp opcode. */
        case /* 491 */ OP_lddqu:    /**< IA-32/AMD64 lddqu opcode. */
        case /* 494 */ OP_movsldup: /**< IA-32/AMD64 movsldup opcode. */
        case /* 495 */ OP_movshdup: /**< IA-32/AMD64 movshdup opcode. */
        case /* 496 */ OP_movddup:  /**< IA-32/AMD64 movddup opcode. */

        /* 3D-Now! instructions */
        case /* 522 */ OP_pswapd:        /**< IA-32/AMD64 pswapd opcode. */

        /* SSSE3 */
        case /* 523 */ OP_pshufb:    /**< IA-32/AMD64 pshufb opcode. */
        case /* 538 */ OP_palignr:   /**< IA-32/AMD64 palignr opcode. */

        /* SSE4 (incl AMD (SSE4A) and Intel-specific (SSE4.1, SSE4.2) extensions */
        case /* 545 */ OP_pblendvb:   /**< IA-32/AMD64 pblendvb opcode. */
        case /* 546 */ OP_blendvps:   /**< IA-32/AMD64 blendvps opcode. */
        case /* 547 */ OP_blendvpd:   /**< IA-32/AMD64 blendvpd opcode. */
        
        case /* 549 */ OP_pmovsxbw:   /**< IA-32/AMD64 pmovsxbw opcode. */
        case /* 550 */ OP_pmovsxbd:   /**< IA-32/AMD64 pmovsxbd opcode. */
        case /* 551 */ OP_pmovsxbq:   /**< IA-32/AMD64 pmovsxbq opcode. */
        case /* 552 */ OP_pmovsxwd:   /**< IA-32/AMD64 pmovsxwd opcode. */
        case /* 553 */ OP_pmovsxwq:   /**< IA-32/AMD64 pmovsxwq opcode. */
        case /* 554 */ OP_pmovsxdq:   /**< IA-32/AMD64 pmovsxdq opcode. */
        case /* 559 */ OP_pmovzxbw:   /**< IA-32/AMD64 pmovzxbw opcode. */
        case /* 560 */ OP_pmovzxbd:   /**< IA-32/AMD64 pmovzxbd opcode. */
        case /* 561 */ OP_pmovzxbq:   /**< IA-32/AMD64 pmovzxbq opcode. */
        case /* 562 */ OP_pmovzxwd:   /**< IA-32/AMD64 pmovzxwd opcode. */
        case /* 563 */ OP_pmovzxwq:   /**< IA-32/AMD64 pmovzxwq opcode. */
        case /* 564 */ OP_pmovzxdq:   /**< IA-32/AMD64 pmovzxdq opcode. */

        case /* 577 */ OP_pextrb:     /**< IA-32/AMD64 pextrb opcode. */
        case /* 578 */ OP_pextrd:     /**< IA-32/AMD64 pextrd opcode. */
        case /* 579 */ OP_extractps:  /**< IA-32/AMD64 extractps opcode. */

        case /* 584 */ OP_blendps:    /**< IA-32/AMD64 blendps opcode. */
        case /* 585 */ OP_blendpd:    /**< IA-32/AMD64 blendpd opcode. */
        case /* 586 */ OP_pblendw:    /**< IA-32/AMD64 pblendw opcode. */
        case /* 587 */ OP_pinsrb:     /**< IA-32/AMD64 pinsrb opcode. */
        case /* 588 */ OP_insertps:   /**< IA-32/AMD64 insertps opcode. */
        case /* 589 */ OP_pinsrd:     /**< IA-32/AMD64 pinsrd opcode. */

        /* AVX */
        case /* 638 */ OP_vmovups:          /**< IA-32/AMD64 vmovups opcode. */
        case /* 639 */ OP_vmovupd:          /**< IA-32/AMD64 vmovupd opcode. */
        case /* 640 */ OP_vmovlps:          /**< IA-32/AMD64 vmovlps opcode. */

        case /* 642 */ OP_vmovlpd:          /**< IA-32/AMD64 vmovlpd opcode. */

        case /* 644 */ OP_vunpcklps:        /**< IA-32/AMD64 vunpcklps opcode. */
        case /* 645 */ OP_vunpcklpd:        /**< IA-32/AMD64 vunpcklpd opcode. */
        case /* 646 */ OP_vunpckhps:        /**< IA-32/AMD64 vunpckhps opcode. */
        case /* 647 */ OP_vunpckhpd:        /**< IA-32/AMD64 vunpckhpd opcode. */
        case /* 648 */ OP_vmovhps:          /**< IA-32/AMD64 vmovhps opcode. */

        case /* 650 */ OP_vmovhpd:          /**< IA-32/AMD64 vmovhpd opcode. */
        case /* 651 */ OP_vmovaps:          /**< IA-32/AMD64 vmovaps opcode. */
        case /* 652 */ OP_vmovapd:          /**< IA-32/AMD64 vmovapd opcode. */

        case /* 655 */ OP_vmovntps:         /**< IA-32/AMD64 vmovntps opcode. */
        case /* 656 */ OP_vmovntpd:         /**< IA-32/AMD64 vmovntpd opcode. */

        case /* 665 */ OP_vmovmskps:        /**< IA-32/AMD64 vmovmskps opcode. */
        case /* 666 */ OP_vmovmskpd:        /**< IA-32/AMD64 vmovmskpd opcode. */

        case /* 714 */ OP_vpunpcklbw:       /**< IA-32/AMD64 vpunpcklbw opcode. */
        case /* 715 */ OP_vpunpcklwd:       /**< IA-32/AMD64 vpunpcklwd opcode. */
        case /* 716 */ OP_vpunpckldq:       /**< IA-32/AMD64 vpunpckldq opcode. */
        case /* 717 */ OP_vpacksswb:        /**< IA-32/AMD64 vpacksswb opcode. */

        case /* 721 */ OP_vpackuswb:        /**< IA-32/AMD64 vpackuswb opcode. */
        case /* 722 */ OP_vpunpckhbw:       /**< IA-32/AMD64 vpunpckhbw opcode. */
        case /* 723 */ OP_vpunpckhwd:       /**< IA-32/AMD64 vpunpckhwd opcode. */
        case /* 724 */ OP_vpunpckhdq:       /**< IA-32/AMD64 vpunpckhdq opcode. */
        case /* 725 */ OP_vpackssdw:        /**< IA-32/AMD64 vpackssdw opcode. */
        case /* 726 */ OP_vpunpcklqdq:      /**< IA-32/AMD64 vpunpcklqdq opcode. */
        case /* 727 */ OP_vpunpckhqdq:      /**< IA-32/AMD64 vpunpckhqdq opcode. */
        case /* 729 */ OP_vpshufhw:         /**< IA-32/AMD64 vpshufhw opcode. */
        case /* 730 */ OP_vpshufd:          /**< IA-32/AMD64 vpshufd opcode. */
        case /* 731 */ OP_vpshuflw:         /**< IA-32/AMD64 vpshuflw opcode. */
        case /* 740 */ OP_vpinsrw:          /**< IA-32/AMD64 vpinsrw opcode. */
        case /* 741 */ OP_vpextrw:          /**< IA-32/AMD64 vpextrw opcode. */
        case /* 742 */ OP_vshufps:          /**< IA-32/AMD64 vshufps opcode. */
        case /* 743 */ OP_vshufpd:          /**< IA-32/AMD64 vshufpd opcode. */
        case /* 749 */ OP_vpmovmskb:        /**< IA-32/AMD64 vpmovmskb opcode. */

        case /* 801 */ OP_vpshufb:          /**< IA-32/AMD64 vpshufb opcode. */

        case /* 816 */ OP_vpalignr:         /**< IA-32/AMD64 vpalignr opcode. */
        case /* 817 */ OP_vpblendvb:        /**< IA-32/AMD64 vpblendvb opcode. */
        case /* 818 */ OP_vblendvps:        /**< IA-32/AMD64 vblendvps opcode. */
        case /* 819 */ OP_vblendvpd:        /**< IA-32/AMD64 vblendvpd opcode. */

        case /* 821 */ OP_vpmovsxbw:        /**< IA-32/AMD64 vpmovsxbw opcode. */
        case /* 822 */ OP_vpmovsxbd:        /**< IA-32/AMD64 vpmovsxbd opcode. */
        case /* 823 */ OP_vpmovsxbq:        /**< IA-32/AMD64 vpmovsxbq opcode. */
        case /* 824 */ OP_vpmovsxwd:        /**< IA-32/AMD64 vpmovsxwd opcode. */
        case /* 825 */ OP_vpmovsxwq:        /**< IA-32/AMD64 vpmovsxwq opcode. */
        case /* 826 */ OP_vpmovsxdq:        /**< IA-32/AMD64 vpmovsxdq opcode. */

        case /* 830 */ OP_vpackusdw:        /**< IA-32/AMD64 vpackusdw opcode. */
        case /* 831 */ OP_vpmovzxbw:        /**< IA-32/AMD64 vpmovzxbw opcode. */
        case /* 832 */ OP_vpmovzxbd:        /**< IA-32/AMD64 vpmovzxbd opcode. */
        case /* 833 */ OP_vpmovzxbq:        /**< IA-32/AMD64 vpmovzxbq opcode. */
        case /* 834 */ OP_vpmovzxwd:        /**< IA-32/AMD64 vpmovzxwd opcode. */
        case /* 835 */ OP_vpmovzxwq:        /**< IA-32/AMD64 vpmovzxwq opcode. */
        case /* 836 */ OP_vpmovzxdq:        /**< IA-32/AMD64 vpmovzxdq opcode. */

        case /* 853 */ OP_vpextrb:          /**< IA-32/AMD64 vpextrb opcode. */
        case /* 854 */ OP_vpextrd:          /**< IA-32/AMD64 vpextrd opcode. */
        case /* 855 */ OP_vextractps:       /**< IA-32/AMD64 vextractps opcode. */

        case /* 860 */ OP_vblendps:         /**< IA-32/AMD64 vblendps opcode. */
        case /* 861 */ OP_vblendpd:         /**< IA-32/AMD64 vblendpd opcode. */
        case /* 862 */ OP_vpblendw:         /**< IA-32/AMD64 vpblendw opcode. */
        case /* 863 */ OP_vpinsrb:          /**< IA-32/AMD64 vpinsrb opcode. */
        case /* 864 */ OP_vinsertps:        /**< IA-32/AMD64 vinsertps opcode. */
        case /* 865 */ OP_vpinsrd:          /**< IA-32/AMD64 vpinsrd opcode. */

        case /* 881 */ OP_vbroadcastss:     /**< IA-32/AMD64 vbroadcastss opcode. */
        case /* 882 */ OP_vbroadcastsd:     /**< IA-32/AMD64 vbroadcastsd opcode. */
        case /* 883 */ OP_vbroadcastf128:   /**< IA-32/AMD64 vbroadcastf128 opcode. */
        case /* 884 */ OP_vmaskmovps:       /**< IA-32/AMD64 vmaskmovps opcode. */
        case /* 885 */ OP_vmaskmovpd:       /**< IA-32/AMD64 vmaskmovpd opcode. */
        case /* 886 */ OP_vpermilps:        /**< IA-32/AMD64 vpermilps opcode. */
        case /* 887 */ OP_vpermilpd:        /**< IA-32/AMD64 vpermilpd opcode. */
        case /* 888 */ OP_vperm2f128:       /**< IA-32/AMD64 vperm2f128 opcode. */

        case /* 877 */ OP_vzeroupper:       /**< IA-32/AMD64 vzeroupper opcode. */
        case /* 878 */ OP_vzeroall:         /**< IA-32/AMD64 vzeroall opcode. */
        case /* 879 */ OP_vldmxcsr:         /**< IA-32/AMD64 vldmxcsr opcode. */
        case /* 880 */ OP_vstmxcsr:         /**< IA-32/AMD64 vstmxcsr opcode. */
        case /* 889 */ OP_vinsertf128:      /**< IA-32/AMD64 vinsertf128 opcode. */
        case /* 890 */ OP_vextractf128:     /**< IA-32/AMD64 vextractf128 opcode. */

        /* AMD XOP */
        case /* 990 */ OP_vpcmov:      /**< IA-32/AMD64 vpcmov opcode. */

        case /* 999 */ OP_vpermil2pd:  /**< IA-32/AMD64 vpermil2pd opcode. */
        case /* 1000 */ OP_vpermil2ps: /**< IA-32/AMD64 vpermil2ps opcode. */

        /* AVX2 */
        case /* 1075 */ OP_vpgatherdd:     /**< IA-32/AMD64 vpgatherdd opcode. */
        case /* 1076 */ OP_vpgatherdq:     /**< IA-32/AMD64 vpgatherdq opcode. */
        case /* 1077 */ OP_vpgatherqd:     /**< IA-32/AMD64 vpgatherqd opcode. */
        case /* 1078 */ OP_vpgatherqq:     /**< IA-32/AMD64 vpgatherqq opcode. */
        case /* 1079 */ OP_vgatherdps:     /**< IA-32/AMD64 vgatherdps opcode. */
        case /* 1080 */ OP_vgatherdpd:     /**< IA-32/AMD64 vgatherdpd opcode. */
        case /* 1081 */ OP_vgatherqps:     /**< IA-32/AMD64 vgatherqps opcode. */
        case /* 1082 */ OP_vgatherqpd:     /**< IA-32/AMD64 vgatherqpd opcode. */
        case /* 1083 */ OP_vbroadcasti128: /**< IA-32/AMD64 vbroadcasti128 opcode. */
        case /* 1084 */ OP_vinserti128:    /**< IA-32/AMD64 vinserti128 opcode. */
        case /* 1085 */ OP_vextracti128:   /**< IA-32/AMD64 vextracti128 opcode. */
        case /* 1086 */ OP_vpmaskmovd:     /**< IA-32/AMD64 vpmaskmovd opcode. */
        case /* 1087 */ OP_vpmaskmovq:     /**< IA-32/AMD64 vpmaskmovq opcode. */
        case /* 1088 */ OP_vperm2i128:     /**< IA-32/AMD64 vperm2i128 opcode. */
        case /* 1089 */ OP_vpermd:         /**< IA-32/AMD64 vpermd opcode. */
        case /* 1090 */ OP_vpermps:        /**< IA-32/AMD64 vpermps opcode. */
        case /* 1091 */ OP_vpermq:         /**< IA-32/AMD64 vpermq opcode. */
        case /* 1092 */ OP_vpermpd:        /**< IA-32/AMD64 vpermpd opcode. */
        case /* 1093 */ OP_vpblendd:       /**< IA-32/AMD64 vpblendd opcode. */
        case /* 1099 */ OP_vpbroadcastb:   /**< IA-32/AMD64 vpbroadcastb opcode. */
        case /* 1100 */ OP_vpbroadcastw:   /**< IA-32/AMD64 vpbroadcastw opcode. */
        case /* 1101 */ OP_vpbroadcastd:   /**< IA-32/AMD64 vpbroadcastd opcode. */
        case /* 1102 */ OP_vpbroadcastq:   /**< IA-32/AMD64 vpbroadcastq opcode. */

        /* Intel AVX-512 VEX */
        case /* 1107 */ OP_kmovw:    /**< IA-32/AMD64 AVX-512 kmovw opcode. */
        case /* 1108 */ OP_kmovb:    /**< IA-32/AMD64 AVX-512 kmovb opcode. */
        case /* 1109 */ OP_kmovq:    /**< IA-32/AMD64 AVX-512 kmovq opcode. */
        case /* 1110 */ OP_kmovd:    /**< IA-32/AMD64 AVX-512 kmovd opcode. */

        case /* 1119 */ OP_kunpckbw: /**< IA-32/AMD64 AVX-512 kunpckbw opcode. */
        case /* 1120 */ OP_kunpckwd: /**< IA-32/AMD64 AVX-512 kunpckwd opcode. */
        case /* 1121 */ OP_kunpckdq: /**< IA-32/AMD64 AVX-512 kunpckdq opcode. */

        /* Intel AVX-512 EVEX */
        case /* 1158 */ OP_valignd:         /**< IA-32/AMD64 AVX-512 OP_valignd opcode. */
        case /* 1159 */ OP_valignq:         /**< IA-32/AMD64 AVX-512 OP_valignq opcode. */
        case /* 1160 */ OP_vblendmpd:       /**< IA-32/AMD64 AVX-512 OP_vblendmpd opcode. */
        case /* 1161 */ OP_vblendmps:       /**< IA-32/AMD64 AVX-512 OP_vblendmps opcode. */
        case /* 1162 */ OP_vbroadcastf32x2: /**< IA-32/AMD64 AVX-512 OP_vbroadcastf32x2 opcode. */
        case /* 1163 */ OP_vbroadcastf32x4: /**< IA-32/AMD64 AVX-512 OP_vbroadcastf32x4 opcode. */
        case /* 1164 */ OP_vbroadcastf32x8: /**< IA-32/AMD64 AVX-512 OP_vbroadcastf32x8 opcode. */
        case /* 1165 */ OP_vbroadcastf64x2: /**< IA-32/AMD64 AVX-512 OP_vbroadcastf64x2 opcode. */
        case /* 1166 */ OP_vbroadcastf64x4: /**< IA-32/AMD64 AVX-512 OP_vbroadcastf64x4 opcode. */
        case /* 1167 */ OP_vbroadcasti32x2: /**< IA-32/AMD64 AVX-512 OP_vbroadcasti32x2 opcode. */
        case /* 1168 */ OP_vbroadcasti32x4: /**< IA-32/AMD64 AVX-512 OP_vbroadcasti32x4 opcode. */
        case /* 1169 */ OP_vbroadcasti32x8: /**< IA-32/AMD64 AVX-512 OP_vbroadcasti32x8 opcode. */
        case /* 1170 */ OP_vbroadcasti64x2: /**< IA-32/AMD64 AVX-512 OP_vbroadcasti64x2 opcode. */
        case /* 1171 */ OP_vbroadcasti64x4: /**< IA-32/AMD64 AVX-512 OP_vbroadcasti64x4 opcode. */
        case /* 1172 */ OP_vcompresspd:     /**< IA-32/AMD64 AVX-512 OP_vcompresspd opcode. */
        case /* 1173 */ OP_vcompressps:     /**< IA-32/AMD64 AVX-512 OP_vcompressps opcode. */

        case /* 1201 */ OP_vexpandpd:       /**< IA-32/AMD64 AVX-512 OP_vexpandpd opcode. */
        case /* 1202 */ OP_vexpandps:       /**< IA-32/AMD64 AVX-512 OP_vexpandps opcode. */
        case /* 1203 */ OP_vextractf32x4:   /**< IA-32/AMD64 AVX-512 OP_vextractf32x4 opcode. */
        case /* 1204 */ OP_vextractf32x8:   /**< IA-32/AMD64 AVX-512 OP_vextractf32x8 opcode. */
        case /* 1205 */ OP_vextractf64x2:   /**< IA-32/AMD64 AVX-512 OP_vextractf64x2 opcode. */
        case /* 1206 */ OP_vextractf64x4:   /**< IA-32/AMD64 AVX-512 OP_vextractf64x4 opcode. */
        case /* 1207 */ OP_vextracti32x4:   /**< IA-32/AMD64 AVX-512 OP_vextracti32x4 opcode. */
        case /* 1208 */ OP_vextracti32x8:   /**< IA-32/AMD64 AVX-512 OP_vextracti32x8 opcode. */
        case /* 1209 */ OP_vextracti64x2:   /**< IA-32/AMD64 AVX-512 OP_vextracti64x2 opcode. */
        case /* 1210 */ OP_vextracti64x4:   /**< IA-32/AMD64 AVX-512 OP_vextracti64x4 opcode. */

        case /* 1235 */ OP_vinsertf32x4:    /**< IA-32/AMD64 AVX-512 OP_vinsertf32x4 opcode. */
        case /* 1236 */ OP_vinsertf32x8:    /**< IA-32/AMD64 AVX-512 OP_vinsertf32x8 opcode. */
        case /* 1237 */ OP_vinsertf64x2:    /**< IA-32/AMD64 AVX-512 OP_vinsertf64x2 opcode. */
        case /* 1238 */ OP_vinsertf64x4:    /**< IA-32/AMD64 AVX-512 OP_vinsertf64x4 opcode. */
        case /* 1239 */ OP_vinserti32x4:    /**< IA-32/AMD64 AVX-512 OP_vinserti32x4 opcode. */
        case /* 1240 */ OP_vinserti32x8:    /**< IA-32/AMD64 AVX-512 OP_vinserti32x8 opcode. */
        case /* 1241 */ OP_vinserti64x2:    /**< IA-32/AMD64 AVX-512 OP_vinserti64x2 opcode. */
        case /* 1242 */ OP_vinserti64x4:    /**< IA-32/AMD64 AVX-512 OP_vinserti64x4 opcode. */
        case /* 1243 */ OP_vmovdqa32:       /**< IA-32/AMD64 AVX-512 OP_vmovdqa32 opcode. */
        case /* 1244 */ OP_vmovdqa64:       /**< IA-32/AMD64 AVX-512 OP_vmovdqa64 opcode. */
        case /* 1245 */ OP_vmovdqu16:       /**< IA-32/AMD64 AVX-512 OP_vmovdqu16 opcode. */
        case /* 1246 */ OP_vmovdqu32:       /**< IA-32/AMD64 AVX-512 OP_vmovdqu32 opcode. */
        case /* 1247 */ OP_vmovdqu64:       /**< IA-32/AMD64 AVX-512 OP_vmovdqu64 opcode. */
        case /* 1248 */ OP_vmovdqu8:        /**< IA-32/AMD64 AVX-512 OP_vmovdqu8 opcode. */

        case /* 1254 */ OP_vpblendmb:       /**< IA-32/AMD64 AVX-512 OP_vpblendmb opcode. */
        case /* 1255 */ OP_vpblendmd:       /**< IA-32/AMD64 AVX-512 OP_vpblendmd opcode. */
        case /* 1256 */ OP_vpblendmq:       /**< IA-32/AMD64 AVX-512 OP_vpblendmq opcode. */
        case /* 1257 */ OP_vpblendmw:       /**< IA-32/AMD64 AVX-512 OP_vpblendmw opcode. */
        case /* 1258 */ OP_vpbroadcastmb2q: /**< IA-32/AMD64 AVX-512 OP_vpbroadcastmb2q opcode. */
        case /* 1259 */ OP_vpbroadcastmw2d: /**< IA-32/AMD64 AVX-512 OP_vpbroadcastmw2d opcode. */

        case /* 1268 */ OP_vpcompressd:     /**< IA-32/AMD64 AVX-512 OP_vpcompressd opcode. */
        case /* 1269 */ OP_vpcompressq:     /**< IA-32/AMD64 AVX-512 OP_vpcompressq opcode. */

        case /* 1272 */ OP_vpermb:          /**< IA-32/AMD64 AVX-512 OP_vpermb opcode. */
        case /* 1273 */ OP_vpermi2b:        /**< IA-32/AMD64 AVX-512 OP_vpermi2b opcode. */
        case /* 1274 */ OP_vpermi2d:        /**< IA-32/AMD64 AVX-512 OP_vpermi2d opcode. */
        case /* 1275 */ OP_vpermi2pd:       /**< IA-32/AMD64 AVX-512 OP_vpermi2pd opcode. */
        case /* 1276 */ OP_vpermi2ps:       /**< IA-32/AMD64 AVX-512 OP_vpermi2ps opcode. */
        case /* 1277 */ OP_vpermi2q:        /**< IA-32/AMD64 AVX-512 OP_vpermi2q opcode. */
        case /* 1278 */ OP_vpermi2w:        /**< IA-32/AMD64 AVX-512 OP_vpermi2w opcode. */
        case /* 1279 */ OP_vpermt2b:        /**< IA-32/AMD64 AVX-512 OP_vpermt2b opcode. */
        case /* 1280 */ OP_vpermt2d:        /**< IA-32/AMD64 AVX-512 OP_vpermt2d opcode. */
        case /* 1281 */ OP_vpermt2pd:       /**< IA-32/AMD64 AVX-512 OP_vpermt2pd opcode. */
        case /* 1282 */ OP_vpermt2ps:       /**< IA-32/AMD64 AVX-512 OP_vpermt2ps opcode. */
        case /* 1283 */ OP_vpermt2q:        /**< IA-32/AMD64 AVX-512 OP_vpermt2q opcode. */
        case /* 1284 */ OP_vpermt2w:        /**< IA-32/AMD64 AVX-512 OP_vpermt2w opcode. */
        case /* 1285 */ OP_vpermw:          /**< IA-32/AMD64 AVX-512 OP_vpermw opcode. */

        case /* 1286 */ OP_vpexpandd:       /**< IA-32/AMD64 AVX-512 OP_vpexpandd opcode. */
        case /* 1287 */ OP_vpexpandq:       /**< IA-32/AMD64 AVX-512 OP_vpexpandq opcode. */
        // There is a define for each one of this two values
        // case /* 1288 */ OP_vpextrq:         /**< IA-32/AMD64 AVX-512 OP_vpextrq opcode. */
        // case /* 1289 */ OP_vpinsrq:         /**< IA-32/AMD64 AVX-512 OP_vpinsrq opcode. */

        case /* 1298 */ OP_vpmovb2m:        /**< IA-32/AMD64 AVX-512 OP_vpmovb2m opcode. */
        case /* 1299 */ OP_vpmovd2m:        /**< IA-32/AMD64 AVX-512 OP_vpmovd2m opcode. */
        case /* 1300 */ OP_vpmovdb:         /**< IA-32/AMD64 AVX-512 OP_vpmovdb opcode. */
        case /* 1301 */ OP_vpmovdw:         /**< IA-32/AMD64 AVX-512 OP_vpmovdw opcode. */
        case /* 1302 */ OP_vpmovm2b:        /**< IA-32/AMD64 AVX-512 OP_vpmovm2b opcode. */
        case /* 1303 */ OP_vpmovm2d:        /**< IA-32/AMD64 AVX-512 OP_vpmovm2d opcode. */
        case /* 1304 */ OP_vpmovm2q:        /**< IA-32/AMD64 AVX-512 OP_vpmovm2q opcode. */
        case /* 1305 */ OP_vpmovm2w:        /**< IA-32/AMD64 AVX-512 OP_vpmovm2w opcode. */
        case /* 1306 */ OP_vpmovq2m:        /**< IA-32/AMD64 AVX-512 OP_vpmovq2m opcode. */
        case /* 1307 */ OP_vpmovqb:         /**< IA-32/AMD64 AVX-512 OP_vpmovqb opcode. */
        case /* 1308 */ OP_vpmovqd:         /**< IA-32/AMD64 AVX-512 OP_vpmovqd opcode. */
        case /* 1309 */ OP_vpmovqw:         /**< IA-32/AMD64 AVX-512 OP_vpmovqw opcode. */
        case /* 1310 */ OP_vpmovsdb:        /**< IA-32/AMD64 AVX-512 OP_vpmovsdb opcode. */
        case /* 1311 */ OP_vpmovsdw:        /**< IA-32/AMD64 AVX-512 OP_vpmovsdw opcode. */
        case /* 1312 */ OP_vpmovsqb:        /**< IA-32/AMD64 AVX-512 OP_vpmovsqb opcode. */
        case /* 1313 */ OP_vpmovsqd:        /**< IA-32/AMD64 AVX-512 OP_vpmovsqd opcode. */
        case /* 1314 */ OP_vpmovsqw:        /**< IA-32/AMD64 AVX-512 OP_vpmovsqw opcode. */
        case /* 1315 */ OP_vpmovswb:        /**< IA-32/AMD64 AVX-512 OP_vpmovswb opcode. */
        case /* 1316 */ OP_vpmovusdb:       /**< IA-32/AMD64 AVX-512 OP_vpmovusdb opcode. */
        case /* 1317 */ OP_vpmovusdw:       /**< IA-32/AMD64 AVX-512 OP_vpmovusdw opcode. */
        case /* 1318 */ OP_vpmovusqb:       /**< IA-32/AMD64 AVX-512 OP_vpmovusqb opcode. */
        case /* 1319 */ OP_vpmovusqd:       /**< IA-32/AMD64 AVX-512 OP_vpmovusqd opcode. */
        case /* 1320 */ OP_vpmovusqw:       /**< IA-32/AMD64 AVX-512 OP_vpmovusqw opcode. */
        case /* 1321 */ OP_vpmovuswb:       /**< IA-32/AMD64 AVX-512 OP_vpmovuswb opcode. */
        case /* 1322 */ OP_vpmovw2m:        /**< IA-32/AMD64 AVX-512 OP_vpmovw2m opcode. */
        case /* 1323 */ OP_vpmovwb:         /**< IA-32/AMD64 AVX-512 OP_vpmovwb opcode. */

        case /* 1335 */ OP_vpscatterdd:     /**< IA-32/AMD64 AVX-512 OP_vpscatterdd opcode. */
        case /* 1336 */ OP_vpscatterdq:     /**< IA-32/AMD64 AVX-512 OP_vpscatterdq opcode. */
        case /* 1337 */ OP_vpscatterqd:     /**< IA-32/AMD64 AVX-512 OP_vpscatterqd opcode. */
        case /* 1338 */ OP_vpscatterqq:     /**< IA-32/AMD64 AVX-512 OP_vpscatterqq opcode. */

        case /* 1388 */ OP_vscatterdpd:     /**< IA-32/AMD64 AVX-512 OP_vscatterdpd opcode. */
        case /* 1389 */ OP_vscatterdps:     /**< IA-32/AMD64 AVX-512 OP_vscatterdps opcode. */
        case /* 1390 */ OP_vscatterqpd:     /**< IA-32/AMD64 AVX-512 OP_vscatterqpd opcode. */
        case /* 1391 */ OP_vscatterqps:     /**< IA-32/AMD64 AVX-512 OP_vscatterqps opcode. */

        case /* 1400 */ OP_vshuff32x4:      /**< IA-32/AMD64 AVX-512 OP_vshuff32x4 opcode. */
        case /* 1401 */ OP_vshuff64x2:      /**< IA-32/AMD64 AVX-512 OP_vshuff64x2 opcode. */
        case /* 1402 */ OP_vshufi32x4:      /**< IA-32/AMD64 AVX-512 OP_vshufi32x4 opcode. */
        case /* 1403 */ OP_vshufi64x2:      /**< IA-32/AMD64 AVX-512 OP_vshufi64x2 opcode. */ return true;

        default: return false;
    }
}

DR_API
bool
instr_is_ldst(instr_t *instr) {
    return instr_is_scalar_mov(instr) || instr_is_simd_mov(instr);
}

static bool
instr_is_scalar_integer(instr_t *instr) {
    switch (instr_get_opcode(instr)) {
        case /*   4 */ OP_add:      /**< IA-32/AMD64 add opcode. */
        case /*   5 */ OP_or:       /**< IA-32/AMD64 or opcode. */
        case /*   6 */ OP_adc:      /**< IA-32/AMD64 adc opcode. */
        case /*   7 */ OP_sbb:      /**< IA-32/AMD64 sbb opcode. */
        case /*   8 */ OP_and:      /**< IA-32/AMD64 and opcode. */
        case /*  10 */ OP_sub:      /**< IA-32/AMD64 sub opcode. */
        case /*  12 */ OP_xor:      /**< IA-32/AMD64 xor opcode. */
        case /*  14 */ OP_cmp:      /**< IA-32/AMD64 cmp opcode. */
        case /*  16 */ OP_inc:      /**< IA-32/AMD64 inc opcode. */
        case /*  17 */ OP_dec:      /**< IA-32/AMD64 dec opcode. */
        case /*  25 */ OP_imul:     /**< IA-32/AMD64 imul opcode. */

        case /*  60 */ OP_test:  /**< IA-32/AMD64 test opcode. */
        case /*  61 */ OP_lea:   /**< IA-32/AMD64 lea opcode. */

        case /*  63 */ OP_cwde:  /**< IA-32/AMD64 cwde opcode. */
        case /*  64 */ OP_cdq:   /**< IA-32/AMD64 cdq opcode. */

        case /* 185 */ OP_bt:         /**< IA-32/AMD64 bt opcode. */
        case /* 186 */ OP_shld:       /**< IA-32/AMD64 shld opcode. */
        case /* 188 */ OP_bts:        /**< IA-32/AMD64 bts opcode. */
        case /* 189 */ OP_shrd:       /**< IA-32/AMD64 shrd opcode. */
        case /* 192 */ OP_btr:        /**< IA-32/AMD64 btr opcode. */

        case /* 197 */ OP_btc:        /**< IA-32/AMD64 btc opcode. */
        case /* 198 */ OP_bsf:        /**< IA-32/AMD64 bsf opcode. */
        case /* 199 */ OP_bsr:        /**< IA-32/AMD64 bsr opcode. */
        case /* 201 */ OP_xadd:       /**< IA-32/AMD64 xadd opcode. */
        case /* 205 */ OP_bswap:      /**< IA-32/AMD64 bswap opcode. */

        case /* 253 */ OP_rol:         /**< IA-32/AMD64 rol opcode. */
        case /* 254 */ OP_ror:         /**< IA-32/AMD64 ror opcode. */
        case /* 255 */ OP_rcl:         /**< IA-32/AMD64 rcl opcode. */
        case /* 256 */ OP_rcr:         /**< IA-32/AMD64 rcr opcode. */
        case /* 257 */ OP_shl:         /**< IA-32/AMD64 shl opcode. */
        case /* 258 */ OP_shr:         /**< IA-32/AMD64 shr opcode. */
        case /* 259 */ OP_sar:         /**< IA-32/AMD64 sar opcode. */
        case /* 260 */ OP_not:         /**< IA-32/AMD64 not opcode. */
        case /* 261 */ OP_neg:         /**< IA-32/AMD64 neg opcode. */
        case /* 262 */ OP_mul:         /**< IA-32/AMD64 mul opcode. */
        case /* 263 */ OP_div:         /**< IA-32/AMD64 div opcode. */
        case /* 264 */ OP_idiv:        /**< IA-32/AMD64 idiv opcode. */

        /* Intel BMI1 */
        /* (includes non-immed form of OP_bextr) */
        case /* 1055 */ OP_andn:   /**< IA-32/AMD64 andn opcode. */
        case /* 1059 */ OP_tzcnt:  /**< IA-32/AMD64 tzcnt opcode. */

        /* Intel BMI2 */
        case /* 1063 */ OP_sarx: /**< IA-32/AMD64 sarx opcode. */
        case /* 1064 */ OP_shlx: /**< IA-32/AMD64 shlx opcode. */
        case /* 1065 */ OP_shrx: /**< IA-32/AMD64 shrx opcode. */
        case /* 1066 */ OP_rorx: /**< IA-32/AMD64 rorx opcode. */
        case /* 1067 */ OP_mulx: /**< IA-32/AMD64 mulx opcode. */

        /* Intel ADX */
        case /* 1105 */ OP_adox: /**< IA-32/AMD64 adox opcode. */
        case /* 1106 */ OP_adcx: /**< IA-32/AMD64 adox opcode. */

        /* SSE4 (incl AMD (SSE4A) and Intel-specific (SSE4.1, SSE4.2) extensions */
        case /* 539 */ OP_popcnt:     /**< IA-32/AMD64 popcnt opcode. */
        case /* 544 */ OP_lzcnt:      /**< IA-32/AMD64 lzcnt opcode. */ return true;

        default: return false;
    }
}

static bool
instr_is_simd_integer(instr_t *instr) {
    switch (instr_get_opcode(instr)) {
        case /* 130 */ OP_pcmpgtb:    /**< IA-32/AMD64 pcmpgtb opcode. */
        case /* 131 */ OP_pcmpgtw:    /**< IA-32/AMD64 pcmpgtw opcode. */
        case /* 132 */ OP_pcmpgtd:    /**< IA-32/AMD64 pcmpgtd opcode. */

        case /* 148 */ OP_pcmpeqb:    /**< IA-32/AMD64 pcmpeqb opcode. */
        case /* 149 */ OP_pcmpeqw:    /**< IA-32/AMD64 pcmpeqw opcode. */
        case /* 150 */ OP_pcmpeqd:    /**< IA-32/AMD64 pcmpeqd opcode. */

        case /* 206 */ OP_psrlw:      /**< IA-32/AMD64 psrlw opcode. */
        case /* 207 */ OP_psrld:      /**< IA-32/AMD64 psrld opcode. */
        case /* 208 */ OP_psrlq:      /**< IA-32/AMD64 psrlq opcode. */
        case /* 209 */ OP_paddq:      /**< IA-32/AMD64 paddq opcode. */
        case /* 210 */ OP_pmullw:     /**< IA-32/AMD64 pmullw opcode. */
        case /* 212 */ OP_psubusb:    /**< IA-32/AMD64 psubusb opcode. */
        case /* 213 */ OP_psubusw:    /**< IA-32/AMD64 psubusw opcode. */
        case /* 214 */ OP_pminub:     /**< IA-32/AMD64 pminub opcode. */
        case /* 215 */ OP_pand:       /**< IA-32/AMD64 pand opcode. */
        case /* 216 */ OP_paddusb:    /**< IA-32/AMD64 paddusb opcode. */
        case /* 217 */ OP_paddusw:    /**< IA-32/AMD64 paddusw opcode. */
        case /* 218 */ OP_pmaxub:     /**< IA-32/AMD64 pmaxub opcode. */
        case /* 219 */ OP_pandn:      /**< IA-32/AMD64 pandn opcode. */
        case /* 220 */ OP_pavgb:      /**< IA-32/AMD64 pavgb opcode. */
        case /* 221 */ OP_psraw:      /**< IA-32/AMD64 psraw opcode. */
        case /* 222 */ OP_psrad:      /**< IA-32/AMD64 psrad opcode. */
        case /* 223 */ OP_pavgw:      /**< IA-32/AMD64 pavgw opcode. */
        case /* 224 */ OP_pmulhuw:    /**< IA-32/AMD64 pmulhuw opcode. */
        case /* 225 */ OP_pmulhw:     /**< IA-32/AMD64 pmulhw opcode. */
        case /* 228 */ OP_psubsb:     /**< IA-32/AMD64 psubsb opcode. */
        case /* 229 */ OP_psubsw:     /**< IA-32/AMD64 psubsw opcode. */
        case /* 230 */ OP_pminsw:     /**< IA-32/AMD64 pminsw opcode. */
        case /* 231 */ OP_por:        /**< IA-32/AMD64 por opcode. */
        case /* 232 */ OP_paddsb:     /**< IA-32/AMD64 paddsb opcode. */
        case /* 233 */ OP_paddsw:     /**< IA-32/AMD64 paddsw opcode. */
        case /* 234 */ OP_pmaxsw:     /**< IA-32/AMD64 pmaxsw opcode. */
        case /* 235 */ OP_pxor:       /**< IA-32/AMD64 pxor opcode. */
        case /* 236 */ OP_psllw:      /**< IA-32/AMD64 psllw opcode. */
        case /* 237 */ OP_pslld:      /**< IA-32/AMD64 pslld opcode. */
        case /* 238 */ OP_psllq:      /**< IA-32/AMD64 psllq opcode. */
        case /* 239 */ OP_pmuludq:    /**< IA-32/AMD64 pmuludq opcode. */
        case /* 240 */ OP_pmaddwd:    /**< IA-32/AMD64 pmaddwd opcode. */
        case /* 241 */ OP_psadbw:     /**< IA-32/AMD64 psadbw opcode. */
        case /* 244 */ OP_psubb:      /**< IA-32/AMD64 psubb opcode. */
        case /* 245 */ OP_psubw:      /**< IA-32/AMD64 psubw opcode. */
        case /* 246 */ OP_psubd:      /**< IA-32/AMD64 psubd opcode. */
        case /* 247 */ OP_psubq:      /**< IA-32/AMD64 psubq opcode. */
        case /* 248 */ OP_paddb:      /**< IA-32/AMD64 paddb opcode. */
        case /* 249 */ OP_paddw:      /**< IA-32/AMD64 paddw opcode. */
        case /* 250 */ OP_paddd:      /**< IA-32/AMD64 paddd opcode. */
        case /* 251 */ OP_psrldq:     /**< IA-32/AMD64 psrldq opcode. */
        case /* 252 */ OP_pslldq:     /**< IA-32/AMD64 pslldq opcode. */

        /* SSSE3 */
        case /* 524 */ OP_phaddw:    /**< IA-32/AMD64 phaddw opcode. */
        case /* 525 */ OP_phaddd:    /**< IA-32/AMD64 phaddd opcode. */
        case /* 526 */ OP_phaddsw:   /**< IA-32/AMD64 phaddsw opcode. */
        case /* 527 */ OP_pmaddubsw: /**< IA-32/AMD64 pmaddubsw opcode. */
        case /* 528 */ OP_phsubw:    /**< IA-32/AMD64 phsubw opcode. */
        case /* 529 */ OP_phsubd:    /**< IA-32/AMD64 phsubd opcode. */
        case /* 530 */ OP_phsubsw:   /**< IA-32/AMD64 phsubsw opcode. */
        case /* 531 */ OP_psignb:    /**< IA-32/AMD64 psignb opcode. */
        case /* 532 */ OP_psignw:    /**< IA-32/AMD64 psignw opcode. */
        case /* 533 */ OP_psignd:    /**< IA-32/AMD64 psignd opcode. */
        case /* 534 */ OP_pmulhrsw:  /**< IA-32/AMD64 pmulhrsw opcode. */
        case /* 535 */ OP_pabsb:     /**< IA-32/AMD64 pabsb opcode. */
        case /* 536 */ OP_pabsw:     /**< IA-32/AMD64 pabsw opcode. */
        case /* 537 */ OP_pabsd:     /**< IA-32/AMD64 pabsd opcode. */

        /* SSE4 (incl AMD (SSE4A) and Intel-specific (SSE4.1, SSE4.2) extensions */
        case /* 548 */ OP_ptest:      /**< IA-32/AMD64 ptest opcode. */
        case /* 555 */ OP_pmuldq:     /**< IA-32/AMD64 pmuldq opcode. */
        case /* 556 */ OP_pcmpeqq:    /**< IA-32/AMD64 pcmpeqq opcode. */
        case /* 558 */ OP_packusdw:   /**< IA-32/AMD64 packusdw opcode. */
        case /* 565 */ OP_pcmpgtq:    /**< IA-32/AMD64 pcmpgtq opcode. */
        case /* 566 */ OP_pminsb:     /**< IA-32/AMD64 pminsb opcode. */
        case /* 567 */ OP_pminsd:     /**< IA-32/AMD64 pminsd opcode. */
        case /* 568 */ OP_pminuw:     /**< IA-32/AMD64 pminuw opcode. */
        case /* 569 */ OP_pminud:     /**< IA-32/AMD64 pminud opcode. */
        case /* 570 */ OP_pmaxsb:     /**< IA-32/AMD64 pmaxsb opcode. */
        case /* 571 */ OP_pmaxsd:     /**< IA-32/AMD64 pmaxsd opcode. */
        case /* 572 */ OP_pmaxuw:     /**< IA-32/AMD64 pmaxuw opcode. */
        case /* 573 */ OP_pmaxud:     /**< IA-32/AMD64 pmaxud opcode. */
        case /* 574 */ OP_pmulld:     /**< IA-32/AMD64 pmulld opcode. */
        case /* 575 */ OP_phminposuw: /**< IA-32/AMD64 phminposuw opcode. */
        case /* 592 */ OP_mpsadbw:    /**< IA-32/AMD64 mpsadbw opcode. */

        /* AVX */
        case /* 732 */ OP_vpcmpeqb:         /**< IA-32/AMD64 vpcmpeqb opcode. */
        case /* 733 */ OP_vpcmpeqw:         /**< IA-32/AMD64 vpcmpeqw opcode. */
        case /* 734 */ OP_vpcmpeqd:         /**< IA-32/AMD64 vpcmpeqd opcode. */

        case /* 744 */ OP_vpsrlw:           /**< IA-32/AMD64 vpsrlw opcode. */
        case /* 745 */ OP_vpsrld:           /**< IA-32/AMD64 vpsrld opcode. */
        case /* 746 */ OP_vpsrlq:           /**< IA-32/AMD64 vpsrlq opcode. */
        case /* 747 */ OP_vpaddq:           /**< IA-32/AMD64 vpaddq opcode. */
        case /* 748 */ OP_vpmullw:          /**< IA-32/AMD64 vpmullw opcode. */

        case /* 750 */ OP_vpsubusb:         /**< IA-32/AMD64 vpsubusb opcode. */
        case /* 751 */ OP_vpsubusw:         /**< IA-32/AMD64 vpsubusw opcode. */
        case /* 752 */ OP_vpminub:          /**< IA-32/AMD64 vpminub opcode. */
        case /* 753 */ OP_vpand:            /**< IA-32/AMD64 vpand opcode. */
        case /* 754 */ OP_vpaddusb:         /**< IA-32/AMD64 vpaddusb opcode. */
        case /* 755 */ OP_vpaddusw:         /**< IA-32/AMD64 vpaddusw opcode. */
        case /* 756 */ OP_vpmaxub:          /**< IA-32/AMD64 vpmaxub opcode. */
        case /* 757 */ OP_vpandn:           /**< IA-32/AMD64 vpandn opcode. */
        case /* 758 */ OP_vpavgb:           /**< IA-32/AMD64 vpavgb opcode. */
        case /* 759 */ OP_vpsraw:           /**< IA-32/AMD64 vpsraw opcode. */
        case /* 760 */ OP_vpsrad:           /**< IA-32/AMD64 vpsrad opcode. */
        case /* 761 */ OP_vpavgw:           /**< IA-32/AMD64 vpavgw opcode. */
        case /* 762 */ OP_vpmulhuw:         /**< IA-32/AMD64 vpmulhuw opcode. */
        case /* 763 */ OP_vpmulhw:          /**< IA-32/AMD64 vpmulhw opcode. */

        case /* 768 */ OP_vpsubsb:          /**< IA-32/AMD64 vpsubsb opcode. */
        case /* 769 */ OP_vpsubsw:          /**< IA-32/AMD64 vpsubsw opcode. */
        case /* 770 */ OP_vpminsw:          /**< IA-32/AMD64 vpminsw opcode. */
        case /* 771 */ OP_vpor:             /**< IA-32/AMD64 vpor opcode. */
        case /* 772 */ OP_vpaddsb:          /**< IA-32/AMD64 vpaddsb opcode. */
        case /* 773 */ OP_vpaddsw:          /**< IA-32/AMD64 vpaddsw opcode. */
        case /* 774 */ OP_vpmaxsw:          /**< IA-32/AMD64 vpmaxsw opcode. */
        case /* 775 */ OP_vpxor:            /**< IA-32/AMD64 vpxor opcode. */
        case /* 776 */ OP_vpsllw:           /**< IA-32/AMD64 vpsllw opcode. */
        case /* 777 */ OP_vpslld:           /**< IA-32/AMD64 vpslld opcode. */
        case /* 778 */ OP_vpsllq:           /**< IA-32/AMD64 vpsllq opcode. */
        case /* 779 */ OP_vpmuludq:         /**< IA-32/AMD64 vpmuludq opcode. */
        case /* 780 */ OP_vpmaddwd:         /**< IA-32/AMD64 vpmaddwd opcode. */
        case /* 781 */ OP_vpsadbw:          /**< IA-32/AMD64 vpsadbw opcode. */

        case /* 783 */ OP_vpsubb:           /**< IA-32/AMD64 vpsubb opcode. */
        case /* 784 */ OP_vpsubw:           /**< IA-32/AMD64 vpsubw opcode. */
        case /* 785 */ OP_vpsubd:           /**< IA-32/AMD64 vpsubd opcode. */
        case /* 786 */ OP_vpsubq:           /**< IA-32/AMD64 vpsubq opcode. */
        case /* 787 */ OP_vpaddb:           /**< IA-32/AMD64 vpaddb opcode. */
        case /* 788 */ OP_vpaddw:           /**< IA-32/AMD64 vpaddw opcode. */
        case /* 789 */ OP_vpaddd:           /**< IA-32/AMD64 vpaddd opcode. */
        case /* 790 */ OP_vpsrldq:          /**< IA-32/AMD64 vpsrldq opcode. */
        case /* 791 */ OP_vpslldq:          /**< IA-32/AMD64 vpslldq opcode. */

        case /* 802 */ OP_vphaddw:          /**< IA-32/AMD64 vphaddw opcode. */
        case /* 803 */ OP_vphaddd:          /**< IA-32/AMD64 vphaddd opcode. */
        case /* 804 */ OP_vphaddsw:         /**< IA-32/AMD64 vphaddsw opcode. */
        case /* 805 */ OP_vpmaddubsw:       /**< IA-32/AMD64 vpmaddubsw opcode. */
        case /* 806 */ OP_vphsubw:          /**< IA-32/AMD64 vphsubw opcode. */
        case /* 807 */ OP_vphsubd:          /**< IA-32/AMD64 vphsubd opcode. */
        case /* 808 */ OP_vphsubsw:         /**< IA-32/AMD64 vphsubsw opcode. */
        case /* 809 */ OP_vpsignb:          /**< IA-32/AMD64 vpsignb opcode. */
        case /* 810 */ OP_vpsignw:          /**< IA-32/AMD64 vpsignw opcode. */
        case /* 811 */ OP_vpsignd:          /**< IA-32/AMD64 vpsignd opcode. */
        case /* 812 */ OP_vpmulhrsw:        /**< IA-32/AMD64 vpmulhrsw opcode. */
        case /* 813 */ OP_vpabsb:           /**< IA-32/AMD64 vpabsb opcode. */
        case /* 814 */ OP_vpabsw:           /**< IA-32/AMD64 vpabsw opcode. */
        case /* 815 */ OP_vpabsd:           /**< IA-32/AMD64 vpabsd opcode. */

        // TODO: MOV?
        case /* 820 */ OP_vptest:           /**< IA-32/AMD64 vptest opcode. */

        case /* 827 */ OP_vpmuldq:          /**< IA-32/AMD64 vpmuldq opcode. */
        case /* 828 */ OP_vpcmpeqq:         /**< IA-32/AMD64 vpcmpeqq opcode. */

        case /* 837 */ OP_vpcmpgtq:         /**< IA-32/AMD64 vpcmpgtq opcode. */
        case /* 838 */ OP_vpminsb:          /**< IA-32/AMD64 vpminsb opcode. */
        case /* 839 */ OP_vpminsd:          /**< IA-32/AMD64 vpminsd opcode. */
        case /* 840 */ OP_vpminuw:          /**< IA-32/AMD64 vpminuw opcode. */
        case /* 841 */ OP_vpminud:          /**< IA-32/AMD64 vpminud opcode. */
        case /* 842 */ OP_vpmaxsb:          /**< IA-32/AMD64 vpmaxsb opcode. */
        case /* 843 */ OP_vpmaxsd:          /**< IA-32/AMD64 vpmaxsd opcode. */
        case /* 844 */ OP_vpmaxuw:          /**< IA-32/AMD64 vpmaxuw opcode. */
        case /* 845 */ OP_vpmaxud:          /**< IA-32/AMD64 vpmaxud opcode. */
        case /* 846 */ OP_vpmulld:          /**< IA-32/AMD64 vpmulld opcode. */

        case /* 847 */ OP_vphminposuw:      /**< IA-32/AMD64 vphminposuw opcode. */
        case /* 868 */ OP_vmpsadbw:         /**< IA-32/AMD64 vmpsadbw opcode. */

        /* FMA */
        // TODO: LOGICAL?
        case /* 991 */ OP_vpcomb:      /**< IA-32/AMD64 vpcomb opcode. */
        case /* 992 */ OP_vpcomw:      /**< IA-32/AMD64 vpcomw opcode. */
        case /* 993 */ OP_vpcomd:      /**< IA-32/AMD64 vpcomd opcode. */
        case /* 994 */ OP_vpcomq:      /**< IA-32/AMD64 vpcomq opcode. */
        case /* 995 */ OP_vpcomub:     /**< IA-32/AMD64 vpcomub opcode. */
        case /* 996 */ OP_vpcomuw:     /**< IA-32/AMD64 vpcomuw opcode. */
        case /* 997 */ OP_vpcomud:     /**< IA-32/AMD64 vpcomud opcode. */
        case /* 998 */ OP_vpcomuq:     /**< IA-32/AMD64 vpcomuq opcode. */

        /* AMD XOP */
        case /* 1001 */ OP_vphaddbw:   /**< IA-32/AMD64 vphaddbw opcode. */
        case /* 1002 */ OP_vphaddbd:   /**< IA-32/AMD64 vphaddbd opcode. */
        case /* 1003 */ OP_vphaddbq:   /**< IA-32/AMD64 vphaddbq opcode. */
        case /* 1004 */ OP_vphaddwd:   /**< IA-32/AMD64 vphaddwd opcode. */
        case /* 1005 */ OP_vphaddwq:   /**< IA-32/AMD64 vphaddwq opcode. */
        case /* 1006 */ OP_vphadddq:   /**< IA-32/AMD64 vphadddq opcode. */
        case /* 1007 */ OP_vphaddubw:  /**< IA-32/AMD64 vphaddubw opcode. */
        case /* 1008 */ OP_vphaddubd:  /**< IA-32/AMD64 vphaddubd opcode. */
        case /* 1009 */ OP_vphaddubq:  /**< IA-32/AMD64 vphaddubq opcode. */
        case /* 1010 */ OP_vphadduwd:  /**< IA-32/AMD64 vphadduwd opcode. */
        case /* 1011 */ OP_vphadduwq:  /**< IA-32/AMD64 vphadduwq opcode. */
        case /* 1012 */ OP_vphaddudq:  /**< IA-32/AMD64 vphaddudq opcode. */
        case /* 1013 */ OP_vphsubbw:   /**< IA-32/AMD64 vphsubbw opcode. */
        case /* 1014 */ OP_vphsubwd:   /**< IA-32/AMD64 vphsubwd opcode. */
        case /* 1015 */ OP_vphsubdq:   /**< IA-32/AMD64 vphsubdq opcode. */
        case /* 1016 */ OP_vpmacssww:  /**< IA-32/AMD64 vpmacssww opcode. */
        case /* 1017 */ OP_vpmacsswd:  /**< IA-32/AMD64 vpmacsswd opcode. */
        case /* 1018 */ OP_vpmacssdql: /**< IA-32/AMD64 vpmacssdql opcode. */
        case /* 1019 */ OP_vpmacssdd:  /**< IA-32/AMD64 vpmacssdd opcode. */
        case /* 1020 */ OP_vpmacssdqh: /**< IA-32/AMD64 vpmacssdqh opcode. */
        case /* 1021 */ OP_vpmacsww:   /**< IA-32/AMD64 vpmacsww opcode. */
        case /* 1022 */ OP_vpmacswd:   /**< IA-32/AMD64 vpmacswd opcode. */
        case /* 1023 */ OP_vpmacsdql:  /**< IA-32/AMD64 vpmacsdql opcode. */
        case /* 1024 */ OP_vpmacsdd:   /**< IA-32/AMD64 vpmacsdd opcode. */
        case /* 1025 */ OP_vpmacsdqh:  /**< IA-32/AMD64 vpmacsdqh opcode. */
        case /* 1026 */ OP_vpmadcsswd: /**< IA-32/AMD64 vpmadcsswd opcode. */
        case /* 1027 */ OP_vpmadcswd:  /**< IA-32/AMD64 vpmadcswd opcode. */

        // TODO: MOV?
        case /* 1028 */ OP_vpperm:     /**< IA-32/AMD64 vpperm opcode. */
        case /* 1029 */ OP_vprotb:     /**< IA-32/AMD64 vprotb opcode. */
        case /* 1030 */ OP_vprotw:     /**< IA-32/AMD64 vprotw opcode. */
        case /* 1031 */ OP_vprotd:     /**< IA-32/AMD64 vprotd opcode. */
        case /* 1032 */ OP_vprotq:     /**< IA-32/AMD64 vprotq opcode. */
        case /* 1033 */ OP_vpshlb:     /**< IA-32/AMD64 vpshlb opcode. */
        case /* 1034 */ OP_vpshlw:     /**< IA-32/AMD64 vpshlw opcode. */
        case /* 1035 */ OP_vpshld:     /**< IA-32/AMD64 vpshld opcode. */
        case /* 1036 */ OP_vpshlq:     /**< IA-32/AMD64 vpshlq opcode. */
        case /* 1037 */ OP_vpshab:     /**< IA-32/AMD64 vpshab opcode. */
        case /* 1038 */ OP_vpshaw:     /**< IA-32/AMD64 vpshaw opcode. */
        case /* 1039 */ OP_vpshad:     /**< IA-32/AMD64 vpshad opcode. */
        case /* 1040 */ OP_vpshaq:     /**< IA-32/AMD64 vpshaq opcode. */

        /* AVX2 */
        case /* 1094 */ OP_vpsllvd:        /**< IA-32/AMD64 vpsllvd opcode. */
        case /* 1095 */ OP_vpsllvq:        /**< IA-32/AMD64 vpsllvq opcode. */
        case /* 1096 */ OP_vpsravd:        /**< IA-32/AMD64 vpsravd opcode. */
        case /* 1097 */ OP_vpsrlvd:        /**< IA-32/AMD64 vpsrlvd opcode. */
        case /* 1098 */ OP_vpsrlvq:        /**< IA-32/AMD64 vpsrlvq opcode. */

        /* Intel AVX-512 VEX */
        case /* 1111 */ OP_kandw:    /**< IA-32/AMD64 AVX-512 kandw opcode. */
        case /* 1112 */ OP_kandb:    /**< IA-32/AMD64 AVX-512 kandb opcode. */
        case /* 1113 */ OP_kandq:    /**< IA-32/AMD64 AVX-512 kandq opcode. */
        case /* 1114 */ OP_kandd:    /**< IA-32/AMD64 AVX-512 kandd opcode. */
        case /* 1115 */ OP_kandnw:   /**< IA-32/AMD64 AVX-512 kandnw opcode. */
        case /* 1116 */ OP_kandnb:   /**< IA-32/AMD64 AVX-512 kandnb opcode. */
        case /* 1117 */ OP_kandnq:   /**< IA-32/AMD64 AVX-512 kandnq opcode. */
        case /* 1118 */ OP_kandnd:   /**< IA-32/AMD64 AVX-512 kandnd opcode. */

        case /* 1122 */ OP_knotw:    /**< IA-32/AMD64 AVX-512 knotw opcode. */
        case /* 1123 */ OP_knotb:    /**< IA-32/AMD64 AVX-512 knotb opcode. */
        case /* 1124 */ OP_knotq:    /**< IA-32/AMD64 AVX-512 knotq opcode. */
        case /* 1125 */ OP_knotd:    /**< IA-32/AMD64 AVX-512 knotd opcode. */
        case /* 1126 */ OP_korw:     /**< IA-32/AMD64 AVX-512 korw opcode. */
        case /* 1127 */ OP_korb:     /**< IA-32/AMD64 AVX-512 korb opcode. */
        case /* 1128 */ OP_korq:     /**< IA-32/AMD64 AVX-512 korq opcode. */
        case /* 1129 */ OP_kord:     /**< IA-32/AMD64 AVX-512 kord opcode. */
        case /* 1130 */ OP_kxnorw:   /**< IA-32/AMD64 AVX-512 kxnorw opcode. */
        case /* 1131 */ OP_kxnorb:   /**< IA-32/AMD64 AVX-512 kxnorb opcode. */
        case /* 1132 */ OP_kxnorq:   /**< IA-32/AMD64 AVX-512 kxnorq opcode. */
        case /* 1133 */ OP_kxnord:   /**< IA-32/AMD64 AVX-512 kxnord opcode. */
        case /* 1134 */ OP_kxorw:    /**< IA-32/AMD64 AVX-512 kxorw opcode. */
        case /* 1135 */ OP_kxorb:    /**< IA-32/AMD64 AVX-512 kxorb opcode. */
        case /* 1136 */ OP_kxorq:    /**< IA-32/AMD64 AVX-512 kxorq opcode. */
        case /* 1137 */ OP_kxord:    /**< IA-32/AMD64 AVX-512 kxord opcode. */
        case /* 1138 */ OP_kaddw:    /**< IA-32/AMD64 AVX-512 kaddw opcode. */
        case /* 1139 */ OP_kaddb:    /**< IA-32/AMD64 AVX-512 kaddb opcode. */
        case /* 1140 */ OP_kaddq:    /**< IA-32/AMD64 AVX-512 kaddq opcode. */
        case /* 1141 */ OP_kaddd:    /**< IA-32/AMD64 AVX-512 kaddd opcode. */

        case /* 1142 */ OP_kortestw: /**< IA-32/AMD64 AVX-512 kortestw opcode. */
        case /* 1143 */ OP_kortestb: /**< IA-32/AMD64 AVX-512 kortestb opcode. */
        case /* 1144 */ OP_kortestq: /**< IA-32/AMD64 AVX-512 kortestq opcode. */
        case /* 1145 */ OP_kortestd: /**< IA-32/AMD64 AVX-512 kortestd opcode. */
        case /* 1146 */ OP_kshiftlw: /**< IA-32/AMD64 AVX-512 kshiftlw opcode. */
        case /* 1147 */ OP_kshiftlb: /**< IA-32/AMD64 AVX-512 kshiftlb opcode. */
        case /* 1148 */ OP_kshiftlq: /**< IA-32/AMD64 AVX-512 kshiftlq opcode. */
        case /* 1149 */ OP_kshiftld: /**< IA-32/AMD64 AVX-512 kshiftld opcode. */
        case /* 1150 */ OP_kshiftrw: /**< IA-32/AMD64 AVX-512 kshiftrw opcode. */
        case /* 1151 */ OP_kshiftrb: /**< IA-32/AMD64 AVX-512 kshiftrb opcode. */
        case /* 1152 */ OP_kshiftrq: /**< IA-32/AMD64 AVX-512 kshiftrq opcode. */
        case /* 1153 */ OP_kshiftrd: /**< IA-32/AMD64 AVX-512 kshiftrd opcode. */

        case /* 1154 */ OP_ktestw:   /**< IA-32/AMD64 AVX-512 ktestd opcode. */
        case /* 1155 */ OP_ktestb:   /**< IA-32/AMD64 AVX-512 ktestd opcode. */
        case /* 1156 */ OP_ktestq:   /**< IA-32/AMD64 AVX-512 ktestd opcode. */
        case /* 1157 */ OP_ktestd:   /**< IA-32/AMD64 AVX-512 ktestd opcode. */

        /* Intel AVX-512 EVEX */
        case /* 1198 */ OP_vdbpsadbw:       /**< IA-32/AMD64 AVX-512 OP_vdbpsadbw opcode. */

        case /* 1249 */ OP_vpabsq:          /**< IA-32/AMD64 AVX-512 OP_vpabsq opcode. */
        case /* 1250 */ OP_vpandd:          /**< IA-32/AMD64 AVX-512 OP_vpandd opcode. */
        case /* 1251 */ OP_vpandnd:         /**< IA-32/AMD64 AVX-512 OP_vpandnd opcode. */
        case /* 1252 */ OP_vpandnq:         /**< IA-32/AMD64 AVX-512 OP_vpandnq opcode. */
        case /* 1253 */ OP_vpandq:          /**< IA-32/AMD64 AVX-512 OP_vpandq opcode. */

        // TODO: LOGICAL?
        case /* 1260 */ OP_vpcmpb:          /**< IA-32/AMD64 AVX-512 OP_vpcmpb opcode. */
        case /* 1261 */ OP_vpcmpd:          /**< IA-32/AMD64 AVX-512 OP_vpcmpd opcode. */
        case /* 1262 */ OP_vpcmpq:          /**< IA-32/AMD64 AVX-512 OP_vpcmpq opcode. */
        case /* 1263 */ OP_vpcmpub:         /**< IA-32/AMD64 AVX-512 OP_vpcmpub opcode. */
        case /* 1264 */ OP_vpcmpud:         /**< IA-32/AMD64 AVX-512 OP_vpcmpud opcode. */
        case /* 1265 */ OP_vpcmpuq:         /**< IA-32/AMD64 AVX-512 OP_vpcmpuq opcode. */
        case /* 1266 */ OP_vpcmpuw:         /**< IA-32/AMD64 AVX-512 OP_vpcmpuw opcode. */
        case /* 1267 */ OP_vpcmpw:          /**< IA-32/AMD64 AVX-512 OP_vpcmpw opcode. */

        case /* 1290 */ OP_vplzcntd:        /**< IA-32/AMD64 AVX-512 OP_vplzcntd opcode. */
        case /* 1291 */ OP_vplzcntq:        /**< IA-32/AMD64 AVX-512 OP_vplzcntq opcode. */
        case /* 1292 */ OP_vpmadd52huq:     /**< IA-32/AMD64 AVX-512 OP_vpmadd52huq opcode. */
        case /* 1293 */ OP_vpmadd52luq:     /**< IA-32/AMD64 AVX-512 OP_vpmadd52luq opcode. */
        case /* 1294 */ OP_vpmaxsq:         /**< IA-32/AMD64 AVX-512 OP_vpmaxsq opcode. */
        case /* 1295 */ OP_vpmaxuq:         /**< IA-32/AMD64 AVX-512 OP_vpmaxuq opcode. */
        case /* 1296 */ OP_vpminsq:         /**< IA-32/AMD64 AVX-512 OP_vpminsq opcode. */
        case /* 1297 */ OP_vpminuq:         /**< IA-32/AMD64 AVX-512 OP_vpminuq opcode. */

        case /* 1324 */ OP_vpmullq:         /**< IA-32/AMD64 AVX-512 OP_vpmullq opcode. */

        // TODO: LOGICAL?
        case /* 1325 */ OP_vpord:           /**< IA-32/AMD64 AVX-512 OP_vpord opcode. */
        case /* 1326 */ OP_vporq:           /**< IA-32/AMD64 AVX-512 OP_vporq opcode. */
        case /* 1327 */ OP_vprold:          /**< IA-32/AMD64 AVX-512 OP_vprold opcode. */
        case /* 1328 */ OP_vprolq:          /**< IA-32/AMD64 AVX-512 OP_vprolq opcode. */
        case /* 1329 */ OP_vprolvd:         /**< IA-32/AMD64 AVX-512 OP_vprolvd opcode. */
        case /* 1330 */ OP_vprolvq:         /**< IA-32/AMD64 AVX-512 OP_vprolvq opcode. */
        case /* 1331 */ OP_vprord:          /**< IA-32/AMD64 AVX-512 OP_vprord opcode. */
        case /* 1332 */ OP_vprorq:          /**< IA-32/AMD64 AVX-512 OP_vprorq opcode. */
        case /* 1333 */ OP_vprorvd:         /**< IA-32/AMD64 AVX-512 OP_vprorvd opcode. */
        case /* 1334 */ OP_vprorvq:         /**< IA-32/AMD64 AVX-512 OP_vprorvq opcode. */

        // TODO: LOGICAL?
        case /* 1339 */ OP_vpsllvw:         /**< IA-32/AMD64 AVX-512 OP_vpsllvw opcode. */
        case /* 1340 */ OP_vpsraq:          /**< IA-32/AMD64 AVX-512 OP_vpsraq opcode. */
        case /* 1341 */ OP_vpsravq:         /**< IA-32/AMD64 AVX-512 OP_vpsravq opcode. */
        case /* 1342 */ OP_vpsravw:         /**< IA-32/AMD64 AVX-512 OP_vpsravw opcode. */
        case /* 1343 */ OP_vpsrlvw:         /**< IA-32/AMD64 AVX-512 OP_vpsrlvw opcode. */
        case /* 1344 */ OP_vpternlogd:      /**< IA-32/AMD64 AVX-512 OP_vpternlogd opcode. */
        case /* 1345 */ OP_vpternlogq:      /**< IA-32/AMD64 AVX-512 OP_vpternlogd opcode. */
        case /* 1346 */ OP_vptestmb:        /**< IA-32/AMD64 AVX-512 OP_vptestmb opcode. */
        case /* 1347 */ OP_vptestmd:        /**< IA-32/AMD64 AVX-512 OP_vptestmd opcode. */
        case /* 1348 */ OP_vptestmq:        /**< IA-32/AMD64 AVX-512 OP_vptestmq opcode. */
        case /* 1349 */ OP_vptestmw:        /**< IA-32/AMD64 AVX-512 OP_vptestmw opcode. */
        case /* 1350 */ OP_vptestnmb:       /**< IA-32/AMD64 AVX-512 OP_vptestnmb opcode. */
        case /* 1351 */ OP_vptestnmd:       /**< IA-32/AMD64 AVX-512 OP_vptestnmd opcode. */
        case /* 1352 */ OP_vptestnmq:       /**< IA-32/AMD64 AVX-512 OP_vptestnmq opcode. */
        case /* 1353 */ OP_vptestnmw:       /**< IA-32/AMD64 AVX-512 OP_vptestnmw opcode. */
        case /* 1354 */ OP_vpxord:          /**< IA-32/AMD64 AVX-512 OP_vpxordvpxord opcode. */
        case /* 1355 */ OP_vpxorq:          /**< IA-32/AMD64 AVX-512 OP_vpxorq opcode. */ return true;

        default: return false;
    }
}

DR_API
bool
instr_is_integer(instr_t *instr) {
    return instr_is_scalar_integer(instr) || instr_is_simd_integer(instr);
}

static bool
instr_is_scalar_float(instr_t *instr) {
    switch (instr_get_opcode(instr)) {
        case /* 399 */ OP_fadd:    /**< IA-32/AMD64 fadd opcode. */
        case /* 400 */ OP_fmul:    /**< IA-32/AMD64 fmul opcode. */
        case /* 401 */ OP_fcom:    /**< IA-32/AMD64 fcom opcode. */
        case /* 402 */ OP_fcomp:   /**< IA-32/AMD64 fcomp opcode. */
        case /* 403 */ OP_fsub:    /**< IA-32/AMD64 fsub opcode. */
        case /* 404 */ OP_fsubr:   /**< IA-32/AMD64 fsubr opcode. */
        case /* 405 */ OP_fdiv:    /**< IA-32/AMD64 fdiv opcode. */
        case /* 406 */ OP_fdivr:   /**< IA-32/AMD64 fdivr opcode. */
        case /* 414 */ OP_fiadd:   /**< IA-32/AMD64 fiadd opcode. */
        case /* 415 */ OP_fimul:   /**< IA-32/AMD64 fimul opcode. */
        case /* 416 */ OP_ficom:   /**< IA-32/AMD64 ficom opcode. */
        case /* 417 */ OP_ficomp:  /**< IA-32/AMD64 ficomp opcode. */
        case /* 418 */ OP_fisub:   /**< IA-32/AMD64 fisub opcode. */
        case /* 419 */ OP_fisubr:  /**< IA-32/AMD64 fisubr opcode. */
        case /* 420 */ OP_fidiv:   /**< IA-32/AMD64 fidiv opcode. */
        case /* 421 */ OP_fidivr:  /**< IA-32/AMD64 fidivr opcode. */

        case /* 432 */ OP_fchs:     /**< IA-32/AMD64 fchs opcode. */
        case /* 433 */ OP_fabs:     /**< IA-32/AMD64 fabs opcode. */
        case /* 434 */ OP_ftst:     /**< IA-32/AMD64 ftst opcode. */
        case /* 435 */ OP_fxam:     /**< IA-32/AMD64 fxam opcode. */

        case /* 443 */ OP_f2xm1:    /**< IA-32/AMD64 f2xm1 opcode. */
        case /* 444 */ OP_fyl2x:    /**< IA-32/AMD64 fyl2x opcode. */
        case /* 445 */ OP_fptan:    /**< IA-32/AMD64 fptan opcode. */
        case /* 446 */ OP_fpatan:   /**< IA-32/AMD64 fpatan opcode. */
        case /* 448 */ OP_fprem1:   /**< IA-32/AMD64 fprem1 opcode. */
        case /* 451 */ OP_fprem:    /**< IA-32/AMD64 fprem opcode. */
        case /* 452 */ OP_fyl2xp1:  /**< IA-32/AMD64 fyl2xp1 opcode. */
        case /* 453 */ OP_fsqrt:    /**< IA-32/AMD64 fsqrt opcode. */
        case /* 454 */ OP_fsincos:  /**< IA-32/AMD64 fsincos opcode. */
        case /* 455 */ OP_frndint:  /**< IA-32/AMD64 frndint opcode. */
        case /* 456 */ OP_fscale:   /**< IA-32/AMD64 fscale opcode. */
        case /* 457 */ OP_fsin:     /**< IA-32/AMD64 fsin opcode. */
        case /* 458 */ OP_fcos:     /**< IA-32/AMD64 fcos opcode. */
        case /* 473 */ OP_fucom:    /**< IA-32/AMD64 fucom opcode. */
        case /* 474 */ OP_fucomp:   /**< IA-32/AMD64 fucomp opcode. */
        case /* 475 */ OP_faddp:    /**< IA-32/AMD64 faddp opcode. */
        case /* 476 */ OP_fmulp:    /**< IA-32/AMD64 fmulp opcode. */
        case /* 477 */ OP_fcompp:   /**< IA-32/AMD64 fcompp opcode. */
        case /* 478 */ OP_fsubrp:   /**< IA-32/AMD64 fsubrp opcode. */
        case /* 479 */ OP_fsubp:    /**< IA-32/AMD64 fsubp opcode. */
        case /* 480 */ OP_fdivrp:   /**< IA-32/AMD64 fdivrp opcode. */
        case /* 481 */ OP_fdivp:    /**< IA-32/AMD64 fdivp opcode. */
        case /* 482 */ OP_fucomip:  /**< IA-32/AMD64 fucomip opcode. */
        case /* 483 */ OP_fcomip:   /**< IA-32/AMD64 fcomip opcode. */

        case /* 319 */ OP_ucomiss:   /**< IA-32/AMD64 ucomiss opcode. */
        case /* 320 */ OP_ucomisd:   /**< IA-32/AMD64 ucomisd opcode. */
        case /* 321 */ OP_comiss:    /**< IA-32/AMD64 comiss opcode. */
        case /* 322 */ OP_comisd:    /**< IA-32/AMD64 comisd opcode. */

        case /* 326 */ OP_sqrtss:    /**< IA-32/AMD64 sqrtss opcode. */

        case /* 328 */ OP_sqrtsd:    /**< IA-32/AMD64 sqrtsd opcode. */

        case /* 330 */ OP_rsqrtss:   /**< IA-32/AMD64 rsqrtss opcode. */

        case /* 332 */ OP_rcpss:     /**< IA-32/AMD64 rcpss opcode. */

        case /* 342 */ OP_addss:     /**< IA-32/AMD64 addss opcode. */

        case /* 344 */ OP_addsd:     /**< IA-32/AMD64 addsd opcode. */

        case /* 346 */ OP_mulss:     /**< IA-32/AMD64 mulss opcode. */

        case /* 348 */ OP_mulsd:     /**< IA-32/AMD64 mulsd opcode. */

        case /* 357 */ OP_subss:     /**< IA-32/AMD64 subss opcode. */

        case /* 359 */ OP_subsd:     /**< IA-32/AMD64 subsd opcode. */

        case /* 361 */ OP_minss:     /**< IA-32/AMD64 minss opcode. */

        case /* 363 */ OP_minsd:     /**< IA-32/AMD64 minsd opcode. */

        case /* 365 */ OP_divss:     /**< IA-32/AMD64 divss opcode. */

        case /* 367 */ OP_divsd:     /**< IA-32/AMD64 divsd opcode. */

        case /* 369 */ OP_maxss:     /**< IA-32/AMD64 maxss opcode. */

        case /* 371 */ OP_maxsd:     /**< IA-32/AMD64 maxsd opcode. */

        case /* 373 */ OP_cmpss:     /**< IA-32/AMD64 cmpss opcode. */

        case /* 375 */ OP_cmpsd:     /**< IA-32/AMD64 cmpsd opcode. */

        /* SSE3 instructions */

        /* 3D-Now! instructions */
        case /* 499 */ OP_pavgusb:       /**< IA-32/AMD64 pavgusb opcode. */
        case /* 500 */ OP_pfadd:         /**< IA-32/AMD64 pfadd opcode. */
        case /* 501 */ OP_pfacc:         /**< IA-32/AMD64 pfacc opcode. */
        case /* 502 */ OP_pfcmpge:       /**< IA-32/AMD64 pfcmpge opcode. */
        case /* 503 */ OP_pfcmpgt:       /**< IA-32/AMD64 pfcmpgt opcode. */
        case /* 504 */ OP_pfcmpeq:       /**< IA-32/AMD64 pfcmpeq opcode. */
        case /* 505 */ OP_pfmin:         /**< IA-32/AMD64 pfmin opcode. */
        case /* 506 */ OP_pfmax:         /**< IA-32/AMD64 pfmax opcode. */
        case /* 507 */ OP_pfmul:         /**< IA-32/AMD64 pfmul opcode. */
        case /* 508 */ OP_pfrcp:         /**< IA-32/AMD64 pfrcp opcode. */
        case /* 509 */ OP_pfrcpit1:      /**< IA-32/AMD64 pfrcpit1 opcode. */
        case /* 510 */ OP_pfrcpit2:      /**< IA-32/AMD64 pfrcpit2 opcode. */
        case /* 511 */ OP_pfrsqrt:       /**< IA-32/AMD64 pfrsqrt opcode. */
        case /* 512 */ OP_pfrsqit1:      /**< IA-32/AMD64 pfrsqit1 opcode. */
        case /* 513 */ OP_pmulhrw:       /**< IA-32/AMD64 pmulhrw opcode. */
        case /* 514 */ OP_pfsub:         /**< IA-32/AMD64 pfsub opcode. */
        case /* 515 */ OP_pfsubr:        /**< IA-32/AMD64 pfsubr opcode. */
        case /* 516 */ OP_pi2fd:         /**< IA-32/AMD64 pi2fd opcode. */
        case /* 517 */ OP_pf2id:         /**< IA-32/AMD64 pf2id opcode. */
        case /* 518 */ OP_pi2fw:         /**< IA-32/AMD64 pi2fw opcode. */
        case /* 519 */ OP_pf2iw:         /**< IA-32/AMD64 pf2iw opcode. */
        case /* 520 */ OP_pfnacc:        /**< IA-32/AMD64 pfnacc opcode. */
        case /* 521 */ OP_pfpnacc:       /**< IA-32/AMD64 pfpnacc opcode. */

        /* SSE4 (incl AMD (SSE4A) and Intel-specific (SSE4.1, SSE4.2) extensions */
        case /* 582 */ OP_roundss:    /**< IA-32/AMD64 roundss opcode. */
        case /* 583 */ OP_roundsd:    /**< IA-32/AMD64 roundsd opcode. */

        /* AVX */
        case /* 661 */ OP_vucomiss:         /**< IA-32/AMD64 vucomiss opcode. */
        case /* 662 */ OP_vucomisd:         /**< IA-32/AMD64 vucomisd opcode. */
        case /* 663 */ OP_vcomiss:          /**< IA-32/AMD64 vcomiss opcode. */
        case /* 664 */ OP_vcomisd:          /**< IA-32/AMD64 vcomisd opcode. */

        case /* 668 */ OP_vsqrtss:          /**< IA-32/AMD64 vsqrtss opcode. */

        case /* 670 */ OP_vsqrtsd:          /**< IA-32/AMD64 vsqrtsd opcode. */

        case /* 672 */ OP_vrsqrtss:         /**< IA-32/AMD64 vrsqrtss opcode. */

        case /* 674 */ OP_vrcpss:           /**< IA-32/AMD64 vrcpss opcode. */

        case /* 684 */ OP_vaddss:           /**< IA-32/AMD64 vaddss opcode. */

        case /* 686 */ OP_vaddsd:           /**< IA-32/AMD64 vaddsd opcode. */

        case /* 688 */ OP_vmulss:           /**< IA-32/AMD64 vmulss opcode. */
        
        case /* 690 */ OP_vmulsd:           /**< IA-32/AMD64 vmulsd opcode. */

        case /* 699 */ OP_vsubss:           /**< IA-32/AMD64 vsubss opcode. */

        case /* 701 */ OP_vsubsd:           /**< IA-32/AMD64 vsubsd opcode. */

        case /* 703 */ OP_vminss:           /**< IA-32/AMD64 vminss opcode. */

        case /* 705 */ OP_vminsd:           /**< IA-32/AMD64 vminsd opcode. */

        case /* 707 */ OP_vdivss:           /**< IA-32/AMD64 vdivss opcode. */

        case /* 709 */ OP_vdivsd:           /**< IA-32/AMD64 vdivsd opcode. */

        case /* 711 */ OP_vmaxss:           /**< IA-32/AMD64 vmaxss opcode. */
        
        case /* 713 */ OP_vmaxsd:           /**< IA-32/AMD64 vmaxsd opcode. */

        case /* 718 */ OP_vpcmpgtb:         /**< IA-32/AMD64 vpcmpgtb opcode. */
        case /* 719 */ OP_vpcmpgtw:         /**< IA-32/AMD64 vpcmpgtw opcode. */
        case /* 720 */ OP_vpcmpgtd:         /**< IA-32/AMD64 vpcmpgtd opcode. */

        case /* 737 */ OP_vcmpss:           /**< IA-32/AMD64 vcmpss opcode. */

        case /* 739 */ OP_vcmpsd:           /**< IA-32/AMD64 vcmpsd opcode. */


        case /* 858 */ OP_vroundss:         /**< IA-32/AMD64 vroundss opcode. */
        case /* 859 */ OP_vroundsd:         /**< IA-32/AMD64 vroundsd opcode. */

        /* FMA */
        case /* 899 */ OP_vfmadd132ss:    /**< IA-32/AMD64 vfmadd132ss opcode. */

        case /* 900 */ OP_vfmadd132sd:    /**< IA-32/AMD64 vfmadd132sd opcode. */
        case /* 901 */ OP_vfmadd213ss:    /**< IA-32/AMD64 vfmadd213ss opcode. */
        case /* 902 */ OP_vfmadd213sd:    /**< IA-32/AMD64 vfmadd213sd opcode. */
        case /* 903 */ OP_vfmadd231ss:    /**< IA-32/AMD64 vfmadd231ss opcode. */
        case /* 904 */ OP_vfmadd231sd:    /**< IA-32/AMD64 vfmadd231sd opcode. */

        case /* 923 */ OP_vfmsub132ss:    /**< IA-32/AMD64 vfmsub132ss opcode. */
        case /* 924 */ OP_vfmsub132sd:    /**< IA-32/AMD64 vfmsub132sd opcode. */
        case /* 925 */ OP_vfmsub213ss:    /**< IA-32/AMD64 vfmsub213ss opcode. */
        case /* 926 */ OP_vfmsub213sd:    /**< IA-32/AMD64 vfmsub213sd opcode. */
        case /* 927 */ OP_vfmsub231ss:    /**< IA-32/AMD64 vfmsub231ss opcode. */
        case /* 928 */ OP_vfmsub231sd:    /**< IA-32/AMD64 vfmsub231sd opcode. */

        case /* 935 */ OP_vfnmadd132ss:   /**< IA-32/AMD64 vfnmadd132ss opcode. */
        case /* 936 */ OP_vfnmadd132sd:   /**< IA-32/AMD64 vfnmadd132sd opcode. */
        case /* 937 */ OP_vfnmadd213ss:   /**< IA-32/AMD64 vfnmadd213ss opcode. */
        case /* 938 */ OP_vfnmadd213sd:   /**< IA-32/AMD64 vfnmadd213sd opcode. */
        case /* 939 */ OP_vfnmadd231ss:   /**< IA-32/AMD64 vfnmadd231ss opcode. */
        case /* 940 */ OP_vfnmadd231sd:   /**< IA-32/AMD64 vfnmadd231sd opcode. */

        case /* 947 */ OP_vfnmsub132ss:   /**< IA-32/AMD64 vfnmsub132ss opcode. */
        case /* 948 */ OP_vfnmsub132sd:   /**< IA-32/AMD64 vfnmsub132sd opcode. */
        case /* 949 */ OP_vfnmsub213ss:   /**< IA-32/AMD64 vfnmsub213ss opcode. */
        case /* 950 */ OP_vfnmsub213sd:   /**< IA-32/AMD64 vfnmsub213sd opcode. */
        case /* 951 */ OP_vfnmsub231ss:   /**< IA-32/AMD64 vfnmsub231ss opcode. */
        case /* 952 */ OP_vfnmsub231sd:   /**< IA-32/AMD64 vfnmsub231sd opcode. */

        /* AMD FMA4 */
        case /* 972 */ OP_vfmaddss:    /**< IA-32/AMD64 vfmaddss opcode. */
        case /* 973 */ OP_vfmaddsd:    /**< IA-32/AMD64 vfmaddsd opcode. */

        case /* 976 */ OP_vfmsubss:    /**< IA-32/AMD64 vfmsubss opcode. */
        case /* 977 */ OP_vfmsubsd:    /**< IA-32/AMD64 vfmsubsd opcode. */

        case /* 980 */ OP_vfnmaddss:   /**< IA-32/AMD64 vfnmaddss opcode. */
        case /* 981 */ OP_vfnmaddsd:   /**< IA-32/AMD64 vfnmaddsd opcode. */

        case /* 984 */ OP_vfnmsubss:   /**< IA-32/AMD64 vfnmsubss opcode. */
        case /* 985 */ OP_vfnmsubsd:   /**< IA-32/AMD64 vfnmsubsd opcode. */

        /* AMD XOP */
        case /* 988 */ OP_vfrczss:     /**< IA-32/AMD64 vfrczss opcode. */
        case /* 989 */ OP_vfrczsd:     /**< IA-32/AMD64 vfrczsd opcode. */

        /* Intel AVX-512 VEX */

        // TODO: GET:MANTISA AND EXPONENT -> OTHER?
        case /* 1229 */ OP_vgetexpsd:       /**< IA-32/AMD64 AVX-512 OP_vgetexpsd opcode. */
        case /* 1230 */ OP_vgetexpss:       /**< IA-32/AMD64 AVX-512 OP_vgetexpss opcode. */

        case /* 1233 */ OP_vgetmantsd:      /**< IA-32/AMD64 AVX-512 OP_vgetmantsd opcode. */
        case /* 1234 */ OP_vgetmantss:      /**< IA-32/AMD64 AVX-512 OP_vgetmantss opcode. */

        case /* 1362 */ OP_vrcp14sd:        /**< IA-32/AMD64 AVX-512 OP_vrcp14sd opcode. */
        case /* 1363 */ OP_vrcp14ss:        /**< IA-32/AMD64 AVX-512 OP_vrcp14ss opcode. */

        case /* 1366 */ OP_vrcp28sd:        /**< IA-32/AMD64 AVX-512 OP_vrcp28sd opcode. */
        case /* 1367 */ OP_vrcp28ss:        /**< IA-32/AMD64 AVX-512 OP_vrcp28ss opcode. */

        case /* 1378 */ OP_vrsqrt14sd:      /**< IA-32/AMD64 AVX-512 OP_vrsqrt14sd opcode. */
        case /* 1379 */ OP_vrsqrt14ss:      /**< IA-32/AMD64 AVX-512 OP_vrsqrt14ss opcode. */
        
        case /* 1382 */ OP_vrsqrt28sd:      /**< IA-32/AMD64 AVX-512 OP_vrsqrt28sd opcode. */
        case /* 1383 */ OP_vrsqrt28ss:      /**< IA-32/AMD64 AVX-512 OP_vrsqrt28ss opcode. */ return true;

        default: return false;
    }
}

static bool
instr_is_simd_float(instr_t *instr) {
    switch (instr_get_opcode(instr)) {
        case /* 325 */ OP_sqrtps:    /**< IA-32/AMD64 sqrtps opcode. */

        case /* 327 */ OP_sqrtpd:    /**< IA-32/AMD64 sqrtpd opcode. */

        case /* 329 */ OP_rsqrtps:   /**< IA-32/AMD64 rsqrtps opcode. */

        case /* 331 */ OP_rcpps:     /**< IA-32/AMD64 rcpps opcode. */

        case /* 333 */ OP_andps:     /**< IA-32/AMD64 andps opcode. */
        case /* 334 */ OP_andpd:     /**< IA-32/AMD64 andpd opcode. */
        case /* 335 */ OP_andnps:    /**< IA-32/AMD64 andnps opcode. */
        case /* 336 */ OP_andnpd:    /**< IA-32/AMD64 andnpd opcode. */
        case /* 337 */ OP_orps:      /**< IA-32/AMD64 orps opcode. */
        case /* 338 */ OP_orpd:      /**< IA-32/AMD64 orpd opcode. */
        case /* 339 */ OP_xorps:     /**< IA-32/AMD64 xorps opcode. */
        case /* 340 */ OP_xorpd:     /**< IA-32/AMD64 xorpd opcode. */
        case /* 341 */ OP_addps:     /**< IA-32/AMD64 addps opcode. */

        case /* 343 */ OP_addpd:     /**< IA-32/AMD64 addpd opcode. */

        case /* 345 */ OP_mulps:     /**< IA-32/AMD64 mulps opcode. */

        case /* 347 */ OP_mulpd:     /**< IA-32/AMD64 mulpd opcode. */
        
        case /* 356 */ OP_subps:     /**< IA-32/AMD64 subps opcode. */

        case /* 358 */ OP_subpd:     /**< IA-32/AMD64 subpd opcode. */
        
        case /* 360 */ OP_minps:     /**< IA-32/AMD64 minps opcode. */
        
        case /* 362 */ OP_minpd:     /**< IA-32/AMD64 minpd opcode. */

        case /* 364 */ OP_divps:     /**< IA-32/AMD64 divps opcode. */

        case /* 366 */ OP_divpd:     /**< IA-32/AMD64 divpd opcode. */

        case /* 368 */ OP_maxps:     /**< IA-32/AMD64 maxps opcode. */

        case /* 370 */ OP_maxpd:     /**< IA-32/AMD64 maxpd opcode. */

        case /* 372 */ OP_cmpps:     /**< IA-32/AMD64 cmpps opcode. */

        case /* 374 */ OP_cmppd:     /**< IA-32/AMD64 cmppd opcode. */

        case /* 376 */ OP_shufps:    /**< IA-32/AMD64 shufps opcode. */
        case /* 377 */ OP_shufpd:    /**< IA-32/AMD64 shufpd opcode. */

        case /* 485 */ OP_haddpd:   /**< IA-32/AMD64 haddpd opcode. */
        case /* 486 */ OP_haddps:   /**< IA-32/AMD64 haddps opcode. */
        case /* 487 */ OP_hsubpd:   /**< IA-32/AMD64 hsubpd opcode. */
        case /* 488 */ OP_hsubps:   /**< IA-32/AMD64 hsubps opcode. */
        case /* 489 */ OP_addsubpd: /**< IA-32/AMD64 addsubpd opcode. */
        case /* 490 */ OP_addsubps: /**< IA-32/AMD64 addsubps opcode. */

        case /* 580 */ OP_roundps:    /**< IA-32/AMD64 roundps opcode. */
        case /* 581 */ OP_roundpd:    /**< IA-32/AMD64 roundpd opcode. */
        
        case /* 590 */ OP_dpps:       /**< IA-32/AMD64 dpps opcode. */
        case /* 591 */ OP_dppd:       /**< IA-32/AMD64 dppd opcode. */

        case /* 667 */ OP_vsqrtps:          /**< IA-32/AMD64 vsqrtps opcode. */

        case /* 669 */ OP_vsqrtpd:          /**< IA-32/AMD64 vsqrtpd opcode. */

        case /* 671 */ OP_vrsqrtps:         /**< IA-32/AMD64 vrsqrtps opcode. */

        case /* 673 */ OP_vrcpps:           /**< IA-32/AMD64 vrcpps opcode. */
        
        case /* 675 */ OP_vandps:           /**< IA-32/AMD64 vandps opcode. */
        case /* 676 */ OP_vandpd:           /**< IA-32/AMD64 vandpd opcode. */
        case /* 677 */ OP_vandnps:          /**< IA-32/AMD64 vandnps opcode. */
        case /* 678 */ OP_vandnpd:          /**< IA-32/AMD64 vandnpd opcode. */
        case /* 679 */ OP_vorps:            /**< IA-32/AMD64 vorps opcode. */
        case /* 680 */ OP_vorpd:            /**< IA-32/AMD64 vorpd opcode. */
        case /* 681 */ OP_vxorps:           /**< IA-32/AMD64 vxorps opcode. */
        case /* 682 */ OP_vxorpd:           /**< IA-32/AMD64 vxorpd opcode. */
        case /* 683 */ OP_vaddps:           /**< IA-32/AMD64 vaddps opcode. */

        case /* 685 */ OP_vaddpd:           /**< IA-32/AMD64 vaddpd opcode. */

        case /* 687 */ OP_vmulps:           /**< IA-32/AMD64 vmulps opcode. */

        case /* 689 */ OP_vmulpd:           /**< IA-32/AMD64 vmulpd opcode. */

        case /* 698 */ OP_vsubps:           /**< IA-32/AMD64 vsubps opcode. */

        case /* 700 */ OP_vsubpd:           /**< IA-32/AMD64 vsubpd opcode. */

        case /* 702 */ OP_vminps:           /**< IA-32/AMD64 vminps opcode. */

        case /* 704 */ OP_vminpd:           /**< IA-32/AMD64 vminpd opcode. */

        case /* 706 */ OP_vdivps:           /**< IA-32/AMD64 vdivps opcode. */

        case /* 708 */ OP_vdivpd:           /**< IA-32/AMD64 vdivpd opcode. */

        case /* 710 */ OP_vmaxps:           /**< IA-32/AMD64 vmaxps opcode. */

        case /* 712 */ OP_vmaxpd:           /**< IA-32/AMD64 vmaxpd opcode. */

        case /* 736 */ OP_vcmpps:           /**< IA-32/AMD64 vcmpps opcode. */
        
        case /* 738 */ OP_vcmppd:           /**< IA-32/AMD64 vcmppd opcode. */
        
        case /* 794 */ OP_vhaddpd:          /**< IA-32/AMD64 vhaddpd opcode. */
        case /* 795 */ OP_vhaddps:          /**< IA-32/AMD64 vhaddps opcode. */
        case /* 796 */ OP_vhsubpd:          /**< IA-32/AMD64 vhsubpd opcode. */
        case /* 797 */ OP_vhsubps:          /**< IA-32/AMD64 vhsubps opcode. */
        case /* 798 */ OP_vaddsubpd:        /**< IA-32/AMD64 vaddsubpd opcode. */
        case /* 799 */ OP_vaddsubps:        /**< IA-32/AMD64 vaddsubps opcode. */

        case /* 856 */ OP_vroundps:         /**< IA-32/AMD64 vroundps opcode. */
        case /* 857 */ OP_vroundpd:         /**< IA-32/AMD64 vroundpd opcode. */

        case /* 866 */ OP_vdpps:            /**< IA-32/AMD64 vdpps opcode. */
        case /* 867 */ OP_vdppd:            /**< IA-32/AMD64 vdppd opcode. */
        
        case /* 875 */ OP_vtestps:          /**< IA-32/AMD64 vtestps opcode. */
        case /* 876 */ OP_vtestpd:          /**< IA-32/AMD64 vtestpd opcode. */

        case /* 893 */ OP_vfmadd132ps:    /**< IA-32/AMD64 vfmadd132ps opcode. */
        case /* 894 */ OP_vfmadd132pd:    /**< IA-32/AMD64 vfmadd132pd opcode. */
        case /* 895 */ OP_vfmadd213ps:    /**< IA-32/AMD64 vfmadd213ps opcode. */
        case /* 896 */ OP_vfmadd213pd:    /**< IA-32/AMD64 vfmadd213pd opcode. */
        case /* 897 */ OP_vfmadd231ps:    /**< IA-32/AMD64 vfmadd231ps opcode. */
        case /* 898 */ OP_vfmadd231pd:    /**< IA-32/AMD64 vfmadd231pd opcode. */

        case /* 905 */ OP_vfmaddsub132ps: /**< IA-32/AMD64 vfmaddsub132ps opcode. */
        case /* 906 */ OP_vfmaddsub132pd: /**< IA-32/AMD64 vfmaddsub132pd opcode. */
        case /* 907 */ OP_vfmaddsub213ps: /**< IA-32/AMD64 vfmaddsub213ps opcode. */
        case /* 908 */ OP_vfmaddsub213pd: /**< IA-32/AMD64 vfmaddsub213pd opcode. */
        case /* 909 */ OP_vfmaddsub231ps: /**< IA-32/AMD64 vfmaddsub231ps opcode. */
        case /* 910 */ OP_vfmaddsub231pd: /**< IA-32/AMD64 vfmaddsub231pd opcode. */
        case /* 911 */ OP_vfmsubadd132ps: /**< IA-32/AMD64 vfmsubadd132ps opcode. */
        case /* 912 */ OP_vfmsubadd132pd: /**< IA-32/AMD64 vfmsubadd132pd opcode. */
        case /* 913 */ OP_vfmsubadd213ps: /**< IA-32/AMD64 vfmsubadd213ps opcode. */
        case /* 914 */ OP_vfmsubadd213pd: /**< IA-32/AMD64 vfmsubadd213pd opcode. */
        case /* 915 */ OP_vfmsubadd231ps: /**< IA-32/AMD64 vfmsubadd231ps opcode. */
        case /* 916 */ OP_vfmsubadd231pd: /**< IA-32/AMD64 vfmsubadd231pd opcode. */
        case /* 917 */ OP_vfmsub132ps:    /**< IA-32/AMD64 vfmsub132ps opcode. */
        case /* 918 */ OP_vfmsub132pd:    /**< IA-32/AMD64 vfmsub132pd opcode. */
        case /* 919 */ OP_vfmsub213ps:    /**< IA-32/AMD64 vfmsub213ps opcode. */
        case /* 920 */ OP_vfmsub213pd:    /**< IA-32/AMD64 vfmsub213pd opcode. */
        case /* 921 */ OP_vfmsub231ps:    /**< IA-32/AMD64 vfmsub231ps opcode. */
        case /* 922 */ OP_vfmsub231pd:    /**< IA-32/AMD64 vfmsub231pd opcode. */

        case /* 929 */ OP_vfnmadd132ps:   /**< IA-32/AMD64 vfnmadd132ps opcode. */
        case /* 930 */ OP_vfnmadd132pd:   /**< IA-32/AMD64 vfnmadd132pd opcode. */
        case /* 931 */ OP_vfnmadd213ps:   /**< IA-32/AMD64 vfnmadd213ps opcode. */
        case /* 932 */ OP_vfnmadd213pd:   /**< IA-32/AMD64 vfnmadd213pd opcode. */
        case /* 933 */ OP_vfnmadd231ps:   /**< IA-32/AMD64 vfnmadd231ps opcode. */
        case /* 934 */ OP_vfnmadd231pd:   /**< IA-32/AMD64 vfnmadd231pd opcode. */

        case /* 941 */ OP_vfnmsub132ps:   /**< IA-32/AMD64 vfnmsub132ps opcode. */
        case /* 942 */ OP_vfnmsub132pd:   /**< IA-32/AMD64 vfnmsub132pd opcode. */
        case /* 943 */ OP_vfnmsub213ps:   /**< IA-32/AMD64 vfnmsub213ps opcode. */
        case /* 944 */ OP_vfnmsub213pd:   /**< IA-32/AMD64 vfnmsub213pd opcode. */
        case /* 945 */ OP_vfnmsub231ps:   /**< IA-32/AMD64 vfnmsub231ps opcode. */
        case /* 946 */ OP_vfnmsub231pd:   /**< IA-32/AMD64 vfnmsub231pd opcode. */

        case /* 966 */ OP_vfmaddsubps: /**< IA-32/AMD64 vfmaddsubps opcode. */
        case /* 967 */ OP_vfmaddsubpd: /**< IA-32/AMD64 vfmaddsubpd opcode. */
        case /* 968 */ OP_vfmsubaddps: /**< IA-32/AMD64 vfmsubaddps opcode. */
        case /* 969 */ OP_vfmsubaddpd: /**< IA-32/AMD64 vfmsubaddpd opcode. */
        case /* 970 */ OP_vfmaddps:    /**< IA-32/AMD64 vfmaddps opcode. */
        case /* 971 */ OP_vfmaddpd:    /**< IA-32/AMD64 vfmaddpd opcode. */

        case /* 974 */ OP_vfmsubps:    /**< IA-32/AMD64 vfmsubps opcode. */
        case /* 975 */ OP_vfmsubpd:    /**< IA-32/AMD64 vfmsubpd opcode. */

        case /* 978 */ OP_vfnmaddps:   /**< IA-32/AMD64 vfnmaddps opcode. */
        case /* 979 */ OP_vfnmaddpd:   /**< IA-32/AMD64 vfnmaddpd opcode. */

        case /* 982 */ OP_vfnmsubps:   /**< IA-32/AMD64 vfnmsubps opcode. */
        case /* 983 */ OP_vfnmsubpd:   /**< IA-32/AMD64 vfnmsubpd opcode. */

        case /* 986 */ OP_vfrczps:     /**< IA-32/AMD64 vfrczps opcode. */
        case /* 987 */ OP_vfrczpd:     /**< IA-32/AMD64 vfrczpd opcode. */

        case /* 1199 */ OP_vexp2pd:         /**< IA-32/AMD64 AVX-512 OP_vexp2pd opcode. */
        case /* 1200 */ OP_vexp2ps:         /**< IA-32/AMD64 AVX-512 OP_vexp2ps opcode. */

        case /* 1227 */ OP_vgetexppd:       /**< IA-32/AMD64 AVX-512 OP_vgetexppd opcode. */
        case /* 1228 */ OP_vgetexpps:       /**< IA-32/AMD64 AVX-512 OP_vgetexpps opcode. */

        case /* 1231 */ OP_vgetmantpd:      /**< IA-32/AMD64 AVX-512 OP_vgetmantpd opcode. */
        case /* 1232 */ OP_vgetmantps:      /**< IA-32/AMD64 AVX-512 OP_vgetmantps opcode. */

        case /* 1360 */ OP_vrcp14pd:        /**< IA-32/AMD64 AVX-512 OP_vrcp14pd opcode. */
        case /* 1361 */ OP_vrcp14ps:        /**< IA-32/AMD64 AVX-512 OP_vrcp14ps opcode. */
        
        case /* 1364 */ OP_vrcp28pd:        /**< IA-32/AMD64 AVX-512 OP_vrcp28pd opcode. */
        case /* 1365 */ OP_vrcp28ps:        /**< IA-32/AMD64 AVX-512 OP_vrcp28ps opcode. */

        case /* 1376 */ OP_vrsqrt14pd:      /**< IA-32/AMD64 AVX-512 OP_vrsqrt14pd opcode. */
        case /* 1377 */ OP_vrsqrt14ps:      /**< IA-32/AMD64 AVX-512 OP_vrsqrt14ps opcode. */
        case /* 1380 */ OP_vrsqrt28pd:      /**< IA-32/AMD64 AVX-512 OP_vrsqrt28pd opcode. */
        case /* 1381 */ OP_vrsqrt28ps:      /**< IA-32/AMD64 AVX-512 OP_vrsqrt28ps opcode. */ return true;

        default: return false;
    }
}

DR_API
bool
instr_is_float(instr_t *instr) {
    return instr_is_scalar_float(instr) || instr_is_simd_float(instr);
}

DR_API
bool
instr_is_branch(instr_t *instr) {
    switch (instr_get_opcode(instr)) {
        case /*  26 */ OP_jo_short:   /**< IA-32/AMD64 jo_short opcode. */
        case /*  27 */ OP_jno_short:  /**< IA-32/AMD64 jno_short opcode. */
        case /*  28 */ OP_jb_short:   /**< IA-32/AMD64 jb_short opcode. */
        case /*  29 */ OP_jnb_short:  /**< IA-32/AMD64 jnb_short opcode. */
        case /*  30 */ OP_jz_short:   /**< IA-32/AMD64 jz_short opcode. */
        case /*  31 */ OP_jnz_short:  /**< IA-32/AMD64 jnz_short opcode. */
        case /*  32 */ OP_jbe_short:  /**< IA-32/AMD64 jbe_short opcode. */
        case /*  33 */ OP_jnbe_short: /**< IA-32/AMD64 jnbe_short opcode. */
        case /*  34 */ OP_js_short:   /**< IA-32/AMD64 js_short opcode. */
        case /*  35 */ OP_jns_short:  /**< IA-32/AMD64 jns_short opcode. */
        case /*  36 */ OP_jp_short:   /**< IA-32/AMD64 jp_short opcode. */
        case /*  37 */ OP_jnp_short:  /**< IA-32/AMD64 jnp_short opcode. */
        case /*  38 */ OP_jl_short:   /**< IA-32/AMD64 jl_short opcode. */
        case /*  39 */ OP_jnl_short:  /**< IA-32/AMD64 jnl_short opcode. */
        case /*  40 */ OP_jle_short:  /**< IA-32/AMD64 jle_short opcode. */
        case /*  41 */ OP_jnle_short: /**< IA-32/AMD64 jnle_short opcode. */
        case /*  42 */ OP_call:         /**< IA-32/AMD64 call opcode. */
        case /*  43 */ OP_call_ind:     /**< IA-32/AMD64 call_ind opcode. */
        case /*  44 */ OP_call_far:     /**< IA-32/AMD64 call_far opcode. */
        case /*  45 */ OP_call_far_ind: /**< IA-32/AMD64 call_far_ind opcode. */
        case /*  46 */ OP_jmp:          /**< IA-32/AMD64 jmp opcode. */
        case /*  47 */ OP_jmp_short:    /**< IA-32/AMD64 jmp_short opcode. */
        case /*  48 */ OP_jmp_ind:      /**< IA-32/AMD64 jmp_ind opcode. */
        case /*  49 */ OP_jmp_far:      /**< IA-32/AMD64 jmp_far opcode. */
        case /*  50 */ OP_jmp_far_ind:  /**< IA-32/AMD64 jmp_far_ind opcode. */ 

        case /*  51 */ OP_loopne: /**< IA-32/AMD64 loopne opcode. */
        case /*  52 */ OP_loope:  /**< IA-32/AMD64 loope opcode. */
        case /*  53 */ OP_loop:   /**< IA-32/AMD64 loop opcode. */
        case /*  54 */ OP_jecxz:  /**< IA-32/AMD64 jecxz opcode. */

        case /*  70 */ OP_ret:     /**< IA-32/AMD64 ret opcode. */
        case /*  71 */ OP_ret_far: /**< IA-32/AMD64 ret_far opcode. */

        case /*  76 */ OP_int3:  /**< IA-32/AMD64 int3 opcode. */
        case /*  77 */ OP_int:   /**< IA-32/AMD64 int opcode. */
        case /*  78 */ OP_into:  /**< IA-32/AMD64 into opcode. */
        case /*  79 */ OP_iret:  /**< IA-32/AMD64 iret opcode. */

        case /*  95 */ OP_syscall:   /**< IA-32/AMD64 syscall opcode. */
        case /*  97 */ OP_sysret:    /**< IA-32/AMD64 sysret opcode. */

        case /* 108 */ OP_sysenter:  /**< IA-32/AMD64 sysenter opcode. */
        case /* 109 */ OP_sysexit:   /**< IA-32/AMD64 sysexit opcode. */

        case /* 152 */ OP_jo:   /**< IA-32/AMD64 jo opcode. */
        case /* 153 */ OP_jno:  /**< IA-32/AMD64 jno opcode. */
        case /* 154 */ OP_jb:   /**< IA-32/AMD64 jb opcode. */
        case /* 155 */ OP_jnb:  /**< IA-32/AMD64 jnb opcode. */
        case /* 156 */ OP_jz:   /**< IA-32/AMD64 jz opcode. */
        case /* 157 */ OP_jnz:  /**< IA-32/AMD64 jnz opcode. */
        case /* 158 */ OP_jbe:  /**< IA-32/AMD64 jbe opcode. */
        case /* 159 */ OP_jnbe: /**< IA-32/AMD64 jnbe opcode. */
        case /* 160 */ OP_js:   /**< IA-32/AMD64 js opcode. */
        case /* 161 */ OP_jns:  /**< IA-32/AMD64 jns opcode. */
        case /* 162 */ OP_jp:   /**< IA-32/AMD64 jp opcode. */
        case /* 163 */ OP_jnp:  /**< IA-32/AMD64 jnp opcode. */
        case /* 164 */ OP_jl:   /**< IA-32/AMD64 jl opcode. */
        case /* 165 */ OP_jnl:  /**< IA-32/AMD64 jnl opcode. */
        case /* 166 */ OP_jle:  /**< IA-32/AMD64 jle opcode. */
        case /* 167 */ OP_jnle: /**< IA-32/AMD64 jnle opcode. */ return true;

        default: return false;
    }
}

DR_API
bool
instr_is_stack(instr_t *instr) {
    switch (instr_get_opcode(instr)) {
        case /*  18 */ OP_push:     /**< IA-32/AMD64 push opcode. */
        case /*  19 */ OP_push_imm: /**< IA-32/AMD64 push_imm opcode. */
        case /*  20 */ OP_pop:      /**< IA-32/AMD64 pop opcode. */
        case /*  21 */ OP_pusha:    /**< IA-32/AMD64 pusha opcode. */
        case /*  22 */ OP_popa:     /**< IA-32/AMD64 popa opcode. */

        case /*  66 */ OP_pushf: /**< IA-32/AMD64 pushf opcode. */
        case /*  67 */ OP_popf:  /**< IA-32/AMD64 popf opcode. */
        case /*  74 */ OP_enter: /**< IA-32/AMD64 enter opcode. */
        case /*  75 */ OP_leave: /**< IA-32/AMD64 leave opcode. */

        case /* 191 */ OP_lss:        /**< IA-32/AMD64 lss opcode. */

        // TODO:
        case /* 436 */ OP_fld1:     /**< IA-32/AMD64 fld1 opcode. */
        case /* 437 */ OP_fldl2t:   /**< IA-32/AMD64 fldl2t opcode. */
        case /* 438 */ OP_fldl2e:   /**< IA-32/AMD64 fldl2e opcode. */
        case /* 439 */ OP_fldpi:    /**< IA-32/AMD64 fldpi opcode. */
        case /* 440 */ OP_fldlg2:   /**< IA-32/AMD64 fldlg2 opcode. */
        case /* 441 */ OP_fldln2:   /**< IA-32/AMD64 fldln2 opcode. */
        case /* 442 */ OP_fldz:     /**< IA-32/AMD64 fldz opcode. */
        case /* 449 */ OP_fdecstp:  /**< IA-32/AMD64 fdecstp opcode. */
        case /* 450 */ OP_fincstp:  /**< IA-32/AMD64 fincstp opcode. */
        case /* 474 */ OP_fucomp:   /**< IA-32/AMD64 fucomp opcode. */
        case /* 475 */ OP_faddp:    /**< IA-32/AMD64 faddp opcode. */
        case /* 476 */ OP_fmulp:    /**< IA-32/AMD64 fmulp opcode. */
        case /* 477 */ OP_fcompp:   /**< IA-32/AMD64 fcompp opcode. */
        case /* 478 */ OP_fsubrp:   /**< IA-32/AMD64 fsubrp opcode. */
        case /* 479 */ OP_fsubp:    /**< IA-32/AMD64 fsubp opcode. */
        case /* 480 */ OP_fdivrp:   /**< IA-32/AMD64 fdivrp opcode. */
        case /* 481 */ OP_fdivp:    /**< IA-32/AMD64 fdivp opcode. */
        case /* 482 */ OP_fucomip:  /**< IA-32/AMD64 fucomip opcode. */
        case /* 483 */ OP_fcomip:   /**< IA-32/AMD64 fcomip opcode. */ return true;

        default: return false;
    }
}

/*
 * UNCLASSIFIED INSTRUCTIONS
 */

// /*  65 */ OP_fwait, /**< IA-32/AMD64 fwait opcode. */

// /*  68 */ OP_sahf,  /**< IA-32/AMD64 sahf opcode. */
// /*  69 */ OP_lahf,  /**< IA-32/AMD64 lahf opcode. */

// /*  80 */ OP_aam,   /**< IA-32/AMD64 aam opcode. */
// /*  81 */ OP_aad,   /**< IA-32/AMD64 aad opcode. */
// /*  82 */ OP_xlat,  /**< IA-32/AMD64 xlat opcode. */
// /*  83 */ OP_in,    /**< IA-32/AMD64 in opcode. */
// /*  84 */ OP_out,   /**< IA-32/AMD64 out opcode. */
// /*  85 */ OP_hlt,   /**< IA-32/AMD64 hlt opcode. */
// /*  86 */ OP_cmc,   /**< IA-32/AMD64 cmc opcode. */
// /*  87 */ OP_clc,   /**< IA-32/AMD64 clc opcode. */
// /*  88 */ OP_stc,   /**< IA-32/AMD64 stc opcode. */
// /*  89 */ OP_cli,   /**< IA-32/AMD64 cli opcode. */
// /*  90 */ OP_sti,   /**< IA-32/AMD64 sti opcode. */
// /*  91 */ OP_cld,   /**< IA-32/AMD64 cld opcode. */
// /*  92 */ OP_std,   /**< IA-32/AMD64 std opcode. */

// /*  93 */ OP_lar,       /**< IA-32/AMD64 lar opcode. */
// /*  94 */ OP_lsl,       /**< IA-32/AMD64 lsl opcode. */

// /*  96 */ OP_clts,      /**< IA-32/AMD64 clts opcode. */
// 
// /*  98 */ OP_invd,      /**< IA-32/AMD64 invd opcode. */
// /*  99 */ OP_wbinvd,    /**< IA-32/AMD64 wbinvd opcode. */
// /* 100 */ OP_ud2a,      /**< IA-32/AMD64 ud2a opcode. */
// /* 101 */ OP_nop_modrm, /**< IA-32/AMD64 nop_modrm opcode. */

// /* 104 */ OP_wrmsr,     /**< IA-32/AMD64 wrmsr opcode. */
// /* 105 */ OP_rdtsc,     /**< IA-32/AMD64 rdtsc opcode. */
// /* 106 */ OP_rdmsr,     /**< IA-32/AMD64 rdmsr opcode. */
// /* 107 */ OP_rdpmc,     /**< IA-32/AMD64 rdpmc opcode. */

// /* 151 */ OP_emms,       /**< IA-32/AMD64 emms opcode. */
//
// /* 184 */ OP_cpuid,      /**< IA-32/AMD64 cpuid opcode. */

// /* 187 */ OP_rsm,        /**< IA-32/AMD64 rsm opcode. */
// /* 196 */ OP_ud2b,       /**< IA-32/AMD64 ud2b opcode. */

// /* 265 */ OP_sldt,        /**< IA-32/AMD64 sldt opcode. */
// /* 266 */ OP_str,         /**< IA-32/AMD64 str opcode. */
// /* 278 */ OP_cmpxchg8b,   /**< IA-32/AMD64 cmpxchg8b opcode. */
// /* 283 */ OP_lfence,      /**< IA-32/AMD64 lfence opcode. */
// /* 284 */ OP_mfence,      /**< IA-32/AMD64 mfence opcode. */
// /* 279 */ OP_fxsave32,    /**< IA-32/AMD64 fxsave opcode. */
// /* 280 */ OP_fxrstor32,   /**< IA-32/AMD64 fxrstor opcode. */
// /* 285 */ OP_clflush,     /**< IA-32/AMD64 clflush opcode. */
// /* 286 */ OP_sfence,      /**< IA-32/AMD64 sfence opcode. */
// /* 287 */ OP_prefetchnta, /**< IA-32/AMD64 prefetchnta opcode. */
// /* 288 */ OP_prefetcht0,  /**< IA-32/AMD64 prefetcht0 opcode. */
// /* 289 */ OP_prefetcht1,  /**< IA-32/AMD64 prefetcht1 opcode. */
// /* 290 */ OP_prefetcht2,  /**< IA-32/AMD64 prefetcht2 opcode. */
// /* 291 */ OP_prefetch,    /**< IA-32/AMD64 prefetch opcode. */
// /* 292 */ OP_prefetchw,   /**< IA-32/AMD64 prefetchw opcode. */

// /* 267 */ OP_lldt,        /**< IA-32/AMD64 lldt opcode. */
// /* 268 */ OP_ltr,         /**< IA-32/AMD64 ltr opcode. */
// /* 269 */ OP_verr,        /**< IA-32/AMD64 verr opcode. */
// /* 270 */ OP_verw,        /**< IA-32/AMD64 verw opcode. */
// /* 271 */ OP_sgdt,        /**< IA-32/AMD64 sgdt opcode. */
// /* 272 */ OP_sidt,        /**< IA-32/AMD64 sidt opcode. */
// /* 273 */ OP_lgdt,        /**< IA-32/AMD64 lgdt opcode. */
// /* 274 */ OP_lidt,        /**< IA-32/AMD64 lidt opcode. */
// /* 275 */ OP_smsw,        /**< IA-32/AMD64 smsw opcode. */
// /* 276 */ OP_lmsw,        /**< IA-32/AMD64 lmsw opcode. */
// /* 277 */ OP_invlpg,      /**< IA-32/AMD64 invlpg opcode. */
//
// /* 281 */ OP_ldmxcsr,     /**< IA-32/AMD64 ldmxcsr opcode. */
// /* 282 */ OP_stmxcsr,     /**< IA-32/AMD64 stmxcsr opcode. */
//
// // TODO: MOV/FLOATING POINT/INTEGER??
// /* 307 */ OP_cvtpi2ps,  /**< IA-32/AMD64 cvtpi2ps opcode. */
// /* 308 */ OP_cvtsi2ss,  /**< IA-32/AMD64 cvtsi2ss opcode. */
// /* 309 */ OP_cvtpi2pd,  /**< IA-32/AMD64 cvtpi2pd opcode. */
// /* 310 */ OP_cvtsi2sd,  /**< IA-32/AMD64 cvtsi2sd opcode. */
// /* 311 */ OP_cvttps2pi, /**< IA-32/AMD64 cvttps2pi opcode. */
// /* 312 */ OP_cvttss2si, /**< IA-32/AMD64 cvttss2si opcode. */
// /* 313 */ OP_cvttpd2pi, /**< IA-32/AMD64 cvttpd2pi opcode. */
// /* 314 */ OP_cvttsd2si, /**< IA-32/AMD64 cvttsd2si opcode. */
// /* 315 */ OP_cvtps2pi,  /**< IA-32/AMD64 cvtps2pi opcode. */
// /* 316 */ OP_cvtss2si,  /**< IA-32/AMD64 cvtss2si opcode. */
// /* 317 */ OP_cvtpd2pi,  /**< IA-32/AMD64 cvtpd2pi opcode. */
// /* 318 */ OP_cvtsd2si,  /**< IA-32/AMD64 cvtsd2si opcode. */
//
// // TODO: MOV/FLOATING POINT/INTEGER??
// /* 349 */ OP_cvtps2pd,  /**< IA-32/AMD64 cvtps2pd opcode. */
// /* 350 */ OP_cvtss2sd,  /**< IA-32/AMD64 cvtss2sd opcode. */
// /* 351 */ OP_cvtpd2ps,  /**< IA-32/AMD64 cvtpd2ps opcode. */
// /* 352 */ OP_cvtsd2ss,  /**< IA-32/AMD64 cvtsd2ss opcode. */
// /* 353 */ OP_cvtdq2ps,  /**< IA-32/AMD64 cvtdq2ps opcode. */
// /* 354 */ OP_cvttps2dq, /**< IA-32/AMD64 cvttps2dq opcode. */
// /* 355 */ OP_cvtps2dq,  /**< IA-32/AMD64 cvtps2dq opcode. */
//
// // TODO: MOV/FLOATING POINT/INTEGER??
// /* 378 */ OP_cvtdq2pd,  /**< IA-32/AMD64 cvtdq2pd opcode. */
// /* 379 */ OP_cvttpd2dq, /**< IA-32/AMD64 cvttpd2dq opcode. */
// /* 380 */ OP_cvtpd2dq,  /**< IA-32/AMD64 cvtpd2dq opcode. */
//
// /* 381 */ OP_nop,       /**< IA-32/AMD64 nop opcode. */
// /* 382 */ OP_pause,     /**< IA-32/AMD64 pause opcode. */

// /* 383 */ OP_ins,        /**< IA-32/AMD64 ins opcode. */
// /* 384 */ OP_rep_ins,    /**< IA-32/AMD64 rep_ins opcode. */
// /* 385 */ OP_outs,       /**< IA-32/AMD64 outs opcode. */
// /* 386 */ OP_rep_outs,   /**< IA-32/AMD64 rep_outs opcode. */

// /* 393 */ OP_cmps,       /**< IA-32/AMD64 cmps opcode. */
// /* 394 */ OP_rep_cmps,   /**< IA-32/AMD64 rep_cmps opcode. */
// /* 395 */ OP_repne_cmps, /**< IA-32/AMD64 repne_cmps opcode. */
// /* 396 */ OP_scas,       /**< IA-32/AMD64 scas opcode. */
// /* 397 */ OP_rep_scas,   /**< IA-32/AMD64 rep_scas opcode. */
// /* 398 */ OP_repne_scas, /**< IA-32/AMD64 repne_scas opcode. */

// /* 410 */ OP_fldenv,  /**< IA-32/AMD64 fldenv opcode. */
// /* 411 */ OP_fldcw,   /**< IA-32/AMD64 fldcw opcode. */
// /* 412 */ OP_fnstenv, /**< IA-32/AMD64 fnstenv opcode. */
// /* 413 */ OP_fnstcw,  /**< IA-32/AMD64 fnstcw opcode. */
// /* 425 */ OP_frstor,  /**< IA-32/AMD64 frstor opcode. */
// /* 426 */ OP_fnsave,  /**< IA-32/AMD64 fnsave opcode. */
// /* 427 */ OP_fnstsw,  /**< IA-32/AMD64 fnstsw opcode. */

// /* 428 */ OP_fbld,  /**< IA-32/AMD64 fbld opcode. */
// /* 429 */ OP_fbstp, /**< IA-32/AMD64 fbstp opcode. */

// /* 431 */ OP_fnop,     /**< IA-32/AMD64 fnop opcode. */

// /* 468 */ OP_fnclex,   /**< IA-32/AMD64 fnclex opcode. */
// /* 469 */ OP_fninit,   /**< IA-32/AMD64 fninit opcode. */
// /* 470 */ OP_fucomi,   /**< IA-32/AMD64 fucomi opcode. */
// /* 471 */ OP_fcomi,    /**< IA-32/AMD64 fcomi opcode. */
// /* 472 */ OP_ffree,    /**< IA-32/AMD64 ffree opcode. */

// /* SSE3 instructions */
// /* 492 */ OP_monitor,  /**< IA-32/AMD64 monitor opcode. */
// /* 493 */ OP_mwait,    /**< IA-32/AMD64 mwait opcode. */

// /* 3D-Now! instructions */
// /* 497 */ OP_femms,         /**< IA-32/AMD64 femms opcode. */
// /* 498 */ OP_unknown_3dnow, /**< IA-32/AMD64 unknown_3dnow opcode. */

// /* SSE4 (incl AMD (SSE4A) and Intel-specific (SSE4.1, SSE4.2) extensions */
// /* 593 */ OP_pcmpestrm,  /**< IA-32/AMD64 pcmpestrm opcode. */
// /* 594 */ OP_pcmpestri,  /**< IA-32/AMD64 pcmpestri opcode. */
// /* 595 */ OP_pcmpistrm,  /**< IA-32/AMD64 pcmpistrm opcode. */
// /* 596 */ OP_pcmpistri,  /**< IA-32/AMD64 pcmpistri opcode. */
// /* 576 */ OP_crc32,      /**< IA-32/AMD64 crc32 opcode. */

// /* 598 */ OP_swapgs, /**< IA-32/AMD64 swapgs opcode. */

// /* VMX */
// /* 599 */ OP_vmcall,   /**< IA-32/AMD64 vmcall opcode. */
// /* 600 */ OP_vmlaunch, /**< IA-32/AMD64 vmlaunch opcode. */
// /* 601 */ OP_vmresume, /**< IA-32/AMD64 vmresume opcode. */
// /* 602 */ OP_vmxoff,   /**< IA-32/AMD64 vmxoff opcode. */
// /* 603 */ OP_vmptrst,  /**< IA-32/AMD64 vmptrst opcode. */
// /* 604 */ OP_vmptrld,  /**< IA-32/AMD64 vmptrld opcode. */
// /* 605 */ OP_vmxon,    /**< IA-32/AMD64 vmxon opcode. */
// /* 606 */ OP_vmclear,  /**< IA-32/AMD64 vmclear opcode. */
// /* 607 */ OP_vmread,   /**< IA-32/AMD64 vmread opcode. */
// /* 608 */ OP_vmwrite,  /**< IA-32/AMD64 vmwrite opcode. */

// /* undocumented */
// /* 609 */ OP_int1,   /**< IA-32/AMD64 int1 opcode. */
// /* 610 */ OP_salc,   /**< IA-32/AMD64 salc opcode. */
// /* 611 */ OP_ffreep, /**< IA-32/AMD64 ffreep opcode. */

// /* AMD SVM */
// /* 612 */ OP_vmrun,   /**< IA-32/AMD64 vmrun opcode. */
// /* 613 */ OP_vmmcall, /**< IA-32/AMD64 vmmcall opcode. */
// /* 614 */ OP_vmload,  /**< IA-32/AMD64 vmload opcode. */
// /* 615 */ OP_vmsave,  /**< IA-32/AMD64 vmsave opcode. */
// /* 616 */ OP_stgi,    /**< IA-32/AMD64 stgi opcode. */
// /* 617 */ OP_clgi,    /**< IA-32/AMD64 clgi opcode. */
// /* 618 */ OP_skinit,  /**< IA-32/AMD64 skinit opcode. */
// /* 619 */ OP_invlpga, /**< IA-32/AMD64 invlpga opcode. */
//                       /* AMD though not part of SVM */
// /* 620 */ OP_rdtscp,  /**< IA-32/AMD64 rdtscp opcode. */

// /* Intel VMX additions */
// /* 621 */ OP_invept,  /**< IA-32/AMD64 invept opcode. */
// /* 622 */ OP_invvpid, /**< IA-32/AMD64 invvpid opcode. */

// /* added in Intel Westmere */
// /* 623 */ OP_pclmulqdq,       /**< IA-32/AMD64 pclmulqdq opcode. */
// /* 624 */ OP_aesimc,          /**< IA-32/AMD64 aesimc opcode. */
// /* 625 */ OP_aesenc,          /**< IA-32/AMD64 aesenc opcode. */
// /* 626 */ OP_aesenclast,      /**< IA-32/AMD64 aesenclast opcode. */
// /* 627 */ OP_aesdec,          /**< IA-32/AMD64 aesdec opcode. */
// /* 628 */ OP_aesdeclast,      /**< IA-32/AMD64 aesdeclast opcode. */
// /* 629 */ OP_aeskeygenassist, /**< IA-32/AMD64 aeskeygenassist opcode. */

// /* added in Intel Atom */
// /* 630 */ OP_movbe, /**< IA-32/AMD64 movbe opcode. */

// /* added in Intel Sandy Bridge */
// /* 631 */ OP_xgetbv,     /**< IA-32/AMD64 xgetbv opcode. */
// /* 632 */ OP_xsetbv,     /**< IA-32/AMD64 xsetbv opcode. */
// /* 633 */ OP_xsave32,    /**< IA-32/AMD64 xsave opcode. */
// /* 634 */ OP_xrstor32,   /**< IA-32/AMD64 xrstor opcode. */
// /* 635 */ OP_xsaveopt32, /**< IA-32/AMD64 xsaveopt opcode. */

// /* AVX */
// TODO: MOV/FLOATING POINT/INTEGER??
// case /* 653 */ OP_vcvtsi2ss:        /**< IA-32/AMD64 vcvtsi2ss opcode. */
// case /* 654 */ OP_vcvtsi2sd:        /**< IA-32/AMD64 vcvtsi2sd opcode. */
//
// TODO: MOV/FLOATING POINT/INTEGER??
// case /* 657 */ OP_vcvttss2si:       /**< IA-32/AMD64 vcvttss2si opcode. */
// case /* 658 */ OP_vcvttsd2si:       /**< IA-32/AMD64 vcvttsd2si opcode. */
// case /* 659 */ OP_vcvtss2si:        /**< IA-32/AMD64 vcvtss2si opcode. */
// case /* 660 */ OP_vcvtsd2si:        /**< IA-32/AMD64 vcvtsd2si opcode. */
//
// // TODO: MOV/FLOATING POINT/INTEGER??
// /* 691 */ OP_vcvtps2pd,        /**< IA-32/AMD64 vcvtps2pd opcode. */
// /* 692 */ OP_vcvtss2sd,        /**< IA-32/AMD64 vcvtss2sd opcode. */
// /* 693 */ OP_vcvtpd2ps,        /**< IA-32/AMD64 vcvtpd2ps opcode. */
// /* 694 */ OP_vcvtsd2ss,        /**< IA-32/AMD64 vcvtsd2ss opcode. */
// /* 695 */ OP_vcvtdq2ps,        /**< IA-32/AMD64 vcvtdq2ps opcode. */
// /* 696 */ OP_vcvttps2dq,       /**< IA-32/AMD64 vcvttps2dq opcode. */
// /* 697 */ OP_vcvtps2dq,        /**< IA-32/AMD64 vcvtps2dq opcode. */
//
// // TODO: MOV/FLOATING POINT/INTEGER??
// /* 764 */ OP_vcvtdq2pd,        /**< IA-32/AMD64 vcvtdq2pd opcode. */
// /* 765 */ OP_vcvttpd2dq,       /**< IA-32/AMD64 vcvttpd2dq opcode. */
// /* 766 */ OP_vcvtpd2dq,        /**< IA-32/AMD64 vcvtpd2dq opcode. */
//
// /* 848 */ OP_vaesimc,          /**< IA-32/AMD64 vaesimc opcode. */
// /* 849 */ OP_vaesenc,          /**< IA-32/AMD64 vaesenc opcode. */
// /* 850 */ OP_vaesenclast,      /**< IA-32/AMD64 vaesenclast opcode. */
// /* 851 */ OP_vaesdec,          /**< IA-32/AMD64 vaesdec opcode. */
// /* 852 */ OP_vaesdeclast,      /**< IA-32/AMD64 vaesdeclast opcode. */
//
// /* 869 */ OP_vpcmpestrm,       /**< IA-32/AMD64 vpcmpestrm opcode. */
// /* 870 */ OP_vpcmpestri,       /**< IA-32/AMD64 vpcmpestri opcode. */
// /* 871 */ OP_vpcmpistrm,       /**< IA-32/AMD64 vpcmpistrm opcode. */
// /* 872 */ OP_vpcmpistri,       /**< IA-32/AMD64 vpcmpistri opcode. */
// /* 873 */ OP_vpclmulqdq,       /**< IA-32/AMD64 vpclmulqdq opcode. */
//
// /* 874 */ OP_vaeskeygenassist, /**< IA-32/AMD64 vaeskeygenassist opcode. */
//
// // TODO: MOV/FLOATING POINT/INTEGER??
// /* 891 */ OP_vcvtph2ps, /**< IA-32/AMD64 vcvtph2ps opcode. */
// /* 892 */ OP_vcvtps2ph, /**< IA-32/AMD64 vcvtps2ph opcode. */
//
// /* 955 */ OP_fxsave64,   /**< IA-32/AMD64 fxsave64 opcode. */
// /* 956 */ OP_fxrstor64,  /**< IA-32/AMD64 fxrstor64 opcode. */
// /* 957 */ OP_xsave64,    /**< IA-32/AMD64 xsave64 opcode. */
// /* 958 */ OP_xrstor64,   /**< IA-32/AMD64 xrstor64 opcode. */
// /* 959 */ OP_xsaveopt64, /**< IA-32/AMD64 xsaveopt64 opcode. */

// /* added in Intel Ivy Bridge: RDRAND and FSGSBASE cpuid flags */
// /* 960 */ OP_rdrand,   /**< IA-32/AMD64 rdrand opcode. */
// /* 961 */ OP_rdfsbase, /**< IA-32/AMD64 rdfsbase opcode. */
// /* 962 */ OP_rdgsbase, /**< IA-32/AMD64 rdgsbase opcode. */
// /* 963 */ OP_wrfsbase, /**< IA-32/AMD64 wrfsbase opcode. */
// /* 964 */ OP_wrgsbase, /**< IA-32/AMD64 wrgsbase opcode. */

// /* coming in the future but adding now since enough details are known */
// /* 965 */ OP_rdseed, /**< IA-32/AMD64 rdseed opcode. */

// /* AMD LWP */
// /* 1051 */ OP_llwpcb, /**< IA-32/AMD64 llwpcb opcode. */
// /* 1052 */ OP_slwpcb, /**< IA-32/AMD64 slwpcb opcode. */
// /* 1053 */ OP_lwpins, /**< IA-32/AMD64 lwpins opcode. */
// /* 1054 */ OP_lwpval, /**< IA-32/AMD64 lwpval opcode. */

// /* Intel Safer Mode Extensions */
// /* 1068 */ OP_getsec, /**< IA-32/AMD64 getsec opcode. */

// /* Misc Intel additions */
// /* 1069 */ OP_vmfunc,  /**< IA-32/AMD64 vmfunc opcode. */
// /* 1070 */ OP_invpcid, /**< IA-32/AMD64 invpcid opcode. */

// /* Intel TSX */
// /* 1071 */ OP_xabort, /**< IA-32/AMD64 xabort opcode. */
// /* 1072 */ OP_xbegin, /**< IA-32/AMD64 xbegin opcode. */
// /* 1073 */ OP_xend,   /**< IA-32/AMD64 xend opcode. */
// /* 1074 */ OP_xtest,  /**< IA-32/AMD64 xtest opcode. */

// /* added in Intel Skylake */
// /* 1103 */ OP_xsavec32, /**< IA-32/AMD64 xsavec opcode. */
// /* 1104 */ OP_xsavec64, /**< IA-32/AMD64 xsavec64 opcode. */

// /* Intel AVX-512 EVEX */
// // TODO: MOV/FLOATING POINT/INTEGER??
// /* 1174 */ OP_vcvtpd2qq,       /**< IA-32/AMD64 AVX-512 OP_vcvtpd2qq opcode. */
// /* 1175 */ OP_vcvtpd2udq,      /**< IA-32/AMD64 AVX-512 OP_vcvtpd2udq opcode. */
// /* 1176 */ OP_vcvtpd2uqq,      /**< IA-32/AMD64 AVX-512 OP_vcvtpd2uqq opcode. */
// /* 1177 */ OP_vcvtps2qq,       /**< IA-32/AMD64 AVX-512 OP_vcvtps2qq opcode. */
// /* 1178 */ OP_vcvtps2udq,      /**< IA-32/AMD64 AVX-512 OP_vcvtps2udq opcode. */
// /* 1179 */ OP_vcvtps2uqq,      /**< IA-32/AMD64 AVX-512 OP_vcvtps2uqq opcode. */
// /* 1180 */ OP_vcvtqq2pd,       /**< IA-32/AMD64 AVX-512 OP_vcvtqq2pd opcode. */
// /* 1181 */ OP_vcvtqq2ps,       /**< IA-32/AMD64 AVX-512 OP_vcvtqq2ps opcode. */
// /* 1182 */ OP_vcvtsd2usi,      /**< IA-32/AMD64 AVX-512 OP_vcvtsd2usi opcode. */
// /* 1183 */ OP_vcvtss2usi,      /**< IA-32/AMD64 AVX-512 OP_vcvtss2usi opcode. */
// /* 1184 */ OP_vcvttpd2qq,      /**< IA-32/AMD64 AVX-512 OP_vcvttpd2qq opcode. */
// /* 1185 */ OP_vcvttpd2udq,     /**< IA-32/AMD64 AVX-512 OP_vcvttpd2udq opcode. */
// /* 1186 */ OP_vcvttpd2uqq,     /**< IA-32/AMD64 AVX-512 OP_vcvttpd2uqq opcode. */
// /* 1187 */ OP_vcvttps2qq,      /**< IA-32/AMD64 AVX-512 OP_vcvttps2qq opcode. */
// /* 1188 */ OP_vcvttps2udq,     /**< IA-32/AMD64 AVX-512 OP_vcvttps2udq opcode. */
// /* 1189 */ OP_vcvttps2uqq,     /**< IA-32/AMD64 AVX-512 OP_vcvttps2uqq opcode. */
// /* 1190 */ OP_vcvttsd2usi,     /**< IA-32/AMD64 AVX-512 OP_vcvttsd2usi opcode. */
// /* 1191 */ OP_vcvttss2usi,     /**< IA-32/AMD64 AVX-512 OP_vcvttss2usi opcode. */
// /* 1192 */ OP_vcvtudq2pd,      /**< IA-32/AMD64 AVX-512 OP_vcvtudq2pd opcode. */
// /* 1193 */ OP_vcvtudq2ps,      /**< IA-32/AMD64 AVX-512 OP_vcvtudq2ps opcode. */
// /* 1194 */ OP_vcvtuqq2pd,      /**< IA-32/AMD64 AVX-512 OP_vcvtuqq2pd opcode. */
// /* 1195 */ OP_vcvtuqq2ps,      /**< IA-32/AMD64 AVX-512 OP_vcvtuqq2ps opcode. */
// /* 1196 */ OP_vcvtusi2sd,      /**< IA-32/AMD64 AVX-512 OP_vcvtusi2sd opcode. */
// /* 1197 */ OP_vcvtusi2ss,      /**< IA-32/AMD64 AVX-512 OP_vcvtusi2ss opcode. */

// /* Intel AVX-512 EVEX */
// /* 1211 */ OP_vfixupimmpd,     /**< IA-32/AMD64 AVX-512 OP_vfixupimmpd opcode. */
// /* 1212 */ OP_vfixupimmps,     /**< IA-32/AMD64 AVX-512 OP_vfixupimmps opcode. */
// /* 1213 */ OP_vfixupimmsd,     /**< IA-32/AMD64 AVX-512 OP_vfixupimmsd opcode. */
// /* 1214 */ OP_vfixupimmss,     /**< IA-32/AMD64 AVX-512 OP_vfixupimmss opcode. */
//
// /* 1215 */ OP_vfpclasspd,      /**< IA-32/AMD64 AVX-512 OP_vfpclasspd opcode. */
// /* 1216 */ OP_vfpclassps,      /**< IA-32/AMD64 AVX-512 OP_vfpclassps opcode. */
// /* 1217 */ OP_vfpclasssd,      /**< IA-32/AMD64 AVX-512 OP_vfpclasssd opcode. */
// /* 1218 */ OP_vfpclassss,      /**< IA-32/AMD64 AVX-512 OP_vfpclassss opcode. */
//
// /* 1219 */ OP_vgatherpf0dpd,   /**< IA-32/AMD64 AVX-512 OP_vgatherpf0dps opcode. */
// /* 1220 */ OP_vgatherpf0dps,   /**< IA-32/AMD64 AVX-512 OP_vgatherpf0dps opcode. */
// /* 1221 */ OP_vgatherpf0qpd,   /**< IA-32/AMD64 AVX-512 OP_vgatherpf0qpd opcode. */
// /* 1222 */ OP_vgatherpf0qps,   /**< IA-32/AMD64 AVX-512 OP_vgatherpf0qps opcode. */
// /* 1223 */ OP_vgatherpf1dpd,   /**< IA-32/AMD64 AVX-512 OP_vgatherpf1dpd opcode. */
// /* 1224 */ OP_vgatherpf1dps,   /**< IA-32/AMD64 AVX-512 OP_vgatherpf1dps opcode. */
// /* 1225 */ OP_vgatherpf1qpd,   /**< IA-32/AMD64 AVX-512 OP_vgatherpf1qpd opcode. */
// /* 1226 */ OP_vgatherpf1qps,   /**< IA-32/AMD64 AVX-512 OP_vgatherpf1qps opcode. */
//
// /* 1270 */ OP_vpconflictd,     /**< IA-32/AMD64 AVX-512 OP_vpconflictd opcode. */
// /* 1271 */ OP_vpconflictq,     /**< IA-32/AMD64 AVX-512 OP_vpconflictq opcode. */
//
// /* 1356 */ OP_vrangepd,        /**< IA-32/AMD64 AVX-512 OP_vrangepd opcode. */
// /* 1357 */ OP_vrangeps,        /**< IA-32/AMD64 AVX-512 OP_vrangeps opcode. */
// /* 1358 */ OP_vrangesd,        /**< IA-32/AMD64 AVX-512 OP_vrangesd opcode. */
// /* 1359 */ OP_vrangess,        /**< IA-32/AMD64 AVX-512 OP_vrangess opcode. */
//
// /* 1368 */ OP_vreducepd,       /**< IA-32/AMD64 AVX-512 OP_vreducepd opcode. */
// /* 1369 */ OP_vreduceps,       /**< IA-32/AMD64 AVX-512 OP_vreduceps opcode. */
// /* 1370 */ OP_vreducesd,       /**< IA-32/AMD64 AVX-512 OP_vreducesd opcode. */
// /* 1371 */ OP_vreducess,       /**< IA-32/AMD64 AVX-512 OP_vreducess opcode. */
// /* 1372 */ OP_vrndscalepd,     /**< IA-32/AMD64 AVX-512 OP_vrndscalepd opcode. */
// /* 1373 */ OP_vrndscaleps,     /**< IA-32/AMD64 AVX-512 OP_vrndscaleps opcode. */
// /* 1374 */ OP_vrndscalesd,     /**< IA-32/AMD64 AVX-512 OP_vrndscalesd opcode. */
// /* 1375 */ OP_vrndscaless,     /**< IA-32/AMD64 AVX-512 OP_vrndscaless opcode. */
//
// /* 1384 */ OP_vscalefpd,       /**< IA-32/AMD64 AVX-512 OP_vscalepd opcode. */
// /* 1385 */ OP_vscalefps,       /**< IA-32/AMD64 AVX-512 OP_vscaleps opcode. */
// /* 1386 */ OP_vscalefsd,       /**< IA-32/AMD64 AVX-512 OP_vscalesd opcode. */
// /* 1387 */ OP_vscalefss,       /**< IA-32/AMD64 AVX-512 OP_vscalesss opcode. */
//
// /* 1392 */ OP_vscatterpf0dpd,  /**< IA-32/AMD64 AVX-512 OP_vscatterpf0dpd opcode. */
// /* 1393 */ OP_vscatterpf0dps,  /**< IA-32/AMD64 AVX-512 OP_vscatterpf0dps opcode. */
// /* 1394 */ OP_vscatterpf0qpd,  /**< IA-32/AMD64 AVX-512 OP_vscatterpf0qpd opcode. */
// /* 1395 */ OP_vscatterpf0qps,  /**< IA-32/AMD64 AVX-512 OP_vscatterpf0qps opcode. */
// /* 1396 */ OP_vscatterpf1dpd,  /**< IA-32/AMD64 AVX-512 OP_vscatterpf1dpd opcode. */
// /* 1397 */ OP_vscatterpf1dps,  /**< IA-32/AMD64 AVX-512 OP_vscatterpf1dps opcode. */
// /* 1398 */ OP_vscatterpf1qpd,  /**< IA-32/AMD64 AVX-512 OP_vscatterpf1qpd opcode. */
// /* 1399 */ OP_vscatterpf1qps,  /**< IA-32/AMD64 AVX-512 OP_vscatterpf1qps opcode. */

// /* Intel SHA extensions */
// /* 1404 */ OP_sha1msg1,    /**< IA-32/AMD64 SHA OP_sha1msg1 opcode. */
// /* 1405 */ OP_sha1msg2,    /**< IA-32/AMD64 SHA OP_sha1msg2 opcode. */
// /* 1406 */ OP_sha1nexte,   /**< IA-32/AMD64 SHA OP_sha1nexte opcode. */
// /* 1407 */ OP_sha1rnds4,   /**< IA-32/AMD64 SHA OP_sha1rnds4 opcode. */
// /* 1408 */ OP_sha256msg1,  /**< IA-32/AMD64 SHA OP_sha2msg1 opcode. */
// /* 1409 */ OP_sha256msg2,  /**< IA-32/AMD64 SHA OP_sha2msg2 opcode. */
// /* 1410 */ OP_sha256rnds2, /**< IA-32/AMD64 SHA OP_sha2rnds2 opcode. */

// /* Intel MPX extensions */
// /* 1411 */ OP_bndcl,  /**< IA-32/AMD64 MPX OP_bndcl opcode. */
// /* 1412 */ OP_bndcn,  /**< IA-32/AMD64 MPX OP_bndcn opcode. */
// /* 1413 */ OP_bndcu,  /**< IA-32/AMD64 MPX OP_bndcu opcode. */
// /* 1414 */ OP_bndldx, /**< IA-32/AMD64 MPX OP_bndldx opcode. */
// /* 1415 */ OP_bndmk,  /**< IA-32/AMD64 MPX OP_bndmk opcode. */
// /* 1416 */ OP_bndmov, /**< IA-32/AMD64 MPX OP_bndmov opcode. */
// /* 1417 */ OP_bndstx, /**< IA-32/AMD64 MPX OP_bndstx opcode. */

// /* Intel PT extensions */
// /* 1418 */ OP_ptwrite, /**< IA-32/AMD64 PT OP_ptwrite opcode. */

// /* AMD monitor extensions */
// /* 1419 */ OP_monitorx, /**< AMD64 monitorx opcode. */
// /* 1420 */ OP_mwaitx,   /**< AMD64 mwaitx opcode. */

// /* Intel MPK extensions */
// /* 1421 */ OP_rdpkru, /**< IA-32/AMD64 MPK rdpkru opcode. */
// /* 1422 */ OP_wrpkru, /**< IA-32/AMD64 MPK wrpkru opcode. */

DR_API
bool
instr_is_simd(instr_t *instr) {
    return instr_is_simd_mov(instr) || instr_is_simd_float(instr) || instr_is_simd_integer(instr);
}

DR_API
bool
instr_is_scalar(instr_t *instr) {
    return !instr_is_simd(instr);
}

// DR_API
// bool
// instr_is_simd_simd_64(instr_t *instr) {
//     return instr_is_simd(instr) && instr_is_mmx(instr);
// }

// DR_API
// bool
// instr_is_simd_simd_128(instr_t *instr) {
//     return instr_is_simd(instr) && instr_has_xmm_opnd(instr);
// }

// DR_API
// bool
// instr_is_simd_simd_256(instr_t *instr) {
//     return instr_is_simd(instr) && instr_has_ymm_opnd(instr);
// }

// DR_API
// bool
// instr_is_simd_simd_512(instr_t *instr) {
//     return instr_is_simd(instr) && instr_has_zmm_opnd(instr);
// }

// DR_API
// bool
// instr_is_simd_simd_agn(instr_t *instr) {
//     return false;
// }
