/* **********************************************************
 * Copyright (c) 2014-2020 Google, Inc.  All rights reserved.
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
 * * Neither the name of Google, Inc. nor the names of its contributors may be
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

#include "../globals.h"
#include "instr.h"
#include "decode.h"

/* FIXME i#1551: add A64 and Thumb support throughout */

bool
instr_set_isa_mode(instr_t *instr, dr_isa_mode_t mode)
{
    if (mode == DR_ISA_ARM_THUMB)
        instr->flags |= INSTR_THUMB_MODE;
    else if (mode == DR_ISA_ARM_A32)
        instr->flags &= ~INSTR_THUMB_MODE;
    else
        return false;
    return true;
}

dr_isa_mode_t
instr_get_isa_mode(instr_t *instr)
{
    return TEST(INSTR_THUMB_MODE, instr->flags) ? DR_ISA_ARM_THUMB : DR_ISA_ARM_A32;
}

int
instr_length_arch(dcontext_t *dcontext, instr_t *instr)
{
    if (instr_get_opcode(instr) == OP_LABEL)
        return 0;
    /* Avoid encoding OP_b to avoid reachability checks for added fall-through
     * jumps, whose targets are later changed to the stub prior to emit.
     * Another option is to remove the assert on bad encoding, so that the
     * instr_encode_check_reachability() call in private_instr_encode() can
     * gracefully fail: which we now do, but this is a nice optimization.
     */
    if (instr_get_opcode(instr) == OP_b)
        return 4;
    if (instr_get_isa_mode(instr) == DR_ISA_ARM_THUMB) {
        /* We have to encode to find the size */
        return -1;
    } else
        return ARM_INSTR_SIZE;
}

bool
opc_is_not_a_real_memory_load(int opc)
{
    return false;
}

/* return the branch type of the (branch) inst */
uint
instr_branch_type(instr_t *cti_instr)
{
    instr_get_opcode(cti_instr); /* ensure opcode is valid */
    if (instr_get_opcode(cti_instr) == OP_blx) {
        /* To handle the mode switch we go through the ibl.
         * FIXME i#1551: once we have far linking through stubs we should
         * remove this and have a faster link through the stub.
         */
        return LINK_INDIRECT | LINK_CALL;
    }
    /* We treate a predicated call as a cbr, not a call */
    else if (instr_is_cbr_arch(cti_instr) || instr_is_ubr_arch(cti_instr))
        return LINK_DIRECT | LINK_JMP;
    else if (instr_is_call_direct(cti_instr))
        return LINK_DIRECT | LINK_CALL;
    else if (instr_is_call_indirect(cti_instr))
        return LINK_INDIRECT | LINK_CALL;
    else if (instr_is_return(cti_instr))
        return LINK_INDIRECT | LINK_RETURN;
    else if (instr_is_mbr_arch(cti_instr))
        return LINK_INDIRECT | LINK_JMP;
    else
        CLIENT_ASSERT(false, "instr_branch_type: unknown opcode");
    return LINK_INDIRECT;
}

bool
instr_is_mov(instr_t *instr)
{
    /* FIXME i#1551: NYI */
    CLIENT_ASSERT(false, "NYI");
    return false;
}

bool
instr_is_call_arch(instr_t *instr)
{
    int opc = instr->opcode; /* caller ensures opcode is valid */
    return (opc == OP_bl || opc == OP_blx || opc == OP_blx_ind);
}

bool
instr_is_call_direct(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_bl || opc == OP_blx);
}

bool
instr_is_near_call_direct(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    /* Mode-switch call is not "near".
     * FIXME i#1551: once we switch OP_blx to use far-stub linking instead of
     * ibl we can then consider it "near".
     */
    return (opc == OP_bl);
}

bool
instr_is_call_indirect(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_blx_ind);
}

bool
instr_is_pop(instr_t *instr)
{
    opnd_t memop;
    if (instr_num_srcs(instr) == 0)
        return false;
    memop = instr_get_src(instr, 0);
    if (!opnd_is_base_disp(memop))
        return false;
    return opnd_get_base(memop) == DR_REG_SP;
}

bool
instr_reads_gpr_list(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    switch (opc) {
    case OP_stm:
    case OP_stmib:
    case OP_stmda:
    case OP_stmdb:
    case OP_stm_priv:
    case OP_stmib_priv:
    case OP_stmda_priv:
    case OP_stmdb_priv: return true;
    default: return false;
    }
}

bool
instr_writes_gpr_list(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    switch (opc) {
    case OP_ldm:
    case OP_ldmib:
    case OP_ldmda:
    case OP_ldmdb:
    case OP_ldm_priv:
    case OP_ldmib_priv:
    case OP_ldmda_priv:
    case OP_ldmdb_priv: return true;
    default: return false;
    }
}

bool
instr_reads_reg_list(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    switch (opc) {
    case OP_stm:
    case OP_stmib:
    case OP_stmda:
    case OP_stmdb:
    case OP_stm_priv:
    case OP_stmib_priv:
    case OP_stmda_priv:
    case OP_stmdb_priv:
    case OP_vstm:
    case OP_vstmdb: return true;
    default: return false;
    }
}

bool
instr_writes_reg_list(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    switch (opc) {
    case OP_ldm:
    case OP_ldmib:
    case OP_ldmda:
    case OP_ldmdb:
    case OP_ldm_priv:
    case OP_ldmib_priv:
    case OP_ldmda_priv:
    case OP_ldmdb_priv:
    case OP_vldm:
    case OP_vldmdb: return true;
    default: return false;
    }
}

bool
instr_is_return(instr_t *instr)
{
    /* There is no "return" opcode so we consider a return to be either:
     * A) An indirect branch through lr;
     * B) An instr that reads lr and writes pc;
     *    (XXX: should we limit to a move and rule out an add or shift or whatever?)
     * C) A pop into pc.
     */
    int opc = instr_get_opcode(instr);
    if ((opc == OP_bx || opc == OP_bxj) &&
        opnd_get_reg(instr_get_src(instr, 0)) == DR_REG_LR)
        return true;
    if (!instr_writes_to_reg(instr, DR_REG_PC, DR_QUERY_INCLUDE_ALL))
        return false;
    return (instr_reads_from_reg(instr, DR_REG_LR, DR_QUERY_INCLUDE_ALL) ||
            instr_is_pop(instr));
}

bool
instr_is_cbr_arch(instr_t *instr)
{
    int opc = instr->opcode; /* caller ensures opcode is valid */
    if (opc == OP_cbnz || opc == OP_cbz)
        return true;
    /* We don't consider a predicated indirect branch to be a cbr */
    if (opc == OP_b || opc == OP_b_short ||
        /* Yes, conditional calls are considered cbr */
        opc == OP_bl || opc == OP_blx) {
        dr_pred_type_t pred = instr_get_predicate(instr);
        return (pred != DR_PRED_NONE && pred != DR_PRED_AL);
    }
    /* XXX: should OP_it be considered a cbr? */
    return false;
}

bool
instr_is_mbr_arch(instr_t *instr)
{
    int opc = instr->opcode; /* caller ensures opcode is valid */
    if (opc == OP_bx || opc == OP_bxj || opc == OP_blx_ind || opc == OP_rfe ||
        opc == OP_rfedb || opc == OP_rfeda || opc == OP_rfeib || opc == OP_eret ||
        opc == OP_tbb || opc == OP_tbh)
        return true;
    /* Any instr that writes to the pc, even conditionally (b/c consider that
     * OP_blx_ind when conditional is still an mbr) is an mbr.
     */
    return instr_writes_to_reg(instr, DR_REG_PC, DR_QUERY_INCLUDE_COND_DSTS);
}

bool
instr_is_jump_mem(instr_t *instr)
{
    return instr_get_opcode(instr) == OP_ldr &&
        opnd_get_reg(instr_get_dst(instr, 0)) == DR_REG_PC;
}

bool
instr_is_far_cti(instr_t *instr) /* target address has a segment and offset */
{
    return false;
}

bool
instr_is_far_abs_cti(instr_t *instr)
{
    return false;
}

bool
instr_is_ubr_arch(instr_t *instr)
{
    int opc = instr->opcode; /* caller ensures opcode is valid */
    if (opc == OP_b || opc == OP_b_short) {
        dr_pred_type_t pred = instr_get_predicate(instr);
        return (pred == DR_PRED_NONE || pred == DR_PRED_AL);
    }
    return false;
}

bool
instr_is_near_ubr(instr_t *instr) /* unconditional branch */
{
    return instr_is_ubr(instr);
}

bool
instr_is_cti_short(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_b_short || opc == OP_cbz || opc == OP_cbnz);
}

bool
instr_is_cti_loop(instr_t *instr)
{
    return false;
}

bool
instr_is_cti_short_rewrite(instr_t *instr, byte *pc)
{
    /* We assume all app's cbz/cbnz have been mangled.
     * See comments in x86/'s version of this routine.
     */
    dcontext_t *dcontext;
    dr_isa_mode_t old_mode;
    if (pc == NULL) {
        if (instr == NULL || !instr_has_allocated_bits(instr) ||
            instr->length != CTI_SHORT_REWRITE_LENGTH)
            return false;
        pc = instr_get_raw_bits(instr);
    }
    if (instr != NULL && instr_opcode_valid(instr)) {
        int opc = instr_get_opcode(instr);
        if (opc != OP_cbz && opc != OP_cbnz)
            return false;
    }
    if ((*(pc + 1) != CBNZ_BYTE_A && *(pc + 1) != CBZ_BYTE_A) ||
        /* Further verify by checking for a disp of 1 */
        (*pc & 0xf8) != 0x08)
        return false;
    /* XXX: this would be easier if decode_raw_is_jmp took in isa_mode */
    dcontext = get_thread_private_dcontext();
    if (instr != NULL)
        dr_set_isa_mode(dcontext, instr_get_isa_mode(instr), &old_mode);
    if (!decode_raw_is_jmp(dcontext, pc + CTI_SHORT_REWRITE_B_OFFS))
        return false;
    if (instr != NULL)
        dr_set_isa_mode(dcontext, old_mode, NULL);
    return true;
}

bool
instr_is_interrupt(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_svc);
}

bool
instr_is_syscall(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_svc);
}

bool
instr_is_mov_constant(instr_t *instr, ptr_int_t *value)
{
    int opc = instr_get_opcode(instr);
    if (opc == OP_eor) {
        /* We include OP_eor for symmetry w/ x86, but on ARM "mov reg, #0" is
         * just as compact and there's no reason to use an xor.
         */
        if (opnd_same(instr_get_src(instr, 0), instr_get_dst(instr, 0)) &&
            opnd_same(instr_get_src(instr, 0), instr_get_src(instr, 1)) &&
            /* Must be the form with "sh2, i5_7" and no shift */
            instr_num_srcs(instr) == 4 &&
            opnd_get_immed_int(instr_get_src(instr, 2)) == DR_SHIFT_NONE &&
            opnd_get_immed_int(instr_get_src(instr, 3)) == 0) {
            *value = 0;
            return true;
        } else
            return false;
    } else if (opc == OP_mvn || opc == OP_mvns) {
        opnd_t op = instr_get_src(instr, 0);
        if (opnd_is_immed_int(op)) {
            *value = -opnd_get_immed_int(op);
            return true;
        } else
            return false;
    } else if (opc == OP_mov || opc == OP_movs || opc == OP_movw) {
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

    if (opcode == OP_pld || opcode == OP_pldw || opcode == OP_pli)
        return true;
    return false;
}

bool
instr_is_string_op(instr_t *instr)
{
    return false;
}

bool
instr_is_rep_string_op(instr_t *instr)
{
    return false;
}

bool
instr_is_floating_ex(instr_t *instr, dr_fp_type_t *type OUT)
{
    /* FIXME i#1551: NYI */
    CLIENT_ASSERT(false, "NYI");
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
    return false;
}

bool
instr_is_mmx(instr_t *instr)
{
    /* XXX i#1551: add instr_is_multimedia() (include packed data in GPR's?) */
    return false;
}

bool
instr_is_opmask(instr_t *instr)
{
    return false;
}

bool
instr_is_sse_or_sse2(instr_t *instr)
{
    return false;
}

bool
instr_is_sse(instr_t *instr)
{
    return false;
}

bool
instr_is_sse2(instr_t *instr)
{
    return false;
}

bool
instr_is_3DNow(instr_t *instr)
{
    return false;
}

bool
instr_is_sse3(instr_t *instr)
{
    return false;
}

bool
instr_is_ssse3(instr_t *instr)
{
    return false;
}

bool
instr_is_sse41(instr_t *instr)
{
    return false;
}

bool
instr_is_sse42(instr_t *instr)
{
    return false;
}

bool
instr_is_sse4A(instr_t *instr)
{
    return false;
}

bool
instr_is_mov_imm_to_tos(instr_t *instr)
{
    /* FIXME i#1551: NYI */
    CLIENT_ASSERT(false, "NYI");
    return false;
}

bool
instr_is_undefined(instr_t *instr)
{
    return (instr_opcode_valid(instr) && (instr_get_opcode(instr) == OP_udf));
}

dr_pred_type_t
instr_invert_predicate(dr_pred_type_t pred)
{
    CLIENT_ASSERT(pred != DR_PRED_NONE && pred != DR_PRED_AL && pred != DR_PRED_OP,
                  "invalid cbr predicate");
    /* Flipping the bottom bit inverts a predicate */
    return (dr_pred_type_t)(DR_PRED_EQ + (((uint)pred - DR_PRED_EQ) ^ 0x1));
}

void
instr_invert_cbr(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    dr_pred_type_t pred = instr_get_predicate(instr);
    CLIENT_ASSERT(instr_is_cbr(instr), "instr_invert_cbr: instr not a cbr");
    if (opc == OP_cbnz) {
        instr_set_opcode(instr, OP_cbz);
    } else if (opc == OP_cbz) {
        instr_set_opcode(instr, OP_cbnz);
    } else {
        instr_set_predicate(instr, instr_invert_predicate(pred));
    }
}

static dr_pred_trigger_t
instr_predicate_triggered_priv(instr_t *instr, priv_mcontext_t *mc)
{
    dr_pred_type_t pred = instr_get_predicate(instr);
    switch (pred) {
    case DR_PRED_NONE: return DR_PRED_TRIGGER_NOPRED;
    case DR_PRED_EQ: /* Z == 1 */
        return (TEST(EFLAGS_Z, mc->apsr)) ? DR_PRED_TRIGGER_MATCH
                                          : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_NE: /* Z == 0 */
        return (!TEST(EFLAGS_Z, mc->apsr)) ? DR_PRED_TRIGGER_MATCH
                                           : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_CS: /* C == 1 */
        return (TEST(EFLAGS_C, mc->apsr)) ? DR_PRED_TRIGGER_MATCH
                                          : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_CC: /* C == 0 */
        return (!TEST(EFLAGS_C, mc->apsr)) ? DR_PRED_TRIGGER_MATCH
                                           : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_MI: /* N == 1 */
        return (TEST(EFLAGS_N, mc->apsr)) ? DR_PRED_TRIGGER_MATCH
                                          : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_PL: /* N == 0 */
        return (!TEST(EFLAGS_N, mc->apsr)) ? DR_PRED_TRIGGER_MATCH
                                           : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_VS: /* V == 1 */
        return (TEST(EFLAGS_V, mc->apsr)) ? DR_PRED_TRIGGER_MATCH
                                          : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_VC: /* V == 0 */
        return (!TEST(EFLAGS_V, mc->apsr)) ? DR_PRED_TRIGGER_MATCH
                                           : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_HI: /* C == 1 and Z == 0 */
        return (TEST(EFLAGS_C, mc->apsr) && !TEST(EFLAGS_Z, mc->apsr))
            ? DR_PRED_TRIGGER_MATCH
            : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_LS: /* C == 0 or Z == 1 */
        return (!TEST(EFLAGS_C, mc->apsr) || TEST(EFLAGS_Z, mc->apsr))
            ? DR_PRED_TRIGGER_MATCH
            : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_GE: /* N == V */
        return BOOLS_MATCH(TEST(EFLAGS_N, mc->apsr), TEST(EFLAGS_V, mc->apsr))
            ? DR_PRED_TRIGGER_MATCH
            : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_LT: /* N != V */
        return !BOOLS_MATCH(TEST(EFLAGS_N, mc->apsr), TEST(EFLAGS_V, mc->apsr))
            ? DR_PRED_TRIGGER_MATCH
            : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_GT /* Z == 0 and N == V */:
        return (!TEST(EFLAGS_Z, mc->apsr) &&
                BOOLS_MATCH(TEST(EFLAGS_N, mc->apsr), TEST(EFLAGS_V, mc->apsr)))
            ? DR_PRED_TRIGGER_MATCH
            : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_LE: /* Z == 1 or N != V */
        return (TEST(EFLAGS_Z, mc->apsr) ||
                !BOOLS_MATCH(TEST(EFLAGS_N, mc->apsr), TEST(EFLAGS_V, mc->apsr)))
            ? DR_PRED_TRIGGER_MATCH
            : DR_PRED_TRIGGER_MISMATCH;
    case DR_PRED_AL: return DR_PRED_TRIGGER_MATCH;
    case DR_PRED_OP: return DR_PRED_TRIGGER_NOPRED;
    default: CLIENT_ASSERT(false, "invalid predicate"); return DR_PRED_TRIGGER_INVALID;
    }
}

/* Given a machine state, returns whether or not the cbr instr would be taken
 * if the state is before execution (pre == true) or after (pre == false).
 */
bool
instr_cbr_taken(instr_t *instr, priv_mcontext_t *mc, bool pre)
{
    int opc = instr_get_opcode(instr);
    dr_pred_trigger_t trigger = instr_predicate_triggered_priv(instr, mc);
    CLIENT_ASSERT(instr_is_cbr(instr), "instr_cbr_taken: instr not a cbr");
    if (trigger == DR_PRED_TRIGGER_MISMATCH)
        return false;
    if (opc == OP_cbnz || opc == OP_cbz) {
        reg_id_t reg;
        reg_t val;
        CLIENT_ASSERT(opnd_is_reg(instr_get_src(instr, 1)), "invalid OP_cb{,n}z");
        reg = opnd_get_reg(instr_get_src(instr, 1));
        val = reg_get_value_priv(reg, mc);
        if (opc == OP_cbnz)
            return (val != 0);
        else
            return (val == 0);
    } else {
        CLIENT_ASSERT(instr_get_predicate(instr) != DR_PRED_NONE &&
                          instr_get_predicate(instr) != DR_PRED_AL,
                      "invalid cbr type");
        return (trigger == DR_PRED_TRIGGER_MATCH);
    }
}

/* Given eflags, returns whether or not the conditional branch opc would be taken */
static bool
opc_jcc_taken(int opc, reg_t eflags)
{
    /* FIXME i#1551: NYI */
    CLIENT_ASSERT(false, "NYI");
    return false;
}

/* Given eflags, returns whether or not the conditional branch instr would be taken */
bool
instr_jcc_taken(instr_t *instr, reg_t eflags)
{
    /* FIXME i#1551: NYI -- make exported routine x86-only and export
     * instr_cbr_taken() (but need public mcontext)?
     */
    return opc_jcc_taken(instr_get_opcode(instr), eflags);
}

DR_API
/* Converts a cmovcc opcode \p cmovcc_opcode to the OP_jcc opcode that
 * tests the same bits in eflags.
 */
int
instr_cmovcc_to_jcc(int cmovcc_opcode)
{
    /* FIXME i#1551: NYI */
    CLIENT_ASSERT(false, "NYI");
    return OP_INVALID;
}

DR_API
bool
instr_cmovcc_triggered(instr_t *instr, reg_t eflags)
{
    /* FIXME i#1551: NYI */
    CLIENT_ASSERT(false, "NYI");
    return false;
}

DR_API
dr_pred_trigger_t
instr_predicate_triggered(instr_t *instr, dr_mcontext_t *mc)
{
    return instr_predicate_triggered_priv(instr, dr_mcontext_as_priv_mcontext(mc));
}

bool
instr_predicate_reads_srcs(dr_pred_type_t pred)
{
    return false;
}

bool
instr_predicate_writes_eflags(dr_pred_type_t pred)
{
    return false;
}

bool
instr_predicate_is_cond(dr_pred_type_t pred)
{
    return pred != DR_PRED_NONE && pred != DR_PRED_AL && pred != DR_PRED_OP;
}

bool
reg_is_gpr(reg_id_t reg)
{
    return (DR_REG_R0 <= reg && reg <= DR_REG_R15);
}

bool
reg_is_segment(reg_id_t reg)
{
    return false;
}

bool
reg_is_stack(reg_id_t reg) 
{
    return (reg == DR_REG_SP);
}

bool
reg_is_simd(reg_id_t reg)
{
    return (reg >= DR_REG_Q0 && reg <= DR_REG_B31);
}

bool
reg_is_vector_simd(reg_id_t reg)
{
    return false;
}

bool
reg_is_opmask(reg_id_t reg)
{
    return false;
}

bool
reg_is_bnd(reg_id_t reg)
{
    return false;
}

bool
reg_is_strictly_zmm(reg_id_t reg)
{
    return false;
}

bool
reg_is_ymm(reg_id_t reg)
{
    return false;
}

bool
reg_is_strictly_ymm(reg_id_t reg)
{
    return false;
}

bool
reg_is_xmm(reg_id_t reg)
{
    return false;
}

bool
reg_is_strictly_xmm(reg_id_t reg)
{
    return false;
}

bool
reg_is_mmx(reg_id_t reg)
{
    return false;
}

bool
reg_is_fp(reg_id_t reg)
{
    return false;
}

bool
instr_is_nop(instr_t *inst)
{
    int opcode = instr_get_opcode(inst);
    return (opcode == OP_nop);
}

bool
opnd_same_sizes_ok(opnd_size_t s1, opnd_size_t s2, bool is_reg)
{
    /* We don't have the same varying sizes that x86 has */
    return (s1 == s2);
}

instr_t *
instr_create_nbyte_nop(dcontext_t *dcontext, uint num_bytes, bool raw)
{
    /* FIXME i#1551: NYI on ARM */
    ASSERT_NOT_IMPLEMENTED(false);
    return NULL;
}

bool
instr_reads_thread_register(instr_t *instr)
{
    opnd_t opnd;

    /* mrc p15, 0, reg_base, c13, c0, 3 */
    if (instr_get_opcode(instr) != OP_mrc)
        return false;
    ASSERT(opnd_is_reg(instr_get_dst(instr, 0)));
    opnd = instr_get_src(instr, 0);
    if (!opnd_is_immed_int(opnd) || opnd_get_immed_int(opnd) != USR_TLS_COPROC_15)
        return false;
    opnd = instr_get_src(instr, 1);
    if (!opnd_is_immed_int(opnd) || opnd_get_immed_int(opnd) != 0)
        return false;
    opnd = instr_get_src(instr, 2);
    if (!opnd_is_reg(opnd) || opnd_get_reg(opnd) != DR_REG_CR13)
        return false;
    opnd = instr_get_src(instr, 3);
    if (!opnd_is_reg(opnd) || opnd_get_reg(opnd) != DR_REG_CR0)
        return false;
    opnd = instr_get_src(instr, 4);
    if (!opnd_is_immed_int(opnd) || opnd_get_immed_int(opnd) != USR_TLS_REG_OPCODE)
        return false;
    return true;
}

/* check if instr is mangle instruction stolen reg move: e.g.,
 * r8 is the stolen reg, and in inline syscall mangling:
 *  +20   m4 @0x53adcab0  e588a004   str    %r10 -> +0x04(%r8)[4byte]
 *  +24   m4 @0x53ade98c  e1a0a008   mov    %r8 -> %r10              <== stolen reg move
 *  +28   m4 @0x53adf0a0  e5880000   str    %r0 -> (%r8)[4byte]
 *  +32   L3              ef000000   svc    $0x00000000
 *  +36   m4 @0x53afb368  e1a0800a   mov    %r10 -> %r8              <== stolen reg move
 *  +40   m4 @0x53af838c  e598a004   ldr    +0x04(%r8)[4byte] -> %r10
 */
bool
instr_is_stolen_reg_move(instr_t *instr, bool *save, reg_id_t *reg)
{
    reg_id_t myreg;
    CLIENT_ASSERT(instr != NULL, "internal error: NULL argument");
    if (reg == NULL)
        reg = &myreg;
    if (instr_is_app(instr) || instr_get_opcode(instr) != OP_mov)
        return false;
    ASSERT(instr_num_srcs(instr) == 1 && instr_num_dsts(instr) == 1 &&
           opnd_is_reg(instr_get_src(instr, 0)) && opnd_is_reg(instr_get_dst(instr, 0)));
    if (opnd_get_reg(instr_get_src(instr, 0)) == dr_reg_stolen) {
        if (save != NULL)
            *save = true;
        *reg = opnd_get_reg(instr_get_dst(instr, 0));
        ASSERT(*reg != dr_reg_stolen);
        return true;
    }
    if (opnd_get_reg(instr_get_dst(instr, 0)) == dr_reg_stolen) {
        if (save != NULL)
            *save = false;
        *reg = opnd_get_reg(instr_get_src(instr, 0));
        return true;
    }
    return false;
}

DR_API
bool
instr_is_exclusive_load(instr_t *instr)
{
    int opcode = instr_get_opcode(instr);
    return (opcode == OP_ldrex || opcode == OP_ldrexb || opcode == OP_ldrexd ||
            opcode == OP_ldrexh || opcode == OP_ldaex || opcode == OP_ldaexb ||
            opcode == OP_ldaexd || opcode == OP_ldaexh);
}

DR_API
bool
instr_is_exclusive_store(instr_t *instr)
{
    int opcode = instr_get_opcode(instr);
    return (opcode == OP_strex || opcode == OP_strexb || opcode == OP_strexd ||
            opcode == OP_strexh || opcode == OP_stlex || opcode == OP_stlexb ||
            opcode == OP_stlexd || opcode == OP_stlexh);
}

DR_API
bool
instr_is_scatter(instr_t *instr)
{
    /* XXX i#3837: no scatter-store on ARM? */
    return false;
}

DR_API
bool
instr_is_gather(instr_t *instr)
{
    /* XXX i#3837: no gather-load on ARM? */
    return false;
}

DR_API
bool
instr_is_simd(instr_t *instr) {
    // If the source or destination register is a SIMD register, the instruction
    // is SIMD
    for (int a = 0; a < instr_num_srcs(instr); a++) {
        if (reg_is_simd(opnd_get_reg(instr_get_src(instr, a)))) {
            return true;
        }
    }
    for (int a = 0; a < instr_num_dsts(instr); a++) {
        if (reg_is_simd(opnd_get_reg(instr_get_dst(instr, a)))) {
            return true;
        }
    }

    return false;
}

DR_API
bool
instr_is_scalar(instr_t *instr) {
    return !instr_is_simd(instr);
}

DR_API
bool
op_is_mov(int op_code) {
    switch (op_code) {
        /*
         *
         */
        case /*  60 */ OP_lda:            /**< ARM lda opcode. */
        case /*  61 */ OP_ldab:           /**< ARM ldab opcode. */
        case /*  62 */ OP_ldaex:          /**< ARM ldaex opcode. */
        case /*  63 */ OP_ldaexb:         /**< ARM ldaexb opcode. */
        case /*  64 */ OP_ldaexd:         /**< ARM ldaexd opcode. */
        case /*  65 */ OP_ldaexh:         /**< ARM ldaexh opcode. */
        case /*  66 */ OP_ldah:           /**< ARM ldah opcode. */

        // TODO: OTHERS?
        case /*  67 */ OP_ldc:            /**< ARM ldc opcode. */
        case /*  68 */ OP_ldc2:           /**< ARM ldc2 opcode. */
        case /*  69 */ OP_ldc2l:          /**< ARM ldc2l opcode. */
        case /*  70 */ OP_ldcl:           /**< ARM ldcl opcode. */
        case /*  71 */ OP_ldm:            /**< ARM ldm opcode. */
        case /*  72 */ OP_ldm_priv:       /**< ARM ldm_priv opcode. */
        case /*  73 */ OP_ldmda:          /**< ARM ldmda opcode. */
        case /*  74 */ OP_ldmda_priv:     /**< ARM ldmda_priv opcode. */
        case /*  75 */ OP_ldmdb:          /**< ARM ldmdb opcode. */
        case /*  76 */ OP_ldmdb_priv:     /**< ARM ldmdb_priv opcode. */
        case /*  77 */ OP_ldmib:          /**< ARM ldmib opcode. */
        case /*  78 */ OP_ldmib_priv:     /**< ARM ldmib_priv opcode. */

        case /*  79 */ OP_ldr:            /**< ARM ldr opcode. */
        case /*  80 */ OP_ldrb:           /**< ARM ldrb opcode. */
        case /*  81 */ OP_ldrbt:          /**< ARM ldrbt opcode. */
        case /*  82 */ OP_ldrd:           /**< ARM ldrd opcode. */
        case /*  83 */ OP_ldrex:          /**< ARM ldrex opcode. */
        case /*  84 */ OP_ldrexb:         /**< ARM ldrexb opcode. */
        case /*  85 */ OP_ldrexd:         /**< ARM ldrexd opcode. */
        case /*  86 */ OP_ldrexh:         /**< ARM ldrexh opcode. */
        case /*  87 */ OP_ldrh:           /**< ARM ldrh opcode. */
        case /*  88 */ OP_ldrht:          /**< ARM ldrht opcode. */
        case /*  89 */ OP_ldrsb:          /**< ARM ldrsb opcode. */
        case /*  90 */ OP_ldrsbt:         /**< ARM ldrsbt opcode. */
        case /*  91 */ OP_ldrsh:          /**< ARM ldrsh opcode. */
        case /*  92 */ OP_ldrsht:         /**< ARM ldrsht opcode. */
        case /*  93 */ OP_ldrt:           /**< ARM ldrt opcode. */

        // TODO: OTHERS?
        case /*  99 */ OP_mcr:            /**< ARM mcr opcode. */
        case /* 100 */ OP_mcr2:           /**< ARM mcr2 opcode. */
        case /* 101 */ OP_mcrr:           /**< ARM mcrr opcode. */
        case /* 102 */ OP_mcrr2:          /**< ARM mcrr2 opcode. */

        case /* 106 */ OP_mov:            /**< ARM mov opcode. */
        case /* 107 */ OP_movs:           /**< ARM movs opcode. */
        case /* 108 */ OP_movt:           /**< ARM movt opcode. */
        case /* 109 */ OP_movw:           /**< ARM movw opcode. */

        // TODO: OTHERS?
        case /* 110 */ OP_mrc:            /**< ARM mrc opcode. */
        case /* 111 */ OP_mrc2:           /**< ARM mrc2 opcode. */
        case /* 112 */ OP_mrrc:           /**< ARM mrrc opcode. */
        case /* 113 */ OP_mrrc2:          /**< ARM mrrc2 opcode. */
        case /* 114 */ OP_mrs:            /**< ARM mrs opcode. */
        case /* 115 */ OP_mrs_priv:       /**< ARM mrs_priv opcode. */
        case /* 116 */ OP_msr:            /**< ARM msr opcode. */
        case /* 117 */ OP_msr_priv:       /**< ARM msr_priv opcode. */

        case /* 127 */ OP_pkhbt:          /**< ARM pkhbt opcode. */
        case /* 128 */ OP_pkhtb:          /**< ARM pkhtb opcode. */

        // TODO: OTHERS?
        case /* 233 */ OP_stc:            /**< ARM stc opcode. */
        case /* 234 */ OP_stc2:           /**< ARM stc2 opcode. */
        case /* 235 */ OP_stc2l:          /**< ARM stc2l opcode. */
        case /* 236 */ OP_stcl:           /**< ARM stcl opcode. */

        case /* 237 */ OP_stl:            /**< ARM stl opcode. */
        case /* 238 */ OP_stlb:           /**< ARM stlb opcode. */
        case /* 239 */ OP_stlex:          /**< ARM stlex opcode. */
        case /* 240 */ OP_stlexb:         /**< ARM stlexb opcode. */
        case /* 241 */ OP_stlexd:         /**< ARM stlexd opcode. */
        case /* 242 */ OP_stlexh:         /**< ARM stlexh opcode. */
        case /* 243 */ OP_stlh:           /**< ARM stlh opcode. */
        case /* 244 */ OP_stm:            /**< ARM stm opcode. */
        case /* 245 */ OP_stm_priv:       /**< ARM stm_priv opcode. */
        case /* 246 */ OP_stmda:          /**< ARM stmda opcode. */
        case /* 247 */ OP_stmda_priv:     /**< ARM stmda_priv opcode. */
        case /* 248 */ OP_stmdb:          /**< ARM stmdb opcode. */
        case /* 249 */ OP_stmdb_priv:     /**< ARM stmdb_priv opcode. */
        case /* 250 */ OP_stmib:          /**< ARM stmib opcode. */
        case /* 251 */ OP_stmib_priv:     /**< ARM stmib_priv opcode. */
        case /* 252 */ OP_str:            /**< ARM str opcode. */
        case /* 253 */ OP_strb:           /**< ARM strb opcode. */
        case /* 254 */ OP_strbt:          /**< ARM strbt opcode. */
        case /* 255 */ OP_strd:           /**< ARM strd opcode. */
        case /* 256 */ OP_strex:          /**< ARM strex opcode. */
        case /* 257 */ OP_strexb:         /**< ARM strexb opcode. */
        case /* 258 */ OP_strexd:         /**< ARM strexd opcode. */
        case /* 259 */ OP_strexh:         /**< ARM strexh opcode. */
        case /* 260 */ OP_strh:           /**< ARM strh opcode. */
        case /* 261 */ OP_strht:          /**< ARM strht opcode. */
        case /* 262 */ OP_strt:           /**< ARM strt opcode. */

        case /* 267 */ OP_swp:            /**< ARM swp opcode. */
        case /* 268 */ OP_swpb:           /**< ARM swpb opcode. */

        /*
        *
        */
        case /* 461 */ OP_vdup_16:        /**< ARM vdup_16 opcode. */
        case /* 462 */ OP_vdup_32:        /**< ARM vdup_32 opcode. */
        case /* 463 */ OP_vdup_8:         /**< ARM vdup_8 opcode. */

        case /* 486 */ OP_vld1_16:        /**< ARM vld1_16 opcode. */
        case /* 487 */ OP_vld1_32:        /**< ARM vld1_32 opcode. */
        case /* 488 */ OP_vld1_64:        /**< ARM vld1_64 opcode. */
        case /* 489 */ OP_vld1_8:         /**< ARM vld1_8 opcode. */
        case /* 490 */ OP_vld1_dup_16:    /**< ARM vld1_dup_16 opcode. */
        case /* 491 */ OP_vld1_dup_32:    /**< ARM vld1_dup_32 opcode. */
        case /* 492 */ OP_vld1_dup_8:     /**< ARM vld1_dup_8 opcode. */
        case /* 493 */ OP_vld1_lane_16:   /**< ARM vld1_lane_16 opcode. */
        case /* 494 */ OP_vld1_lane_32:   /**< ARM vld1_lane_32 opcode. */
        case /* 495 */ OP_vld1_lane_8:    /**< ARM vld1_lane_8 opcode. */
        case /* 496 */ OP_vld2_16:        /**< ARM vld2_16 opcode. */
        case /* 497 */ OP_vld2_32:        /**< ARM vld2_32 opcode. */
        case /* 498 */ OP_vld2_8:         /**< ARM vld2_8 opcode. */
        case /* 499 */ OP_vld2_dup_16:    /**< ARM vld2_dup_16 opcode. */
        case /* 500 */ OP_vld2_dup_32:    /**< ARM vld2_dup_32 opcode. */
        case /* 501 */ OP_vld2_dup_8:     /**< ARM vld2_dup_8 opcode. */
        case /* 502 */ OP_vld2_lane_16:   /**< ARM vld2_lane_16 opcode. */
        case /* 503 */ OP_vld2_lane_32:   /**< ARM vld2_lane_32 opcode. */
        case /* 504 */ OP_vld2_lane_8:    /**< ARM vld2_lane_8 opcode. */
        case /* 505 */ OP_vld3_16:        /**< ARM vld3_16 opcode. */
        case /* 506 */ OP_vld3_32:        /**< ARM vld3_32 opcode. */
        case /* 507 */ OP_vld3_8:         /**< ARM vld3_8 opcode. */
        case /* 508 */ OP_vld3_dup_16:    /**< ARM vld3_dup_16 opcode. */
        case /* 509 */ OP_vld3_dup_32:    /**< ARM vld3_dup_32 opcode. */
        case /* 510 */ OP_vld3_dup_8:     /**< ARM vld3_dup_8 opcode. */
        case /* 511 */ OP_vld3_lane_16:   /**< ARM vld3_lane_16 opcode. */
        case /* 512 */ OP_vld3_lane_32:   /**< ARM vld3_lane_32 opcode. */
        case /* 513 */ OP_vld3_lane_8:    /**< ARM vld3_lane_8 opcode. */
        case /* 514 */ OP_vld4_16:        /**< ARM vld4_16 opcode. */
        case /* 515 */ OP_vld4_32:        /**< ARM vld4_32 opcode. */
        case /* 516 */ OP_vld4_8:         /**< ARM vld4_8 opcode. */
        case /* 517 */ OP_vld4_dup_16:    /**< ARM vld4_dup_16 opcode. */
        case /* 518 */ OP_vld4_dup_32:    /**< ARM vld4_dup_32 opcode. */
        case /* 519 */ OP_vld4_dup_8:     /**< ARM vld4_dup_8 opcode. */
        case /* 520 */ OP_vld4_lane_16:   /**< ARM vld4_lane_16 opcode. */
        case /* 521 */ OP_vld4_lane_32:   /**< ARM vld4_lane_32 opcode. */
        case /* 522 */ OP_vld4_lane_8:    /**< ARM vld4_lane_8 opcode. */
        case /* 523 */ OP_vldm:           /**< ARM vldm opcode. */
        case /* 524 */ OP_vldmdb:         /**< ARM vldmdb opcode. */
        case /* 525 */ OP_vldr:           /**< ARM vldr opcode. */

        case /* 566 */ OP_vmov:           /**< ARM vmov opcode. */
        case /* 567 */ OP_vmov_16:        /**< ARM vmov_16 opcode. */
        case /* 568 */ OP_vmov_32:        /**< ARM vmov_32 opcode. */
        case /* 569 */ OP_vmov_8:         /**< ARM vmov_8 opcode. */
        case /* 570 */ OP_vmov_f32:       /**< ARM vmov_f32 opcode. */
        case /* 571 */ OP_vmov_f64:       /**< ARM vmov_f64 opcode. */
        case /* 572 */ OP_vmov_i16:       /**< ARM vmov_i16 opcode. */
        case /* 573 */ OP_vmov_i32:       /**< ARM vmov_i32 opcode. */
        case /* 574 */ OP_vmov_i64:       /**< ARM vmov_i64 opcode. */
        case /* 575 */ OP_vmov_i8:        /**< ARM vmov_i8 opcode. */
        case /* 576 */ OP_vmov_s16:       /**< ARM vmov_s16 opcode. */
        case /* 577 */ OP_vmov_s8:        /**< ARM vmov_s8 opcode. */
        case /* 578 */ OP_vmov_u16:       /**< ARM vmov_u16 opcode. */
        case /* 579 */ OP_vmov_u8:        /**< ARM vmov_u8 opcode. */
        case /* 580 */ OP_vmovl_s16:      /**< ARM vmovl_s16 opcode. */
        case /* 581 */ OP_vmovl_s32:      /**< ARM vmovl_s32 opcode. */
        case /* 582 */ OP_vmovl_s8:       /**< ARM vmovl_s8 opcode. */
        case /* 583 */ OP_vmovl_u16:      /**< ARM vmovl_u16 opcode. */
        case /* 584 */ OP_vmovl_u32:      /**< ARM vmovl_u32 opcode. */
        case /* 585 */ OP_vmovl_u8:       /**< ARM vmovl_u8 opcode. */
        case /* 586 */ OP_vmovn_i16:      /**< ARM vmovn_i16 opcode. */
        case /* 587 */ OP_vmovn_i32:      /**< ARM vmovn_i32 opcode. */
        case /* 588 */ OP_vmovn_i64:      /**< ARM vmovn_i64 opcode. */
        case /* 589 */ OP_vmrs:           /**< ARM vmrs opcode. */
        case /* 590 */ OP_vmsr:           /**< ARM vmsr opcode. */

        case /* 673 */ OP_vqmovn_s16:     /**< ARM vqmovn_s16 opcode. */
        case /* 674 */ OP_vqmovn_s32:     /**< ARM vqmovn_s32 opcode. */
        case /* 675 */ OP_vqmovn_s64:     /**< ARM vqmovn_s64 opcode. */
        case /* 676 */ OP_vqmovn_u16:     /**< ARM vqmovn_u16 opcode. */
        case /* 677 */ OP_vqmovn_u32:     /**< ARM vqmovn_u32 opcode. */
        case /* 678 */ OP_vqmovn_u64:     /**< ARM vqmovn_u64 opcode. */
        case /* 679 */ OP_vqmovun_s16:    /**< ARM vqmovun_s16 opcode. */
        case /* 680 */ OP_vqmovun_s32:    /**< ARM vqmovun_s32 opcode. */
        case /* 681 */ OP_vqmovun_s64:    /**< ARM vqmovun_s64 opcode. */

        case /* 860 */ OP_vst1_16:        /**< ARM vst1_16 opcode. */
        case /* 861 */ OP_vst1_32:        /**< ARM vst1_32 opcode. */
        case /* 862 */ OP_vst1_64:        /**< ARM vst1_64 opcode. */
        case /* 863 */ OP_vst1_8:         /**< ARM vst1_8 opcode. */
        case /* 864 */ OP_vst1_lane_16:   /**< ARM vst1_lane_16 opcode. */
        case /* 865 */ OP_vst1_lane_32:   /**< ARM vst1_lane_32 opcode. */
        case /* 866 */ OP_vst1_lane_8:    /**< ARM vst1_lane_8 opcode. */
        case /* 867 */ OP_vst2_16:        /**< ARM vst2_16 opcode. */
        case /* 868 */ OP_vst2_32:        /**< ARM vst2_32 opcode. */
        case /* 869 */ OP_vst2_8:         /**< ARM vst2_8 opcode. */
        case /* 870 */ OP_vst2_lane_16:   /**< ARM vst2_lane_16 opcode. */
        case /* 871 */ OP_vst2_lane_32:   /**< ARM vst2_lane_32 opcode. */
        case /* 872 */ OP_vst2_lane_8:    /**< ARM vst2_lane_8 opcode. */
        case /* 873 */ OP_vst3_16:        /**< ARM vst3_16 opcode. */
        case /* 874 */ OP_vst3_32:        /**< ARM vst3_32 opcode. */
        case /* 875 */ OP_vst3_8:         /**< ARM vst3_8 opcode. */
        case /* 876 */ OP_vst3_lane_16:   /**< ARM vst3_lane_16 opcode. */
        case /* 877 */ OP_vst3_lane_32:   /**< ARM vst3_lane_32 opcode. */
        case /* 878 */ OP_vst3_lane_8:    /**< ARM vst3_lane_8 opcode. */
        case /* 879 */ OP_vst4_16:        /**< ARM vst4_16 opcode. */
        case /* 880 */ OP_vst4_32:        /**< ARM vst4_32 opcode. */
        case /* 881 */ OP_vst4_8:         /**< ARM vst4_8 opcode. */
        case /* 882 */ OP_vst4_lane_16:   /**< ARM vst4_lane_16 opcode. */
        case /* 883 */ OP_vst4_lane_32:   /**< ARM vst4_lane_32 opcode. */
        case /* 884 */ OP_vst4_lane_8:    /**< ARM vst4_lane_8 opcode. */
        case /* 885 */ OP_vstm:           /**< ARM vstm opcode. */
        case /* 886 */ OP_vstmdb:         /**< ARM vstmdb opcode. */
        case /* 887 */ OP_vstr:           /**< ARM vstr opcode. */

        case /* 909 */ OP_vswp:           /**< ARM vswp opcode. */
        case /* 910 */ OP_vtbl_8:         /**< ARM vtbl_8 opcode. */
        case /* 911 */ OP_vtbx_8:         /**< ARM vtbx_8 opcode. */
        case /* 912 */ OP_vtrn_16:        /**< ARM vtrn_16 opcode. */
        case /* 913 */ OP_vtrn_32:        /**< ARM vtrn_32 opcode. */
        case /* 914 */ OP_vtrn_8:         /**< ARM vtrn_8 opcode. */

        case /* 918 */ OP_vuzp_16:        /**< ARM vuzp_16 opcode. */
        case /* 919 */ OP_vuzp_32:        /**< ARM vuzp_32 opcode. */
        case /* 920 */ OP_vuzp_8:         /**< ARM vuzp_8 opcode. */
        case /* 921 */ OP_vzip_16:        /**< ARM vzip_16 opcode. */
        case /* 922 */ OP_vzip_32:        /**< ARM vzip_32 opcode. */
        case /* 923 */ OP_vzip_8:         /**< ARM vzip_8 opcode. */ return true;
        
        default: return false;
    }
}

DR_API
bool
instr_is_scalar_mov(instr_t *instr) {
    return op_is_mov(instr_get_opcode(instr) && !instr_is_simd(instr))
}

DR_API
bool
instr_is_simd_mov(instr_t *instr) {
    return op_is_mov(instr_get_opcode(instr) && instr_is_simd(instr))
}

DR_API
bool
op_is_integer(int op_code) {
    switch (op_code) {
        /*
        *
        */
        case: /*   4 */ OP_adc:            /**< ARM adc opcode. */
        case: /*   5 */ OP_adcs:           /**< ARM adcs opcode. */
        case: /*   6 */ OP_add:            /**< ARM add opcode. */
        case: /*   7 */ OP_adds:           /**< ARM adds opcode. */
        case: /*   8 */ OP_addw:           /**< ARM addw opcode. */
        case: /*  13 */ OP_and:            /**< ARM and opcode. */
        case: /*  14 */ OP_ands:           /**< ARM ands opcode. */
        case: /*  15 */ OP_asr:            /**< ARM asr opcode. */
        case: /*  16 */ OP_asrs:           /**< ARM asrs opcode. */

        case: /*  34 */ OP_clz:            /**< ARM clz opcode. */
        case: /*  35 */ OP_cmn:            /**< ARM cmn opcode. */
        case: /*  36 */ OP_cmp:            /**< ARM cmp opcode. */

        case: /*  53 */ OP_eor:            /**< ARM eor opcode. */
        case: /*  54 */ OP_eors:           /**< ARM eors opcode. */

        case: /*  95 */ OP_lsl:            /**< ARM lsl opcode. */
        case: /*  96 */ OP_lsls:           /**< ARM lsls opcode. */
        case: /*  97 */ OP_lsr:            /**< ARM lsr opcode. */
        case: /*  98 */ OP_lsrs:           /**< ARM lsrs opcode. */

        case: /* 103 */ OP_mla:            /**< ARM mla opcode. */
        case: /* 104 */ OP_mlas:           /**< ARM mlas opcode. */
        case: /* 105 */ OP_mls:            /**< ARM mls opcode. */

        case: /* 118 */ OP_mul:            /**< ARM mul opcode. */
        case: /* 119 */ OP_muls:           /**< ARM muls opcode. */

        case: /* 120 */ OP_mvn:            /**< ARM mvn opcode. */
        case: /* 121 */ OP_mvns:           /**< ARM mvns opcode. */

        case: /* 123 */ OP_orn:            /**< ARM orn opcode. */
        case: /* 124 */ OP_orns:           /**< ARM orns opcode. */
        case: /* 125 */ OP_orr:            /**< ARM orr opcode. */
        case: /* 126 */ OP_orrs:           /**< ARM orrs opcode. */

        case: /* 132 */ OP_qadd:           /**< ARM qadd opcode. */
        case: /* 133 */ OP_qadd16:         /**< ARM qadd16 opcode. */
        case: /* 134 */ OP_qadd8:          /**< ARM qadd8 opcode. */
        case: /* 135 */ OP_qasx:           /**< ARM qasx opcode. */
        case: /* 136 */ OP_qdadd:          /**< ARM qdadd opcode. */
        case: /* 137 */ OP_qdsub:          /**< ARM qdsub opcode. */
        case: /* 138 */ OP_qsax:           /**< ARM qsax opcode. */
        case: /* 139 */ OP_qsub:           /**< ARM qsub opcode. */
        case: /* 140 */ OP_qsub16:         /**< ARM qsub16 opcode. */
        case: /* 141 */ OP_qsub8:          /**< ARM qsub8 opcode. */

        case: /* 142 */ OP_rbit:           /**< ARM rbit opcode. */
        case: /* 143 */ OP_rev:            /**< ARM rev opcode. */
        case: /* 144 */ OP_rev16:          /**< ARM rev16 opcode. */
        case: /* 145 */ OP_revsh:          /**< ARM revsh opcode. */

        case: /* 150 */ OP_ror:            /**< ARM ror opcode. */
        case: /* 151 */ OP_rors:           /**< ARM rors opcode. */
        case: /* 152 */ OP_rrx:            /**< ARM rrx opcode. */
        case: /* 153 */ OP_rrxs:           /**< ARM rrxs opcode. */
        case: /* 154 */ OP_rsb:            /**< ARM rsb opcode. */
        case: /* 155 */ OP_rsbs:           /**< ARM rsbs opcode. */
        case: /* 156 */ OP_rsc:            /**< ARM rsc opcode. */
        case: /* 157 */ OP_rscs:           /**< ARM rscs opcode. */
        case: /* 158 */ OP_sadd16:         /**< ARM sadd16 opcode. */
        case: /* 159 */ OP_sadd8:          /**< ARM sadd8 opcode. */
        case: /* 160 */ OP_sasx:           /**< ARM sasx opcode. */
        case: /* 161 */ OP_sbc:            /**< ARM sbc opcode. */
        case: /* 162 */ OP_sbcs:           /**< ARM sbcs opcode. */
        case: /* 163 */ OP_sbfx:           /**< ARM sbfx opcode. */
        case: /* 164 */ OP_sdiv:           /**< ARM sdiv opcode. */
        case: /* 165 */ OP_sel:            /**< ARM sel opcode. */

        case: /* 179 */ OP_shadd16:        /**< ARM shadd16 opcode. */
        case: /* 180 */ OP_shadd8:         /**< ARM shadd8 opcode. */
        case: /* 181 */ OP_shasx:          /**< ARM shasx opcode. */
        case: /* 182 */ OP_shsax:          /**< ARM shsax opcode. */
        case: /* 183 */ OP_shsub16:        /**< ARM shsub16 opcode. */
        case: /* 184 */ OP_shsub8:         /**< ARM shsub8 opcode. */
        case: /* 185 */ OP_smc:            /**< ARM smc opcode. */
        case: /* 186 */ OP_smlabb:         /**< ARM smlabb opcode. */
        case: /* 187 */ OP_smlabt:         /**< ARM smlabt opcode. */
        case: /* 188 */ OP_smlad:          /**< ARM smlad opcode. */
        case: /* 189 */ OP_smladx:         /**< ARM smladx opcode. */
        case: /* 190 */ OP_smlal:          /**< ARM smlal opcode. */
        case: /* 191 */ OP_smlalbb:        /**< ARM smlalbb opcode. */
        case: /* 192 */ OP_smlalbt:        /**< ARM smlalbt opcode. */
        case: /* 193 */ OP_smlald:         /**< ARM smlald opcode. */
        case: /* 194 */ OP_smlaldx:        /**< ARM smlaldx opcode. */
        case: /* 195 */ OP_smlals:         /**< ARM smlals opcode. */
        case: /* 196 */ OP_smlaltb:        /**< ARM smlaltb opcode. */
        case: /* 197 */ OP_smlaltt:        /**< ARM smlaltt opcode. */
        case: /* 198 */ OP_smlatb:         /**< ARM smlatb opcode. */
        case: /* 199 */ OP_smlatt:         /**< ARM smlatt opcode. */
        case: /* 200 */ OP_smlawb:         /**< ARM smlawb opcode. */
        case: /* 201 */ OP_smlawt:         /**< ARM smlawt opcode. */
        case: /* 202 */ OP_smlsd:          /**< ARM smlsd opcode. */
        case: /* 203 */ OP_smlsdx:         /**< ARM smlsdx opcode. */
        case: /* 204 */ OP_smlsld:         /**< ARM smlsld opcode. */
        case: /* 205 */ OP_smlsldx:        /**< ARM smlsldx opcode. */
        case: /* 206 */ OP_smmla:          /**< ARM smmla opcode. */
        case: /* 207 */ OP_smmlar:         /**< ARM smmlar opcode. */
        case: /* 208 */ OP_smmls:          /**< ARM smmls opcode. */
        case: /* 209 */ OP_smmlsr:         /**< ARM smmlsr opcode. */
        case: /* 210 */ OP_smmul:          /**< ARM smmul opcode. */
        case: /* 211 */ OP_smmulr:         /**< ARM smmulr opcode. */
        case: /* 212 */ OP_smuad:          /**< ARM smuad opcode. */
        case: /* 213 */ OP_smuadx:         /**< ARM smuadx opcode. */
        case: /* 214 */ OP_smulbb:         /**< ARM smulbb opcode. */
        case: /* 215 */ OP_smulbt:         /**< ARM smulbt opcode. */
        case: /* 216 */ OP_smull:          /**< ARM smull opcode. */
        case: /* 217 */ OP_smulls:         /**< ARM smulls opcode. */
        case: /* 218 */ OP_smultb:         /**< ARM smultb opcode. */
        case: /* 219 */ OP_smultt:         /**< ARM smultt opcode. */
        case: /* 220 */ OP_smulwb:         /**< ARM smulwb opcode. */
        case: /* 221 */ OP_smulwt:         /**< ARM smulwt opcode. */
        case: /* 222 */ OP_smusd:          /**< ARM smusd opcode. */
        case: /* 223 */ OP_smusdx:         /**< ARM smusdx opcode. */

        case: /* 228 */ OP_ssat:           /**< ARM ssat opcode. */
        case: /* 229 */ OP_ssat16:         /**< ARM ssat16 opcode. */
        case: /* 230 */ OP_ssax:           /**< ARM ssax opcode. */
        case: /* 231 */ OP_ssub16:         /**< ARM ssub16 opcode. */
        case: /* 232 */ OP_ssub8:          /**< ARM ssub8 opcode. */

        case: /* 269 */ OP_sxtab:          /**< ARM sxtab opcode. */
        case: /* 270 */ OP_sxtab16:        /**< ARM sxtab16 opcode. */
        case: /* 271 */ OP_sxtah:          /**< ARM sxtah opcode. */
        case: /* 272 */ OP_sxtb:           /**< ARM sxtb opcode. */
        case: /* 273 */ OP_sxtb16:         /**< ARM sxtb16 opcode. */
        case: /* 274 */ OP_sxth:           /**< ARM sxth opcode. */

        case: /* 263 */ OP_sub:            /**< ARM sub opcode. */
        case: /* 265 */ OP_subw:           /**< ARM subw opcode. */

        case: /* 277 */ OP_teq:            /**< ARM teq opcode. */
        case: /* 278 */ OP_tst:            /**< ARM tst opcode. */
        case: /* 279 */ OP_uadd16:         /**< ARM uadd16 opcode. */
        case: /* 280 */ OP_uadd8:          /**< ARM uadd8 opcode. */
        case: /* 281 */ OP_uasx:           /**< ARM uasx opcode. */
        case: /* 282 */ OP_ubfx:           /**< ARM ubfx opcode. */
        case: /* 283 */ OP_udf:            /**< ARM udf opcode. */
        case: /* 284 */ OP_udiv:           /**< ARM udiv opcode. */
        case: /* 285 */ OP_uhadd16:        /**< ARM uhadd16 opcode. */
        case: /* 286 */ OP_uhadd8:         /**< ARM uhadd8 opcode. */
        case: /* 287 */ OP_uhasx:          /**< ARM uhasx opcode. */
        case: /* 288 */ OP_uhsax:          /**< ARM uhsax opcode. */
        case: /* 289 */ OP_uhsub16:        /**< ARM uhsub16 opcode. */
        case: /* 290 */ OP_uhsub8:         /**< ARM uhsub8 opcode. */
        case: /* 291 */ OP_umaal:          /**< ARM umaal opcode. */
        case: /* 292 */ OP_umlal:          /**< ARM umlal opcode. */
        case: /* 293 */ OP_umlals:         /**< ARM umlals opcode. */
        case: /* 294 */ OP_umull:          /**< ARM umull opcode. */
        case: /* 295 */ OP_umulls:         /**< ARM umulls opcode. */
        case: /* 296 */ OP_uqadd16:        /**< ARM uqadd16 opcode. */
        case: /* 297 */ OP_uqadd8:         /**< ARM uqadd8 opcode. */
        case: /* 298 */ OP_uqasx:          /**< ARM uqasx opcode. */
        case: /* 299 */ OP_uqsax:          /**< ARM uqsax opcode. */
        case: /* 300 */ OP_uqsub16:        /**< ARM uqsub16 opcode. */
        case: /* 301 */ OP_uqsub8:         /**< ARM uqsub8 opcode. */
        case: /* 302 */ OP_usad8:          /**< ARM usad8 opcode. */
        case: /* 303 */ OP_usada8:         /**< ARM usada8 opcode. */
        case: /* 304 */ OP_usat:           /**< ARM usat opcode. */
        case: /* 305 */ OP_usat16:         /**< ARM usat16 opcode. */
        case: /* 306 */ OP_usax:           /**< ARM usax opcode. */
        case: /* 307 */ OP_usub16:         /**< ARM usub16 opcode. */
        case: /* 308 */ OP_usub8:          /**< ARM usub8 opcode. */
        case: /* 309 */ OP_uxtab:          /**< ARM uxtab opcode. */
        case: /* 310 */ OP_uxtab16:        /**< ARM uxtab16 opcode. */
        case: /* 311 */ OP_uxtah:          /**< ARM uxtah opcode. */
        case: /* 312 */ OP_uxtb:           /**< ARM uxtb opcode. */
        case: /* 313 */ OP_uxtb16:         /**< ARM uxtb16 opcode. */
        case: /* 314 */ OP_uxth:           /**< ARM uxth opcode. */

        case: /* 315 */ OP_vaba_s16:       /**< ARM vaba_s16 opcode. */
        case: /* 316 */ OP_vaba_s32:       /**< ARM vaba_s32 opcode. */
        case: /* 317 */ OP_vaba_s8:        /**< ARM vaba_s8 opcode. */
        case: /* 318 */ OP_vaba_u16:       /**< ARM vaba_u16 opcode. */
        case: /* 319 */ OP_vaba_u32:       /**< ARM vaba_u32 opcode. */
        case: /* 320 */ OP_vaba_u8:        /**< ARM vaba_u8 opcode. */
        case: /* 321 */ OP_vabal_s16:      /**< ARM vabal_s16 opcode. */
        case: /* 322 */ OP_vabal_s32:      /**< ARM vabal_s32 opcode. */
        case: /* 323 */ OP_vabal_s8:       /**< ARM vabal_s8 opcode. */
        case: /* 324 */ OP_vabal_u16:      /**< ARM vabal_u16 opcode. */
        case: /* 325 */ OP_vabal_u32:      /**< ARM vabal_u32 opcode. */
        case: /* 326 */ OP_vabal_u8:       /**< ARM vabal_u8 opcode. */
        case: /* 327 */ OP_vabd_s16:       /**< ARM vabd_s16 opcode. */
        case: /* 328 */ OP_vabd_s32:       /**< ARM vabd_s32 opcode. */
        case: /* 329 */ OP_vabd_s8:        /**< ARM vabd_s8 opcode. */
        case: /* 330 */ OP_vabd_u16:       /**< ARM vabd_u16 opcode. */
        case: /* 331 */ OP_vabd_u32:       /**< ARM vabd_u32 opcode. */
        case: /* 332 */ OP_vabd_u8:        /**< ARM vabd_u8 opcode. */
        case: /* 333 */ OP_vabdl_s16:      /**< ARM vabdl_s16 opcode. */
        case: /* 334 */ OP_vabdl_s32:      /**< ARM vabdl_s32 opcode. */
        case: /* 335 */ OP_vabdl_s8:       /**< ARM vabdl_s8 opcode. */
        case: /* 336 */ OP_vabdl_u16:      /**< ARM vabdl_u16 opcode. */
        case: /* 337 */ OP_vabdl_u32:      /**< ARM vabdl_u32 opcode. */
        case: /* 338 */ OP_vabdl_u8:       /**< ARM vabdl_u8 opcode. */

        case: /* 341 */ OP_vabs_s16:       /**< ARM vabs_s16 opcode. */
        case: /* 342 */ OP_vabs_s32:       /**< ARM vabs_s32 opcode. */
        case: /* 343 */ OP_vabs_s8:        /**< ARM vabs_s8 opcode. */

        case: /* 348 */ OP_vadd_i16:       /**< ARM vadd_i16 opcode. */
        case: /* 349 */ OP_vadd_i32:       /**< ARM vadd_i32 opcode. */
        case: /* 350 */ OP_vadd_i64:       /**< ARM vadd_i64 opcode. */
        case: /* 351 */ OP_vadd_i8:        /**< ARM vadd_i8 opcode. */
        case: /* 352 */ OP_vaddhn_i16:     /**< ARM vaddhn_i16 opcode. */
        case: /* 353 */ OP_vaddhn_i32:     /**< ARM vaddhn_i32 opcode. */
        case: /* 354 */ OP_vaddhn_i64:     /**< ARM vaddhn_i64 opcode. */
        case: /* 355 */ OP_vaddl_s16:      /**< ARM vaddl_s16 opcode. */
        case: /* 356 */ OP_vaddl_s32:      /**< ARM vaddl_s32 opcode. */
        case: /* 357 */ OP_vaddl_s8:       /**< ARM vaddl_s8 opcode. */
        case: /* 358 */ OP_vaddl_u16:      /**< ARM vaddl_u16 opcode. */
        case: /* 359 */ OP_vaddl_u32:      /**< ARM vaddl_u32 opcode. */
        case: /* 360 */ OP_vaddl_u8:       /**< ARM vaddl_u8 opcode. */
        case: /* 361 */ OP_vaddw_s16:      /**< ARM vaddw_s16 opcode. */
        case: /* 362 */ OP_vaddw_s32:      /**< ARM vaddw_s32 opcode. */
        case: /* 363 */ OP_vaddw_s8:       /**< ARM vaddw_s8 opcode. */
        case: /* 364 */ OP_vaddw_u16:      /**< ARM vaddw_u16 opcode. */
        case: /* 365 */ OP_vaddw_u32:      /**< ARM vaddw_u32 opcode. */
        case: /* 366 */ OP_vaddw_u8:       /**< ARM vaddw_u8 opcode. */
        case: /* 367 */ OP_vand:           /**< ARM vand opcode. */
        case: /* 368 */ OP_vbic:           /**< ARM vbic opcode. */
        case: /* 369 */ OP_vbic_i16:       /**< ARM vbic_i16 opcode. */
        case: /* 370 */ OP_vbic_i32:       /**< ARM vbic_i32 opcode. */

        // TODO: ???
        case: /* 371 */ OP_vbif:           /**< ARM vbif opcode. */

        case: /* 372 */ OP_vbit:           /**< ARM vbit opcode. */
        case: /* 373 */ OP_vbsl:           /**< ARM vbsl opcode. */

        case: /* 375 */ OP_vceq_i16:       /**< ARM vceq_i16 opcode. */
        case: /* 376 */ OP_vceq_i32:       /**< ARM vceq_i32 opcode. */
        case: /* 377 */ OP_vceq_i8:        /**< ARM vceq_i8 opcode. */

        case: /* 379 */ OP_vcge_s16:       /**< ARM vcge_s16 opcode. */
        case: /* 380 */ OP_vcge_s32:       /**< ARM vcge_s32 opcode. */
        case: /* 381 */ OP_vcge_s8:        /**< ARM vcge_s8 opcode. */
        case: /* 382 */ OP_vcge_u16:       /**< ARM vcge_u16 opcode. */
        case: /* 383 */ OP_vcge_u32:       /**< ARM vcge_u32 opcode. */
        case: /* 384 */ OP_vcge_u8:        /**< ARM vcge_u8 opcode. */

        case: /* 386 */ OP_vcgt_s16:       /**< ARM vcgt_s16 opcode. */
        case: /* 387 */ OP_vcgt_s32:       /**< ARM vcgt_s32 opcode. */
        case: /* 388 */ OP_vcgt_s8:        /**< ARM vcgt_s8 opcode. */
        case: /* 389 */ OP_vcgt_u16:       /**< ARM vcgt_u16 opcode. */
        case: /* 390 */ OP_vcgt_u32:       /**< ARM vcgt_u32 opcode. */
        case: /* 391 */ OP_vcgt_u8:        /**< ARM vcgt_u8 opcode. */

        case: /* 393 */ OP_vcle_s16:       /**< ARM vcle_s16 opcode. */
        case: /* 394 */ OP_vcle_s32:       /**< ARM vcle_s32 opcode. */
        case: /* 395 */ OP_vcle_s8:        /**< ARM vcle_s8 opcode. */
        case: /* 396 */ OP_vcls_s16:       /**< ARM vcls_s16 opcode. */
        case: /* 397 */ OP_vcls_s32:       /**< ARM vcls_s32 opcode. */
        case: /* 398 */ OP_vcls_s8:        /**< ARM vcls_s8 opcode. */

        case: /* 400 */ OP_vclt_s16:       /**< ARM vclt_s16 opcode. */
        case: /* 401 */ OP_vclt_s32:       /**< ARM vclt_s32 opcode. */
        case: /* 402 */ OP_vclt_s8:        /**< ARM vclt_s8 opcode. */
        case: /* 403 */ OP_vclz_i16:       /**< ARM vclz_i16 opcode. */
        case: /* 404 */ OP_vclz_i32:       /**< ARM vclz_i32 opcode. */
        case: /* 405 */ OP_vclz_i8:        /**< ARM vclz_i8 opcode. */

        case: /* 464 */ OP_veor:           /**< ARM veor opcode. */
        case: /* 465 */ OP_vext:           /**< ARM vext opcode. */

        case: /* 474 */ OP_vhadd_s16:      /**< ARM vhadd_s16 opcode. */
        case: /* 475 */ OP_vhadd_s32:      /**< ARM vhadd_s32 opcode. */
        case: /* 476 */ OP_vhadd_s8:       /**< ARM vhadd_s8 opcode. */
        case: /* 477 */ OP_vhadd_u16:      /**< ARM vhadd_u16 opcode. */
        case: /* 478 */ OP_vhadd_u32:      /**< ARM vhadd_u32 opcode. */
        case: /* 479 */ OP_vhadd_u8:       /**< ARM vhadd_u8 opcode. */
        case: /* 480 */ OP_vhsub_s16:      /**< ARM vhsub_s16 opcode. */
        case: /* 481 */ OP_vhsub_s32:      /**< ARM vhsub_s32 opcode. */
        case: /* 482 */ OP_vhsub_s8:       /**< ARM vhsub_s8 opcode. */
        case: /* 483 */ OP_vhsub_u16:      /**< ARM vhsub_u16 opcode. */
        case: /* 484 */ OP_vhsub_u32:      /**< ARM vhsub_u32 opcode. */
        case: /* 485 */ OP_vhsub_u8:       /**< ARM vhsub_u8 opcode. */

        case: /* 527 */ OP_vmax_s16:       /**< ARM vmax_s16 opcode. */
        case: /* 528 */ OP_vmax_s32:       /**< ARM vmax_s32 opcode. */
        case: /* 529 */ OP_vmax_s8:        /**< ARM vmax_s8 opcode. */
        case: /* 530 */ OP_vmax_u16:       /**< ARM vmax_u16 opcode. */
        case: /* 531 */ OP_vmax_u32:       /**< ARM vmax_u32 opcode. */
        case: /* 532 */ OP_vmax_u8:        /**< ARM vmax_u8 opcode. */

        case: /* 536 */ OP_vmin_s16:       /**< ARM vmin_s16 opcode. */
        case: /* 537 */ OP_vmin_s32:       /**< ARM vmin_s32 opcode. */
        case: /* 538 */ OP_vmin_s8:        /**< ARM vmin_s8 opcode. */
        case: /* 539 */ OP_vmin_u16:       /**< ARM vmin_u16 opcode. */
        case: /* 540 */ OP_vmin_u32:       /**< ARM vmin_u32 opcode. */
        case: /* 541 */ OP_vmin_u8:        /**< ARM vmin_u8 opcode. */

        case: /* 546 */ OP_vmla_i16:       /**< ARM vmla_i16 opcode. */
        case: /* 547 */ OP_vmla_i32:       /**< ARM vmla_i32 opcode. */
        case: /* 548 */ OP_vmla_i8:        /**< ARM vmla_i8 opcode. */
        case: /* 549 */ OP_vmlal_s16:      /**< ARM vmlal_s16 opcode. */
        case: /* 550 */ OP_vmlal_s32:      /**< ARM vmlal_s32 opcode. */
        case: /* 551 */ OP_vmlal_s8:       /**< ARM vmlal_s8 opcode. */
        case: /* 552 */ OP_vmlal_u16:      /**< ARM vmlal_u16 opcode. */
        case: /* 553 */ OP_vmlal_u32:      /**< ARM vmlal_u32 opcode. */
        case: /* 554 */ OP_vmlal_u8:       /**< ARM vmlal_u8 opcode. */

        case: /* 557 */ OP_vmls_i16:       /**< ARM vmls_i16 opcode. */
        case: /* 558 */ OP_vmls_i32:       /**< ARM vmls_i32 opcode. */
        case: /* 559 */ OP_vmls_i8:        /**< ARM vmls_i8 opcode. */
        case: /* 560 */ OP_vmlsl_s16:      /**< ARM vmlsl_s16 opcode. */
        case: /* 561 */ OP_vmlsl_s32:      /**< ARM vmlsl_s32 opcode. */
        case: /* 562 */ OP_vmlsl_s8:       /**< ARM vmlsl_s8 opcode. */
        case: /* 563 */ OP_vmlsl_u16:      /**< ARM vmlsl_u16 opcode. */
        case: /* 564 */ OP_vmlsl_u32:      /**< ARM vmlsl_u32 opcode. */
        case: /* 565 */ OP_vmlsl_u8:       /**< ARM vmlsl_u8 opcode. */

        case: /* 593 */ OP_vmul_i16:       /**< ARM vmul_i16 opcode. */
        case: /* 594 */ OP_vmul_i32:       /**< ARM vmul_i32 opcode. */
        case: /* 595 */ OP_vmul_i8:        /**< ARM vmul_i8 opcode. */
        case: /* 596 */ OP_vmul_p32:       /**< ARM vmul_p32 opcode. */
        case: /* 597 */ OP_vmul_p8:        /**< ARM vmul_p8 opcode. */
        case: /* 598 */ OP_vmull_p32:      /**< ARM vmull_p32 opcode. */
        case: /* 599 */ OP_vmull_p8:       /**< ARM vmull_p8 opcode. */
        case: /* 600 */ OP_vmull_s16:      /**< ARM vmull_s16 opcode. */
        case: /* 601 */ OP_vmull_s32:      /**< ARM vmull_s32 opcode. */
        case: /* 602 */ OP_vmull_s8:       /**< ARM vmull_s8 opcode. */
        case: /* 603 */ OP_vmull_u16:      /**< ARM vmull_u16 opcode. */
        case: /* 604 */ OP_vmull_u32:      /**< ARM vmull_u32 opcode. */
        case: /* 605 */ OP_vmull_u8:       /**< ARM vmull_u8 opcode. */

        case: /* 606 */ OP_vmvn:           /**< ARM vmvn opcode. */
        case: /* 607 */ OP_vmvn_i16:       /**< ARM vmvn_i16 opcode. */
        case: /* 608 */ OP_vmvn_i32:       /**< ARM vmvn_i32 opcode. */

        case: /* 611 */ OP_vneg_s16:       /**< ARM vneg_s16 opcode. */
        case: /* 612 */ OP_vneg_s32:       /**< ARM vneg_s32 opcode. */
        case: /* 613 */ OP_vneg_s8:        /**< ARM vneg_s8 opcode. */

        case: /* 620 */ OP_vorn:           /**< ARM vorn opcode. */
        case: /* 621 */ OP_vorr:           /**< ARM vorr opcode. */
        case: /* 622 */ OP_vorr_i16:       /**< ARM vorr_i16 opcode. */
        case: /* 623 */ OP_vorr_i32:       /**< ARM vorr_i32 opcode. */

        case: /* 624 */ OP_vpadal_s16:     /**< ARM vpadal_s16 opcode. */
        case: /* 625 */ OP_vpadal_s32:     /**< ARM vpadal_s32 opcode. */
        case: /* 626 */ OP_vpadal_s8:      /**< ARM vpadal_s8 opcode. */
        case: /* 627 */ OP_vpadal_u16:     /**< ARM vpadal_u16 opcode. */
        case: /* 628 */ OP_vpadal_u32:     /**< ARM vpadal_u32 opcode. */
        case: /* 629 */ OP_vpadal_u8:      /**< ARM vpadal_u8 opcode. */

        case: /* 631 */ OP_vpadd_i16:      /**< ARM vpadd_i16 opcode. */
        case: /* 632 */ OP_vpadd_i32:      /**< ARM vpadd_i32 opcode. */
        case: /* 633 */ OP_vpadd_i8:       /**< ARM vpadd_i8 opcode. */
        case: /* 634 */ OP_vpaddl_s16:     /**< ARM vpaddl_s16 opcode. */
        case: /* 635 */ OP_vpaddl_s32:     /**< ARM vpaddl_s32 opcode. */
        case: /* 636 */ OP_vpaddl_s8:      /**< ARM vpaddl_s8 opcode. */
        case: /* 637 */ OP_vpaddl_u16:     /**< ARM vpaddl_u16 opcode. */
        case: /* 638 */ OP_vpaddl_u32:     /**< ARM vpaddl_u32 opcode. */
        case: /* 639 */ OP_vpaddl_u8:      /**< ARM vpaddl_u8 opcode. */

        case: /* 641 */ OP_vpmax_s16:      /**< ARM vpmax_s16 opcode. */
        case: /* 642 */ OP_vpmax_s32:      /**< ARM vpmax_s32 opcode. */
        case: /* 643 */ OP_vpmax_s8:       /**< ARM vpmax_s8 opcode. */
        case: /* 644 */ OP_vpmax_u16:      /**< ARM vpmax_u16 opcode. */
        case: /* 645 */ OP_vpmax_u32:      /**< ARM vpmax_u32 opcode. */
        case: /* 646 */ OP_vpmax_u8:       /**< ARM vpmax_u8 opcode. */

        case: /* 648 */ OP_vpmin_s16:      /**< ARM vpmin_s16 opcode. */
        case: /* 649 */ OP_vpmin_s32:      /**< ARM vpmin_s32 opcode. */
        case: /* 650 */ OP_vpmin_s8:       /**< ARM vpmin_s8 opcode. */
        case: /* 651 */ OP_vpmin_u16:      /**< ARM vpmin_u16 opcode. */
        case: /* 652 */ OP_vpmin_u32:      /**< ARM vpmin_u32 opcode. */
        case: /* 653 */ OP_vpmin_u8:       /**< ARM vpmin_u8 opcode. */
        case: /* 654 */ OP_vqabs_s16:      /**< ARM vqabs_s16 opcode. */
        case: /* 655 */ OP_vqabs_s32:      /**< ARM vqabs_s32 opcode. */
        case: /* 656 */ OP_vqabs_s8:       /**< ARM vqabs_s8 opcode. */
        case: /* 657 */ OP_vqadd_s16:      /**< ARM vqadd_s16 opcode. */
        case: /* 658 */ OP_vqadd_s32:      /**< ARM vqadd_s32 opcode. */
        case: /* 659 */ OP_vqadd_s64:      /**< ARM vqadd_s64 opcode. */
        case: /* 660 */ OP_vqadd_s8:       /**< ARM vqadd_s8 opcode. */
        case: /* 661 */ OP_vqadd_u16:      /**< ARM vqadd_u16 opcode. */
        case: /* 662 */ OP_vqadd_u32:      /**< ARM vqadd_u32 opcode. */
        case: /* 663 */ OP_vqadd_u64:      /**< ARM vqadd_u64 opcode. */
        case: /* 664 */ OP_vqadd_u8:       /**< ARM vqadd_u8 opcode. */
        case: /* 665 */ OP_vqdmlal_s16:    /**< ARM vqdmlal_s16 opcode. */
        case: /* 666 */ OP_vqdmlal_s32:    /**< ARM vqdmlal_s32 opcode. */
        case: /* 667 */ OP_vqdmlsl_s16:    /**< ARM vqdmlsl_s16 opcode. */
        case: /* 668 */ OP_vqdmlsl_s32:    /**< ARM vqdmlsl_s32 opcode. */
        case: /* 669 */ OP_vqdmulh_s16:    /**< ARM vqdmulh_s16 opcode. */
        case: /* 670 */ OP_vqdmulh_s32:    /**< ARM vqdmulh_s32 opcode. */
        case: /* 671 */ OP_vqdmull_s16:    /**< ARM vqdmull_s16 opcode. */
        case: /* 672 */ OP_vqdmull_s32:    /**< ARM vqdmull_s32 opcode. */

        case: /* 682 */ OP_vqneg_s16:      /**< ARM vqneg_s16 opcode. */
        case: /* 683 */ OP_vqneg_s32:      /**< ARM vqneg_s32 opcode. */
        case: /* 684 */ OP_vqneg_s8:       /**< ARM vqneg_s8 opcode. */
        case: /* 685 */ OP_vqrdmulh_s16:   /**< ARM vqrdmulh_s16 opcode. */
        case: /* 686 */ OP_vqrdmulh_s32:   /**< ARM vqrdmulh_s32 opcode. */
        case: /* 687 */ OP_vqrshl_s16:     /**< ARM vqrshl_s16 opcode. */
        case: /* 688 */ OP_vqrshl_s32:     /**< ARM vqrshl_s32 opcode. */
        case: /* 689 */ OP_vqrshl_s64:     /**< ARM vqrshl_s64 opcode. */
        case: /* 690 */ OP_vqrshl_s8:      /**< ARM vqrshl_s8 opcode. */
        case: /* 691 */ OP_vqrshl_u16:     /**< ARM vqrshl_u16 opcode. */
        case: /* 692 */ OP_vqrshl_u32:     /**< ARM vqrshl_u32 opcode. */
        case: /* 693 */ OP_vqrshl_u64:     /**< ARM vqrshl_u64 opcode. */
        case: /* 694 */ OP_vqrshl_u8:      /**< ARM vqrshl_u8 opcode. */
        case: /* 695 */ OP_vqrshrn_s16:    /**< ARM vqrshrn_s16 opcode. */
        case: /* 696 */ OP_vqrshrn_s32:    /**< ARM vqrshrn_s32 opcode. */
        case: /* 697 */ OP_vqrshrn_s64:    /**< ARM vqrshrn_s64 opcode. */
        case: /* 698 */ OP_vqrshrn_u16:    /**< ARM vqrshrn_u16 opcode. */
        case: /* 699 */ OP_vqrshrn_u32:    /**< ARM vqrshrn_u32 opcode. */
        case: /* 700 */ OP_vqrshrn_u64:    /**< ARM vqrshrn_u64 opcode. */
        case: /* 701 */ OP_vqrshrun_s16:   /**< ARM vqrshrun_s16 opcode. */
        case: /* 702 */ OP_vqrshrun_s32:   /**< ARM vqrshrun_s32 opcode. */
        case: /* 703 */ OP_vqrshrun_s64:   /**< ARM vqrshrun_s64 opcode. */
        case: /* 704 */ OP_vqshl_s16:      /**< ARM vqshl_s16 opcode. */
        case: /* 705 */ OP_vqshl_s32:      /**< ARM vqshl_s32 opcode. */
        case: /* 706 */ OP_vqshl_s64:      /**< ARM vqshl_s64 opcode. */
        case: /* 707 */ OP_vqshl_s8:       /**< ARM vqshl_s8 opcode. */
        case: /* 708 */ OP_vqshl_u16:      /**< ARM vqshl_u16 opcode. */
        case: /* 709 */ OP_vqshl_u32:      /**< ARM vqshl_u32 opcode. */
        case: /* 710 */ OP_vqshl_u64:      /**< ARM vqshl_u64 opcode. */
        case: /* 711 */ OP_vqshl_u8:       /**< ARM vqshl_u8 opcode. */
        case: /* 712 */ OP_vqshlu_s16:     /**< ARM vqshlu_s16 opcode. */
        case: /* 713 */ OP_vqshlu_s32:     /**< ARM vqshlu_s32 opcode. */
        case: /* 714 */ OP_vqshlu_s64:     /**< ARM vqshlu_s64 opcode. */
        case: /* 715 */ OP_vqshlu_s8:      /**< ARM vqshlu_s8 opcode. */
        case: /* 716 */ OP_vqshrn_s16:     /**< ARM vqshrn_s16 opcode. */
        case: /* 717 */ OP_vqshrn_s32:     /**< ARM vqshrn_s32 opcode. */
        case: /* 718 */ OP_vqshrn_s64:     /**< ARM vqshrn_s64 opcode. */
        case: /* 719 */ OP_vqshrn_u16:     /**< ARM vqshrn_u16 opcode. */
        case: /* 720 */ OP_vqshrn_u32:     /**< ARM vqshrn_u32 opcode. */
        case: /* 721 */ OP_vqshrn_u64:     /**< ARM vqshrn_u64 opcode. */
        case: /* 722 */ OP_vqshrun_s16:    /**< ARM vqshrun_s16 opcode. */
        case: /* 723 */ OP_vqshrun_s32:    /**< ARM vqshrun_s32 opcode. */
        case: /* 724 */ OP_vqshrun_s64:    /**< ARM vqshrun_s64 opcode. */
        case: /* 725 */ OP_vqsub_s16:      /**< ARM vqsub_s16 opcode. */
        case: /* 726 */ OP_vqsub_s32:      /**< ARM vqsub_s32 opcode. */
        case: /* 727 */ OP_vqsub_s64:      /**< ARM vqsub_s64 opcode. */
        case: /* 728 */ OP_vqsub_s8:       /**< ARM vqsub_s8 opcode. */
        case: /* 729 */ OP_vqsub_u16:      /**< ARM vqsub_u16 opcode. */
        case: /* 730 */ OP_vqsub_u32:      /**< ARM vqsub_u32 opcode. */
        case: /* 731 */ OP_vqsub_u64:      /**< ARM vqsub_u64 opcode. */
        case: /* 732 */ OP_vqsub_u8:       /**< ARM vqsub_u8 opcode. */
        case: /* 733 */ OP_vraddhn_i16:    /**< ARM vraddhn_i16 opcode. */
        case: /* 734 */ OP_vraddhn_i32:    /**< ARM vraddhn_i32 opcode. */
        case: /* 735 */ OP_vraddhn_i64:    /**< ARM vraddhn_i64 opcode. */
        case: /* 736 */ OP_vrecpe_f32:     /**< ARM vrecpe_f32 opcode. */
        case: /* 737 */ OP_vrecpe_u32:     /**< ARM vrecpe_u32 opcode. */

        case: /* 739 */ OP_vrev16_16:      /**< ARM vrev16_16 opcode. */
        case: /* 740 */ OP_vrev16_8:       /**< ARM vrev16_8 opcode. */
        case: /* 741 */ OP_vrev32_16:      /**< ARM vrev32_16 opcode. */
        case: /* 742 */ OP_vrev32_32:      /**< ARM vrev32_32 opcode. */
        case: /* 743 */ OP_vrev32_8:       /**< ARM vrev32_8 opcode. */
        case: /* 744 */ OP_vrev64_16:      /**< ARM vrev64_16 opcode. */
        case: /* 745 */ OP_vrev64_32:      /**< ARM vrev64_32 opcode. */
        case: /* 746 */ OP_vrev64_8:       /**< ARM vrev64_8 opcode. */
        case: /* 747 */ OP_vrhadd_s16:     /**< ARM vrhadd_s16 opcode. */
        case: /* 748 */ OP_vrhadd_s32:     /**< ARM vrhadd_s32 opcode. */
        case: /* 749 */ OP_vrhadd_s8:      /**< ARM vrhadd_s8 opcode. */
        case: /* 750 */ OP_vrhadd_u16:     /**< ARM vrhadd_u16 opcode. */
        case: /* 751 */ OP_vrhadd_u32:     /**< ARM vrhadd_u32 opcode. */
        case: /* 752 */ OP_vrhadd_u8:      /**< ARM vrhadd_u8 opcode. */

        case: /* 769 */ OP_vrshl_s16:      /**< ARM vrshl_s16 opcode. */
        case: /* 770 */ OP_vrshl_s32:      /**< ARM vrshl_s32 opcode. */
        case: /* 771 */ OP_vrshl_s64:      /**< ARM vrshl_s64 opcode. */
        case: /* 772 */ OP_vrshl_s8:       /**< ARM vrshl_s8 opcode. */
        case: /* 773 */ OP_vrshl_u16:      /**< ARM vrshl_u16 opcode. */
        case: /* 774 */ OP_vrshl_u32:      /**< ARM vrshl_u32 opcode. */
        case: /* 775 */ OP_vrshl_u64:      /**< ARM vrshl_u64 opcode. */
        case: /* 776 */ OP_vrshl_u8:       /**< ARM vrshl_u8 opcode. */
        case: /* 777 */ OP_vrshr_s16:      /**< ARM vrshr_s16 opcode. */
        case: /* 778 */ OP_vrshr_s32:      /**< ARM vrshr_s32 opcode. */
        case: /* 779 */ OP_vrshr_s64:      /**< ARM vrshr_s64 opcode. */
        case: /* 780 */ OP_vrshr_s8:       /**< ARM vrshr_s8 opcode. */
        case: /* 781 */ OP_vrshr_u16:      /**< ARM vrshr_u16 opcode. */
        case: /* 782 */ OP_vrshr_u32:      /**< ARM vrshr_u32 opcode. */
        case: /* 783 */ OP_vrshr_u64:      /**< ARM vrshr_u64 opcode. */
        case: /* 784 */ OP_vrshr_u8:       /**< ARM vrshr_u8 opcode. */
        case: /* 785 */ OP_vrshrn_i16:     /**< ARM vrshrn_i16 opcode. */
        case: /* 786 */ OP_vrshrn_i32:     /**< ARM vrshrn_i32 opcode. */
        case: /* 787 */ OP_vrshrn_i64:     /**< ARM vrshrn_i64 opcode. */

        case: /* 789 */ OP_vrsqrte_u32:    /**< ARM vrsqrte_u32 opcode. */

        case: /* 791 */ OP_vrsra_s16:      /**< ARM vrsra_s16 opcode. */
        case: /* 792 */ OP_vrsra_s32:      /**< ARM vrsra_s32 opcode. */
        case: /* 793 */ OP_vrsra_s64:      /**< ARM vrsra_s64 opcode. */
        case: /* 794 */ OP_vrsra_s8:       /**< ARM vrsra_s8 opcode. */
        case: /* 795 */ OP_vrsra_u16:      /**< ARM vrsra_u16 opcode. */
        case: /* 796 */ OP_vrsra_u32:      /**< ARM vrsra_u32 opcode. */
        case: /* 797 */ OP_vrsra_u64:      /**< ARM vrsra_u64 opcode. */
        case: /* 798 */ OP_vrsra_u8:       /**< ARM vrsra_u8 opcode. */
        case: /* 799 */ OP_vrsubhn_i16:    /**< ARM vrsubhn_i16 opcode. */
        case: /* 800 */ OP_vrsubhn_i32:    /**< ARM vrsubhn_i32 opcode. */
        case: /* 801 */ OP_vrsubhn_i64:    /**< ARM vrsubhn_i64 opcode. */

        case: /* 810 */ OP_vshl_i16:       /**< ARM vshl_i16 opcode. */
        case: /* 811 */ OP_vshl_i32:       /**< ARM vshl_i32 opcode. */
        case: /* 812 */ OP_vshl_i64:       /**< ARM vshl_i64 opcode. */
        case: /* 813 */ OP_vshl_i8:        /**< ARM vshl_i8 opcode. */
        case: /* 814 */ OP_vshl_s16:       /**< ARM vshl_s16 opcode. */
        case: /* 815 */ OP_vshl_s32:       /**< ARM vshl_s32 opcode. */
        case: /* 816 */ OP_vshl_s64:       /**< ARM vshl_s64 opcode. */
        case: /* 817 */ OP_vshl_s8:        /**< ARM vshl_s8 opcode. */
        case: /* 818 */ OP_vshl_u16:       /**< ARM vshl_u16 opcode. */
        case: /* 819 */ OP_vshl_u32:       /**< ARM vshl_u32 opcode. */
        case: /* 820 */ OP_vshl_u64:       /**< ARM vshl_u64 opcode. */
        case: /* 821 */ OP_vshl_u8:        /**< ARM vshl_u8 opcode. */
        case: /* 822 */ OP_vshll_i16:      /**< ARM vshll_i16 opcode. */
        case: /* 823 */ OP_vshll_i32:      /**< ARM vshll_i32 opcode. */
        case: /* 824 */ OP_vshll_i8:       /**< ARM vshll_i8 opcode. */
        case: /* 825 */ OP_vshll_s16:      /**< ARM vshll_s16 opcode. */
        case: /* 826 */ OP_vshll_s32:      /**< ARM vshll_s32 opcode. */
        case: /* 827 */ OP_vshll_s8:       /**< ARM vshll_s8 opcode. */
        case: /* 828 */ OP_vshll_u16:      /**< ARM vshll_u16 opcode. */
        case: /* 829 */ OP_vshll_u32:      /**< ARM vshll_u32 opcode. */
        case: /* 830 */ OP_vshll_u8:       /**< ARM vshll_u8 opcode. */
        case: /* 831 */ OP_vshr_s16:       /**< ARM vshr_s16 opcode. */
        case: /* 832 */ OP_vshr_s32:       /**< ARM vshr_s32 opcode. */
        case: /* 833 */ OP_vshr_s64:       /**< ARM vshr_s64 opcode. */
        case: /* 834 */ OP_vshr_s8:        /**< ARM vshr_s8 opcode. */
        case: /* 835 */ OP_vshr_u16:       /**< ARM vshr_u16 opcode. */
        case: /* 836 */ OP_vshr_u32:       /**< ARM vshr_u32 opcode. */
        case: /* 837 */ OP_vshr_u64:       /**< ARM vshr_u64 opcode. */
        case: /* 838 */ OP_vshr_u8:        /**< ARM vshr_u8 opcode. */
        case: /* 839 */ OP_vshrn_i16:      /**< ARM vshrn_i16 opcode. */
        case: /* 840 */ OP_vshrn_i32:      /**< ARM vshrn_i32 opcode. */
        case: /* 841 */ OP_vshrn_i64:      /**< ARM vshrn_i64 opcode. */
        case: /* 842 */ OP_vsli_16:        /**< ARM vsli_16 opcode. */
        case: /* 843 */ OP_vsli_32:        /**< ARM vsli_32 opcode. */
        case: /* 844 */ OP_vsli_64:        /**< ARM vsli_64 opcode. */
        case: /* 845 */ OP_vsli_8:         /**< ARM vsli_8 opcode. */

        case: /* 848 */ OP_vsra_s16:       /**< ARM vsra_s16 opcode. */
        case: /* 849 */ OP_vsra_s32:       /**< ARM vsra_s32 opcode. */
        case: /* 850 */ OP_vsra_s64:       /**< ARM vsra_s64 opcode. */
        case: /* 851 */ OP_vsra_s8:        /**< ARM vsra_s8 opcode. */
        case: /* 852 */ OP_vsra_u16:       /**< ARM vsra_u16 opcode. */
        case: /* 853 */ OP_vsra_u32:       /**< ARM vsra_u32 opcode. */
        case: /* 854 */ OP_vsra_u64:       /**< ARM vsra_u64 opcode. */
        case: /* 855 */ OP_vsra_u8:        /**< ARM vsra_u8 opcode. */
        case: /* 856 */ OP_vsri_16:        /**< ARM vsri_16 opcode. */
        case: /* 857 */ OP_vsri_32:        /**< ARM vsri_32 opcode. */
        case: /* 858 */ OP_vsri_64:        /**< ARM vsri_64 opcode. */
        case: /* 859 */ OP_vsri_8:         /**< ARM vsri_8 opcode. */

        case: /* 890 */ OP_vsub_i16:       /**< ARM vsub_i16 opcode. */
        case: /* 891 */ OP_vsub_i32:       /**< ARM vsub_i32 opcode. */
        case: /* 892 */ OP_vsub_i64:       /**< ARM vsub_i64 opcode. */
        case: /* 893 */ OP_vsub_i8:        /**< ARM vsub_i8 opcode. */
        case: /* 894 */ OP_vsubhn_i16:     /**< ARM vsubhn_i16 opcode. */
        case: /* 895 */ OP_vsubhn_i32:     /**< ARM vsubhn_i32 opcode. */
        case: /* 896 */ OP_vsubhn_i64:     /**< ARM vsubhn_i64 opcode. */
        case: /* 897 */ OP_vsubl_s16:      /**< ARM vsubl_s16 opcode. */
        case: /* 898 */ OP_vsubl_s32:      /**< ARM vsubl_s32 opcode. */
        case: /* 899 */ OP_vsubl_s8:       /**< ARM vsubl_s8 opcode. */
        case: /* 900 */ OP_vsubl_u16:      /**< ARM vsubl_u16 opcode. */
        case: /* 901 */ OP_vsubl_u32:      /**< ARM vsubl_u32 opcode. */
        case: /* 902 */ OP_vsubl_u8:       /**< ARM vsubl_u8 opcode. */
        case: /* 903 */ OP_vsubw_s16:      /**< ARM vsubw_s16 opcode. */
        case: /* 904 */ OP_vsubw_s32:      /**< ARM vsubw_s32 opcode. */
        case: /* 905 */ OP_vsubw_s8:       /**< ARM vsubw_s8 opcode. */
        case: /* 906 */ OP_vsubw_u16:      /**< ARM vsubw_u16 opcode. */
        case: /* 907 */ OP_vsubw_u32:      /**< ARM vsubw_u32 opcode. */
        case: /* 908 */ OP_vsubw_u8:       /**< ARM vsubw_u8 opcode. */

        case: /* 915 */ OP_vtst_16:        /**< ARM vtst_16 opcode. */
        case: /* 916 */ OP_vtst_32:        /**< ARM vtst_32 opcode. */
        case: /* 917 */ OP_vtst_8:         /**< ARM vtst_8 opcode. */ return true;

        default: return false;
    }
}

DR_API
bool
instr_is_scalar_float(instr_t *instr) {
    return op_is_integer(instr_get_opcode(instr) && !instr_is_simd(instr))
}

DR_API
bool
instr_is_simd_float(instr_t *instr) {
    return op_is_integer(instr_get_opcode(instr) && instr_is_simd(instr))
}

DR_API
bool
op_is_float(int op_code) {
    switch (op_code) {
        case: /* 339 */ OP_vabs_f32:       /**< ARM vabs_f32 opcode. */
        case: /* 340 */ OP_vabs_f64:       /**< ARM vabs_f64 opcode. */

        case: /* 344 */ OP_vacge_f32:      /**< ARM vacge_f32 opcode. */
        case: /* 345 */ OP_vacgt_f32:      /**< ARM vacgt_f32 opcode. */
        case: /* 346 */ OP_vadd_f32:       /**< ARM vadd_f32 opcode. */
        case: /* 347 */ OP_vadd_f64:       /**< ARM vadd_f64 opcode. */

        case: /* 374 */ OP_vceq_f32:       /**< ARM vceq_f32 opcode. */

        case: /* 378 */ OP_vcge_f32:       /**< ARM vcge_f32 opcode. */

        case: /* 385 */ OP_vcgt_f32:       /**< ARM vcgt_f32 opcode. */

        case: /* 392 */ OP_vcle_f32:       /**< ARM vcle_f32 opcode. */

        case: /* 399 */ OP_vclt_f32:       /**< ARM vclt_f32 opcode. */

        case: /* 406 */ OP_vcmp_f32:       /**< ARM vcmp_f32 opcode. */
        case: /* 407 */ OP_vcmp_f64:       /**< ARM vcmp_f64 opcode. */
        case: /* 408 */ OP_vcmpe_f32:      /**< ARM vcmpe_f32 opcode. */
        case: /* 409 */ OP_vcmpe_f64:      /**< ARM vcmpe_f64 opcode. */

        case: /* 459 */ OP_vdiv_f32:       /**< ARM vdiv_f32 opcode. */
        case: /* 460 */ OP_vdiv_f64:       /**< ARM vdiv_f64 opcode. */

        case: /* 466 */ OP_vfma_f32:       /**< ARM vfma_f32 opcode. */
        case: /* 467 */ OP_vfma_f64:       /**< ARM vfma_f64 opcode. */
        case: /* 468 */ OP_vfms_f32:       /**< ARM vfms_f32 opcode. */
        case: /* 469 */ OP_vfms_f64:       /**< ARM vfms_f64 opcode. */
        case: /* 470 */ OP_vfnma_f32:      /**< ARM vfnma_f32 opcode. */
        case: /* 471 */ OP_vfnma_f64:      /**< ARM vfnma_f64 opcode. */
        case: /* 472 */ OP_vfnms_f32:      /**< ARM vfnms_f32 opcode. */
        case: /* 473 */ OP_vfnms_f64:      /**< ARM vfnms_f64 opcode. */

        case: /* 526 */ OP_vmax_f32:       /**< ARM vmax_f32 opcode. */

        case: /* 533 */ OP_vmaxnm_f32:     /**< ARM vmaxnm_f32 opcode. */
        case: /* 534 */ OP_vmaxnm_f64:     /**< ARM vmaxnm_f64 opcode. */
        case: /* 535 */ OP_vmin_f32:       /**< ARM vmin_f32 opcode. */

        case: /* 542 */ OP_vminnm_f32:     /**< ARM vminnm_f32 opcode. */
        case: /* 543 */ OP_vminnm_f64:     /**< ARM vminnm_f64 opcode. */
        case: /* 544 */ OP_vmla_f32:       /**< ARM vmla_f32 opcode. */
        case: /* 545 */ OP_vmla_f64:       /**< ARM vmla_f64 opcode. */

        case: /* 555 */ OP_vmls_f32:       /**< ARM vmls_f32 opcode. */
        case: /* 556 */ OP_vmls_f64:       /**< ARM vmls_f64 opcode. */

        case: /* 591 */ OP_vmul_f32:       /**< ARM vmul_f32 opcode. */
        case: /* 592 */ OP_vmul_f64:       /**< ARM vmul_f64 opcode. */

        case: /* 609 */ OP_vneg_f32:       /**< ARM vneg_f32 opcode. */
        case: /* 610 */ OP_vneg_f64:       /**< ARM vneg_f64 opcode. */

        case: /* 614 */ OP_vnmla_f32:      /**< ARM vnmla_f32 opcode. */
        case: /* 615 */ OP_vnmla_f64:      /**< ARM vnmla_f64 opcode. */
        case: /* 616 */ OP_vnmls_f32:      /**< ARM vnmls_f32 opcode. */
        case: /* 617 */ OP_vnmls_f64:      /**< ARM vnmls_f64 opcode. */
        case: /* 618 */ OP_vnmul_f32:      /**< ARM vnmul_f32 opcode. */
        case: /* 619 */ OP_vnmul_f64:      /**< ARM vnmul_f64 opcode. */

        case: /* 630 */ OP_vpadd_f32:      /**< ARM vpadd_f32 opcode. */

        case: /* 640 */ OP_vpmax_f32:      /**< ARM vpmax_f32 opcode. */

        case: /* 647 */ OP_vpmin_f32:      /**< ARM vpmin_f32 opcode. */

        case: /* 738 */ OP_vrecps_f32:     /**< ARM vrecps_f32 opcode. */

        case: /* 788 */ OP_vrsqrte_f32:    /**< ARM vrsqrte_f32 opcode. */

        case: /* 790 */ OP_vrsqrts_f32:    /**< ARM vrsqrts_f32 opcode. */

        case: /* 802 */ OP_vsel_eq_f32:    /**< ARM vsel_eq_f32 opcode. */
        case: /* 803 */ OP_vsel_eq_f64:    /**< ARM vsel_eq_f64 opcode. */
        case: /* 804 */ OP_vsel_ge_f32:    /**< ARM vsel_ge_f32 opcode. */
        case: /* 805 */ OP_vsel_ge_f64:    /**< ARM vsel_ge_f64 opcode. */
        case: /* 806 */ OP_vsel_gt_f32:    /**< ARM vsel_gt_f32 opcode. */
        case: /* 807 */ OP_vsel_gt_f64:    /**< ARM vsel_gt_f64 opcode. */
        case: /* 808 */ OP_vsel_vs_f32:    /**< ARM vsel_vs_f32 opcode. */
        case: /* 809 */ OP_vsel_vs_f64:    /**< ARM vsel_vs_f64 opcode. */

        case: /* 846 */ OP_vsqrt_f32:      /**< ARM vsqrt_f32 opcode. */
        case: /* 847 */ OP_vsqrt_f64:      /**< ARM vsqrt_f64 opcode. */

        case: /* 888 */ OP_vsub_f32:       /**< ARM vsub_f32 opcode. */
        case: /* 889 */ OP_vsub_f64:       /**< ARM vsub_f64 opcode. */ return true;

        default: return false;
}

DR_API
bool
instr_is_scalar_float(instr_t *instr) {
    return op_is_float(instr_get_opcode(instr) && !instr_is_simd(instr))
}

DR_API
bool
instr_is_simd_float(instr_t *instr) {
    return op_is_float(instr_get_opcode(instr) && instr_is_simd(instr))
}

DR_API
bool
instr_is_branch(instr_t *instr) {
    switch (instr_get_opcode(instr)) {
        case: /*  17 */ OP_b,              /**< ARM b opcode. */
        case: /*  18 */ OP_b_short,        /**< ARM b_short opcode. */

        case: /*  24 */ OP_bl,             /**< ARM bl opcode. */
        case: /*  25 */ OP_blx,            /**< ARM blx opcode. */
        case: /*  26 */ OP_blx_ind,        /**< ARM blx_ind opcode. */
        case: /*  27 */ OP_bx,             /**< ARM bx opcode. */
        case: /*  28 */ OP_bxj,            /**< ARM bxj opcode. */

        case: /*  29 */ OP_cbnz,           /**< ARM cbnz opcode. */
        case: /*  30 */ OP_cbz,            /**< ARM cbz opcode. */

        // TODO: OTHERS?
        case: /*  55 */ OP_eret,           /**< ARM eret opcode. */

        // TODO: OTHERS?
        case: /* 146 */ OP_rfe,            /**< ARM rfe opcode. */
        case: /* 147 */ OP_rfeda,          /**< ARM rfeda opcode. */
        case: /* 148 */ OP_rfedb,          /**< ARM rfedb opcode. */
        case: /* 149 */ OP_rfeib,          /**< ARM rfeib opcode. */

        // TODO: ?
        case: /* 264 */ OP_subs,           /**< ARM subs opcode. */

        case: /* 275 */ OP_tbb,            /**< ARM tbb opcode. */
        case: /* 276 */ OP_tbh,            /**< ARM tbh opcode. */
    }
}

DR_API
bool
instr_is_stack(instr_t *instr) {
    switch (instr_get_opcode(instr)) {
        case: /* 224 */ OP_srs,            /**< ARM srs opcode. */
        case: /* 225 */ OP_srsda,          /**< ARM srsda opcode. */
        case: /* 226 */ OP_srsdb,          /**< ARM srsdb opcode. */
        case: /* 227 */ OP_srsib,          /**< ARM srsib opcode. */ return true;

        default: return false;
    }
}

/*
 * UNCLASSIFIED INSTRUCTIONS
 */

// /*   0 */ OP_INVALID,
// /* NULL, */ /**< INVALID opcode */
// /*   1 */ OP_UNDECODED,
// /* NULL, */ /**< UNDECODED opcode */
// /*   2 */ OP_CONTD,
// /* NULL, */ /**< CONTD opcode */
// /*   3 */ OP_LABEL,
// /* NULL, */ /**< LABEL opcode */

// /*   9 */ OP_aesd_8,         /**< ARM aesd_8 opcode. */
// /*  10 */ OP_aese_8,         /**< ARM aese_8 opcode. */
// /*  11 */ OP_aesimc_8,       /**< ARM aesimc_8 opcode. */
// /*  12 */ OP_aesmc_8,        /**< ARM aesmc_8 opcode. */

// /*  19 */ OP_bfc,            /**< ARM bfc opcode. */
// /*  20 */ OP_bfi,            /**< ARM bfi opcode. */
// /*  21 */ OP_bic,            /**< ARM bic opcode. */
// /*  22 */ OP_bics,           /**< ARM bics opcode. */
// /*  23 */ OP_bkpt,           /**< ARM bkpt opcode. */

// /*  31 */ OP_cdp,            /**< ARM cdp opcode. */
// /*  32 */ OP_cdp2,           /**< ARM cdp2 opcode. */
// /*  33 */ OP_clrex,          /**< ARM clrex opcode. */

// /*  37 */ OP_cps,            /**< ARM cps opcode. */
// /*  38 */ OP_cpsid,          /**< ARM cpsid opcode. */
// /*  39 */ OP_cpsie,          /**< ARM cpsie opcode. */

// /*  40 */ OP_crc32b,         /**< ARM crc32b opcode. */
// /*  41 */ OP_crc32cb,        /**< ARM crc32cb opcode. */
// /*  42 */ OP_crc32h,         /**< ARM crc32h opcode. */
// /*  43 */ OP_crc32ch,        /**< ARM crc32ch opcode. */
// /*  44 */ OP_crc32w,         /**< ARM crc32w opcode. */
// /*  45 */ OP_crc32cw,        /**< ARM crc32cw opcode. */

// /*  46 */ OP_dbg,            /**< ARM dbg opcode. */
// /*  47 */ OP_dcps1,          /**< ARM dcps1 opcode. */
// /*  48 */ OP_dcps2,          /**< ARM dcps2 opcode. */
// /*  49 */ OP_dcps3,          /**< ARM dcps3 opcode. */

// /*  50 */ OP_dmb,            /**< ARM dmb opcode. */
// /*  51 */ OP_dsb,            /**< ARM dsb opcode. */

// /*  52 */ OP_enterx,         /**< ARM enterx opcode. */

// /*  56 */ OP_hlt,            /**< ARM hlt opcode. */
// /*  57 */ OP_hvc,            /**< ARM hvc opcode. */
// /*  58 */ OP_isb,            /**< ARM isb opcode. */

// /*  59 */ OP_it,             /**< ARM it opcode. */

// /*  94 */ OP_leavex,         /**< ARM leavex opcode. */

// /* 122 */ OP_nop,            /**< ARM nop opcode. */

// /* 129 */ OP_pld,            /**< ARM pld opcode. */
// /* 130 */ OP_pldw,           /**< ARM pldw opcode. */
// /* 131 */ OP_pli,            /**< ARM pli opcode. */

// /* 166 */ OP_setend,         /**< ARM setend opcode. */
// /* 167 */ OP_sev,            /**< ARM sev opcode. */
// /* 168 */ OP_sevl,           /**< ARM sevl opcode. */

// /* 169 */ OP_sha1c_32,       /**< ARM sha1c_32 opcode. */
// /* 170 */ OP_sha1h_32,       /**< ARM sha1h_32 opcode. */
// /* 171 */ OP_sha1m_32,       /**< ARM sha1m_32 opcode. */
// /* 172 */ OP_sha1p_32,       /**< ARM sha1p_32 opcode. */
// /* 173 */ OP_sha1su0_32,     /**< ARM sha1su0_32 opcode. */
// /* 174 */ OP_sha1su1_32,     /**< ARM sha1su1_32 opcode. */
// /* 175 */ OP_sha256h2_32,    /**< ARM sha256h2_32 opcode. */
// /* 176 */ OP_sha256h_32,     /**< ARM sha256h_32 opcode. */
// /* 177 */ OP_sha256su0_32,   /**< ARM sha256su0_32 opcode. */
// /* 178 */ OP_sha256su1_32,   /**< ARM sha256su1_32 opcode. */

// /* 266 */ OP_svc,            /**< ARM svc opcode. */

// TODO: MOV/INTEGER/FLOAT?
// /* 410 */ OP_vcnt_8,         /**< ARM vcnt_8 opcode. */
// /* 411 */ OP_vcvt_f16_f32,   /**< ARM vcvt_f16_f32 opcode. */
// /* 412 */ OP_vcvt_f32_f16,   /**< ARM vcvt_f32_f16 opcode. */
// /* 413 */ OP_vcvt_f32_f64,   /**< ARM vcvt_f32_f64 opcode. */
// /* 414 */ OP_vcvt_f32_s16,   /**< ARM vcvt_f32_s16 opcode. */
// /* 415 */ OP_vcvt_f32_s32,   /**< ARM vcvt_f32_s32 opcode. */
// /* 416 */ OP_vcvt_f32_u16,   /**< ARM vcvt_f32_u16 opcode. */
// /* 417 */ OP_vcvt_f32_u32,   /**< ARM vcvt_f32_u32 opcode. */
// /* 418 */ OP_vcvt_f64_f32,   /**< ARM vcvt_f64_f32 opcode. */
// /* 419 */ OP_vcvt_f64_s16,   /**< ARM vcvt_f64_s16 opcode. */
// /* 420 */ OP_vcvt_f64_s32,   /**< ARM vcvt_f64_s32 opcode. */
// /* 421 */ OP_vcvt_f64_u16,   /**< ARM vcvt_f64_u16 opcode. */
// /* 422 */ OP_vcvt_f64_u32,   /**< ARM vcvt_f64_u32 opcode. */
// /* 423 */ OP_vcvt_s16_f32,   /**< ARM vcvt_s16_f32 opcode. */
// /* 424 */ OP_vcvt_s16_f64,   /**< ARM vcvt_s16_f64 opcode. */
// /* 425 */ OP_vcvt_s32_f32,   /**< ARM vcvt_s32_f32 opcode. */
// /* 426 */ OP_vcvt_s32_f64,   /**< ARM vcvt_s32_f64 opcode. */
// /* 427 */ OP_vcvt_u16_f32,   /**< ARM vcvt_u16_f32 opcode. */
// /* 428 */ OP_vcvt_u16_f64,   /**< ARM vcvt_u16_f64 opcode. */
// /* 429 */ OP_vcvt_u32_f32,   /**< ARM vcvt_u32_f32 opcode. */
// /* 430 */ OP_vcvt_u32_f64,   /**< ARM vcvt_u32_f64 opcode. */
// /* 431 */ OP_vcvta_s32_f32,  /**< ARM vcvta_s32_f32 opcode. */
// /* 432 */ OP_vcvta_s32_f64,  /**< ARM vcvta_s32_f64 opcode. */
// /* 433 */ OP_vcvta_u32_f32,  /**< ARM vcvta_u32_f32 opcode. */
// /* 434 */ OP_vcvta_u32_f64,  /**< ARM vcvta_u32_f64 opcode. */
// /* 435 */ OP_vcvtb_f16_f32,  /**< ARM vcvtb_f16_f32 opcode. */
// /* 436 */ OP_vcvtb_f16_f64,  /**< ARM vcvtb_f16_f64 opcode. */
// /* 437 */ OP_vcvtb_f32_f16,  /**< ARM vcvtb_f32_f16 opcode. */
// /* 438 */ OP_vcvtb_f64_f16,  /**< ARM vcvtb_f64_f16 opcode. */
// /* 439 */ OP_vcvtm_s32_f32,  /**< ARM vcvtm_s32_f32 opcode. */
// /* 440 */ OP_vcvtm_s32_f64,  /**< ARM vcvtm_s32_f64 opcode. */
// /* 441 */ OP_vcvtm_u32_f32,  /**< ARM vcvtm_u32_f32 opcode. */
// /* 442 */ OP_vcvtm_u32_f64,  /**< ARM vcvtm_u32_f64 opcode. */
// /* 443 */ OP_vcvtn_s32_f32,  /**< ARM vcvtn_s32_f32 opcode. */
// /* 444 */ OP_vcvtn_s32_f64,  /**< ARM vcvtn_s32_f64 opcode. */
// /* 445 */ OP_vcvtn_u32_f32,  /**< ARM vcvtn_u32_f32 opcode. */
// /* 446 */ OP_vcvtn_u32_f64,  /**< ARM vcvtn_u32_f64 opcode. */
// /* 447 */ OP_vcvtp_s32_f32,  /**< ARM vcvtp_s32_f32 opcode. */
// /* 448 */ OP_vcvtp_s32_f64,  /**< ARM vcvtp_s32_f64 opcode. */
// /* 449 */ OP_vcvtp_u32_f32,  /**< ARM vcvtp_u32_f32 opcode. */
// /* 450 */ OP_vcvtp_u32_f64,  /**< ARM vcvtp_u32_f64 opcode. */
// /* 451 */ OP_vcvtr_s32_f32,  /**< ARM vcvtr_s32_f32 opcode. */
// /* 452 */ OP_vcvtr_s32_f64,  /**< ARM vcvtr_s32_f64 opcode. */
// /* 453 */ OP_vcvtr_u32_f32,  /**< ARM vcvtr_u32_f32 opcode. */
// /* 454 */ OP_vcvtr_u32_f64,  /**< ARM vcvtr_u32_f64 opcode. */
// /* 455 */ OP_vcvtt_f16_f32,  /**< ARM vcvtt_f16_f32 opcode. */
// /* 456 */ OP_vcvtt_f16_f64,  /**< ARM vcvtt_f16_f64 opcode. */
// /* 457 */ OP_vcvtt_f32_f16,  /**< ARM vcvtt_f32_f16 opcode. */
// /* 458 */ OP_vcvtt_f64_f16,  /**< ARM vcvtt_f64_f16 opcode. */

// TODO: MOV/FLOAT/INTEGER?
// /* 753 */ OP_vrinta_f32_f32, /**< ARM vrinta_f32_f32 opcode. */
// /* 754 */ OP_vrinta_f64_f64, /**< ARM vrinta_f64_f64 opcode. */
// /* 755 */ OP_vrintm_f32_f32, /**< ARM vrintm_f32_f32 opcode. */
// /* 756 */ OP_vrintm_f64_f64, /**< ARM vrintm_f64_f64 opcode. */
// /* 757 */ OP_vrintn_f32_f32, /**< ARM vrintn_f32_f32 opcode. */
// /* 758 */ OP_vrintn_f64_f64, /**< ARM vrintn_f64_f64 opcode. */
// /* 759 */ OP_vrintp_f32_f32, /**< ARM vrintp_f32_f32 opcode. */
// /* 760 */ OP_vrintp_f64_f64, /**< ARM vrintp_f64_f64 opcode. */
// /* 761 */ OP_vrintr_f32,     /**< ARM vrintr_f32 opcode. */
// /* 762 */ OP_vrintr_f64,     /**< ARM vrintr_f64 opcode. */
// /* 763 */ OP_vrintx_f32,     /**< ARM vrintx_f32 opcode. */
// /* 764 */ OP_vrintx_f32_f32, /**< ARM vrintx_f32_f32 opcode. */
// /* 765 */ OP_vrintx_f64,     /**< ARM vrintx_f64 opcode. */
// /* 766 */ OP_vrintz_f32,     /**< ARM vrintz_f32 opcode. */
// /* 767 */ OP_vrintz_f32_f32, /**< ARM vrintz_f32_f32 opcode. */
// /* 768 */ OP_vrintz_f64,     /**< ARM vrintz_f64 opcode. */

// /* 924 */ OP_wfe,            /**< ARM wfe opcode. */
// /* 925 */ OP_wfi,            /**< ARM wfi opcode. */
// /* 926 */ OP_yield,          /**< ARM yield opcode. */