/* **********************************************************
 * Copyright (c) 2017-2020 Google, Inc.  All rights reserved.
 * Copyright (c) 2016 ARM Limited. All rights reserved.
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
 * * Neither the name of ARM Limited nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL ARM LIMITED OR CONTRIBUTORS BE LIABLE
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

#include "opcode_names.h"

bool
instr_set_isa_mode(instr_t *instr, dr_isa_mode_t mode)
{
    return (mode == DR_ISA_ARM_A64);
}

dr_isa_mode_t
instr_get_isa_mode(instr_t *instr)
{
    return DR_ISA_ARM_A64;
}

int
instr_length_arch(dcontext_t *dcontext, instr_t *instr)
{
    if (instr_get_opcode(instr) == OP_LABEL)
        return 0;
    if (instr_get_opcode(instr) == OP_ldstex) {
        ASSERT(instr->length != 0);
        return instr->length;
    }
    ASSERT(instr_get_opcode(instr) != OP_ldstex);
    return AARCH64_INSTR_SIZE;
}

bool
opc_is_not_a_real_memory_load(int opc)
{
    return (opc == OP_adr || opc == OP_adrp);
}

uint
instr_branch_type(instr_t *cti_instr)
{
    int opcode = instr_get_opcode(cti_instr);
    switch (opcode) {
    case OP_b:
    case OP_bcond:
    case OP_cbnz:
    case OP_cbz:
    case OP_tbnz:
    case OP_tbz: return LINK_DIRECT | LINK_JMP;
    case OP_bl: return LINK_DIRECT | LINK_CALL;
    case OP_blr: return LINK_INDIRECT | LINK_CALL;
    case OP_br: return LINK_INDIRECT | LINK_JMP;
    case OP_ret: return LINK_INDIRECT | LINK_RETURN;
    }
    CLIENT_ASSERT(false, "instr_branch_type: unknown opcode");
    return LINK_INDIRECT;
}

const char *
get_opcode_name(int opc)
{
    return opcode_names[opc];
}

bool
instr_is_mov(instr_t *instr)
{
    ASSERT_NOT_IMPLEMENTED(false); /* FIXME i#1569 */
    return false;
}

bool
instr_is_call_arch(instr_t *instr)
{
    int opc = instr->opcode; /* caller ensures opcode is valid */
    return (opc == OP_bl || opc == OP_blr);
}

bool
instr_is_call_direct(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_bl);
}

bool
instr_is_near_call_direct(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_bl);
}

bool
instr_is_call_indirect(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_blr);
}

bool
instr_is_return(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_ret);
}

bool
instr_is_cbr_arch(instr_t *instr)
{
    int opc = instr->opcode;                   /* caller ensures opcode is valid */
    return (opc == OP_bcond ||                 /* clang-format: keep */
            opc == OP_cbnz || opc == OP_cbz || /* clang-format: keep */
            opc == OP_tbnz || opc == OP_tbz);
}

bool
instr_is_mbr_arch(instr_t *instr)
{
    int opc = instr->opcode; /* caller ensures opcode is valid */
    return (opc == OP_blr || opc == OP_br || opc == OP_ret);
}

bool
instr_is_far_cti(instr_t *instr)
{
    return false;
}

bool
instr_is_ubr_arch(instr_t *instr)
{
    int opc = instr->opcode; /* caller ensures opcode is valid */
    return (opc == OP_b);
}

bool
instr_is_near_ubr(instr_t *instr)
{
    return instr_is_ubr(instr);
}

bool
instr_is_cti_short(instr_t *instr)
{
    /* The branch with smallest reach is TBNZ/TBZ, with range +/- 32 KiB.
     * We have restricted MAX_FRAGMENT_SIZE on AArch64 accordingly.
     */
    return false;
}

bool
instr_is_cti_loop(instr_t *instr)
{
    return false;
}

bool
instr_is_cti_short_rewrite(instr_t *instr, byte *pc)
{
    return false;
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
    uint opc = instr_get_opcode(instr);

    /* We include several instructions that an assembler might generate for
     * "MOV reg, #imm", but not EOR or SUB or other instructions that could
     * in theory be used to generate a zero, nor "MOV reg, wzr/xzr" (for now).
     */

    /* movn/movz reg, imm */
    if (opc == OP_movn || opc == OP_movz) {
        opnd_t op = instr_get_src(instr, 0);
        if (opnd_is_immed_int(op)) {
            ptr_int_t imm = opnd_get_immed_int(op);
            *value = (opc == OP_movn ? ~imm : imm);
            return true;
        } else
            return false;
    }

    /* orr/add/sub reg, xwr/xzr, imm */
    if (opc == OP_orr || opc == OP_add || opc == OP_sub) {
        opnd_t reg = instr_get_src(instr, 0);
        opnd_t imm = instr_get_src(instr, 1);
        if (opnd_is_reg(reg) &&
            (opnd_get_reg(reg) == DR_REG_WZR || opnd_get_reg(reg) == DR_REG_XZR) &&
            opnd_is_immed_int(imm)) {
            *value = opnd_get_immed_int(imm);
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
    return opcode == OP_prfm || opcode == OP_prfum;
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
instr_saves_float_pc(instr_t *instr)
{
    return false;
}

/* Is this an instruction that we must intercept in order to detect a
 * self-modifying program?
 */
bool
instr_is_icache_op(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
#define SYS_ARG_IC_IVAU 0x1ba9
    if (opc == OP_sys && opnd_get_immed_int(instr_get_src(instr, 0)) == SYS_ARG_IC_IVAU)
        return true; /* ic ivau, xT */
    if (opc == OP_isb)
        return true; /* isb */
    return false;
}

bool
instr_is_undefined(instr_t *instr)
{
    /* FIXME i#1569: Without a complete decoder we cannot recognise all
     * unallocated encodings, but for testing purposes we can recognise
     * some of them: blocks at the top and bottom of the encoding space.
     */
    if (instr_opcode_valid(instr) && instr_get_opcode(instr) == OP_xx) {
        uint enc = opnd_get_immed_int(instr_get_src(instr, 0));
        return ((enc & 0x18000000) == 0 || (~enc & 0xde000000) == 0);
    }
    return false;
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
    } else if (opc == OP_tbnz) {
        instr_set_opcode(instr, OP_tbz);
    } else if (opc == OP_tbz) {
        instr_set_opcode(instr, OP_tbnz);
    } else {
        instr_set_predicate(instr, instr_invert_predicate(pred));
    }
}

bool
instr_cbr_taken(instr_t *instr, priv_mcontext_t *mc, bool pre)
{
    ASSERT_NOT_IMPLEMENTED(false); /* FIXME i#1569 */
    return false;
}

bool
instr_predicate_reads_srcs(dr_pred_type_t pred)
{
    ASSERT_NOT_IMPLEMENTED(false); /* FIXME i#1569 */
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
    return pred != DR_PRED_NONE && pred != DR_PRED_AL && pred != DR_PRED_NV;
}

bool
reg_is_gpr(reg_id_t reg)
{
    return (reg >= DR_REG_START_64 && reg <= DR_REG_STOP_64) ||
        (reg >= DR_REG_START_32 && reg <= DR_REG_STOP_32);
}

bool
reg_is_simd(reg_id_t reg)
{
    return (DR_REG_Q0 <= reg && reg <= DR_REG_B31);
}

bool
reg_is_vector_simd(reg_id_t reg)
{
    return (reg >= DR_REG_Q0 && reg <= DR_REG_Q31) ||
           (reg >= DR_REG_Z0 && reg <= DR_REG_P15);
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
    /* i#1312: check why this assertion is here and not
     * in the other x86 related reg_is_ functions.
     */
    ASSERT_NOT_IMPLEMENTED(false); /* FIXME i#1569 */
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
instr_is_opmask(instr_t *instr)
{
    return false;
}

bool
reg_is_fp(reg_id_t reg)
{
    ASSERT_NOT_IMPLEMENTED(false); /* FIXME i#1569 */
    return false;
}

bool
instr_is_nop(instr_t *instr)
{
    uint opc = instr_get_opcode(instr);
    return (opc == OP_nop);
}

bool
opnd_same_sizes_ok(opnd_size_t s1, opnd_size_t s2, bool is_reg)
{
    return (s1 == s2);
}

instr_t *
instr_create_nbyte_nop(dcontext_t *dcontext, uint num_bytes, bool raw)
{
    ASSERT_NOT_IMPLEMENTED(false); /* FIXME i#1569 */
    return NULL;
}

bool
instr_reads_thread_register(instr_t *instr)
{
    return (instr_get_opcode(instr) == OP_mrs && opnd_is_reg(instr_get_src(instr, 0)) &&
            opnd_get_reg(instr_get_src(instr, 0)) == DR_REG_TPIDR_EL0);
}

bool
instr_writes_thread_register(instr_t *instr)
{
    return (instr_get_opcode(instr) == OP_msr && instr_num_dsts(instr) == 1 &&
            opnd_is_reg(instr_get_dst(instr, 0)) &&
            opnd_get_reg(instr_get_dst(instr, 0)) == DR_REG_TPIDR_EL0);
}

/* Identify one of the reg-reg moves inserted as part of stolen reg mangling:
 *   +0    m4  f9000380   str    %x0 -> (%x28)[8byte]
 * Move stolen reg to x0:
 *   +4    m4  aa1c03e0   orr    %xzr %x28 lsl $0x0000000000000000 -> %x0
 *   +8    m4  f9401b9c   ldr    +0x30(%x28)[8byte] -> %x28
 *   +12   L3  f81e0ffc   str    %x28 %sp $0xffffffffffffffe0 -> -0x20(%sp)[8byte] %sp
 * Move x0 back to stolenr eg:
 *   +16   m4  aa0003fc   orr    %xzr %x0 lsl $0x0000000000000000 -> %x28
 *   +20   m4  f9400380   ldr    (%x28)[8byte] -> %x0
 */
bool
instr_is_stolen_reg_move(instr_t *instr, bool *save, reg_id_t *reg)
{
    CLIENT_ASSERT(instr != NULL, "internal error: NULL argument");
    if (instr_is_app(instr) || instr_get_opcode(instr) != OP_orr)
        return false;
    ASSERT(instr_num_srcs(instr) == 4 && instr_num_dsts(instr) == 1 &&
           opnd_is_reg(instr_get_src(instr, 1)) && opnd_is_reg(instr_get_dst(instr, 0)));
    if (opnd_get_reg(instr_get_src(instr, 1)) == dr_reg_stolen) {
        if (save != NULL)
            *save = true;
        if (reg != NULL) {
            *reg = opnd_get_reg(instr_get_dst(instr, 0));
            ASSERT(*reg != dr_reg_stolen);
        }
        return true;
    }
    if (opnd_get_reg(instr_get_dst(instr, 0)) == dr_reg_stolen) {
        if (save != NULL)
            *save = false;
        if (reg != NULL)
            *reg = opnd_get_reg(instr_get_src(instr, 0));
        return true;
    }
    return false;
}

DR_API
bool
instr_is_exclusive_load(instr_t *instr)
{
    switch (instr_get_opcode(instr)) {
    case OP_ldaxp:
    case OP_ldaxr:
    case OP_ldaxrb:
    case OP_ldaxrh:
    case OP_ldxp:
    case OP_ldxr:
    case OP_ldxrb:
    case OP_ldxrh: return true;
    }
    return false;
}

DR_API
bool
instr_is_exclusive_store(instr_t *instr)
{
    switch (instr_get_opcode(instr)) {
    case OP_stlxp:
    case OP_stlxr:
    case OP_stlxrb:
    case OP_stlxrh:
    case OP_stxp:
    case OP_stxr:
    case OP_stxrb:
    case OP_stxrh: return true;
    }
    return false;
}

DR_API
bool
instr_is_scatter(instr_t *instr)
{
    /* FIXME i#3837: add support. */
    ASSERT_NOT_IMPLEMENTED(false);
    return false;
}

DR_API
bool
instr_is_gather(instr_t *instr)
{
    /* FIXME i#3837: add support. */
    ASSERT_NOT_IMPLEMENTED(false);
    return false;
}

dr_pred_type_t
instr_invert_predicate(dr_pred_type_t pred)
{
    switch (pred) {
    case DR_PRED_EQ: return DR_PRED_NE;
    case DR_PRED_NE: return DR_PRED_EQ;
    case DR_PRED_CS: return DR_PRED_CC;
    case DR_PRED_CC: return DR_PRED_CS;
    case DR_PRED_MI: return DR_PRED_PL;
    case DR_PRED_PL: return DR_PRED_MI;
    case DR_PRED_VS: return DR_PRED_VC;
    case DR_PRED_VC: return DR_PRED_VS;
    case DR_PRED_HI: return DR_PRED_LS;
    case DR_PRED_LS: return DR_PRED_HI;
    case DR_PRED_GE: return DR_PRED_LT;
    case DR_PRED_LT: return DR_PRED_GE;
    case DR_PRED_GT: return DR_PRED_LE;
    case DR_PRED_LE: return DR_PRED_GT;
    default: CLIENT_ASSERT(false, "Incorrect predicate value"); return DR_PRED_NONE;
    }
}

DR_API
bool
instr_is_ldst(instr_t *instr) 
{
    switch (instr_get_opcode(instr)) {
        case /*   78 */     OP_csel: /**< AArch64 csel opcode. */
        case /*   79 */     OP_csinc: /**< AArch64 csinc opcode. */
        case /*   80 */     OP_csinv: /**< AArch64 csinv opcode. */
        case /*   81 */     OP_csneg: /**< AArch64 csneg opcode. */

        case /*   88 */     OP_dup: /**< AArch64 dup opcode. */

        case /*   92 */     OP_ext: /**< AArch64 ext opcode. */
        case /*   93 */     OP_extr: /**< AArch64 extr opcode. */

        case /*  171 */     OP_ins: /**< AArch64 ins opcode. */

        case /*  173 */     OP_ld1: /**< AArch64 ld1 opcode. */
        case /*  174 */     OP_ld1r: /**< AArch64 ld1r opcode. */
        case /*  175 */     OP_ld2: /**< AArch64 ld2 opcode. */
        case /*  176 */     OP_ld2r: /**< AArch64 ld2r opcode. */
        case /*  177 */     OP_ld3: /**< AArch64 ld3 opcode. */
        case /*  178 */     OP_ld3r: /**< AArch64 ld3r opcode. */
        case /*  179 */     OP_ld4: /**< AArch64 ld4 opcode. */
        case /*  180 */     OP_ld4r: /**< AArch64 ld4r opcode. */

        case /*  224 */     OP_ldnp: /**< AArch64 ldnp opcode. */
        case /*  225 */     OP_ldp: /**< AArch64 ldp opcode. */
        case /*  226 */     OP_ldpsw: /**< AArch64 ldpsw opcode. */
        case /*  227 */     OP_ldr: /**< AArch64 ldr opcode. */
        case /*  228 */     OP_ldrb: /**< AArch64 ldrb opcode. */
        case /*  229 */     OP_ldrh: /**< AArch64 ldrh opcode. */
        case /*  230 */     OP_ldrsb: /**< AArch64 ldrsb opcode. */
        case /*  231 */     OP_ldrsh: /**< AArch64 ldrsh opcode. */
        case /*  232 */     OP_ldrsw: /**< AArch64 ldrsw opcode. */

        case /*  269 */     OP_ldtr: /**< AArch64 ldtr opcode. */
        case /*  270 */     OP_ldtrb: /**< AArch64 ldtrb opcode. */
        case /*  271 */     OP_ldtrh: /**< AArch64 ldtrh opcode. */
        case /*  272 */     OP_ldtrsb: /**< AArch64 ldtrsb opcode. */
        case /*  273 */     OP_ldtrsh: /**< AArch64 ldtrsh opcode. */
        case /*  274 */     OP_ldtrsw: /**< AArch64 ldtrsw opcode. */

        case /*  299 */     OP_ldur: /**< AArch64 ldur opcode. */
        case /*  300 */     OP_ldurb: /**< AArch64 ldurb opcode. */
        case /*  301 */     OP_ldurh: /**< AArch64 ldurh opcode. */
        case /*  302 */     OP_ldursb: /**< AArch64 ldursb opcode. */
        case /*  303 */     OP_ldursh: /**< AArch64 ldursh opcode. */
        case /*  304 */     OP_ldursw: /**< AArch64 ldursw opcode. */

        case /*  314 */     OP_movi: /**< AArch64 movi opcode. */
        case /*  315 */     OP_movk: /**< AArch64 movk opcode. */
        case /*  316 */     OP_movn: /**< AArch64 movn opcode. */
        case /*  317 */     OP_movz: /**< AArch64 movz opcode. */
        case /*  318 */     OP_mrs: /**< AArch64 mrs opcode. */
        case /*  319 */     OP_msr: /**< AArch64 msr opcode. */

        case /*  322 */     OP_mvni: /**< AArch64 mvni opcode. */

        case /*  361 */     OP_sbfm: /**< AArch64 sbfm opcode. */

        case /*  397 */     OP_smov: /**< AArch64 smov opcode. */

        case /*  444 */     OP_st1: /**< AArch64 st1 opcode. */
        case /*  445 */     OP_st2: /**< AArch64 st2 opcode. */
        case /*  446 */     OP_st3: /**< AArch64 st3 opcode. */
        case /*  447 */     OP_st4: /**< AArch64 st4 opcode. */

        case /*  448 */     OP_stlr: /**< AArch64 stlr opcode. */
        case /*  449 */     OP_stlrb: /**< AArch64 stlrb opcode. */
        case /*  450 */     OP_stlrh: /**< AArch64 stlrh opcode. */
        case /*  451 */     OP_stlxp: /**< AArch64 stlxp opcode. */
        case /*  452 */     OP_stlxr: /**< AArch64 stlxr opcode. */
        case /*  453 */     OP_stlxrb: /**< AArch64 stlxrb opcode. */
        case /*  454 */     OP_stlxrh: /**< AArch64 stlxrh opcode. */
        case /*  455 */     OP_stnp: /**< AArch64 stnp opcode. */
        case /*  456 */     OP_stp: /**< AArch64 stp opcode. */
        case /*  457 */     OP_str: /**< AArch64 str opcode. */
        case /*  458 */     OP_strb: /**< AArch64 strb opcode. */
        case /*  459 */     OP_strh: /**< AArch64 strh opcode. */
        case /*  460 */     OP_sttr: /**< AArch64 sttr opcode. */
        case /*  461 */     OP_sttrb: /**< AArch64 sttrb opcode. */
        case /*  462 */     OP_sttrh: /**< AArch64 sttrh opcode. */
        case /*  463 */     OP_stur: /**< AArch64 stur opcode. */
        case /*  464 */     OP_sturb: /**< AArch64 sturb opcode. */
        case /*  465 */     OP_sturh: /**< AArch64 sturh opcode. */
        case /*  466 */     OP_stxp: /**< AArch64 stxp opcode. */
        case /*  467 */     OP_stxr: /**< AArch64 stxr opcode. */
        case /*  468 */     OP_stxrb: /**< AArch64 stxrb opcode. */
        case /*  469 */     OP_stxrh: /**< AArch64 stxrh opcode. */

        case /*  476 */     OP_swp: /**< AArch64 swp opcode. */
        case /*  477 */     OP_swpa: /**< AArch64 swpa opcode. */
        case /*  478 */     OP_swpab: /**< AArch64 swpab opcode. */
        case /*  479 */     OP_swpah: /**< AArch64 swpah opcode. */
        case /*  480 */     OP_swpal: /**< AArch64 swpal opcode. */
        case /*  481 */     OP_swpalb: /**< AArch64 swpalb opcode. */
        case /*  482 */     OP_swpalh: /**< AArch64 swpalh opcode. */
        case /*  483 */     OP_swpb: /**< AArch64 swpb opcode. */
        case /*  484 */     OP_swph: /**< AArch64 swph opcode. */
        case /*  485 */     OP_swpl: /**< AArch64 swpl opcode. */
        case /*  486 */     OP_swplb: /**< AArch64 swplb opcode. */
        case /*  487 */     OP_swplh: /**< AArch64 swplh opcode. */

        case /*  494 */     OP_trn1: /**< AArch64 trn1 opcode. */
        case /*  495 */     OP_trn2: /**< AArch64 trn2 opcode. */

        case /*  509 */     OP_ubfm: /**< AArch64 ubfm opcode. */

        case /*  526 */     OP_umov: /**< AArch64 umov opcode. */

        case /*  557 */     OP_uzp1: /**< AArch64 uzp1 opcode. */
        case /*  558 */     OP_uzp2: /**< AArch64 uzp2 opcode. */

        case /*  565 */     OP_zip1: /**< AArch64 zip1 opcode. */
        case /*  566 */     OP_zip2: /**< AArch64 zip2 opcode. */ return true;
        default: return false;
    }
}

DR_API
bool
instr_is_integer(instr_t *instr)
{
    switch (instr_get_opcode(instr)) {
        case/*    6 */     OP_abs: /**< AArch64 abs opcode. */
        case/*    7 */     OP_adc: /**< AArch64 adc opcode. */
        case/*    8 */     OP_adcs: /**< AArch64 adcs opcode. */
        case/*    9 */     OP_add: /**< AArch64 add opcode. */
        case/*   10 */     OP_addhn: /**< AArch64 addhn opcode. */
        case/*   11 */     OP_addhn2: /**< AArch64 addhn2 opcode. */
        case/*   12 */     OP_addp: /**< AArch64 addp opcode. */
        case/*   13 */     OP_adds: /**< AArch64 adds opcode. */
        case/*   14 */     OP_addv: /**< AArch64 addv opcode. */
        case/*   15 */     OP_adr: /**< AArch64 adr opcode. */
        case/*   16 */     OP_adrp: /**< AArch64 adrp opcode. */

        case/*   21 */     OP_and: /**< AArch64 and opcode. */
        case/*   22 */     OP_ands: /**< AArch64 ands opcode. */
        case/*   23 */     OP_asrv: /**< AArch64 asrv opcode. */

        case/*   28 */     OP_bfm: /**< AArch64 bfm opcode. */
        case/*   29 */     OP_bic: /**< AArch64 bic opcode. */
        case/*   30 */     OP_bics: /**< AArch64 bics opcode. */
        case/*   31 */     OP_bif: /**< AArch64 bif opcode. */
        case/*   32 */     OP_bit: /**< AArch64 bit opcode. */

        case/*   37 */     OP_bsl: /**< AArch64 bsl opcode. */

        case/*   56 */     OP_ccmn: /**< AArch64 ccmn opcode. */
        case/*   57 */     OP_ccmp: /**< AArch64 ccmp opcode. */

        case/*   59 */     OP_cls: /**< AArch64 cls opcode. */
        case/*   60 */     OP_clz: /**< AArch64 clz opcode. */

        case/*   61 */     OP_cmeq: /**< AArch64 cmeq opcode. */
        case/*   62 */     OP_cmge: /**< AArch64 cmge opcode. */
        case/*   63 */     OP_cmgt: /**< AArch64 cmgt opcode. */
        case/*   64 */     OP_cmhi: /**< AArch64 cmhi opcode. */
        case/*   65 */     OP_cmhs: /**< AArch64 cmhs opcode. */
        case/*   66 */     OP_cmle: /**< AArch64 cmle opcode. */
        case/*   67 */     OP_cmlt: /**< AArch64 cmlt opcode. */
        case/*   68 */     OP_cmtst: /**< AArch64 cmtst opcode. */
        case/*   69 */     OP_cnt: /**< AArch64 cnt opcode. */

        case/*   89 */     OP_eon: /**< AArch64 eon opcode. */
        case/*   90 */     OP_eor: /**< AArch64 eor opcode. */

        case/*  309 */     OP_lslv: /**< AArch64 lslv opcode. */
        case/*  310 */     OP_lsrv: /**< AArch64 lsrv opcode. */
        case/*  311 */     OP_madd: /**< AArch64 madd opcode. */
        case/*  312 */     OP_mla: /**< AArch64 mla opcode. */
        case/*  313 */     OP_mls: /**< AArch64 mls opcode. */

        case/*  320 */     OP_msub: /**< AArch64 msub opcode. */
        case/*  321 */     OP_mul: /**< AArch64 mul opcode. */

        case/*  323 */     OP_neg: /**< AArch64 neg opcode. */

        case/*  325 */     OP_not: /**< AArch64 not opcode. */
        case/*  326 */     OP_orn: /**< AArch64 orn opcode. */
        case/*  327 */     OP_orr: /**< AArch64 orr opcode. */
        case/*  328 */     OP_pmul: /**< AArch64 pmul opcode. */
        case/*  329 */     OP_pmull: /**< AArch64 pmull opcode. */
        case/*  330 */     OP_pmull2: /**< AArch64 pmull2 opcode. */

        case/*  333 */     OP_raddhn: /**< AArch64 raddhn opcode. */
        case/*  334 */     OP_raddhn2: /**< AArch64 raddhn2 opcode. */
        case/*  335 */     OP_rbit: /**< AArch64 rbit opcode. */

        case/*  337 */     OP_rev: /**< AArch64 rev opcode. */
        case/*  338 */     OP_rev16: /**< AArch64 rev16 opcode. */
        case/*  339 */     OP_rev32: /**< AArch64 rev32 opcode. */
        case/*  340 */     OP_rev64: /**< AArch64 rev64 opcode. */
        case/*  341 */     OP_rorv: /**< AArch64 rorv opcode. */
        case/*  342 */     OP_rshrn: /**< AArch64 rshrn opcode. */
        case/*  343 */     OP_rshrn2: /**< AArch64 rshrn2 opcode. */
        case/*  344 */     OP_rsubhn: /**< AArch64 rsubhn opcode. */
        case/*  345 */     OP_rsubhn2: /**< AArch64 rsubhn2 opcode. */
        case/*  346 */     OP_saba: /**< AArch64 saba opcode. */
        case/*  347 */     OP_sabal: /**< AArch64 sabal opcode. */
        case/*  348 */     OP_sabal2: /**< AArch64 sabal2 opcode. */
        case/*  349 */     OP_sabd: /**< AArch64 sabd opcode. */
        case/*  350 */     OP_sabdl: /**< AArch64 sabdl opcode. */
        case/*  351 */     OP_sabdl2: /**< AArch64 sabdl2 opcode. */
        case/*  352 */     OP_sadalp: /**< AArch64 sadalp opcode. */
        case/*  353 */     OP_saddl: /**< AArch64 saddl opcode. */
        case/*  354 */     OP_saddl2: /**< AArch64 saddl2 opcode. */
        case/*  355 */     OP_saddlp: /**< AArch64 saddlp opcode. */
        case/*  356 */     OP_saddlv: /**< AArch64 saddlv opcode. */
        case/*  357 */     OP_saddw: /**< AArch64 saddw opcode. */
        case/*  358 */     OP_saddw2: /**< AArch64 saddw2 opcode. */
        case/*  359 */     OP_sbc: /**< AArch64 sbc opcode. */
        case/*  360 */     OP_sbcs: /**< AArch64 sbcs opcode. */

        case/*  363 */     OP_sdiv: /**< AArch64 sdiv opcode. */
        case/*  364 */     OP_sdot: /**< AArch64 sdot opcode. */

        case/*  377 */     OP_shadd: /**< AArch64 shadd opcode. */
        case/*  378 */     OP_shl: /**< AArch64 shl opcode. */
        case/*  379 */     OP_shll: /**< AArch64 shll opcode. */
        case/*  380 */     OP_shll2: /**< AArch64 shll2 opcode. */
        case/*  381 */     OP_shrn: /**< AArch64 shrn opcode. */
        case/*  382 */     OP_shrn2: /**< AArch64 shrn2 opcode. */
        case/*  383 */     OP_shsub: /**< AArch64 shsub opcode. */
        case/*  384 */     OP_sli: /**< AArch64 sli opcode. */
        case/*  385 */     OP_smaddl: /**< AArch64 smaddl opcode. */
        case/*  386 */     OP_smax: /**< AArch64 smax opcode. */
        case/*  387 */     OP_smaxp: /**< AArch64 smaxp opcode. */
        case/*  388 */     OP_smaxv: /**< AArch64 smaxv opcode. */

        case/*  390 */     OP_smin: /**< AArch64 smin opcode. */
        case/*  391 */     OP_sminp: /**< AArch64 sminp opcode. */
        case/*  392 */     OP_sminv: /**< AArch64 sminv opcode. */
        case/*  393 */     OP_smlal: /**< AArch64 smlal opcode. */
        case/*  394 */     OP_smlal2: /**< AArch64 smlal2 opcode. */
        case/*  395 */     OP_smlsl: /**< AArch64 smlsl opcode. */
        case/*  396 */     OP_smlsl2: /**< AArch64 smlsl2 opcode. */

        case/*  398 */     OP_smsubl: /**< AArch64 smsubl opcode. */
        case/*  399 */     OP_smulh: /**< AArch64 smulh opcode. */
        case/*  400 */     OP_smull: /**< AArch64 smull opcode. */
        case/*  401 */     OP_smull2: /**< AArch64 smull2 opcode. */
        case/*  402 */     OP_sqabs: /**< AArch64 sqabs opcode. */
        case/*  403 */     OP_sqadd: /**< AArch64 sqadd opcode. */
        case/*  404 */     OP_sqdmlal: /**< AArch64 sqdmlal opcode. */
        case/*  405 */     OP_sqdmlal2: /**< AArch64 sqdmlal2 opcode. */
        case/*  406 */     OP_sqdmlsl: /**< AArch64 sqdmlsl opcode. */
        case/*  407 */     OP_sqdmlsl2: /**< AArch64 sqdmlsl2 opcode. */
        case/*  408 */     OP_sqdmulh: /**< AArch64 sqdmulh opcode. */
        case/*  409 */     OP_sqdmull: /**< AArch64 sqdmull opcode. */
        case/*  410 */     OP_sqdmull2: /**< AArch64 sqdmull2 opcode. */
        case/*  411 */     OP_sqneg: /**< AArch64 sqneg opcode. */
        case/*  412 */     OP_sqrdmlah: /**< AArch64 sqrdmlah opcode. */
        case/*  413 */     OP_sqrdmulh: /**< AArch64 sqrdmulh opcode. */
        case/*  414 */     OP_sqrshl: /**< AArch64 sqrshl opcode. */
        case/*  415 */     OP_sqrshrn: /**< AArch64 sqrshrn opcode. */
        case/*  416 */     OP_sqrshrn2: /**< AArch64 sqrshrn2 opcode. */
        case/*  417 */     OP_sqrshrun: /**< AArch64 sqrshrun opcode. */
        case/*  418 */     OP_sqrshrun2: /**< AArch64 sqrshrun2 opcode. */
        case/*  419 */     OP_sqshl: /**< AArch64 sqshl opcode. */
        case/*  420 */     OP_sqshlu: /**< AArch64 sqshlu opcode. */
        case/*  421 */     OP_sqshrn: /**< AArch64 sqshrn opcode. */
        case/*  422 */     OP_sqshrn2: /**< AArch64 sqshrn2 opcode. */
        case/*  423 */     OP_sqshrun: /**< AArch64 sqshrun opcode. */
        case/*  424 */     OP_sqshrun2: /**< AArch64 sqshrun2 opcode. */
        case/*  425 */     OP_sqsub: /**< AArch64 sqsub opcode. */
        case/*  426 */     OP_sqxtn: /**< AArch64 sqxtn opcode. */
        case/*  427 */     OP_sqxtn2: /**< AArch64 sqxtn2 opcode. */
        case/*  428 */     OP_sqxtun: /**< AArch64 sqxtun opcode. */
        case/*  429 */     OP_sqxtun2: /**< AArch64 sqxtun2 opcode. */
        case/*  430 */     OP_srhadd: /**< AArch64 srhadd opcode. */

        case/*  431 */     OP_sri: /**< AArch64 sri opcode. */
        case/*  432 */     OP_srshl: /**< AArch64 srshl opcode. */
        case/*  433 */     OP_srshr: /**< AArch64 srshr opcode. */
        case/*  434 */     OP_srsra: /**< AArch64 srsra opcode. */
        case/*  435 */     OP_sshl: /**< AArch64 sshl opcode. */
        case/*  436 */     OP_sshll: /**< AArch64 sshll opcode. */
        case/*  437 */     OP_sshll2: /**< AArch64 sshll2 opcode. */
        case/*  438 */     OP_sshr: /**< AArch64 sshr opcode. */
        case/*  439 */     OP_ssra: /**< AArch64 ssra opcode. */
        case/*  440 */     OP_ssubl: /**< AArch64 ssubl opcode. */
        case/*  441 */     OP_ssubl2: /**< AArch64 ssubl2 opcode. */
        case/*  442 */     OP_ssubw: /**< AArch64 ssubw opcode. */
        case/*  443 */     OP_ssubw2: /**< AArch64 ssubw2 opcode. */

        case/*  470 */     OP_sub: /**< AArch64 sub opcode. */
        case/*  471 */     OP_subhn: /**< AArch64 subhn opcode. */
        case/*  472 */     OP_subhn2: /**< AArch64 subhn2 opcode. */
        case/*  473 */     OP_subs: /**< AArch64 subs opcode. */
        case/*  474 */     OP_suqadd: /**< AArch64 suqadd opcode. */

        case/*  496 */     OP_uaba: /**< AArch64 uaba opcode. */
        case/*  497 */     OP_uabal: /**< AArch64 uabal opcode. */
        case/*  498 */     OP_uabal2: /**< AArch64 uabal2 opcode. */
        case/*  499 */     OP_uabd: /**< AArch64 uabd opcode. */
        case/*  500 */     OP_uabdl: /**< AArch64 uabdl opcode. */
        case/*  501 */     OP_uabdl2: /**< AArch64 uabdl2 opcode. */
        case/*  502 */     OP_uadalp: /**< AArch64 uadalp opcode. */
        case/*  503 */     OP_uaddl: /**< AArch64 uaddl opcode. */
        case/*  504 */     OP_uaddl2: /**< AArch64 uaddl2 opcode. */
        case/*  505 */     OP_uaddlp: /**< AArch64 uaddlp opcode. */
        case/*  506 */     OP_uaddlv: /**< AArch64 uaddlv opcode. */
        case/*  507 */     OP_uaddw: /**< AArch64 uaddw opcode. */
        case/*  508 */     OP_uaddw2: /**< AArch64 uaddw2 opcode. */

        case/*  511 */     OP_udiv: /**< AArch64 udiv opcode. */
        case/*  512 */     OP_udot: /**< AArch64 udot opcode. */
        case/*  513 */     OP_uhadd: /**< AArch64 uhadd opcode. */
        case/*  514 */     OP_uhsub: /**< AArch64 uhsub opcode. */
        case/*  515 */     OP_umaddl: /**< AArch64 umaddl opcode. */
        case/*  516 */     OP_umax: /**< AArch64 umax opcode. */
        case/*  517 */     OP_umaxp: /**< AArch64 umaxp opcode. */
        case/*  518 */     OP_umaxv: /**< AArch64 umaxv opcode. */
        case/*  519 */     OP_umin: /**< AArch64 umin opcode. */
        case/*  520 */     OP_uminp: /**< AArch64 uminp opcode. */
        case/*  521 */     OP_uminv: /**< AArch64 uminv opcode. */
        case/*  522 */     OP_umlal: /**< AArch64 umlal opcode. */
        case/*  523 */     OP_umlal2: /**< AArch64 umlal2 opcode. */
        case/*  524 */     OP_umlsl: /**< AArch64 umlsl opcode. */
        case/*  525 */     OP_umlsl2: /**< AArch64 umlsl2 opcode. */

        case/*  527 */     OP_umsubl: /**< AArch64 umsubl opcode. */
        case/*  528 */     OP_umulh: /**< AArch64 umulh opcode. */
        case/*  529 */     OP_umull: /**< AArch64 umull opcode. */
        case/*  530 */     OP_umull2: /**< AArch64 umull2 opcode. */
        case/*  531 */     OP_uqadd: /**< AArch64 uqadd opcode. */
        case/*  532 */     OP_uqrshl: /**< AArch64 uqrshl opcode. */
        case/*  533 */     OP_uqrshrn: /**< AArch64 uqrshrn opcode. */
        case/*  534 */     OP_uqrshrn2: /**< AArch64 uqrshrn2 opcode. */
        case/*  535 */     OP_uqshl: /**< AArch64 uqshl opcode. */
        case/*  536 */     OP_uqshrn: /**< AArch64 uqshrn opcode. */
        case/*  537 */     OP_uqshrn2: /**< AArch64 uqshrn2 opcode. */
        case/*  538 */     OP_uqsub: /**< AArch64 uqsub opcode. */
        case/*  539 */     OP_uqxtn: /**< AArch64 uqxtn opcode. */
        case/*  540 */     OP_uqxtn2: /**< AArch64 uqxtn2 opcode. */
        case/*  541 */     OP_urecpe: /**< AArch64 urecpe opcode. */
        case/*  542 */     OP_urhadd: /**< AArch64 urhadd opcode. */
        case/*  543 */     OP_urshl: /**< AArch64 urshl opcode. */
        case/*  544 */     OP_urshr: /**< AArch64 urshr opcode. */
        case/*  545 */     OP_ursqrte: /**< AArch64 ursqrte opcode. */
        case/*  546 */     OP_ursra: /**< AArch64 ursra opcode. */
        case/*  547 */     OP_ushl: /**< AArch64 ushl opcode. */
        case/*  548 */     OP_ushll: /**< AArch64 ushll opcode. */
        case/*  549 */     OP_ushll2: /**< AArch64 ushll2 opcode. */
        case/*  550 */     OP_ushr: /**< AArch64 ushr opcode. */
        case/*  551 */     OP_usqadd: /**< AArch64 usqadd opcode. */
        case/*  552 */     OP_usra: /**< AArch64 usra opcode. */
        case/*  553 */     OP_usubl: /**< AArch64 usubl opcode. */
        case/*  554 */     OP_usubl2: /**< AArch64 usubl2 opcode. */
        case/*  555 */     OP_usubw: /**< AArch64 usubw opcode. */
        case/*  556 */     OP_usubw2: /**< AArch64 usubw2 opcode. */

        case/*  562 */     OP_xtn: /**< AArch64 xtn opcode. */
        case/*  563 */     OP_xtn2: /**< AArch64 xtn2 opcode. */ return true;
        default: return false;
    }
}

DR_API
bool
instr_is_float(instr_t *instr)
{
    switch (instr_get_opcode(instr)) {
        case /*   94 */     OP_fabd: /**< AArch64 fabd opcode. */
        case /*   95 */     OP_fabs: /**< AArch64 fabs opcode. */
        case /*   96 */     OP_facge: /**< AArch64 facge opcode. */
        case /*   97 */     OP_facgt: /**< AArch64 facgt opcode. */
        case /*   98 */     OP_fadd: /**< AArch64 fadd opcode. */
        case /*   99 */     OP_faddp: /**< AArch64 faddp opcode. */
        case /*  100 */     OP_fccmp: /**< AArch64 fccmp opcode. */
        case /*  101 */     OP_fccmpe: /**< AArch64 fccmpe opcode. */
        case /*  102 */     OP_fcmeq: /**< AArch64 fcmeq opcode. */
        case /*  103 */     OP_fcmge: /**< AArch64 fcmge opcode. */
        case /*  104 */     OP_fcmgt: /**< AArch64 fcmgt opcode. */
        case /*  105 */     OP_fcmle: /**< AArch64 fcmle opcode. */
        case /*  106 */     OP_fcmlt: /**< AArch64 fcmlt opcode. */
        case /*  107 */     OP_fcmp: /**< AArch64 fcmp opcode. */
        case /*  108 */     OP_fcmpe: /**< AArch64 fcmpe opcode. */
        case /*  109 */     OP_fcsel: /**< AArch64 fcsel opcode. */
        case /*  110 */     OP_fcvt: /**< AArch64 fcvt opcode. */
        case /*  111 */     OP_fcvtas: /**< AArch64 fcvtas opcode. */
        case /*  112 */     OP_fcvtau: /**< AArch64 fcvtau opcode. */
        case /*  113 */     OP_fcvtl: /**< AArch64 fcvtl opcode. */
        case /*  114 */     OP_fcvtl2: /**< AArch64 fcvtl2 opcode. */
        case /*  115 */     OP_fcvtms: /**< AArch64 fcvtms opcode. */
        case /*  116 */     OP_fcvtmu: /**< AArch64 fcvtmu opcode. */
        case /*  117 */     OP_fcvtn: /**< AArch64 fcvtn opcode. */
        case /*  118 */     OP_fcvtn2: /**< AArch64 fcvtn2 opcode. */
        case /*  119 */     OP_fcvtns: /**< AArch64 fcvtns opcode. */
        case /*  120 */     OP_fcvtnu: /**< AArch64 fcvtnu opcode. */
        case /*  121 */     OP_fcvtps: /**< AArch64 fcvtps opcode. */
        case /*  122 */     OP_fcvtpu: /**< AArch64 fcvtpu opcode. */
        case /*  123 */     OP_fcvtxn: /**< AArch64 fcvtxn opcode. */
        case /*  124 */     OP_fcvtxn2: /**< AArch64 fcvtxn2 opcode. */
        case /*  125 */     OP_fcvtzs: /**< AArch64 fcvtzs opcode. */
        case /*  126 */     OP_fcvtzu: /**< AArch64 fcvtzu opcode. */
        case /*  127 */     OP_fdiv: /**< AArch64 fdiv opcode. */
        case /*  128 */     OP_fmadd: /**< AArch64 fmadd opcode. */
        case /*  129 */     OP_fmax: /**< AArch64 fmax opcode. */
        case /*  130 */     OP_fmaxnm: /**< AArch64 fmaxnm opcode. */
        case /*  131 */     OP_fmaxnmp: /**< AArch64 fmaxnmp opcode. */
        case /*  132 */     OP_fmaxnmv: /**< AArch64 fmaxnmv opcode. */
        case /*  133 */     OP_fmaxp: /**< AArch64 fmaxp opcode. */
        case /*  134 */     OP_fmaxv: /**< AArch64 fmaxv opcode. */
        case /*  135 */     OP_fmin: /**< AArch64 fmin opcode. */
        case /*  136 */     OP_fminnm: /**< AArch64 fminnm opcode. */
        case /*  137 */     OP_fminnmp: /**< AArch64 fminnmp opcode. */
        case /*  138 */     OP_fminnmv: /**< AArch64 fminnmv opcode. */
        case /*  139 */     OP_fminp: /**< AArch64 fminp opcode. */
        case /*  140 */     OP_fminv: /**< AArch64 fminv opcode. */
        case /*  141 */     OP_fmla: /**< AArch64 fmla opcode. */
        case /*  142 */     OP_fmlal: /**< AArch64 fmlal opcode. */
        case /*  143 */     OP_fmlal2: /**< AArch64 fmlal2 opcode. */
        case /*  144 */     OP_fmls: /**< AArch64 fmls opcode. */
        case /*  145 */     OP_fmlsl: /**< AArch64 fmlsl opcode. */
        case /*  146 */     OP_fmlsl2: /**< AArch64 fmlsl2 opcode. */
        case /*  147 */     OP_fmov: /**< AArch64 fmov opcode. */
        case /*  148 */     OP_fmsub: /**< AArch64 fmsub opcode. */
        case /*  149 */     OP_fmul: /**< AArch64 fmul opcode. */
        case /*  150 */     OP_fmulx: /**< AArch64 fmulx opcode. */
        case /*  151 */     OP_fneg: /**< AArch64 fneg opcode. */
        case /*  152 */     OP_fnmadd: /**< AArch64 fnmadd opcode. */
        case /*  153 */     OP_fnmsub: /**< AArch64 fnmsub opcode. */
        case /*  154 */     OP_fnmul: /**< AArch64 fnmul opcode. */
        case /*  155 */     OP_frecpe: /**< AArch64 frecpe opcode. */
        case /*  156 */     OP_frecps: /**< AArch64 frecps opcode. */
        case /*  157 */     OP_frecpx: /**< AArch64 frecpx opcode. */
        case /*  158 */     OP_frinta: /**< AArch64 frinta opcode. */
        case /*  159 */     OP_frinti: /**< AArch64 frinti opcode. */
        case /*  160 */     OP_frintm: /**< AArch64 frintm opcode. */
        case /*  161 */     OP_frintn: /**< AArch64 frintn opcode. */
        case /*  162 */     OP_frintp: /**< AArch64 frintp opcode. */
        case /*  163 */     OP_frintx: /**< AArch64 frintx opcode. */
        case /*  164 */     OP_frintz: /**< AArch64 frintz opcode. */
        case /*  165 */     OP_frsqrte: /**< AArch64 frsqrte opcode. */
        case /*  166 */     OP_frsqrts: /**< AArch64 frsqrts opcode. */
        case /*  167 */     OP_fsqrt: /**< AArch64 fsqrt opcode. */
        case /*  168 */     OP_fsub: /**< AArch64 fsub opcode. */ return true;
        default: return false;
    }
}

DR_API
bool
instr_is_branch(instr_t *instr)
{
    switch (instr_get_opcode(instr)) {
        case /*   26 */     OP_b: /**< AArch64 b opcode. */
        case /*   27 */     OP_bcond: /**< AArch64 bcond opcode. */

        case /*   33 */     OP_bl: /**< AArch64 bl opcode. */
        case /*   34 */     OP_blr: /**< AArch64 blr opcode. */
        case /*   35 */     OP_br: /**< AArch64 br opcode. */

        case /*   54 */     OP_cbnz: /**< AArch64 cbnz opcode. */
        case /*   55 */     OP_cbz: /**< AArch64 cbz opcode. */

        case /*   91 */     OP_eret: /**< AArch64 eret opcode. */

        case /*  336 */     OP_ret: /**< AArch64 ret opcode. */ return true;
        default: return false;
    }
}

/*
 * Other
 */
// /*   17 */     OP_aesd, /**< AArch64 aesd opcode. */
// /*   18 */     OP_aese, /**< AArch64 aese opcode. */
// /*   19 */     OP_aesimc, /**< AArch64 aesimc opcode. */
// /*   20 */     OP_aesmc, /**< AArch64 aesmc opcode. */

// /*   24 */     OP_autia1716, /**< AArch64 autia1716 opcode. */
// /*   25 */     OP_autib1716, /**< AArch64 autib1716 opcode. */

// /*   36 */     OP_brk, /**< AArch64 brk opcode. */

// /*   38 */     OP_cas, /**< AArch64 cas opcode. */
// /*   39 */     OP_casa, /**< AArch64 casa opcode. */
// /*   40 */     OP_casab, /**< AArch64 casab opcode. */
// /*   41 */     OP_casah, /**< AArch64 casah opcode. */
// /*   42 */     OP_casal, /**< AArch64 casal opcode. */
// /*   43 */     OP_casalb, /**< AArch64 casalb opcode. */
// /*   44 */     OP_casalh, /**< AArch64 casalh opcode. */
// /*   45 */     OP_casb, /**< AArch64 casb opcode. */
// /*   46 */     OP_cash, /**< AArch64 cash opcode. */
// /*   47 */     OP_casl, /**< AArch64 casl opcode. */
// /*   48 */     OP_caslb, /**< AArch64 caslb opcode. */
// /*   49 */     OP_caslh, /**< AArch64 caslh opcode. */
// /*   50 */     OP_casp, /**< AArch64 casp opcode. */
// /*   51 */     OP_caspa, /**< AArch64 caspa opcode. */
// /*   52 */     OP_caspal, /**< AArch64 caspal opcode. */
// /*   53 */     OP_caspl, /**< AArch64 caspl opcode. */

// /*   58 */     OP_clrex, /**< AArch64 clrex opcode. */

// /*   70 */     OP_crc32b, /**< AArch64 crc32b opcode. */
// /*   71 */     OP_crc32cb, /**< AArch64 crc32cb opcode. */
// /*   72 */     OP_crc32ch, /**< AArch64 crc32ch opcode. */
// /*   73 */     OP_crc32cw, /**< AArch64 crc32cw opcode. */
// /*   74 */     OP_crc32cx, /**< AArch64 crc32cx opcode. */
// /*   75 */     OP_crc32h, /**< AArch64 crc32h opcode. */
// /*   76 */     OP_crc32w, /**< AArch64 crc32w opcode. */
// /*   77 */     OP_crc32x, /**< AArch64 crc32x opcode. */

// /*   82 */     OP_dcps1, /**< AArch64 dcps1 opcode. */
// /*   83 */     OP_dcps2, /**< AArch64 dcps2 opcode. */
// /*   84 */     OP_dcps3, /**< AArch64 dcps3 opcode. */
// /*   85 */     OP_dmb, /**< AArch64 dmb opcode. */
// /*   86 */     OP_drps, /**< AArch64 drps opcode. */
// /*   87 */     OP_dsb, /**< AArch64 dsb opcode. */

// /*  169 */     OP_hlt, /**< AArch64 hlt opcode. */
// /*  170 */     OP_hvc, /**< AArch64 hvc opcode. */

// /*  172 */     OP_isb, /**< AArch64 isb opcode. */

// /*  181 */     OP_ldadd, /**< AArch64 ldadd opcode. */
// /*  182 */     OP_ldadda, /**< AArch64 ldadda opcode. */
// /*  183 */     OP_ldaddab, /**< AArch64 ldaddab opcode. */
// /*  184 */     OP_ldaddah, /**< AArch64 ldaddah opcode. */
// /*  185 */     OP_ldaddal, /**< AArch64 ldaddal opcode. */
// /*  186 */     OP_ldaddalb, /**< AArch64 ldaddalb opcode. */
// /*  187 */     OP_ldaddalh, /**< AArch64 ldaddalh opcode. */
// /*  188 */     OP_ldaddb, /**< AArch64 ldaddb opcode. */
// /*  189 */     OP_ldaddh, /**< AArch64 ldaddh opcode. */
// /*  190 */     OP_ldaddl, /**< AArch64 ldaddl opcode. */
// /*  191 */     OP_ldaddlb, /**< AArch64 ldaddlb opcode. */
// /*  192 */     OP_ldaddlh, /**< AArch64 ldaddlh opcode. */
// /*  193 */     OP_ldar, /**< AArch64 ldar opcode. */
// /*  194 */     OP_ldarb, /**< AArch64 ldarb opcode. */
// /*  195 */     OP_ldarh, /**< AArch64 ldarh opcode. */
// /*  196 */     OP_ldaxp, /**< AArch64 ldaxp opcode. */
// /*  197 */     OP_ldaxr, /**< AArch64 ldaxr opcode. */
// /*  198 */     OP_ldaxrb, /**< AArch64 ldaxrb opcode. */
// /*  199 */     OP_ldaxrh, /**< AArch64 ldaxrh opcode. */
// /*  200 */     OP_ldclr, /**< AArch64 ldclr opcode. */
// /*  201 */     OP_ldclra, /**< AArch64 ldclra opcode. */
// /*  202 */     OP_ldclrab, /**< AArch64 ldclrab opcode. */
// /*  203 */     OP_ldclrah, /**< AArch64 ldclrah opcode. */
// /*  204 */     OP_ldclral, /**< AArch64 ldclral opcode. */
// /*  205 */     OP_ldclralb, /**< AArch64 ldclralb opcode. */
// /*  206 */     OP_ldclralh, /**< AArch64 ldclralh opcode. */
// /*  207 */     OP_ldclrb, /**< AArch64 ldclrb opcode. */
// /*  208 */     OP_ldclrh, /**< AArch64 ldclrh opcode. */
// /*  209 */     OP_ldclrl, /**< AArch64 ldclrl opcode. */
// /*  210 */     OP_ldclrlb, /**< AArch64 ldclrlb opcode. */
// /*  211 */     OP_ldclrlh, /**< AArch64 ldclrlh opcode. */
// /*  212 */     OP_ldeor, /**< AArch64 ldeor opcode. */
// /*  213 */     OP_ldeora, /**< AArch64 ldeora opcode. */
// /*  214 */     OP_ldeorab, /**< AArch64 ldeorab opcode. */
// /*  215 */     OP_ldeorah, /**< AArch64 ldeorah opcode. */
// /*  216 */     OP_ldeoral, /**< AArch64 ldeoral opcode. */
// /*  217 */     OP_ldeoralb, /**< AArch64 ldeoralb opcode. */
// /*  218 */     OP_ldeoralh, /**< AArch64 ldeoralh opcode. */
// /*  219 */     OP_ldeorb, /**< AArch64 ldeorb opcode. */
// /*  220 */     OP_ldeorh, /**< AArch64 ldeorh opcode. */
// /*  221 */     OP_ldeorl, /**< AArch64 ldeorl opcode. */
// /*  222 */     OP_ldeorlb, /**< AArch64 ldeorlb opcode. */
// /*  223 */     OP_ldeorlh, /**< AArch64 ldeorlh opcode. */

// /*  233 */     OP_ldset, /**< AArch64 ldset opcode. */
// /*  234 */     OP_ldseta, /**< AArch64 ldseta opcode. */
// /*  235 */     OP_ldsetab, /**< AArch64 ldsetab opcode. */
// /*  236 */     OP_ldsetah, /**< AArch64 ldsetah opcode. */
// /*  237 */     OP_ldsetal, /**< AArch64 ldsetal opcode. */
// /*  238 */     OP_ldsetalb, /**< AArch64 ldsetalb opcode. */
// /*  239 */     OP_ldsetalh, /**< AArch64 ldsetalh opcode. */
// /*  240 */     OP_ldsetb, /**< AArch64 ldsetb opcode. */
// /*  241 */     OP_ldseth, /**< AArch64 ldseth opcode. */
// /*  242 */     OP_ldsetl, /**< AArch64 ldsetl opcode. */
// /*  243 */     OP_ldsetlb, /**< AArch64 ldsetlb opcode. */
// /*  244 */     OP_ldsetlh, /**< AArch64 ldsetlh opcode. */
// /*  245 */     OP_ldsmax, /**< AArch64 ldsmax opcode. */
// /*  246 */     OP_ldsmaxa, /**< AArch64 ldsmaxa opcode. */
// /*  247 */     OP_ldsmaxab, /**< AArch64 ldsmaxab opcode. */
// /*  248 */     OP_ldsmaxah, /**< AArch64 ldsmaxah opcode. */
// /*  249 */     OP_ldsmaxal, /**< AArch64 ldsmaxal opcode. */
// /*  250 */     OP_ldsmaxalb, /**< AArch64 ldsmaxalb opcode. */
// /*  251 */     OP_ldsmaxalh, /**< AArch64 ldsmaxalh opcode. */
// /*  252 */     OP_ldsmaxb, /**< AArch64 ldsmaxb opcode. */
// /*  253 */     OP_ldsmaxh, /**< AArch64 ldsmaxh opcode. */
// /*  254 */     OP_ldsmaxl, /**< AArch64 ldsmaxl opcode. */
// /*  255 */     OP_ldsmaxlb, /**< AArch64 ldsmaxlb opcode. */
// /*  256 */     OP_ldsmaxlh, /**< AArch64 ldsmaxlh opcode. */
// /*  257 */     OP_ldsmin, /**< AArch64 ldsmin opcode. */
// /*  258 */     OP_ldsmina, /**< AArch64 ldsmina opcode. */
// /*  259 */     OP_ldsminab, /**< AArch64 ldsminab opcode. */
// /*  260 */     OP_ldsminah, /**< AArch64 ldsminah opcode. */
// /*  261 */     OP_ldsminal, /**< AArch64 ldsminal opcode. */
// /*  262 */     OP_ldsminalb, /**< AArch64 ldsminalb opcode. */
// /*  263 */     OP_ldsminalh, /**< AArch64 ldsminalh opcode. */
// /*  264 */     OP_ldsminb, /**< AArch64 ldsminb opcode. */
// /*  265 */     OP_ldsminh, /**< AArch64 ldsminh opcode. */
// /*  266 */     OP_ldsminl, /**< AArch64 ldsminl opcode. */
// /*  267 */     OP_ldsminlb, /**< AArch64 ldsminlb opcode. */
// /*  268 */     OP_ldsminlh, /**< AArch64 ldsminlh opcode. */

// /*  275 */     OP_ldumax, /**< AArch64 ldumax opcode. */
// /*  276 */     OP_ldumaxa, /**< AArch64 ldumaxa opcode. */
// /*  277 */     OP_ldumaxab, /**< AArch64 ldumaxab opcode. */
// /*  278 */     OP_ldumaxah, /**< AArch64 ldumaxah opcode. */
// /*  279 */     OP_ldumaxal, /**< AArch64 ldumaxal opcode. */
// /*  280 */     OP_ldumaxalb, /**< AArch64 ldumaxalb opcode. */
// /*  281 */     OP_ldumaxalh, /**< AArch64 ldumaxalh opcode. */
// /*  282 */     OP_ldumaxb, /**< AArch64 ldumaxb opcode. */
// /*  283 */     OP_ldumaxh, /**< AArch64 ldumaxh opcode. */
// /*  284 */     OP_ldumaxl, /**< AArch64 ldumaxl opcode. */
// /*  285 */     OP_ldumaxlb, /**< AArch64 ldumaxlb opcode. */
// /*  286 */     OP_ldumaxlh, /**< AArch64 ldumaxlh opcode. */
// /*  287 */     OP_ldumin, /**< AArch64 ldumin opcode. */
// /*  288 */     OP_ldumina, /**< AArch64 ldumina opcode. */
// /*  289 */     OP_lduminab, /**< AArch64 lduminab opcode. */
// /*  290 */     OP_lduminah, /**< AArch64 lduminah opcode. */
// /*  291 */     OP_lduminal, /**< AArch64 lduminal opcode. */
// /*  292 */     OP_lduminalb, /**< AArch64 lduminalb opcode. */
// /*  293 */     OP_lduminalh, /**< AArch64 lduminalh opcode. */
// /*  294 */     OP_lduminb, /**< AArch64 lduminb opcode. */
// /*  295 */     OP_lduminh, /**< AArch64 lduminh opcode. */
// /*  296 */     OP_lduminl, /**< AArch64 lduminl opcode. */
// /*  297 */     OP_lduminlb, /**< AArch64 lduminlb opcode. */
// /*  298 */     OP_lduminlh, /**< AArch64 lduminlh opcode. */

// /*  305 */     OP_ldxp, /**< AArch64 ldxp opcode. */
// /*  306 */     OP_ldxr, /**< AArch64 ldxr opcode. */
// /*  307 */     OP_ldxrb, /**< AArch64 ldxrb opcode. */
// /*  308 */     OP_ldxrh, /**< AArch64 ldxrh opcode. */

// /*  324 */     OP_nop, /**< AArch64 nop opcode. */

// /*  331 */     OP_prfm, /**< AArch64 prfm opcode. */
// /*  332 */     OP_prfum, /**< AArch64 prfum opcode. */

// // TODO: MOV/FLOATING POINT/INTEGER??
// /*  362 */     OP_scvtf, /**< AArch64 scvtf opcode. */

// /*  365 */     OP_sev, /**< AArch64 sev opcode. */
// /*  366 */     OP_sevl, /**< AArch64 sevl opcode. */

// /*  367 */     OP_sha1c, /**< AArch64 sha1c opcode. */
// /*  368 */     OP_sha1h, /**< AArch64 sha1h opcode. */
// /*  369 */     OP_sha1m, /**< AArch64 sha1m opcode. */
// /*  370 */     OP_sha1p, /**< AArch64 sha1p opcode. */
// /*  371 */     OP_sha1su0, /**< AArch64 sha1su0 opcode. */
// /*  372 */     OP_sha1su1, /**< AArch64 sha1su1 opcode. */
// /*  373 */     OP_sha256h, /**< AArch64 sha256h opcode. */
// /*  374 */     OP_sha256h2, /**< AArch64 sha256h2 opcode. */
// /*  375 */     OP_sha256su0, /**< AArch64 sha256su0 opcode. */
// /*  376 */     OP_sha256su1, /**< AArch64 sha256su1 opcode. */

// /*  389 */     OP_smc, /**< AArch64 smc opcode. */

// /*  475 */     OP_svc, /**< AArch64 svc opcode. */

// /*  488 */     OP_sys, /**< AArch64 sys opcode. */
// /*  489 */     OP_sysl, /**< AArch64 sysl opcode. */
// /*  490 */     OP_tbl, /**< AArch64 tbl opcode. */
// /*  491 */     OP_tbnz, /**< AArch64 tbnz opcode. */
// /*  492 */     OP_tbx, /**< AArch64 tbx opcode. */
// /*  493 */     OP_tbz, /**< AArch64 tbz opcode. */

// /*  510 */     OP_ucvtf, /**< AArch64 ucvtf opcode. */

// /*  559 */     OP_wfe, /**< AArch64 wfe opcode. */
// /*  560 */     OP_wfi, /**< AArch64 wfi opcode. */
// /*  561 */     OP_xpaclri, /**< AArch64 xpaclri opcode. */

// /*  564 */     OP_yield, /**< AArch64 yield opcode. */

// /*  567 */     OP_udf, /**< AArch64 udf opcode. */

DR_API
bool
instr_is_simd(instr_t *instr)
{
    opnd_t opnd;
    for (int i = 0; i < instr_num_dsts(instr); i++) {
        opnd = instr_get_dst(instr, i);
        if (opnd_is_reg(opnd) && reg_is_vector_simd(opnd_get_reg(opnd))) {
            return true;
        }
    }
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        opnd = instr_get_src(instr, i);
        if (opnd_is_reg(opnd) && reg_is_vector_simd(opnd_get_reg(opnd))) {
            return true;
        }
    }
    return false;
}

DR_API
bool
instr_is_scalar(instr_t *instr)
{
    return !instr_is_simd(instr);
}