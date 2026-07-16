/* 指令执行体 — 由 axvm_interp.c 以 switch 或 computed goto 两种调度方式包含 */
/* 禁止直接 include；须先定义 AXVM_OP_BEGIN / AXVM_OP_NEXT */

        AXVM_OP_BEGIN(AXOP_NOP, op_nop)
            AXVM_OP_NEXT();

        AXVM_OP_BEGIN(AXOP_HALT, op_halt)
            ctx->halted = 1;
            return AXVM_ERR_HALT;

        AXVM_OP_BEGIN(AXOP_LDRI64, op_ldri64) {
            uint8_t rd = 0;
            uint64_t imm = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd)) return AXVM_ERR_BAD_INSN;
            st = read_u64(ctx, &cursor, &imm);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, rd, imm);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_LDRI64_VADDR, op_ldri64_vaddr) {
            uint8_t rd = 0;
            uint64_t vaddr = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd)) return AXVM_ERR_BAD_INSN;
            st = read_u64(ctx, &cursor, &vaddr);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, rd, ctx->module_load_base + vaddr);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_ADD_IMM, op_add_imm) {
            uint8_t rd = 0, rs = 0;
            uint32_t imm = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK || rd > AXVM_REG_XZR || !axvm_reg_src_ok(rs)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &imm);
            if (st != AXVM_OK) return st;
            {
                uint64_t v = axvm_reg_base(ctx, rs) + (int32_t)imm;
                if (rd == AXVM_REG_XZR) {
                    ctx->sp = v;
                } else {
                    st = axvm_reg_write(ctx, rd, v);
                    if (st != AXVM_OK) return st;
                }
            }
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_SUB_IMM, op_sub_imm) {
            uint8_t rd = 0, rs = 0;
            uint32_t imm = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK || rd > AXVM_REG_XZR || !axvm_reg_src_ok(rs)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &imm);
            if (st != AXVM_OK) return st;
            {
                uint64_t v = axvm_reg_base(ctx, rs) - (int32_t)imm;
                if (rd == AXVM_REG_XZR) {
                    ctx->sp = v;
                } else {
                    st = axvm_reg_write(ctx, rd, v);
                    if (st != AXVM_OK) return st;
                }
            }
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_ADD_REG, op_add_reg) {
            uint8_t rd = 0, rn = 0, rm = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_reg_src_ok(rn) || !axvm_reg_src_ok(rm)) return AXVM_ERR_BAD_INSN;
            st = axvm_reg_write(ctx, rd, axvm_reg_read(ctx, rn) + axvm_reg_read(ctx, rm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_SUB_REG, op_sub_reg) {
            uint8_t rd = 0, rn = 0, rm = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_reg_src_ok(rn) || !axvm_reg_src_ok(rm)) return AXVM_ERR_BAD_INSN;
            st = axvm_reg_write(ctx, rd, axvm_reg_read(ctx, rn) - axvm_reg_read(ctx, rm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_AND_REG, op_and_reg) {
            uint8_t rd = 0, rn = 0, rm = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_reg_src_ok(rn) || !axvm_reg_src_ok(rm)) return AXVM_ERR_BAD_INSN;
            st = axvm_reg_write(ctx, rd, axvm_reg_read(ctx, rn) & axvm_reg_read(ctx, rm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_ORR_REG, op_orr_reg) {
            uint8_t rd = 0, rn = 0, rm = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_reg_src_ok(rn) || !axvm_reg_src_ok(rm)) return AXVM_ERR_BAD_INSN;
            st = axvm_reg_write(ctx, rd, axvm_reg_read(ctx, rn) | axvm_reg_read(ctx, rm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_MUL_REG, op_mul_reg) {
            uint8_t rd = 0, rn = 0, rm = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_reg_src_ok(rn) || !axvm_reg_src_ok(rm)) return AXVM_ERR_BAD_INSN;
            st = axvm_reg_write(ctx, rd, axvm_reg_read(ctx, rn) * axvm_reg_read(ctx, rm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_MOVK, op_movk) {
            uint8_t rd = 0, hw = 0;
            uint16_t imm = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &hw);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, (uint8_t *)&imm);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, ((uint8_t *)&imm) + 1);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || hw > 3) return AXVM_ERR_BAD_INSN;
            {
                uint64_t cur = axvm_reg_read(ctx, rd);
                uint64_t shift = (uint64_t)hw * 16u;
                uint64_t mask = ~(0xFFFFULL << shift);
                cur = (cur & mask) | (((uint64_t)imm) << shift);
                st = axvm_reg_write(ctx, rd, cur);
                if (st != AXVM_OK) return st;
            }
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_CSEL_REG, op_csel_reg) {
            uint8_t rd = 0, rn = 0, rm = 0, cond = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &cond);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_reg_src_ok(rn) || !axvm_reg_src_ok(rm)) return AXVM_ERR_BAD_INSN;
            uint64_t pick = cond_pass(ctx->nzcv, cond) ? axvm_reg_read(ctx, rn) : axvm_reg_read(ctx, rm);
            st = axvm_reg_write(ctx, rd, pick);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_CMP_REG, op_cmp_reg) {
            uint8_t rn = 0, rm = 0;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK) return st;
            st = exec_cmp(ctx, rn, rm);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_CMP_REG32, op_cmp_reg32) {
            uint8_t rn = 0, rm = 0;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK) return st;
            st = exec_cmp32(ctx, rn, rm);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_CMP_IMM, op_cmp_imm) {
            uint8_t rn = 0, is32 = 0;
            uint32_t imm = 0;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &is32);
            if (st != AXVM_OK || !axvm_reg_src_ok(rn) || is32 > 1) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &imm);
            if (st != AXVM_OK) return st;
            if (is32) {
                uint32_t vn = (uint32_t)axvm_reg_read(ctx, rn);
                uint32_t vm = (uint32_t)imm;
                uint32_t res = vn - vm;
                uint32_t n = (res >> 31) & 1u;
                uint32_t z = (res == 0) ? 1u : 0u;
                uint32_t c = (vn >= vm) ? 1u : 0u;
                uint32_t v = ((((vn ^ vm) & (vn ^ res)) >> 31) & 1u);
                ctx->nzcv = (ctx->nzcv & ~0xFu) | (v << 3) | (n << 2) | (z << 1) | c;
            } else {
                uint64_t vn = axvm_reg_read(ctx, rn);
                uint64_t vm = (uint64_t)(int64_t)(int32_t)imm;
                uint64_t res = vn - vm;
                uint32_t n = (uint32_t)((res >> 63) & 1u);
                uint32_t z = (res == 0) ? 1u : 0u;
                uint32_t c = (vn >= vm) ? 1u : 0u;
                uint32_t v = (uint32_t)((((vn ^ vm) & (vn ^ res)) >> 63) & 1u);
                ctx->nzcv = (ctx->nzcv & ~0xFu) | (v << 3) | (n << 2) | (z << 1) | c;
            }
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_MOV_REG, op_mov_reg) {
            uint8_t rd = 0, rm = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_reg_src_ok(rm)) return AXVM_ERR_BAD_INSN;
            st = axvm_reg_write(ctx, rd, axvm_reg_read(ctx, rm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_LDR_U64, op_ldr_u64) {
            uint8_t rt = 0, rn = 0;
            uint32_t off = 0;
            uint64_t val = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || rt > AXVM_REG_XZR || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_load64(ctx, axvm_reg_base(ctx, rn) + (int32_t)off, &val);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, rt, val);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_STR_U64, op_str_u64) {
            uint8_t rt = 0, rn = 0;
            uint32_t off = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_reg_src_ok(rt) || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            {
                uint64_t addr = axvm_reg_base(ctx, rn) + (int32_t)off;
                if (addr & 7) {
                    AXVM_LOGE("op_str_u64 align rt=%u rn=%u off=%d addr=0x%llx sp=0x%llx pc=%llu",
                              (unsigned)rt, (unsigned)rn, (int32_t)off,
                              (unsigned long long)addr,
                              (unsigned long long)ctx->sp,
                              (unsigned long long)ctx->pc);
                }
                st = mem_store64(ctx, addr, axvm_reg_read(ctx, rt));
            }
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_BR, op_br) {
            int32_t rel = 0;
            st = read_u32(ctx, &cursor, (uint32_t *)&rel);
            if (st != AXVM_OK) return st;
            st = branch_to(ctx, hdr, rel);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_B_COND, op_b_cond) {
            uint8_t cond = 0;
            int32_t rel = 0;
            st = read_u8(ctx, &cursor, &cond);
            if (st != AXVM_OK) return st;
            st = read_u32(ctx, &cursor, (uint32_t *)&rel);
            if (st != AXVM_OK) return st;
            if (cond_pass(ctx->nzcv, cond)) {
                st = branch_to(ctx, hdr, rel);
                if (st != AXVM_OK) return st;
            }
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_EOR_REG, op_eor_reg) {
            uint8_t rd = 0, rn = 0, rm = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_reg_src_ok(rn) || !axvm_reg_src_ok(rm)) return AXVM_ERR_BAD_INSN;
            st = axvm_reg_write(ctx, rd, axvm_reg_read(ctx, rn) ^ axvm_reg_read(ctx, rm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_LSL_IMM, op_lsl_imm) {
            uint8_t rd = 0, rs = 0, sh = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &sh);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_reg_src_ok(rs) || sh > 63) return AXVM_ERR_BAD_INSN;
            st = axvm_reg_write(ctx, rd, axvm_reg_read(ctx, rs) << sh);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_LSR_IMM, op_lsr_imm) {
            uint8_t rd = 0, rs = 0, sh = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &sh);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_reg_src_ok(rs) || sh > 63) return AXVM_ERR_BAD_INSN;
            st = axvm_reg_write(ctx, rd, axvm_reg_read(ctx, rs) >> sh);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_MVN_REG, op_mvn_reg) {
            uint8_t rd = 0, rm = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_reg_src_ok(rm)) return AXVM_ERR_BAD_INSN;
            st = axvm_reg_write(ctx, rd, ~axvm_reg_read(ctx, rm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_ASR_IMM, op_asr_imm) {
            uint8_t rd = 0, rs = 0, sh = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &sh);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_reg_src_ok(rs) || sh > 63) return AXVM_ERR_BAD_INSN;
            int64_t v = (int64_t)axvm_reg_read(ctx, rs);
            st = axvm_reg_write(ctx, rd, (uint64_t)(v >> sh));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_ZEXT32, op_zext32) {
            uint8_t rd = 0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK || rd > AXVM_REG_XZR) return AXVM_ERR_BAD_INSN;
            st = axvm_reg_write(ctx, rd, (uint32_t)axvm_reg_read(ctx, rd));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_LDR_U32, op_ldr_u32) {
            uint8_t rt = 0, rn = 0;
            uint32_t off = 0, val = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || rt > AXVM_REG_XZR || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_load32(ctx, axvm_reg_base(ctx, rn) + (int32_t)off, &val);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, rt, val);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_STR_U32, op_str_u32) {
            uint8_t rt = 0, rn = 0;
            uint32_t off = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_reg_src_ok(rt) || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_store32(ctx, axvm_reg_base(ctx, rn) + (int32_t)off, (uint32_t)axvm_reg_read(ctx, rt));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_LDUR_U64, op_ldur_u64) {
            uint8_t rt = 0, rn = 0;
            uint32_t off = 0;
            uint64_t val = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || rt > AXVM_REG_XZR || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_load64(ctx, axvm_reg_base(ctx, rn) + (int32_t)off, &val);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, rt, val);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_STUR_U64, op_stur_u64) {
            uint8_t rt = 0, rn = 0;
            uint32_t off = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_reg_src_ok(rt) || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_store64(ctx, axvm_reg_base(ctx, rn) + (int32_t)off, axvm_reg_read(ctx, rt));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_LDUR_U32, op_ldur_u32) {
            uint8_t rt = 0, rn = 0;
            uint32_t off = 0, val = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || rt > AXVM_REG_XZR || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_load32(ctx, axvm_reg_base(ctx, rn) + (int32_t)off, &val);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, rt, val);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_STUR_U32, op_stur_u32) {
            uint8_t rt = 0, rn = 0;
            uint32_t off = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_reg_src_ok(rt) || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_store32(ctx, axvm_reg_base(ctx, rn) + (int32_t)off, (uint32_t)axvm_reg_read(ctx, rt));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_LDR_U8, op_ldr_u8) {
            uint8_t rt = 0, rn = 0, val = 0;
            uint32_t off = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || rt > AXVM_REG_XZR || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_load8(ctx, axvm_reg_base(ctx, rn) + (int32_t)off, &val);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, rt, val);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_STR_U8, op_str_u8) {
            uint8_t rt = 0, rn = 0;
            uint32_t off = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_reg_src_ok(rt) || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_store8(ctx, axvm_reg_base(ctx, rn) + (int32_t)off, (uint8_t)axvm_reg_read(ctx, rt));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_LDR_U16, op_ldr_u16) {
            uint8_t rt = 0, rn = 0;
            uint16_t val = 0;
            uint32_t off = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || rt > AXVM_REG_XZR || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_load16(ctx, axvm_reg_base(ctx, rn) + (int32_t)off, &val);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, rt, val);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_STR_U16, op_str_u16) {
            uint8_t rt = 0, rn = 0;
            uint32_t off = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_reg_src_ok(rt) || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_store16(ctx, axvm_reg_base(ctx, rn) + (int32_t)off, (uint16_t)axvm_reg_read(ctx, rt));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_LDR_REGOFF, op_ldr_regoff) {
            uint8_t rt = 0, rn = 0, rm = 0, width = 0, extend = 0, scale = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &width);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &extend);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &scale);
            if (st != AXVM_OK || rt > AXVM_REG_XZR || !axvm_reg_src_ok(rn) ||
                !axvm_reg_src_ok(rm) || scale > 3) return AXVM_ERR_BAD_INSN;
            uint64_t idx = axvm_reg_read(ctx, rm);
            switch (extend) {
            case 2: idx = (uint32_t)idx; break;
            case 3: break;
            case 6: idx = (uint64_t)(int64_t)(int32_t)idx; break;
            case 7: break;
            default: return AXVM_ERR_BAD_INSN;
            }
            uint64_t addr = axvm_reg_base(ctx, rn) + (idx << scale);
            switch (width) {
            case 8: {
                uint64_t val = 0;
                st = mem_load64(ctx, addr, &val);
                if (st != AXVM_OK) return st;
                st = axvm_reg_write(ctx, rt, val);
                break;
            }
            case 4: {
                uint32_t val = 0;
                st = mem_load32(ctx, addr, &val);
                if (st != AXVM_OK) return st;
                st = axvm_reg_write(ctx, rt, val);
                break;
            }
            case 2: {
                uint16_t val = 0;
                st = mem_load16(ctx, addr, &val);
                if (st != AXVM_OK) return st;
                st = axvm_reg_write(ctx, rt, val);
                break;
            }
            case 1: {
                uint8_t val = 0;
                st = mem_load8(ctx, addr, &val);
                if (st != AXVM_OK) return st;
                st = axvm_reg_write(ctx, rt, val);
                break;
            }
            default:
                return AXVM_ERR_BAD_INSN;
            }
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_STR_REGOFF, op_str_regoff) {
            uint8_t rt = 0, rn = 0, rm = 0, width = 0, extend = 0, scale = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rm);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &width);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &extend);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &scale);
            if (st != AXVM_OK || !axvm_reg_src_ok(rt) || !axvm_reg_src_ok(rn) ||
                !axvm_reg_src_ok(rm) || scale > 3) return AXVM_ERR_BAD_INSN;
            uint64_t idx = axvm_reg_read(ctx, rm);
            switch (extend) {
            case 2: idx = (uint32_t)idx; break;
            case 3: break;
            case 6: idx = (uint64_t)(int64_t)(int32_t)idx; break;
            case 7: break;
            default: return AXVM_ERR_BAD_INSN;
            }
            uint64_t addr = axvm_reg_base(ctx, rn) + (idx << scale);
            uint64_t val = axvm_reg_read(ctx, rt);
            switch (width) {
            case 8:
                st = mem_store64(ctx, addr, val);
                break;
            case 4:
                st = mem_store32(ctx, addr, (uint32_t)val);
                break;
            case 2:
                st = mem_store16(ctx, addr, (uint16_t)val);
                break;
            case 1:
                st = mem_store8(ctx, addr, (uint8_t)val);
                break;
            default:
                return AXVM_ERR_BAD_INSN;
            }
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_BL_NATIVE, op_bl_native) {
            uint16_t slot = 0;
            uint64_t nret = 0;
            st = read_u16(ctx, &cursor, &slot);
            if (st != AXVM_OK) return st;
            st = axvm_bridge_call_native(ctx, slot, &nret);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, 0, nret);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_BR_REG, op_br_reg) {
            uint8_t rn = 0;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            uint64_t addr = axvm_reg_read(ctx, rn);
            if (ctx->branch_map_count > 0 && ctx->branch_func_vaddr != 0) {
                uint64_t func_lo = ctx->branch_func_vaddr;
                uint64_t func_hi = ctx->branch_func_vaddr + (uint64_t)ctx->branch_func_size;
                uint64_t abs_lo = ctx->module_load_base + ctx->branch_func_vaddr;
                uint64_t abs_hi = abs_lo + (uint64_t)ctx->branch_func_size;
                uint32_t arm_off = 0;
                int in_branch_func = 0;
                if (addr >= abs_lo && addr < abs_hi) {
                    arm_off = (uint32_t)(addr - abs_lo);
                    in_branch_func = 1;
                } else if (addr >= func_lo && addr < func_hi) {
                    arm_off = (uint32_t)(addr - func_lo);
                    in_branch_func = 1;
                }
                if (in_branch_func) {
                uint32_t vm_off = 0;
                if (axvm_branch_map_lookup(ctx, arm_off, &vm_off)) {
                    ctx->pc = vm_off;
                    AXVM_OP_NEXT();
                }
                }
            }
            uint64_t nret = 0;
            st = axvm_bridge_call_native_addr(ctx, (void *)(uintptr_t)addr, &nret);
            if (st != AXVM_OK) return st;
            ctx->ret_pending = 1;
            ctx->ret_val = nret;
            return AXVM_OK;
        }
        AXVM_OP_BEGIN(AXOP_BLR_REG, op_blr_reg) {
            uint8_t rn = 0;
            uint64_t nret = 0;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            uint64_t call_addr = axvm_reg_read(ctx, rn);
            st = axvm_bridge_call_native_addr(ctx,
                                              (void *)(uintptr_t)call_addr,
                                              &nret);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, 0, nret);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_CALL_NAT, op_call_nat) {
            uint64_t addr = 0;
            uint64_t nret = 0;
            st = read_u64(ctx, &cursor, &addr);
            if (st != AXVM_OK) return st;
            st = axvm_bridge_call_native_addr(ctx, (void *)(uintptr_t)addr, &nret);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, 0, nret);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_CALL_NAT_VADDR, op_call_nat_vaddr) {
            uint64_t vaddr = 0;
            uint64_t nret = 0;
            st = read_u64(ctx, &cursor, &vaddr);
            if (st != AXVM_OK) return st;
            st = axvm_bridge_call_native_addr(ctx,
                                              (void *)(uintptr_t)(ctx->module_load_base + vaddr),
                                              &nret);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, 0, nret);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_PUSH_PAIR, op_push_pair) {
            uint8_t rt = 0, rt2 = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rt2);
            if (st != AXVM_OK || !axvm_reg_src_ok(rt) || !axvm_reg_src_ok(rt2)) return AXVM_ERR_BAD_INSN;
            ctx->sp -= 16;
            if (ctx->sp & 0xF) return AXVM_ERR_ALIGN;
            st = mem_store64(ctx, ctx->sp, axvm_reg_read(ctx, rt2));
            if (st != AXVM_OK) return st;
            st = mem_store64(ctx, ctx->sp + 8, axvm_reg_read(ctx, rt));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_POP_PAIR, op_pop_pair) {
            uint8_t rt = 0, rt2 = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rt2);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rt) || !axvm_reg_dst_ok(rt2)) return AXVM_ERR_BAD_INSN;
            if (ctx->sp & 0xF) return AXVM_ERR_ALIGN;
            uint64_t v1 = 0, v2 = 0;
            st = mem_load64(ctx, ctx->sp, &v2);
            if (st != AXVM_OK) return st;
            st = mem_load64(ctx, ctx->sp + 8, &v1);
            if (st != AXVM_OK) return st;
            ctx->sp += 16;
            st = axvm_reg_write(ctx, rt, v1);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, rt2, v2);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }

#if defined(AXVM_NESTED_VM) && AXVM_NESTED_VM
        AXVM_OP_BEGIN(AXOP_VM_ENTER, op_vm_enter) {
            uint32_t child_off = 0;
            uint8_t argc = 0;
            st = read_u32(ctx, &cursor, &child_off);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &argc);
            if (st != AXVM_OK) {
                return st;
            }
            uint64_t rv = axvm_nested_vm_enter(ctx, child_off, argc);
            st = axvm_reg_write(ctx, 0, rv);
            if (st != AXVM_OK) {
                return st;
            }
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_VM_LEAVE, op_vm_leave) {
            ctx->ret_pending = 1;
            ctx->ret_val = axvm_reg_read(ctx, 0);
            return AXVM_OK;
        }
#endif

        AXVM_OP_BEGIN(AXOP_JUNK, op_junk) {
            uint8_t pad = 0;
            st = read_u8(ctx, &cursor, &pad);
            if (st != AXVM_OK) {
                return st;
            }
            for (uint8_t j = 0; j < pad; ++j) {
                uint8_t dummy = 0;
                st = read_u8(ctx, &cursor, &dummy);
                if (st != AXVM_OK) {
                    return st;
                }
            }
            AXVM_OP_NEXT();
        }

#include "axvm_interp_fp.inc"

#include "axvm_interp_atomic.inc"

        AXVM_OP_BEGIN(AXOP_RET, op_ret)
            ctx->ret_pending = 1;
            ctx->ret_val = axvm_reg_read(ctx, 0);
            axvm_guard_observe_ret(axvm_guard_global(), ctx, ctx->ret_val);
            return AXVM_OK;
