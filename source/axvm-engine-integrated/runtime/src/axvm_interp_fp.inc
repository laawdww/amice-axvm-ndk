/* 模块 F 浮点指令 — 由 axvm_interp_insns.inc 在 AXVM_FLOAT_VM 下包含 */

#if defined(AXVM_FLOAT_VM) && AXVM_FLOAT_VM

        AXVM_OP_BEGIN(AXOP_FLDR_D, op_fldr_d) {
            uint8_t vt = 0, rn = 0;
            uint32_t off = 0;
            uint64_t bits = 0;
            st = read_u8(ctx, &cursor, &vt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_freg_dst_ok(vt) || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_load64(ctx, axvm_reg_base(ctx, rn) + (uint64_t)off, &bits);
            if (st != AXVM_OK) return st;
            st = axvm_freg_write_bits(ctx, vt, bits);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FSTR_D, op_fstr_d) {
            uint8_t vt = 0, rn = 0;
            uint32_t off = 0;
            uint64_t bits = 0;
            st = read_u8(ctx, &cursor, &vt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_freg_src_ok(vt) || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            bits = axvm_freg_read_bits(ctx, vt);
            st = mem_store64(ctx, axvm_reg_base(ctx, rn) + (uint64_t)off, bits);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FLDR_S, op_fldr_s) {
            uint8_t vt = 0, rn = 0;
            uint32_t off = 0;
            uint32_t w = 0;
            float sf = 0.0f;
            st = read_u8(ctx, &cursor, &vt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_freg_dst_ok(vt) || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            st = mem_load32(ctx, axvm_reg_base(ctx, rn) + (uint64_t)off, &w);
            if (st != AXVM_OK) return st;
            memcpy(&sf, &w, sizeof(sf));
            st = axvm_freg_write(ctx, vt, (double)sf);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FSTR_S, op_fstr_s) {
            uint8_t vt = 0, rn = 0;
            uint32_t off = 0;
            float sf = 0.0f;
            uint32_t w = 0;
            st = read_u8(ctx, &cursor, &vt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_freg_src_ok(vt) || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            sf = (float)axvm_freg_read(ctx, vt);
            memcpy(&w, &sf, sizeof(w));
            st = mem_store32(ctx, axvm_reg_base(ctx, rn) + (uint64_t)off, w);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FLDR_Q, op_fldr_q) {
            uint8_t vt = 0, rn = 0;
            uint32_t off = 0;
            uint64_t lo = 0, hi = 0;
            st = read_u8(ctx, &cursor, &vt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_freg_dst_ok(vt) || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            uint64_t addr = axvm_reg_base(ctx, rn) + (uint64_t)(int32_t)off;
            st = mem_load64(ctx, addr, &lo);
            if (st != AXVM_OK) return st;
            st = mem_load64(ctx, addr + 8, &hi);
            if (st != AXVM_OK) return st;
            st = axvm_freg_write_bits(ctx, vt, lo);
            if (st != AXVM_OK) return st;
            st = axvm_freg_write_q_hi_bits(ctx, vt, hi);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FSTR_Q, op_fstr_q) {
            uint8_t vt = 0, rn = 0;
            uint32_t off = 0;
            st = read_u8(ctx, &cursor, &vt);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK || !axvm_freg_src_ok(vt) || !axvm_reg_src_ok(rn)) return AXVM_ERR_BAD_INSN;
            st = read_u32(ctx, &cursor, &off);
            if (st != AXVM_OK) return st;
            uint64_t addr = axvm_reg_base(ctx, rn) + (uint64_t)(int32_t)off;
            st = mem_store64(ctx, addr, axvm_freg_read_bits(ctx, vt));
            if (st != AXVM_OK) return st;
            st = mem_store64(ctx, addr + 8, axvm_freg_read_q_hi_bits(ctx, vt));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FADD_D, op_fadd_d) {
            uint8_t vd = 0, vn = 0, vm = 0;
            st = read_u8(ctx, &cursor, &vd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vm);
            if (st != AXVM_OK || !axvm_freg_dst_ok(vd) || !axvm_freg_src_ok(vn) || !axvm_freg_src_ok(vm)) return AXVM_ERR_BAD_INSN;
            st = axvm_freg_write(ctx, vd, axvm_freg_read(ctx, vn) + axvm_freg_read(ctx, vm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FSUB_D, op_fsub_d) {
            uint8_t vd = 0, vn = 0, vm = 0;
            st = read_u8(ctx, &cursor, &vd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vm);
            if (st != AXVM_OK || !axvm_freg_dst_ok(vd) || !axvm_freg_src_ok(vn) || !axvm_freg_src_ok(vm)) return AXVM_ERR_BAD_INSN;
            st = axvm_freg_write(ctx, vd, axvm_freg_read(ctx, vn) - axvm_freg_read(ctx, vm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FMUL_D, op_fmul_d) {
            uint8_t vd = 0, vn = 0, vm = 0;
            st = read_u8(ctx, &cursor, &vd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vm);
            if (st != AXVM_OK || !axvm_freg_dst_ok(vd) || !axvm_freg_src_ok(vn) || !axvm_freg_src_ok(vm)) return AXVM_ERR_BAD_INSN;
            st = axvm_freg_write(ctx, vd, axvm_freg_read(ctx, vn) * axvm_freg_read(ctx, vm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FDIV_D, op_fdiv_d) {
            uint8_t vd = 0, vn = 0, vm = 0;
            st = read_u8(ctx, &cursor, &vd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vm);
            if (st != AXVM_OK || !axvm_freg_dst_ok(vd) || !axvm_freg_src_ok(vn) || !axvm_freg_src_ok(vm)) return AXVM_ERR_BAD_INSN;
            st = axvm_freg_write(ctx, vd, axvm_freg_read(ctx, vn) / axvm_freg_read(ctx, vm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FCMP_D, op_fcmp_d) {
            uint8_t vn = 0, vm = 0;
            st = read_u8(ctx, &cursor, &vn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vm);
            if (st != AXVM_OK || !axvm_freg_src_ok(vn) || !axvm_freg_src_ok(vm)) return AXVM_ERR_BAD_INSN;
            axvm_freg_set_cmp_flags(&ctx->nzcv, axvm_freg_read(ctx, vn), axvm_freg_read(ctx, vm));
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FMOV_D_REG, op_fmov_d_reg) {
            uint8_t vd = 0, vm = 0;
            st = read_u8(ctx, &cursor, &vd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vm);
            if (st != AXVM_OK || !axvm_freg_dst_ok(vd) || !axvm_freg_src_ok(vm)) return AXVM_ERR_BAD_INSN;
            st = axvm_freg_write(ctx, vd, axvm_freg_read(ctx, vm));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FMOV_X_BITS, op_fmov_x_bits) {
            uint8_t xd = 0, vn = 0;
            uint64_t bits = 0;
            double dv = 0.0;
            st = read_u8(ctx, &cursor, &xd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vn);
            if (st != AXVM_OK || !axvm_reg_dst_ok(xd) || !axvm_freg_src_ok(vn)) return AXVM_ERR_BAD_INSN;
            (void)dv;
            bits = axvm_freg_read_bits(ctx, vn);
            st = axvm_reg_write(ctx, xd, bits);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FMOV_D_BITS, op_fmov_d_bits) {
            uint8_t vd = 0, xn = 0;
            uint64_t bits = 0;
            double dv = 0.0;
            st = read_u8(ctx, &cursor, &vd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &xn);
            if (st != AXVM_OK || !axvm_freg_dst_ok(vd) || !axvm_reg_src_ok(xn)) return AXVM_ERR_BAD_INSN;
            bits = axvm_reg_read(ctx, xn);
            (void)dv;
            st = axvm_freg_write_bits(ctx, vd, bits);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FMOV_D_X, op_fmov_d_x) {
            uint8_t vd = 0, xn = 0;
            st = read_u8(ctx, &cursor, &vd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &xn);
            if (st != AXVM_OK || !axvm_freg_dst_ok(vd) || !axvm_reg_src_ok(xn)) return AXVM_ERR_BAD_INSN;
            st = axvm_freg_write(ctx, vd, (double)(int64_t)axvm_reg_read(ctx, xn));
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FCVT_DS, op_fcvt_ds) {
            uint8_t vd = 0, vn = 0;
            float sf = 0.0f;
            st = read_u8(ctx, &cursor, &vd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vn);
            if (st != AXVM_OK || !axvm_freg_dst_ok(vd) || !axvm_freg_src_ok(vn)) return AXVM_ERR_BAD_INSN;
            sf = (float)axvm_freg_read(ctx, vn);
            st = axvm_freg_write(ctx, vd, (double)sf);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_FCVTZS_D, op_fcvtzs_d) {
            uint8_t rd = 0, vn = 0, is32 = 0;
            double dv = 0.0;
            st = read_u8(ctx, &cursor, &rd);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &vn);
            if (st != AXVM_OK) return st;
            st = read_u8(ctx, &cursor, &is32);
            if (st != AXVM_OK || !axvm_reg_dst_ok(rd) || !axvm_freg_src_ok(vn)) return AXVM_ERR_BAD_INSN;
            dv = axvm_freg_read(ctx, vn);
            if (is32) {
                st = axvm_reg_write(ctx, rd, (uint32_t)(int32_t)dv);
            } else {
                st = axvm_reg_write(ctx, rd, (uint64_t)(int64_t)dv);
            }
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_SAVE_SCRATCH, op_save_scratch) {
            ctx->scratch_save0 = axvm_reg_read(ctx, 16);
            ctx->scratch_save1 = axvm_reg_read(ctx, 17);
            AXVM_OP_NEXT();
        }
        AXVM_OP_BEGIN(AXOP_RESTORE_SCRATCH, op_restore_scratch) {
            st = axvm_reg_write(ctx, 16, ctx->scratch_save0);
            if (st != AXVM_OK) return st;
            st = axvm_reg_write(ctx, 17, ctx->scratch_save1);
            if (st != AXVM_OK) return st;
            AXVM_OP_NEXT();
        }

#endif /* AXVM_FLOAT_VM */
