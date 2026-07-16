/* 真原子 opcode handlers — 宿主 __atomic_* + TLS 独占监视器 */

        AXVM_OP_BEGIN(AXOP_ATOMIC_CAS64, op_atomic_cas64) {
            uint8_t rs = 0, rt = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uint64_t *p = (uint64_t *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint64_t expected = axvm_reg_read(ctx, rs);
            uint64_t desired = axvm_reg_read(ctx, rt);
            uint64_t old = expected;
            (void)__atomic_compare_exchange_n(p, &old, desired, 0,
                                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rs, old);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_SWP64, op_atomic_swp64) {
            uint8_t rt = 0, rs = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uint64_t *p = (uint64_t *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint64_t old = __atomic_exchange_n(p, axvm_reg_read(ctx, rs), __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rt, old);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_LDADD64, op_atomic_ldadd64) {
            uint8_t rt = 0, rs = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uint64_t *p = (uint64_t *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint64_t old = __atomic_fetch_add(p, axvm_reg_read(ctx, rs), __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rt, old);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_LDCLR64, op_atomic_ldclr64) {
            uint8_t rt = 0, rs = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uint64_t *p = (uint64_t *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint64_t old = __atomic_fetch_and(p, ~axvm_reg_read(ctx, rs), __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rt, old);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_LDEOR64, op_atomic_ldeor64) {
            uint8_t rt = 0, rs = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uint64_t *p = (uint64_t *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint64_t old = __atomic_fetch_xor(p, axvm_reg_read(ctx, rs), __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rt, old);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_LDSET64, op_atomic_ldset64) {
            uint8_t rt = 0, rs = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uint64_t *p = (uint64_t *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint64_t old = __atomic_fetch_or(p, axvm_reg_read(ctx, rs), __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rt, old);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_LDXR64, op_atomic_ldxr64) {
            uint8_t rt = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uintptr_t addr = (uintptr_t)axvm_reg_read(ctx, rn);
            uint64_t *p = (uint64_t *)addr;
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint64_t val = __atomic_load_n(p, __ATOMIC_ACQUIRE);
            axvm_reg_write(ctx, rt, val);
            axvm_excl_mark(addr);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_STXR64, op_atomic_stxr64) {
            uint8_t rs = 0, rt = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uintptr_t addr = (uintptr_t)axvm_reg_read(ctx, rn);
            uint64_t *p = (uint64_t *)addr;
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            if (axvm_excl_check_clear(addr)) {
                __atomic_store_n(p, axvm_reg_read(ctx, rt), __ATOMIC_RELEASE);
                axvm_reg_write(ctx, rs, 0);
            } else {
                axvm_reg_write(ctx, rs, 1);
            }
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_CASP64, op_atomic_casp64) {
            uint8_t rs = 0, rt = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            typedef unsigned __int128 u128;
            u128 *p = (u128 *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            u128 expected = ((u128)axvm_reg_read(ctx, (uint8_t)(rs + 1)) << 64) |
                            (u128)axvm_reg_read(ctx, rs);
            u128 desired = ((u128)axvm_reg_read(ctx, (uint8_t)(rt + 1)) << 64) |
                           (u128)axvm_reg_read(ctx, rt);
            u128 old = expected;
            (void)__atomic_compare_exchange_n(p, &old, desired, 0,
                                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rs, (uint64_t)old);
            axvm_reg_write(ctx, (uint8_t)(rs + 1), (uint64_t)(old >> 64));
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_LDXP64, op_atomic_ldxp64) {
            uint8_t rt = 0, rt2 = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rt2);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            typedef unsigned __int128 u128;
            uintptr_t addr = (uintptr_t)axvm_reg_read(ctx, rn);
            u128 *p = (u128 *)addr;
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            u128 val = __atomic_load_n(p, __ATOMIC_ACQUIRE);
            axvm_reg_write(ctx, rt, (uint64_t)val);
            axvm_reg_write(ctx, rt2, (uint64_t)(val >> 64));
            axvm_excl_mark(addr);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_STXP64, op_atomic_stxp64) {
            uint8_t rs = 0, rt = 0, rt2 = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rt2);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            typedef unsigned __int128 u128;
            uintptr_t addr = (uintptr_t)axvm_reg_read(ctx, rn);
            u128 *p = (u128 *)addr;
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            if (axvm_excl_check_clear(addr)) {
                u128 neu = ((u128)axvm_reg_read(ctx, rt2) << 64) |
                           (u128)axvm_reg_read(ctx, rt);
                __atomic_store_n(p, neu, __ATOMIC_RELEASE);
                axvm_reg_write(ctx, rs, 0);
            } else {
                axvm_reg_write(ctx, rs, 1);
            }
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_CAS32, op_atomic_cas32) {
            uint8_t rs = 0, rt = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uint32_t *p = (uint32_t *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint32_t expected = (uint32_t)axvm_reg_read(ctx, rs);
            uint32_t desired = (uint32_t)axvm_reg_read(ctx, rt);
            uint32_t old = expected;
            (void)__atomic_compare_exchange_n(p, &old, desired, 0,
                                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rs, (uint64_t)old);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_SWP32, op_atomic_swp32) {
            uint8_t rt = 0, rs = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uint32_t *p = (uint32_t *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint32_t old = __atomic_exchange_n(p, (uint32_t)axvm_reg_read(ctx, rs),
                                              __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rt, (uint64_t)old);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_LDADD32, op_atomic_ldadd32) {
            uint8_t rt = 0, rs = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uint32_t *p = (uint32_t *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint32_t old = __atomic_fetch_add(p, (uint32_t)axvm_reg_read(ctx, rs),
                                             __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rt, (uint64_t)old);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_LDCLR32, op_atomic_ldclr32) {
            uint8_t rt = 0, rs = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uint32_t *p = (uint32_t *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint32_t old = __atomic_fetch_and(p, ~(uint32_t)axvm_reg_read(ctx, rs),
                                             __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rt, (uint64_t)old);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_LDEOR32, op_atomic_ldeor32) {
            uint8_t rt = 0, rs = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uint32_t *p = (uint32_t *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint32_t old = __atomic_fetch_xor(p, (uint32_t)axvm_reg_read(ctx, rs),
                                             __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rt, (uint64_t)old);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_LDSET32, op_atomic_ldset32) {
            uint8_t rt = 0, rs = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uint32_t *p = (uint32_t *)(uintptr_t)axvm_reg_read(ctx, rn);
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint32_t old = __atomic_fetch_or(p, (uint32_t)axvm_reg_read(ctx, rs),
                                            __ATOMIC_SEQ_CST);
            axvm_reg_write(ctx, rt, (uint64_t)old);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_LDXR32, op_atomic_ldxr32) {
            uint8_t rt = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uintptr_t addr = (uintptr_t)axvm_reg_read(ctx, rn);
            uint32_t *p = (uint32_t *)addr;
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            uint32_t val = __atomic_load_n(p, __ATOMIC_ACQUIRE);
            axvm_reg_write(ctx, rt, (uint64_t)val);
            axvm_excl_mark(addr);
            AXVM_OP_NEXT();
        }

        AXVM_OP_BEGIN(AXOP_ATOMIC_STXR32, op_atomic_stxr32) {
            uint8_t rs = 0, rt = 0, rn = 0;
            st = read_u8(ctx, &cursor, &rs);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rt);
            if (st != AXVM_OK) {
                return st;
            }
            st = read_u8(ctx, &cursor, &rn);
            if (st != AXVM_OK) {
                return st;
            }
            uintptr_t addr = (uintptr_t)axvm_reg_read(ctx, rn);
            uint32_t *p = (uint32_t *)addr;
            if (!p) {
                return AXVM_ERR_OOB_MEM;
            }
            if (axvm_excl_check_clear(addr)) {
                __atomic_store_n(p, (uint32_t)axvm_reg_read(ctx, rt), __ATOMIC_RELEASE);
                axvm_reg_write(ctx, rs, 0);
            } else {
                axvm_reg_write(ctx, rs, 1);
            }
            AXVM_OP_NEXT();
        }
