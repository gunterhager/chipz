//! Z80 disassembler.
//!
//! Zig port of the z80dasm.h from the chips project by Andre Weissflog.
//! Decoding strategy: http://www.z80.info/decoding.htm
const std = @import("std");

pub const MAX_MNEMONIC_LEN = 32;
pub const MAX_BYTES = 4;

pub const Result = struct {
    next_pc: u16,
    num_bytes: u8,
    mnemonic: [MAX_MNEMONIC_LEN]u8 = [_]u8{0} ** MAX_MNEMONIC_LEN,
    mnemonic_len: u8,
    cycles: u8 = 0, // base T-state count (0 = unknown)
    cycles_alt: u8 = 0, // alternate count for conditional ops (0 = none)

    pub fn mnemonicSlice(self: *const Result) []const u8 {
        return self.mnemonic[0..self.mnemonic_len];
    }
};

// Register name tables
const r_hl = [_][]const u8{ "B", "C", "D", "E", "H", "L", "(HL)", "A" };
const r_ix = [_][]const u8{ "B", "C", "D", "E", "IXH", "IXL", "(IX", "A" };
const r_iy = [_][]const u8{ "B", "C", "D", "E", "IYH", "IYL", "(IY", "A" };
const rp_hl = [_][]const u8{ "BC", "DE", "HL", "SP" };
const rp_ix = [_][]const u8{ "BC", "DE", "IX", "SP" };
const rp_iy = [_][]const u8{ "BC", "DE", "IY", "SP" };
const rp2_hl = [_][]const u8{ "BC", "DE", "HL", "AF" };
const rp2_ix = [_][]const u8{ "BC", "DE", "IX", "AF" };
const rp2_iy = [_][]const u8{ "BC", "DE", "IY", "AF" };
const cc = [_][]const u8{ "NZ", "Z", "NC", "C", "PO", "PE", "P", "M" };
const alu = [_][]const u8{ "ADD A,", "ADC A,", "SUB ", "SBC A,", "AND ", "XOR ", "OR ", "CP " };
const rot = [_][]const u8{ "RLC ", "RRC ", "RL ", "RR ", "SLA ", "SRA ", "SLL ", "SRL " };
const x0z7 = [_][]const u8{ "RLCA", "RRCA", "RLA", "RRA", "DAA", "CPL", "SCF", "CCF" };
const edx1z7 = [_][]const u8{ "LD I,A", "LD R,A", "LD A,I", "LD A,R", "RRD", "RLD", "NOP (ED)", "NOP (ED)" };
const im_modes = [_][]const u8{ "0", "0", "1", "2", "0", "0", "1", "2" };
const bli = [4][4][]const u8{
    .{ "LDI", "CPI", "INI", "OUTI" },
    .{ "LDD", "CPD", "IND", "OUTD" },
    .{ "LDIR", "CPIR", "INIR", "OTIR" },
    .{ "LDDR", "CPDR", "INDR", "OTDR" },
};

const Ctx = struct {
    pc: u16,
    num_bytes: u8,
    read_fn: *const fn (u16, ?*anyopaque) u8,
    user_data: ?*anyopaque,
    buf: [MAX_MNEMONIC_LEN]u8,
    buf_pos: u8,
    pre: u8, // prefix byte: 0, 0xDD, or 0xFD
    cycles: u8,
    cycles_alt: u8,

    fn fetchU8(self: *Ctx) u8 {
        const v = self.read_fn(self.pc, self.user_data);
        self.pc +%= 1;
        self.num_bytes += 1;
        return v;
    }

    fn fetchI8(self: *Ctx) i8 {
        return @bitCast(self.fetchU8());
    }

    fn fetchU16(self: *Ctx) u16 {
        const lo: u16 = self.fetchU8();
        const hi: u16 = self.fetchU8();
        return lo | (hi << 8);
    }

    fn chr(self: *Ctx, c: u8) void {
        if (self.buf_pos < MAX_MNEMONIC_LEN) {
            self.buf[self.buf_pos] = c;
            self.buf_pos += 1;
        }
    }

    fn str(self: *Ctx, s: []const u8) void {
        for (s) |c| self.chr(c);
    }

    // output signed 8-bit offset as decimal (+d or -d)
    fn strD8(self: *Ctx, val: i8) void {
        if (val < 0) {
            self.chr('-');
            const v: u8 = @intCast(-@as(i16, val));
            if (v >= 100) self.chr('1');
            const v2: u8 = if (v >= 100) v - 100 else v;
            if (v2 / 10 != 0) self.chr('0' + v2 / 10);
            self.chr('0' + v2 % 10);
        } else {
            self.chr('+');
            const v: u8 = @intCast(val);
            if (v >= 100) self.chr('1');
            const v2: u8 = if (v >= 100) v - 100 else v;
            if (v2 / 10 != 0) self.chr('0' + v2 / 10);
            self.chr('0' + v2 % 10);
        }
    }

    // output unsigned 8-bit value as hex (e.g. "1Fh")
    fn strU8(self: *Ctx, val: u8) void {
        const hex = "0123456789ABCDEF";
        self.chr(hex[(val >> 4) & 0xF]);
        self.chr(hex[val & 0xF]);
        self.chr('h');
    }

    // output unsigned 16-bit value as hex (e.g. "1234h")
    fn strU16(self: *Ctx, val: u16) void {
        const hex = "0123456789ABCDEF";
        self.chr(hex[(val >> 12) & 0xF]);
        self.chr(hex[(val >> 8) & 0xF]);
        self.chr(hex[(val >> 4) & 0xF]);
        self.chr(hex[val & 0xF]);
        self.chr('h');
    }

    // (HL) or (IX+d) or (IY+d) — fetches the displacement byte if prefixed
    fn mem(self: *Ctx, regs: []const []const u8) void {
        self.str(regs[6]);
        if (self.pre != 0) {
            const d = self.fetchI8();
            self.strD8(d);
            self.chr(')');
        }
    }

    // (HL) or (IX+d) or (IY+d) — with an already-fetched displacement byte
    fn memD(self: *Ctx, d: i8, regs: []const []const u8) void {
        self.str(regs[6]);
        if (self.pre != 0) {
            self.strD8(d);
            self.chr(')');
        }
    }

    // register or memory reference
    fn memR(self: *Ctx, i: u3, regs: []const []const u8) void {
        if (i == 6) {
            self.mem(regs);
        } else {
            self.str(regs[i]);
        }
    }

    // register or memory reference with pre-fetched displacement
    fn memRd(self: *Ctx, i: u3, d: i8, regs: []const []const u8) void {
        self.str(regs[i]);
        if (i == 6 and self.pre != 0) {
            self.strD8(d);
            self.chr(')');
        }
    }

    fn r(self: *Ctx) []const []const u8 {
        return switch (self.pre) {
            0xDD => &r_ix,
            0xFD => &r_iy,
            else => &r_hl,
        };
    }

    fn rp(self: *Ctx) []const []const u8 {
        return switch (self.pre) {
            0xDD => &rp_ix,
            0xFD => &rp_iy,
            else => &rp_hl,
        };
    }

    fn rp2(self: *Ctx) []const []const u8 {
        return switch (self.pre) {
            0xDD => &rp2_ix,
            0xFD => &rp2_iy,
            else => &rp2_hl,
        };
    }
};

/// Disassemble one Z80 instruction starting at `pc`.
/// `read_fn(addr, user_data)` returns the byte at the given address.
/// Returns the next PC and the disassembled mnemonic string.
pub fn op(pc: u16, read_fn: *const fn (u16, ?*anyopaque) u8, user_data: ?*anyopaque) Result {
    var ctx = Ctx{
        .pc = pc,
        .num_bytes = 0,
        .read_fn = read_fn,
        .user_data = user_data,
        .buf = [_]u8{0} ** MAX_MNEMONIC_LEN,
        .buf_pos = 0,
        .pre = 0,
        .cycles = 0,
        .cycles_alt = 0,
    };
    disasm(&ctx);
    calcCycles(&ctx, pc);
    return Result{
        .next_pc = ctx.pc,
        .num_bytes = ctx.num_bytes,
        .mnemonic = ctx.buf,
        .mnemonic_len = ctx.buf_pos,
        .cycles = ctx.cycles,
        .cycles_alt = ctx.cycles_alt,
    };
}

fn disasm(ctx: *Ctx) void {
    var byte = ctx.fetchU8();

    // handle DD/FD prefix
    if (byte == 0xDD or byte == 0xFD) {
        ctx.pre = byte;
        byte = ctx.fetchU8();
        if (byte == 0xED) {
            ctx.pre = 0; // ED after prefix cancels prefix
        }
    }

    const x: u2 = @truncate(byte >> 6);
    const y: u3 = @truncate((byte >> 3) & 7);
    const z: u3 = @truncate(byte & 7);
    const p: u2 = @truncate(y >> 1);
    const q: u1 = @truncate(y & 1);

    if (x == 1) {
        // 8-bit load block
        if (y == 6) {
            if (z == 6) {
                ctx.str("HALT");
            } else {
                // LD (HL),r / LD (IX+d),r / LD (IY+d),r
                ctx.str("LD ");
                ctx.mem(ctx.r());
                ctx.chr(',');
                if (ctx.pre != 0 and (z == 4 or z == 5)) {
                    ctx.str(r_hl[z]);
                } else {
                    ctx.str(ctx.r()[z]);
                }
            }
        } else if (z == 6) {
            // LD r,(HL) / LD r,(IX+d) / LD r,(IY+d)
            ctx.str("LD ");
            if (ctx.pre != 0 and (y == 4 or y == 5)) {
                ctx.str(r_hl[y]);
            } else {
                ctx.str(ctx.r()[y]);
            }
            ctx.chr(',');
            ctx.mem(ctx.r());
        } else {
            // regular LD r,s
            ctx.str("LD ");
            ctx.str(ctx.r()[y]);
            ctx.chr(',');
            ctx.str(ctx.r()[z]);
        }
    } else if (x == 2) {
        // 8-bit ALU block
        ctx.str(alu[y]);
        ctx.memR(z, ctx.r());
    } else if (x == 0) {
        switch (z) {
            0 => switch (y) {
                0 => ctx.str("NOP"),
                1 => ctx.str("EX AF,AF'"),
                2 => {
                    ctx.str("DJNZ ");
                    const d = ctx.fetchI8();
                    ctx.strU16(ctx.pc +% @as(u16, @bitCast(@as(i16, d))));
                },
                3 => {
                    ctx.str("JR ");
                    const d = ctx.fetchI8();
                    ctx.strU16(ctx.pc +% @as(u16, @bitCast(@as(i16, d))));
                },
                else => {
                    ctx.str("JR ");
                    ctx.str(cc[y - 4]);
                    ctx.chr(',');
                    const d = ctx.fetchI8();
                    ctx.strU16(ctx.pc +% @as(u16, @bitCast(@as(i16, d))));
                },
            },
            1 => {
                if (q == 0) {
                    ctx.str("LD ");
                    ctx.str(ctx.rp()[p]);
                    ctx.chr(',');
                    ctx.strU16(ctx.fetchU16());
                } else {
                    ctx.str("ADD ");
                    ctx.str(ctx.rp()[2]);
                    ctx.chr(',');
                    ctx.str(ctx.rp()[p]);
                }
            },
            2 => {
                ctx.str("LD ");
                switch (y) {
                    0 => ctx.str("(BC),A"),
                    1 => ctx.str("A,(BC)"),
                    2 => ctx.str("(DE),A"),
                    3 => ctx.str("A,(DE)"),
                    4 => {
                        ctx.chr('(');
                        ctx.strU16(ctx.fetchU16());
                        ctx.str("),");
                        ctx.str(ctx.rp()[2]);
                    },
                    5 => {
                        ctx.str(ctx.rp()[2]);
                        ctx.str(",(");
                        ctx.strU16(ctx.fetchU16());
                        ctx.chr(')');
                    },
                    6 => {
                        ctx.chr('(');
                        ctx.strU16(ctx.fetchU16());
                        ctx.str("),A");
                    },
                    7 => {
                        ctx.str("A,(");
                        ctx.strU16(ctx.fetchU16());
                        ctx.chr(')');
                    },
                }
            },
            3 => {
                ctx.str(if (q == 0) "INC " else "DEC ");
                ctx.str(ctx.rp()[p]);
            },
            4 => {
                ctx.str("INC ");
                ctx.memR(y, ctx.r());
            },
            5 => {
                ctx.str("DEC ");
                ctx.memR(y, ctx.r());
            },
            6 => {
                ctx.str("LD ");
                ctx.memR(y, ctx.r());
                ctx.chr(',');
                ctx.strU8(ctx.fetchU8());
            },
            7 => ctx.str(x0z7[y]),
        }
    } else { // x == 3
        switch (z) {
            0 => {
                ctx.str("RET ");
                ctx.str(cc[y]);
            },
            1 => {
                if (q == 0) {
                    ctx.str("POP ");
                    ctx.str(ctx.rp2()[p]);
                } else {
                    switch (p) {
                        0 => ctx.str("RET"),
                        1 => ctx.str("EXX"),
                        2 => {
                            ctx.str("JP (");
                            ctx.str(ctx.rp()[2]);
                            ctx.chr(')');
                        },
                        3 => {
                            ctx.str("LD SP,");
                            ctx.str(ctx.rp()[2]);
                        },
                    }
                }
            },
            2 => {
                ctx.str("JP ");
                ctx.str(cc[y]);
                ctx.chr(',');
                ctx.strU16(ctx.fetchU16());
            },
            3 => {
                switch (y) {
                    0 => {
                        ctx.str("JP ");
                        ctx.strU16(ctx.fetchU16());
                    },
                    1 => { // CB prefix
                        const saved_pre = ctx.pre;
                        var d: i8 = 0;
                        if (saved_pre != 0) {
                            d = ctx.fetchI8();
                        }
                        const cb_op = ctx.fetchU8();
                        const cx: u2 = @truncate(cb_op >> 6);
                        const cy: u3 = @truncate((cb_op >> 3) & 7);
                        const cz: u3 = @truncate(cb_op & 7);
                        if (cx == 0) {
                            ctx.str(rot[cy]);
                            ctx.memRd(cz, d, ctx.r());
                        } else {
                            if (cx == 1) ctx.str("BIT ") else if (cx == 2) ctx.str("RES ") else ctx.str("SET ");
                            ctx.chr('0' + @as(u8, cy));
                            if (saved_pre != 0) {
                                ctx.chr(',');
                                ctx.memD(d, ctx.r());
                            }
                            if (saved_pre == 0 or cz != 6) {
                                ctx.chr(',');
                                ctx.str(ctx.r()[cz]);
                            }
                        }
                    },
                    2 => {
                        ctx.str("OUT (");
                        ctx.strU8(ctx.fetchU8());
                        ctx.str("),A");
                    },
                    3 => {
                        ctx.str("IN A,(");
                        ctx.strU8(ctx.fetchU8());
                        ctx.chr(')');
                    },
                    4 => {
                        ctx.str("EX (SP),");
                        ctx.str(ctx.rp()[2]);
                    },
                    5 => ctx.str("EX DE,HL"),
                    6 => ctx.str("DI"),
                    7 => ctx.str("EI"),
                }
            },
            4 => {
                ctx.str("CALL ");
                ctx.str(cc[y]);
                ctx.chr(',');
                ctx.strU16(ctx.fetchU16());
            },
            5 => {
                if (q == 0) {
                    ctx.str("PUSH ");
                    ctx.str(ctx.rp2()[p]);
                } else {
                    switch (p) {
                        0 => {
                            ctx.str("CALL ");
                            ctx.strU16(ctx.fetchU16());
                        },
                        1 => ctx.str("DBL PREFIX"),
                        3 => ctx.str("DBL PREFIX"),
                        2 => { // ED prefix
                            const ed_op = ctx.fetchU8();
                            const ex: u2 = @truncate(ed_op >> 6);
                            const ey: u3 = @truncate((ed_op >> 3) & 7);
                            const ez: u3 = @truncate(ed_op & 7);
                            const ep: u2 = @truncate(ey >> 1);
                            const eq: u1 = @truncate(ey & 1);
                            if (ex == 0 or ex == 3) {
                                ctx.str("NOP (ED)");
                            } else if (ex == 2) {
                                if (ey >= 4 and ez <= 3) {
                                    ctx.str(bli[ey - 4][ez]);
                                } else {
                                    ctx.str("NOP (ED)");
                                }
                            } else { // ex == 1
                                switch (ez) {
                                    0 => {
                                        ctx.str("IN ");
                                        if (ey != 6) {
                                            ctx.str(r_hl[ey]);
                                            ctx.chr(',');
                                        }
                                        ctx.str("(C)");
                                    },
                                    1 => {
                                        ctx.str("OUT (C),");
                                        ctx.str(if (ey == 6) "0" else r_hl[ey]);
                                    },
                                    2 => {
                                        ctx.str(if (eq == 0) "SBC" else "ADC");
                                        ctx.str(" HL,");
                                        ctx.str(rp_hl[ep]);
                                    },
                                    3 => {
                                        ctx.str("LD ");
                                        if (eq == 0) {
                                            ctx.chr('(');
                                            ctx.strU16(ctx.fetchU16());
                                            ctx.str("),");
                                            ctx.str(rp_hl[ep]);
                                        } else {
                                            ctx.str(rp_hl[ep]);
                                            ctx.str(",(");
                                            ctx.strU16(ctx.fetchU16());
                                            ctx.chr(')');
                                        }
                                    },
                                    4 => ctx.str("NEG"),
                                    5 => ctx.str(if (ey == 1) "RETI" else "RETN"),
                                    6 => {
                                        ctx.str("IM ");
                                        ctx.str(im_modes[ey]);
                                    },
                                    7 => ctx.str(edx1z7[ey]),
                                }
                            }
                        },
                    }
                }
            },
            6 => {
                // ALU n
                ctx.str(alu[y]);
                ctx.strU8(ctx.fetchU8());
            },
            7 => {
                ctx.str("RST ");
                ctx.strU8(@as(u8, y) * 8);
            },
        }
    }
}

fn calcCycles(ctx: *Ctx, start_pc: u16) void {
    var pc = start_pc;
    const b0 = ctx.read_fn(pc, ctx.user_data);
    pc +%= 1;

    var main_byte = b0;
    var pre: u8 = 0;
    if (b0 == 0xDD or b0 == 0xFD) {
        pre = b0;
        main_byte = ctx.read_fn(pc, ctx.user_data);
        pc +%= 1;
        if (main_byte == 0xED) pre = 0;
    }

    // ED prefix
    if (main_byte == 0xED) {
        const ed_op = ctx.read_fn(pc, ctx.user_data);
        const ex: u2 = @truncate(ed_op >> 6);
        const ey: u3 = @truncate((ed_op >> 3) & 7);
        const ez: u3 = @truncate(ed_op & 7);
        if (ex == 0 or ex == 3) {
            ctx.cycles = 8; // NOP (ED)
        } else if (ex == 2) {
            if (ey >= 4 and ez <= 3) {
                ctx.cycles = 16;
                if (ey >= 6) ctx.cycles_alt = 21; // LDIR/LDDR/INIR/OTIR: loop=21, end=16
            } else {
                ctx.cycles = 8;
            }
        } else { // ex == 1
            ctx.cycles = switch (ez) {
                0, 1 => 12, // IN r,(C) / OUT (C),r
                2 => 15, // SBC HL,rp / ADC HL,rp
                3 => 20, // LD (nn),rp / LD rp,(nn)
                4 => 8, // NEG
                5 => 14, // RETI / RETN
                6 => 8, // IM n
                7 => switch (ey) {
                    0, 1, 2, 3 => 9, // LD I/R,A ; LD A,I/R
                    4, 5 => 18, // RRD, RLD
                    else => 8, // NOP (ED)
                },
            };
        }
        return;
    }

    // CB prefix (plain CB or DDCB/FDCB)
    if (main_byte == 0xCB) {
        if (pre != 0) pc +%= 1; // skip displacement byte for DDCB/FDCB
        const cb_op = ctx.read_fn(pc, ctx.user_data);
        const cx: u2 = @truncate(cb_op >> 6);
        const cz: u3 = @truncate(cb_op & 7);
        if (pre != 0) {
            ctx.cycles = if (cx == 1) 20 else 23; // BIT=20, rot/RES/SET=23
        } else {
            const is_hl = (cz == 6);
            ctx.cycles = switch (cx) {
                0 => if (is_hl) @as(u8, 15) else 8, // rot
                1 => if (is_hl) @as(u8, 12) else 8, // BIT
                else => if (is_hl) @as(u8, 15) else 8, // RES, SET
            };
        }
        return;
    }

    const x: u2 = @truncate(main_byte >> 6);
    const y: u3 = @truncate((main_byte >> 3) & 7);
    const z: u3 = @truncate(main_byte & 7);
    const p: u2 = @truncate(y >> 1);
    const q: u1 = @truncate(y & 1);

    switch (x) {
        0 => switch (z) {
            0 => switch (y) {
                0 => ctx.cycles = 4, // NOP
                1 => ctx.cycles = 4, // EX AF,AF'
                2 => {
                    ctx.cycles = 8;
                    ctx.cycles_alt = 13;
                }, // DJNZ: not-taken/taken
                3 => ctx.cycles = 12, // JR e
                else => {
                    ctx.cycles = 7;
                    ctx.cycles_alt = 12;
                }, // JR cc: not-taken/taken
            },
            1 => if (q == 0) {
                ctx.cycles = if (pre != 0) 14 else 10; // LD rp,nn (LD IX,nn=14)
            } else {
                ctx.cycles = if (pre != 0) 15 else 11; // ADD HL/IX/IY,rp
            },
            2 => switch (y) {
                0, 2 => ctx.cycles = 7, // LD (BC/DE),A
                1, 3 => ctx.cycles = 7, // LD A,(BC/DE)
                4, 5 => ctx.cycles = if (pre != 0) 20 else 16, // LD (nn),HL/IX / LD HL/IX,(nn)
                6 => ctx.cycles = 13, // LD (nn),A
                7 => ctx.cycles = 13, // LD A,(nn)
            },
            3 => ctx.cycles = if (pre != 0) 10 else 6, // INC/DEC rp (IX=10)
            4 => { // INC r
                if (y == 6) {
                    ctx.cycles = if (pre != 0) 23 else 11; // INC (HL)=11 / INC (IX+d)=23
                } else if (pre != 0 and (y == 4 or y == 5)) {
                    ctx.cycles = 8; // INC IXH/IXL (undocumented)
                } else {
                    ctx.cycles = 4;
                }
            },
            5 => { // DEC r (same timing as INC r)
                if (y == 6) {
                    ctx.cycles = if (pre != 0) 23 else 11;
                } else if (pre != 0 and (y == 4 or y == 5)) {
                    ctx.cycles = 8;
                } else {
                    ctx.cycles = 4;
                }
            },
            6 => { // LD r,n
                if (y == 6) {
                    ctx.cycles = if (pre != 0) 19 else 10; // LD (HL),n=10 / LD (IX+d),n=19
                } else if (pre != 0 and (y == 4 or y == 5)) {
                    ctx.cycles = 11; // LD IXH/IXL,n (undocumented)
                } else {
                    ctx.cycles = 7;
                }
            },
            7 => ctx.cycles = 4, // RLCA/RRCA/RLA/RRA/DAA/CPL/SCF/CCF
        },
        1 => { // LD r,r / HALT
            if (y == 6 and z == 6) {
                ctx.cycles = 4; // HALT
            } else if (z == 6) {
                ctx.cycles = if (pre != 0) 19 else 7; // LD r,(HL)=7 / LD r,(IX+d)=19
            } else if (y == 6) {
                ctx.cycles = if (pre != 0) 19 else 7; // LD (HL),r=7 / LD (IX+d),r=19
            } else if (pre != 0 and (y == 4 or y == 5 or z == 4 or z == 5)) {
                ctx.cycles = 8; // undocumented IXH/IXL ops
            } else {
                ctx.cycles = 4;
            }
        },
        2 => { // ALU r
            if (z == 6) {
                ctx.cycles = if (pre != 0) 19 else 7; // ALU (HL)=7 / ALU (IX+d)=19
            } else if (pre != 0 and (z == 4 or z == 5)) {
                ctx.cycles = 8; // undocumented ALU IXH/IXL
            } else {
                ctx.cycles = 4;
            }
        },
        3 => switch (z) {
            0 => {
                ctx.cycles = 5;
                ctx.cycles_alt = 11;
            }, // RET cc: not-taken=5, taken=11
            1 => if (q == 0) {
                ctx.cycles = if (pre != 0) 14 else 10; // POP rp=10, POP IX/IY=14
            } else switch (p) {
                0 => ctx.cycles = 10, // RET
                1 => ctx.cycles = 4, // EXX
                2 => ctx.cycles = if (pre != 0) 8 else 4, // JP (HL)=4 / JP (IX/IY)=8
                3 => ctx.cycles = if (pre != 0) 10 else 6, // LD SP,HL=6 / LD SP,IX=10
            },
            2 => ctx.cycles = 10, // JP cc,nn
            3 => switch (y) {
                0 => ctx.cycles = 10, // JP nn
                1 => {}, // CB prefix - handled above
                2 => ctx.cycles = 11, // OUT (n),A
                3 => ctx.cycles = 11, // IN A,(n)
                4 => ctx.cycles = if (pre != 0) 23 else 19, // EX (SP),HL=19 / EX (SP),IX=23
                5 => ctx.cycles = 4, // EX DE,HL
                6 => ctx.cycles = 4, // DI
                7 => ctx.cycles = 4, // EI
            },
            4 => {
                ctx.cycles = 10;
                ctx.cycles_alt = 17;
            }, // CALL cc: not-taken=10, taken=17
            5 => if (q == 0) {
                ctx.cycles = if (pre != 0) 15 else 11; // PUSH rp=11, PUSH IX/IY=15
            } else switch (p) {
                0 => ctx.cycles = 17, // CALL nn
                else => ctx.cycles = 0, // DBL PREFIX / ED
            },
            6 => ctx.cycles = 7, // ALU n
            7 => ctx.cycles = 11, // RST n
        },
    }
}
