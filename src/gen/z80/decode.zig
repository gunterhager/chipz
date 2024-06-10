const std = @import("std");
const format = @import("format.zig");
const ops = @import("ops.zig");

pub fn decode(allocator: std.mem.Allocator) void {
    format.init(allocator);
    decodeMain();
    decodeED();
    decodeCB();
}

fn decodeMain() void {
    for (0..256) |i| {
        const op: u8 = @truncate(i);
        const x: u2 = @truncate((i >> 6) & 3);
        const y: u3 = @truncate((i >> 3) & 7);
        const z: u3 = @truncate(i & 7);
        const p: u2 = @truncate(y >> 1);
        const q: u1 = @truncate(y);
        switch (x) {
            // quadrant 0
            0 => switch (z) {
                0 => switch (y) {
                    0 => ops.nop(op),
                    1 => ops.@"EX AF,AF'"(op),
                    2 => ops.djnz(op),
                    else => {},
                },
                1 => switch (q) {
                    0 => ops.@"LD RP,nn"(op, p),
                    else => {},
                },
                2 => switch (q) {
                    0 => switch (p) {
                        0 => ops.@"LD (BC),A"(op),
                        1 => ops.@"LD (DE),A"(op),
                        2 => ops.@"LD (nn),HL"(op),
                        3 => ops.@"LD (nn),A"(op),
                    },
                    1 => switch (p) {
                        0 => ops.@"LD A,(BC)"(op),
                        1 => ops.@"LD A,(DE)"(op),
                        2 => ops.@"LD HL,(nn)"(op),
                        3 => ops.@"LD A,(nn)"(op),
                    },
                },
                4 => switch (y) {
                    6 => ops.@"INC (HL)"(op),
                    else => ops.@"INC r"(op, y),
                },
                5 => switch (y) {
                    6 => ops.@"DEC (HL)"(op),
                    else => ops.@"DEC r"(op, y),
                },
                6 => switch (y) {
                    6 => ops.@"LD (HL),n"(op),
                    else => ops.@"LD r,n"(op, y),
                },
                7 => switch (y) {
                    0 => ops.rlca(op),
                    1 => ops.rrca(op),
                    2 => ops.rla(op),
                    3 => ops.rra(op),
                    4 => ops.daa(op),
                    5 => ops.cpl(op),
                    6 => ops.scf(op),
                    7 => ops.ccf(op),
                },
                else => {},
            },
            // quadrant 1: 8-bit loads
            1 => {
                if ((y == 6) and (z == 6)) {
                    ops.halt(op);
                } else if (y == 6) {
                    ops.@"LD (HL),r"(op, z);
                } else if (z == 6) {
                    ops.@"LD r,(HL)"(op, y);
                } else {
                    ops.@"LD r,r"(op, y, z);
                }
            },
            // quadrant 2: 8-bit ALU instructions
            2 => {
                if (z == 6) {
                    ops.@"ALU (HL)"(op, y);
                } else {
                    ops.@"ALU r"(op, y, z);
                }
            },
            // quadrant 3
            3 => {
                switch (z) {
                    1 => switch (q) {
                        0 => ops.pop(op, p),
                        1 => switch (p) {
                            1 => ops.exx(op),
                            else => {},
                        },
                    },
                    3 => switch (y) {
                        4 => ops.@"EX (SP),HL"(op),
                        5 => ops.@"EX DE,HL"(op),
                        else => {},
                    },
                    5 => switch (q) {
                        0 => ops.push(op, p),
                        1 => switch (p) {
                            1 => ops.dd(op),
                            3 => ops.fd(op),
                            else => {},
                        },
                    },
                    6 => ops.@"ALU n"(op, y),
                    else => {},
                }
            },
        }
    }
}

fn decodeED() void {}

fn decodeCB() void {}
