// zig fmt: off
const std = @import("std");
const assert = std.debug.assert;
const chips = @import("chips");
const bits = chips.bits;
const z80 = chips.z80;

const Z80 = z80.Z80(z80.DefaultPins, u64);

const A = z80.A;
const F = z80.F;
const B = z80.B;
const C = z80.C;
const D = z80.D;
const E = z80.E;
const L = z80.L;
const H = z80.H;

const CF = z80.CF;
const NF = z80.NF;
const VF = z80.VF;
const PF = z80.PF;
const XF = z80.XF;
const HF = z80.HF;
const YF = z80.YF;
const ZF = z80.ZF;
const SF = z80.SF;

var cpu: Z80 = undefined;
var bus: u64 = 0;
var mem = [_]u8{0} ** 0x10000;

const MREQ = z80.DefaultPins.MREQ;
const RD = z80.DefaultPins.RD;
const WR = z80.DefaultPins.WR;

fn T(cond: bool) void {
    assert(cond);
}

fn flags(f: u8) bool {
    // don't check undocumented flags
    return (cpu.r[F] & ~@as(u8, XF|YF)) == f;
}

fn start(msg: []const u8) void {
    std.debug.print("=> {s} ... ", .{msg});
}

fn ok() void {
    std.debug.print("ok\n", .{});
}

fn init(start_addr: u16, bytes: []const u8) void {
    cpu = Z80{};
    cpu.r[z80.F] = 0;
    cpu.af2 = 0xFF00;
    cpu.bc2 = 0xFFFF;
    cpu.de2 = 0xFFFF;
    cpu.hl2 = 0xFFFF;
    copy(start_addr, bytes);
    cpu.prefetch(start_addr);
    _ = step();
}

fn copy(start_addr: u16, bytes: []const u8) void {
    std.mem.copyForwards(u8, mem[start_addr..bytes.len], bytes);
}

fn tick() void {
    bus = cpu.tick(bus);
    const addr = Z80.getAddr(bus);
    if (bits.tst(bus, MREQ)) {
        if (bits.tst(bus, RD)) {
            bus = Z80.setData(bus, mem[addr]);
        } else if (bits.tst(bus, WR)) {
            mem[addr] = Z80.getData(bus);
        }
    }
    // FIXME: IORQ
}

fn step() usize {
    var num_ticks: usize = 1;
    tick();
    while (!cpu.opdone(bus)) {
        tick();
        num_ticks += 1;
    }
    return num_ticks;
}

fn NOP() void {
    start("NOP");
    const prog = [_]u8{0};
    init(0, &prog);
    T(4 == step());
    T(4 == step());
    ok();
}

fn @"LD r,s/n"() void {
    start("LD r,s/n");
    const prog = [_]u8{
        0x3E, 0x12, // LD A,0x12
        0x47, // LD B,A
        0x4F, // LD C,A
        0x57, // LD D,A
        0x5F, // LD E,A
        0x67, // LD H,A
        0x6F, // LD L,A
        0x7F, // LD A,A
        0x06, 0x13, // LD B,0x13
        0x40, // LD B,B
        0x48, // LD C,B
        0x50, // LD D,B
        0x58, // LD E,B
        0x60, // LD H,B
        0x68, // LD L,B
        0x78, // LD A,B
        0x0E, 0x14, // LD C,0x14
        0x41, // LD B,C
        0x49, // LD C,C
        0x51, // LD D,C
        0x59, // LD E,C
        0x61, // LD H,C
        0x69, // LD L,C
        0x79, // LD A,C
        0x16, 0x15, // LD D,0x15
        0x42, // LD B,D
        0x4A, // LD C,D
        0x52, // LD D,D
        0x5A, // LD E,D
        0x62, // LD H,D
        0x6A, // LD L,D
        0x7A, // LD A,D
        0x1E, 0x16, // LD E,0x16
        0x43, // LD B,E
        0x4B, // LD C,E
        0x53, // LD D,E
        0x5B, // LD E,E
        0x63, // LD H,E
        0x6B, // LD L,E
        0x7B, // LD A,E
        0x26, 0x17, // LD H,0x17
        0x44, // LD B,H
        0x4C, // LD C,H
        0x54, // LD D,H
        0x5C, // LD E,H
        0x64, // LD H,H
        0x6C, // LD L,H
        0x7C, // LD A,H
        0x2E, 0x18, // LD L,0x18
        0x45, // LD B,L
        0x4D, // LD C,L
        0x55, // LD D,L
        0x5D, // LD E,L
        0x65, // LD H,L
        0x6D, // LD L,L
        0x7D, // LD A,L
    };
    init(0, &prog);
    T(7==step()); T(0x12==cpu.r[A]);
    T(4==step()); T(0x12==cpu.r[B]);
    T(4==step()); T(0x12==cpu.r[C]);
    T(4==step()); T(0x12==cpu.r[D]);
    T(4==step()); T(0x12==cpu.r[E]);
    T(4==step()); T(0x12==cpu.r[H]);
    T(4==step()); T(0x12==cpu.r[L]);
    T(4==step()); T(0x12==cpu.r[A]);
    T(7==step()); T(0x13==cpu.r[B]);
    T(4==step()); T(0x13==cpu.r[B]);
    T(4==step()); T(0x13==cpu.r[C]);
    T(4==step()); T(0x13==cpu.r[D]);
    T(4==step()); T(0x13==cpu.r[E]);
    T(4==step()); T(0x13==cpu.r[H]);
    T(4==step()); T(0x13==cpu.r[L]);
    T(4==step()); T(0x13==cpu.r[A]);
    T(7==step()); T(0x14==cpu.r[C]);
    T(4==step()); T(0x14==cpu.r[B]);
    T(4==step()); T(0x14==cpu.r[C]);
    T(4==step()); T(0x14==cpu.r[D]);
    T(4==step()); T(0x14==cpu.r[E]);
    T(4==step()); T(0x14==cpu.r[H]);
    T(4==step()); T(0x14==cpu.r[L]);
    T(4==step()); T(0x14==cpu.r[A]);
    T(7==step()); T(0x15==cpu.r[D]);
    T(4==step()); T(0x15==cpu.r[B]);
    T(4==step()); T(0x15==cpu.r[C]);
    T(4==step()); T(0x15==cpu.r[D]);
    T(4==step()); T(0x15==cpu.r[E]);
    T(4==step()); T(0x15==cpu.r[H]);
    T(4==step()); T(0x15==cpu.r[L]);
    T(4==step()); T(0x15==cpu.r[A]);
    T(7==step()); T(0x16==cpu.r[E]);
    T(4==step()); T(0x16==cpu.r[B]);
    T(4==step()); T(0x16==cpu.r[C]);
    T(4==step()); T(0x16==cpu.r[D]);
    T(4==step()); T(0x16==cpu.r[E]);
    T(4==step()); T(0x16==cpu.r[H]);
    T(4==step()); T(0x16==cpu.r[L]);
    T(4==step()); T(0x16==cpu.r[A]);
    T(7==step()); T(0x17==cpu.r[H]);
    T(4==step()); T(0x17==cpu.r[B]);
    T(4==step()); T(0x17==cpu.r[C]);
    T(4==step()); T(0x17==cpu.r[D]);
    T(4==step()); T(0x17==cpu.r[E]);
    T(4==step()); T(0x17==cpu.r[H]);
    T(4==step()); T(0x17==cpu.r[L]);
    T(4==step()); T(0x17==cpu.r[A]);
    T(7==step()); T(0x18==cpu.r[L]);
    T(4==step()); T(0x18==cpu.r[B]);
    T(4==step()); T(0x18==cpu.r[C]);
    T(4==step()); T(0x18==cpu.r[D]);
    T(4==step()); T(0x18==cpu.r[E]);
    T(4==step()); T(0x18==cpu.r[H]);
    T(4==step()); T(0x18==cpu.r[L]);
    T(4==step()); T(0x18==cpu.r[A]);
    ok();
}

fn @"LD r,(HL)"() void {
    start("LD r,(HL)");
    const prog = [_]u8{
        0x21, 0x00, 0x10,   // LD HL,0x1000
        0x3E, 0x33,         // LD A,0x33
        0x77,               // LD (HL),A
        0x3E, 0x22,         // LD A,0x22
        0x46,               // LD B,(HL)
        0x4E,               // LD C,(HL)
        0x56,               // LD D,(HL)
        0x5E,               // LD E,(HL)
        0x66,               // LD H,(HL)
        0x26, 0x10,         // LD H,0x10
        0x6E,               // LD L,(HL)
        0x2E, 0x00,         // LD L,0x00
        0x7E,               // LD A,(HL)
    };
    init(0, &prog);
    T(10==step()); T(0x1000 == cpu.HL());
    T(7==step()); T(0x33 == cpu.r[A]);
    T(7==step()); T(0x33 == mem[0x1000]);
    T(7==step()); T(0x22 == cpu.r[A]);
    T(7==step()); T(0x33 == cpu.r[B]);
    T(7==step()); T(0x33 == cpu.r[C]);
    T(7==step()); T(0x33 == cpu.r[D]);
    T(7==step()); T(0x33 == cpu.r[E]);
    T(7==step()); T(0x33 == cpu.r[H]);
    T(7==step()); T(0x10 == cpu.r[H]);
    T(7==step()); T(0x33 == cpu.r[L]);
    T(7==step()); T(0x00 == cpu.r[L]);
    T(7==step()); T(0x33 == cpu.r[A]);
    ok();
}

fn @"LD (HL),r"() void {
    start("LD (HL),r");
    const prog = [_]u8{
        0x21, 0x00, 0x10,   // LD HL,0x1000
        0x3E, 0x12,         // LD A,0x12
        0x77,               // LD (HL),A
        0x06, 0x13,         // LD B,0x13
        0x70,               // LD (HL),B
        0x0E, 0x14,         // LD C,0x14
        0x71,               // LD (HL),C
        0x16, 0x15,         // LD D,0x15
        0x72,               // LD (HL),D
        0x1E, 0x16,         // LD E,0x16
        0x73,               // LD (HL),E
        0x74,               // LD (HL),H
        0x75,               // LD (HL),L
    };
    init(0, &prog);
    T(10==step()); T(0x1000 == cpu.HL());
    T(7==step()); T(0x12 == cpu.r[A]);
    T(7==step()); T(0x12 == mem[0x1000]);
    T(7==step()); T(0x13 == cpu.r[B]);
    T(7==step()); T(0x13 == mem[0x1000]);
    T(7==step()); T(0x14 == cpu.r[C]);
    T(7==step()); T(0x14 == mem[0x1000]);
    T(7==step()); T(0x15 == cpu.r[D]);
    T(7==step()); T(0x15 == mem[0x1000]);
    T(7==step()); T(0x16 == cpu.r[E]);
    T(7==step()); T(0x16 == mem[0x1000]);
    T(7==step()); T(0x10 == mem[0x1000]);
    T(7==step()); T(0x00 == mem[0x1000]);
    ok();
}

fn @"ADD A,r/n"() void {
    start("ADD A,r/n");
    const prog = [_]u8{
        0x3E, 0x0F,     // LD A,0x0F
        0x87,           // ADD A,A
        0x06, 0xE0,     // LD B,0xE0
        0x80,           // ADD A,B
        0x3E, 0x81,     // LD A,0x81
        0x0E, 0x80,     // LD C,0x80
        0x81,           // ADD A,C
        0x16, 0xFF,     // LD D,0xFF
        0x82,           // ADD A,D
        0x1E, 0x40,     // LD E,0x40
        0x83,           // ADD A,E
        0x26, 0x80,     // LD H,0x80
        0x84,           // ADD A,H
        0x2E, 0x33,     // LD L,0x33
        0x85,           // ADD A,L
        0xC6, 0x44,     // ADD A,0x44
    };
    init(0, &prog);
    T(7==step()); T(0x0F == cpu.r[A]); T(flags(0));
    T(4==step()); T(0x1E == cpu.r[A]); T(flags(HF));
    T(7==step()); T(0xE0 == cpu.r[B]);
    T(4==step()); T(0xFE == cpu.r[A]); T(flags(SF));
    T(7==step()); T(0x81 == cpu.r[A]);
    T(7==step()); T(0x80 == cpu.r[C]);
    T(4==step()); T(0x01 == cpu.r[A]); T(flags(VF|CF));
    T(7==step()); T(0xFF == cpu.r[D]);
    T(4==step()); T(0x00 == cpu.r[A]); T(flags(ZF|HF|CF));
    T(7==step()); T(0x40 == cpu.r[E]);
    T(4==step()); T(0x40 == cpu.r[A]); T(flags(0));
    T(7==step()); T(0x80 == cpu.r[H]);
    T(4==step()); T(0xC0 == cpu.r[A]); T(flags(SF));
    T(7==step()); T(0x33 == cpu.r[L]);
    T(4==step()); T(0xF3 == cpu.r[A]); T(flags(SF));
    T(7==step()); T(0x37 == cpu.r[A]); T(flags(CF));
    ok();
}

pub fn main() void {
    NOP();
    @"LD r,s/n"();
    @"LD r,(HL)"();
    @"LD (HL),r"();
    @"ADD A,r/n"();
}
