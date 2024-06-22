//------------------------------------------------------------------------------
//  z80zex.zig
//
//  Runs Frank Cringle's zexdoc and zexall test through the Z80 emu. Provide
//  a minimal CP/M environment to make these work.
//------------------------------------------------------------------------------
const std = @import("std");
const assert = std.debug.assert;
const print = std.debug.print;
const chips = @import("chips");
const bits = chips.bits;
const z80 = chips.z80;

const Bus = u64;
const Z80 = z80.Z80(z80.DefaultPins, Bus);
const MREQ = Z80.MREQ;
const RD = Z80.RD;
const WR = Z80.WR;
const C = Z80.C;
const E = Z80.E;
const WZH = Z80.WZH;
const WZL = Z80.WZL;

var cpu: Z80 = undefined;
var mem = [_]u8{0} ** 0x10000;

fn tick(in_bus: Bus) Bus {
    var bus = cpu.tick(in_bus);
    if (bits.tst(bus, MREQ)) {
        const addr = Z80.getAddr(bus);
        if (bits.tst(bus, RD)) {
            bus = Z80.setData(bus, mem[addr]);
        } else if (bits.tst(bus, WR)) {
            mem[addr] = Z80.getData(bus);
        }
    }
    return bus;
}

fn copy(start_addr: u16, bytes: []const u8) void {
    std.mem.copyForwards(u8, mem[start_addr..], bytes);
}

fn putChar(c: u8) void {
    std.io.getStdErr().writer().writeByte(c) catch @panic("write to stderr failed");
}

// emulate character and string output CP/M calls
fn cpmBDOS() void {
    if (2 == cpu.r[C]) {
        // output character in register E
        putChar(cpu.r[E]);
    } else if (9 == cpu.r[C]) {
        // output string pointed to by register DE
        var addr: u16 = cpu.DE();
        while (mem[addr] != '$') {
            putChar(mem[addr]);
            addr +%= 1;
        }
    } else {
        @panic("Unhandled CP/M system call!");
    }
    // emulate a RET
    cpu.r[WZL] = mem[cpu.SP()];
    cpu.incSP();
    cpu.r[WZH] = mem[cpu.SP()];
    cpu.incSP();
    cpu.pc = cpu.WZ();
}

// run the currently configured test
fn runTest() u64 {
    cpu = Z80{};
    cpu.setSP(0xF000);
    cpu.prefetch(0x0100);
    var num_ticks: u64 = 0;
    var bus: Bus = 0;
    while (true) {
        bus = tick(bus);
        // check for BDOS call
        if (cpu.pc == 5) {
            cpmBDOS();
        } else if (cpu.pc == 0) {
            break;
        }
        num_ticks += 1;
    }
    return num_ticks;
}

fn zexall() !void {
    print("ZEXALL...\n\n", .{});
    copy(0x0100, @embedFile("roms/zexall.com"));
    var timer = try std.time.Timer.start();
    const num_ticks = runTest();
    const ns: f64 = @floatFromInt(timer.read());
    print("\n{} ticks in {d:.4} seconds\n", .{ num_ticks, ns / std.time.ns_per_s });
}

pub fn main() !void {
    try zexall();
}
