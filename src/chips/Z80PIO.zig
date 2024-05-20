//! TODO: Z80 PIO implementation

const Self = @This();

const Pins = struct {
    D: [8]comptime_int,
    A: [8]comptime_int,
    ARDY: comptime_int,
    ASTB: comptime_int,
    B: [8]comptime_int,
    BRDY: comptime_int,
    BSTB: comptime_int,
    BASEL: comptime_int,
    CDSEL: comptime_int,
    CE: comptime_int,
    M1: comptime_int,
    IORQ: comptime_int,
    RD: comptime_int,
    INT: comptime_int,
    IEI: comptime_int,
    IEO: comptime_int,
};
