//! TODO: Z80 CTC implementation

const Self = @This();

const Pins = struct {
    D: [8]comptime_int,
    CE: comptime_int,
    CS: [2]comptime_int,
    M1: comptime_int,
    IORQ: comptime_int,
    RD: comptime_int,
    IEI: comptime_int,
    IEO: comptime_int,
    INT: comptime_int,
    CLKTRG0: comptime_int,
    ZCTO0: comptime_int,
    CLKTRG1: comptime_int,
    ZCTO1: comptime_int,
    CLKTRG2: comptime_int,
    ZCTO2: comptime_int,
    CLKTRG3: comptime_int,
    RESET: comptime_int,
};
