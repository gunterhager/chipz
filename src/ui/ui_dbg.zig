//! Z80 CPU debugger UI.
//!
//! Shows a disassembly view centered on the current PC, with step/continue
//! controls, breakpoints, and execution history.
const std = @import("std");
const z80dasm = @import("chips").z80dasm;
const ig = @import("cimgui");
const ui_settings = @import("ui_settings.zig");

pub const MAX_BREAKPOINTS = 32;
pub const NUM_HISTORY = 256;
pub const NUM_DBG_LINES = 48;

pub const TypeConfig = struct {
    bus: type,
    cpu: type,
};

pub const StepMode = enum { none, into, over, tick };

pub const Breakpoint = struct {
    addr: u16,
    enabled: bool,
};

pub fn Type(comptime cfg: TypeConfig) type {
    return struct {
        const Self = @This();
        const Bus = cfg.bus;
        const Z80 = cfg.cpu;

        const M1_MASK = Z80.M1 | Z80.MREQ | Z80.RD;

        pub const Options = struct {
            title: []const u8,
            cpu: *Z80,
            read_cb: *const fn (addr: u16, userdata: ?*anyopaque) u8,
            userdata: ?*anyopaque,
            origin: ig.ImVec2,
            size: ig.ImVec2 = .{},
            open: bool = false,
        };

        const DasmLine = struct {
            addr: u16,
            num_bytes: u8,
            bytes: [4]u8,
            mnemonic: [z80dasm.MAX_MNEMONIC_LEN]u8,
            mnemonic_len: u8,
            cycles: u8,
            cycles_alt: u8,
        };

        title: []const u8,
        cpu: *Z80,
        read_cb: *const fn (addr: u16, userdata: ?*anyopaque) u8,
        userdata: ?*anyopaque,
        origin: ig.ImVec2,
        size: ig.ImVec2,
        open: bool,
        last_open: bool,
        valid: bool,

        stopped: bool,
        step_mode: StepMode,
        cur_op_pc: u16,
        stepover_pc: u16,

        num_breakpoints: u8,
        breakpoints: [MAX_BREAKPOINTS]Breakpoint,
        last_triggered_bp: i8, // index of BP that caused last stop; -1 = none/step
        delete_bp_index: i8, // pending delete confirmation index; -1 = none
        show_breakpoints: bool,

        history: [NUM_HISTORY]u16,
        history_pos: u8,

        show_heatmap: bool,
        show_history: bool,

        show_registers: bool,
        show_buttons: bool,
        show_bytes: bool,
        show_ticks: bool,

        dasm_lines: [NUM_DBG_LINES]DasmLine,
        dasm_num_lines: u8,

        pub fn initInPlace(self: *Self, opts: Options) void {
            self.* = .{
                .title = opts.title,
                .cpu = opts.cpu,
                .read_cb = opts.read_cb,
                .userdata = opts.userdata,
                .origin = opts.origin,
                .size = .{
                    .x = if (opts.size.x == 0) 560 else opts.size.x,
                    .y = if (opts.size.y == 0) 520 else opts.size.y,
                },
                .open = opts.open,
                .last_open = opts.open,
                .valid = true,
                .stopped = false,
                .step_mode = .none,
                .cur_op_pc = opts.cpu.pc,
                .stepover_pc = 0,
                .num_breakpoints = 0,
                .breakpoints = [_]Breakpoint{.{ .addr = 0, .enabled = false }} ** MAX_BREAKPOINTS,
                .last_triggered_bp = -1,
                .delete_bp_index = -1,
                .show_breakpoints = false,
                .history = [_]u16{0} ** NUM_HISTORY,
                .history_pos = 0,
                .show_history = false,
                .show_heatmap = false,
                .show_registers = true,
                .show_buttons = true,
                .show_bytes = true,
                .show_ticks = true,
                .dasm_lines = undefined,
                .dasm_num_lines = 0,
            };
        }

        pub fn discard(self: *Self) void {
            self.valid = false;
        }

        pub fn isStopped(self: *const Self) bool {
            return self.stopped;
        }

        /// Returns true if tick-by-tick execution is needed
        /// (step mode active or breakpoints enabled).
        pub fn needsTickDebug(self: *const Self) bool {
            if (self.step_mode != .none) return true;
            for (self.breakpoints[0..self.num_breakpoints]) |bp| {
                if (bp.enabled) return true;
            }
            return false;
        }

        /// Call after each individual CPU tick.
        /// Returns true if execution should stop.
        pub fn tick(self: *Self, pins: Bus) bool {
            const is_tick_step = self.step_mode == .tick;
            if (pins & M1_MASK == M1_MASK) {
                const pc = Z80.getAddr(pins);
                self.cur_op_pc = pc;
                self.history[self.history_pos] = pc;
                self.history_pos +%= 1;
                for (self.breakpoints[0..self.num_breakpoints], 0..) |bp, i| {
                    if (bp.enabled and bp.addr == pc) {
                        self.stopped = true;
                        self.step_mode = .none;
                        self.last_triggered_bp = @intCast(i);
                        return true;
                    }
                }
                if (self.step_mode == .into) {
                    self.stopped = true;
                    self.step_mode = .none;
                    self.last_triggered_bp = -1;
                    return true;
                }
                if (self.step_mode == .over and pc == self.stepover_pc) {
                    self.stopped = true;
                    self.step_mode = .none;
                    self.last_triggered_bp = -1;
                    return true;
                }
            }
            if (is_tick_step) {
                self.stopped = true;
                self.step_mode = .none;
                self.last_triggered_bp = -1;
                return true;
            }
            return false;
        }

        /// Call after each CPU tick during full-speed execution to track the
        /// current PC. Lightweight: only updates cur_op_pc on M1 cycles.
        pub fn updatePc(self: *Self, pins: Bus) void {
            if (pins & M1_MASK == M1_MASK) {
                self.cur_op_pc = Z80.getAddr(pins);
            }
        }

        pub fn breakExec(self: *Self) void {
            self.stopped = true;
            self.step_mode = .none;
        }

        pub fn continueExec(self: *Self) void {
            self.stopped = false;
            self.step_mode = .none;
        }

        pub fn stepInto(self: *Self) void {
            self.stopped = false;
            self.step_mode = .into;
        }

        pub fn stepOver(self: *Self) void {
            const opcode = self.read_cb(self.cur_op_pc, self.userdata);
            const is_stepover_op = switch (opcode) {
                0xCD, 0xDC, 0xFC, 0xD4, 0xC4, 0xF4, 0xEC, 0xE4, 0xCC, 0x10 => true,
                else => false,
            };
            if (is_stepover_op) {
                const res = z80dasm.op(self.cur_op_pc, self.read_cb, self.userdata);
                self.stepover_pc = res.next_pc;
                self.stopped = false;
                self.step_mode = .over;
            } else {
                self.stepInto();
            }
        }

        pub fn stepTick(self: *Self) void {
            self.stopped = false;
            self.step_mode = .tick;
        }

        fn hasBreakpointAt(self: *const Self, addr: u16) bool {
            for (self.breakpoints[0..self.num_breakpoints]) |bp| {
                if (bp.addr == addr) return true;
            }
            return false;
        }

        fn isBreakpointEnabled(self: *const Self, addr: u16) bool {
            for (self.breakpoints[0..self.num_breakpoints]) |bp| {
                if (bp.addr == addr and bp.enabled) return true;
            }
            return false;
        }

        pub fn addBreakpoint(self: *Self, addr: u16) void {
            if (self.num_breakpoints >= MAX_BREAKPOINTS) return;
            for (self.breakpoints[0..self.num_breakpoints]) |*bp| {
                if (bp.addr == addr) {
                    bp.enabled = true;
                    return;
                }
            }
            self.breakpoints[self.num_breakpoints] = .{ .addr = addr, .enabled = true };
            self.num_breakpoints += 1;
        }

        pub fn removeBreakpoint(self: *Self, addr: u16) void {
            for (self.breakpoints[0..self.num_breakpoints], 0..) |bp, i| {
                if (bp.addr == addr) {
                    self.removeBreakpointByIndex(i);
                    return;
                }
            }
        }

        fn removeBreakpointByIndex(self: *Self, index: usize) void {
            var j = index;
            while (j + 1 < self.num_breakpoints) : (j += 1) {
                self.breakpoints[j] = self.breakpoints[j + 1];
            }
            self.num_breakpoints -= 1;
        }

        pub fn toggleBreakpoint(self: *Self, addr: u16) void {
            if (self.hasBreakpointAt(addr)) {
                self.removeBreakpoint(addr);
            } else {
                self.addBreakpoint(addr);
            }
        }

        fn rebuildDasm(self: *Self, center_pc: u16) void {
            const look_back: u16 = 5 * 4;
            const start = center_pc -% look_back;
            var pc: u16 = start;
            var n: u8 = 0;
            while (n < NUM_DBG_LINES) {
                const op_addr = pc;
                const res = z80dasm.op(pc, self.read_cb, self.userdata);
                var line = DasmLine{
                    .addr = op_addr,
                    .num_bytes = res.num_bytes,
                    .bytes = undefined,
                    .mnemonic = res.mnemonic,
                    .mnemonic_len = res.mnemonic_len,
                    .cycles = res.cycles,
                    .cycles_alt = res.cycles_alt,
                };
                for (0..res.num_bytes) |bi| {
                    line.bytes[bi] = self.read_cb(op_addr +% @as(u16, @intCast(bi)), self.userdata);
                }
                self.dasm_lines[n] = line;
                n += 1;
                pc = res.next_pc;
            }
            self.dasm_num_lines = n;
        }

        fn drawMenuBar(self: *Self) void {
            if (ig.igBeginMenuBar()) {
                if (ig.igBeginMenu("Debug")) {
                    if (ig.igMenuItemEx(if (self.stopped) "Continue [F5]" else "Break [F5]", null, false, true)) {
                        if (self.stopped) self.continueExec() else self.breakExec();
                    }
                    ig.igSeparator();
                    if (ig.igMenuItemEx("Step Over [F6]", null, false, self.stopped)) self.stepOver();
                    if (ig.igMenuItemEx("Step Into [F7]", null, false, self.stopped)) self.stepInto();
                    ig.igSeparator();
                    if (ig.igMenuItemEx("Add Breakpoint [F9]", null, false, true)) self.toggleBreakpoint(self.cur_op_pc);
                    ig.igEndMenu();
                }
                _ = ig.igMenuItemBoolPtr("Breakpoints", null, &self.show_breakpoints, true);

                if (ig.igBeginMenu("Show")) {
                    _ = ig.igMenuItemBoolPtr("Memory Heatmap", null, &self.show_heatmap, true);
                    _ = ig.igMenuItemBoolPtr("Execution History", null, &self.show_history, true);
                    _ = ig.igMenuItemBoolPtr("Breakpoints", null, &self.show_breakpoints, true);
                    ig.igSeparator();
                    _ = ig.igMenuItemBoolPtr("Registers", null, &self.show_registers, true);
                    _ = ig.igMenuItemBoolPtr("Button bar", null, &self.show_buttons, true);
                    _ = ig.igMenuItemBoolPtr("Opcode Bytes", null, &self.show_bytes, true);
                    _ = ig.igMenuItemBoolPtr("Opcode Ticks", null, &self.show_ticks, true);
                    ig.igEndMenu();
                }

                ig.igEndMenuBar();
            }
        }

        fn drawReg(comptime T: type, id: [*c]const u8, label: [*c]const u8, width: f32, ptr: *T) bool {
            const data_type = if (T == u16) ig.ImGuiDataType_U16 else ig.ImGuiDataType_U8;
            const fmt: [*c]const u8 = if (T == u16) "%04X" else "%02X";
            ig.igPushItemWidth(width);
            const changed = ig.igInputScalarEx(id, data_type, ptr, null, null, fmt, ig.ImGuiInputTextFlags_CharsHexadecimal);
            ig.igPopItemWidth();
            ig.igSameLine();
            ig.igTextUnformatted(label);
            return changed;
        }

        fn drawRegisters(self: *Self) void {
            const gw = ig.igCalcTextSize("F").x;
            const w16: f32 = gw * 4 + 8;
            const w8: f32 = gw * 2 + 8;

            if (ig.igBeginTable("##z80_registers", 5, ig.ImGuiTableFlags_None)) {
                for (0..5) |_| {
                    ig.igTableSetupColumnEx("", ig.ImGuiTableColumnFlags_WidthFixed, 64, 0);
                }

                // Row 1: AF BC DE HL WZ
                ig.igTableNextRow();
                _ = ig.igTableNextColumn();
                var t_af = self.cpu.AF();
                if (drawReg(u16, "##r_af", "AF", w16, &t_af)) self.cpu.setAF(t_af);
                _ = ig.igTableNextColumn();
                var t_bc = self.cpu.BC();
                if (drawReg(u16, "##r_bc", "BC", w16, &t_bc)) self.cpu.setBC(t_bc);
                _ = ig.igTableNextColumn();
                var t_de = self.cpu.DE();
                if (drawReg(u16, "##r_de", "DE", w16, &t_de)) self.cpu.setDE(t_de);
                _ = ig.igTableNextColumn();
                var t_hl = self.cpu.HL();
                if (drawReg(u16, "##r_hl", "HL", w16, &t_hl)) self.cpu.setHL(t_hl);
                _ = ig.igTableNextColumn();
                var t_wz = self.cpu.WZ();
                if (drawReg(u16, "##r_wz", "WZ", w16, &t_wz)) self.cpu.setWZ(t_wz);

                // Row 2: AF' BC' DE' HL' I
                ig.igTableNextRow();
                _ = ig.igTableNextColumn();
                _ = drawReg(u16, "##r_af2", "AF'", w16, &self.cpu.af2);
                _ = ig.igTableNextColumn();
                _ = drawReg(u16, "##r_bc2", "BC'", w16, &self.cpu.bc2);
                _ = ig.igTableNextColumn();
                _ = drawReg(u16, "##r_de2", "DE'", w16, &self.cpu.de2);
                _ = ig.igTableNextColumn();
                _ = drawReg(u16, "##r_hl2", "HL'", w16, &self.cpu.hl2);
                _ = ig.igTableNextColumn();
                var t_i = self.cpu.I();
                if (drawReg(u8, "##r_i", "I", w8, &t_i)) self.cpu.setI(t_i);

                // Row 3: IX IY SP PC R
                ig.igTableNextRow();
                _ = ig.igTableNextColumn();
                var t_ix = self.cpu.IX();
                if (drawReg(u16, "##r_ix", "IX", w16, &t_ix)) self.cpu.setIX(t_ix);
                _ = ig.igTableNextColumn();
                var t_iy = self.cpu.IY();
                if (drawReg(u16, "##r_iy", "IY", w16, &t_iy)) self.cpu.setIY(t_iy);
                _ = ig.igTableNextColumn();
                var t_sp = self.cpu.SP();
                if (drawReg(u16, "##r_sp", "SP", w16, &t_sp)) self.cpu.setSP(t_sp);
                _ = ig.igTableNextColumn();
                _ = drawReg(u16, "##r_pc", "PC", w16, &self.cpu.pc);
                _ = ig.igTableNextColumn();
                var t_r = self.cpu.R();
                if (drawReg(u8, "##r_r", "R", w8, &t_r)) self.cpu.setR(t_r);

                // Row 4: IM IFF1 IFF2 flags
                ig.igTableNextRow();
                _ = ig.igTableNextColumn();
                _ = drawReg(u8, "##r_im", "IM", w8, &self.cpu.im);

                _ = ig.igTableNextColumn();
                {
                    ig.igAlignTextToFramePadding();
                    if (self.cpu.iff1 != 0) {
                        ig.igText("IFF1");
                    } else {
                        ig.igTextDisabled("IFF1");
                    }
                }
                _ = ig.igTableNextColumn();
                {
                    ig.igAlignTextToFramePadding();
                    if (self.cpu.iff2 != 0) {
                        ig.igText("IFF2");
                    } else {
                        ig.igTextDisabled("IFF2");
                    }
                }
                _ = ig.igTableNextColumn();
                {
                    const f = self.cpu.r[Z80.F];
                    const flags = [9]u8{
                        if ((f & Z80.SF) != 0) 'S' else '-',
                        if ((f & Z80.ZF) != 0) 'Z' else '-',
                        if ((f & Z80.YF) != 0) 'Y' else '-',
                        if ((f & Z80.HF) != 0) 'H' else '-',
                        if ((f & Z80.XF) != 0) 'X' else '-',
                        if ((f & Z80.VF) != 0) 'V' else '-',
                        if ((f & Z80.NF) != 0) 'N' else '-',
                        if ((f & Z80.CF) != 0) 'C' else '-',
                        0,
                    };
                    ig.igText(&flags);
                }

                ig.igEndTable();
            }
        }

        fn drawBreakpoints(self: *Self) void {
            if (!self.show_breakpoints) return;
            ig.igSetNextWindowSize(.{ .x = 400, .y = 256 }, ig.ImGuiCond_FirstUseEver);
            if (ig.igBegin("Breakpoints", &self.show_breakpoints, ig.ImGuiWindowFlags_None)) {
                var scroll_down = false;
                if (ig.igButton("Add..")) {
                    self.addBreakpoint(self.cur_op_pc);
                    scroll_down = true;
                }
                ig.igSameLine();
                if (ig.igButton("Disable All")) {
                    for (self.breakpoints[0..self.num_breakpoints]) |*bp| {
                        bp.enabled = false;
                    }
                }
                ig.igSameLine();
                if (ig.igButton("Enable All")) {
                    for (self.breakpoints[0..self.num_breakpoints]) |*bp| {
                        bp.enabled = true;
                    }
                }
                ig.igSameLine();
                if (ig.igButton("Delete All")) {
                    ig.igOpenPopup("Delete All?", ig.ImGuiPopupFlags_None);
                }
                if (ig.igBeginPopupModal("Delete All?", null, ig.ImGuiWindowFlags_AlwaysAutoResize)) {
                    ig.igTextUnformatted("Delete all breakpoints?");
                    ig.igSeparator();
                    if (ig.igButton("Ok")) {
                        self.num_breakpoints = 0;
                        self.last_triggered_bp = -1;
                        ig.igCloseCurrentPopup();
                    }
                    ig.igSameLine();
                    if (ig.igButton("Cancel")) {
                        ig.igCloseCurrentPopup();
                    }
                    ig.igEndPopup();
                }
                ig.igSeparator();
                _ = ig.igBeginChild("##bp_list", .{}, ig.ImGuiChildFlags_None, ig.ImGuiWindowFlags_None);
                var del_index: i8 = -1;
                for (self.breakpoints[0..self.num_breakpoints], 0..) |*bp, i| {
                    ig.igPushIDInt(@as(c_int, @intCast(i)));
                    const is_active = self.last_triggered_bp >= 0 and @as(usize, @intCast(self.last_triggered_bp)) == i;
                    if (is_active) {
                        ig.igPushStyleColor(ig.ImGuiCol_CheckMark, 0xFF0000FF);
                    }
                    _ = ig.igCheckbox("##en", &bp.enabled);
                    if (is_active) {
                        ig.igPopStyleColor();
                    }
                    ig.igSameLine();
                    ig.igPushItemWidth(60);
                    _ = ig.igInputScalarEx("##addr", ig.ImGuiDataType_U16, &bp.addr, null, null, "%04X", ig.ImGuiInputTextFlags_CharsHexadecimal);
                    ig.igPopItemWidth();
                    ig.igSameLine();
                    if (ig.igButton("Del")) {
                        del_index = @intCast(i);
                    }
                    ig.igPopID();
                }
                if (del_index >= 0) {
                    self.delete_bp_index = del_index;
                    ig.igOpenPopup("Delete?", ig.ImGuiPopupFlags_None);
                }
                if (self.delete_bp_index >= 0 and ig.igBeginPopupModal("Delete?", null, ig.ImGuiWindowFlags_AlwaysAutoResize)) {
                    var addr_buf: [16]u8 = undefined;
                    const s = std.fmt.bufPrint(&addr_buf, "Delete breakpoint at {X:0>4}?\x00", .{
                        self.breakpoints[@intCast(self.delete_bp_index)].addr,
                    }) catch unreachable;
                    _ = s;
                    ig.igTextUnformatted(&addr_buf);
                    ig.igSeparator();
                    if (ig.igButton("Ok")) {
                        self.removeBreakpointByIndex(@intCast(self.delete_bp_index));
                        if (self.last_triggered_bp == self.delete_bp_index) self.last_triggered_bp = -1;
                        self.delete_bp_index = -1;
                        ig.igCloseCurrentPopup();
                    }
                    ig.igSameLine();
                    if (ig.igButton("Cancel")) {
                        self.delete_bp_index = -1;
                        ig.igCloseCurrentPopup();
                    }
                    ig.igEndPopup();
                }
                if (scroll_down) ig.igSetScrollHereY(1.0);
                ig.igEndChild();
            }
            ig.igEnd();
        }

        fn drawButtons(self: *Self) void {
            const stopped = self.stopped;
            if (stopped) {
                if (ig.igButton("Continue [F5]")) self.continueExec();
            } else {
                if (ig.igButton("Break [F5]")) self.breakExec();
            }
            if (stopped) {
                ig.igSameLine();
                if (ig.igButton("Over [F6]")) self.stepOver();
                ig.igSameLine();
                if (ig.igButton("Into [F7]")) self.stepInto();
                ig.igSameLine();
                if (ig.igButton("Tick [F8]")) self.stepTick();
            }
        }

        fn drawDisasm(self: *Self) void {
            self.rebuildDasm(self.cur_op_pc);

            const glyph_width = ig.igCalcTextSize("F").x;
            const cell_width = 3.0 * glyph_width;

            ig.igPushStyleVarImVec2(ig.ImGuiStyleVar_FramePadding, .{ .x = 0, .y = 0 });
            ig.igPushStyleVarImVec2(ig.ImGuiStyleVar_ItemSpacing, .{ .x = 0, .y = 0 });

            const avail = ig.igGetContentRegionAvail();
            _ = ig.igBeginChild("##dbg_dasm", .{ .x = avail.x, .y = avail.y }, ig.ImGuiChildFlags_None, ig.ImGuiWindowFlags_None);

            for (self.dasm_lines[0..self.dasm_num_lines]) |line| {
                const is_cur = line.addr == self.cur_op_pc;
                const has_bp = self.isBreakpointEnabled(line.addr);

                var num_color_pushes: c_int = 0;
                if (is_cur) {
                    ig.igPushStyleColor(ig.ImGuiCol_Header, 0x6000FFFF); // semi-transparent yellow bg
                    num_color_pushes += 1;
                }
                if (has_bp) {
                    ig.igPushStyleColor(ig.ImGuiCol_Text, 0xFF4040FF); // red text
                    num_color_pushes += 1;
                }

                ig.igPushIDInt(@as(c_int, @intCast(line.addr)));

                // Clickable indicator + address column
                const indicator: []const u8 = if (has_bp) (if (is_cur) ">*" else " *") else (if (is_cur) "> " else "  ");
                var row_buf: [16]u8 = undefined;
                const row_s = std.fmt.bufPrint(&row_buf, "{s}{X:0>4}: \x00", .{ indicator, line.addr }) catch unreachable;
                _ = row_s;
                if (ig.igSelectableEx(&row_buf, is_cur, ig.ImGuiSelectableFlags_None, .{})) {
                    self.toggleBreakpoint(line.addr);
                }
                ig.igSameLine();

                // Bytes
                const line_start_x = ig.igGetCursorPosX();
                for (0..line.num_bytes) |bi| {
                    ig.igSameLineEx(line_start_x + cell_width * @as(f32, @floatFromInt(bi)), 0);
                    var byte_buf: [4]u8 = undefined;
                    const bs = std.fmt.bufPrint(&byte_buf, "{X:0>2} \x00", .{line.bytes[bi]}) catch unreachable;
                    _ = bs;
                    ig.igTextUnformatted(&byte_buf);
                }

                // Mnemonic
                ig.igSameLineEx(line_start_x + cell_width * 4 + glyph_width, 0);
                var mn_buf: [z80dasm.MAX_MNEMONIC_LEN + 1]u8 = undefined;
                @memcpy(mn_buf[0..line.mnemonic_len], line.mnemonic[0..line.mnemonic_len]);
                mn_buf[line.mnemonic_len] = 0;
                ig.igTextUnformatted(&mn_buf);

                // Cycles column
                ig.igSameLineEx(line_start_x + cell_width * 4 + glyph_width * 22, 0);
                if (line.cycles == 0) {
                    ig.igTextUnformatted("?");
                } else if (line.cycles_alt != 0) {
                    var cy_buf: [8]u8 = undefined;
                    const cs = std.fmt.bufPrint(&cy_buf, "{}/{}\x00", .{ line.cycles, line.cycles_alt }) catch unreachable;
                    _ = cs;
                    ig.igTextUnformatted(&cy_buf);
                } else {
                    var cy_buf: [8]u8 = undefined;
                    const cs = std.fmt.bufPrint(&cy_buf, "{}\x00", .{line.cycles}) catch unreachable;
                    _ = cs;
                    ig.igTextUnformatted(&cy_buf);
                }

                ig.igPopID();

                if (num_color_pushes > 0) ig.igPopStyleColorEx(num_color_pushes);

                if (is_cur) ig.igSetScrollHereY(0.3);
            }

            ig.igEndChild();
            ig.igPopStyleVarEx(2);
        }

        fn drawHistory(self: *Self) void {
            if (!ig.igBegin("Execution History", &self.show_history, ig.ImGuiWindowFlags_None)) {
                ig.igEnd();
                return;
            }
            if (ig.igBeginListBox("##history", .{ .x = -1, .y = -1 })) {
                const show: u8 = @min(64, self.history_pos);
                var i: usize = @as(usize, self.history_pos);
                var cnt: u8 = show;
                while (cnt > 0) {
                    cnt -= 1;
                    if (i == 0) i = NUM_HISTORY;
                    i -= 1;
                    var buf: [8]u8 = undefined;
                    const s = std.fmt.bufPrint(&buf, "{X:0>4}\x00", .{self.history[i]}) catch unreachable;
                    _ = s;
                    ig.igTextUnformatted(&buf);
                }
                ig.igEndListBox();
            }
            ig.igEnd();
        }

        fn handleKeys(self: *Self) void {
            if (ig.igIsKeyPressedEx(ig.ImGuiKey_F5, false)) {
                if (self.stopped) self.continueExec() else self.breakExec();
            }
            if (self.stopped) {
                if (ig.igIsKeyPressedEx(ig.ImGuiKey_F6, false)) self.stepOver();
                if (ig.igIsKeyPressedEx(ig.ImGuiKey_F7, false)) self.stepInto();
                if (ig.igIsKeyPressedEx(ig.ImGuiKey_F8, false)) self.stepTick();
                if (ig.igIsKeyPressedEx(ig.ImGuiKey_F9, false)) self.toggleBreakpoint(self.cur_op_pc);
            }
        }

        pub fn draw(self: *Self, bus: Bus) void {
            _ = bus;
            if (self.open != self.last_open) self.last_open = self.open;
            if (!self.open) return;

            self.handleKeys();
            if (self.show_history) self.drawHistory();
            self.drawBreakpoints();

            ig.igSetNextWindowPos(self.origin, ig.ImGuiCond_FirstUseEver);
            ig.igSetNextWindowSize(self.size, ig.ImGuiCond_FirstUseEver);
            if (ig.igBegin(self.title.ptr, &self.open, ig.ImGuiWindowFlags_MenuBar)) {
                self.drawMenuBar();
                if (self.show_registers) {
                    self.drawRegisters();
                    ig.igSeparator();
                }
                if (self.show_buttons) {
                    self.drawButtons();
                    ig.igSeparator();
                }
                self.drawDisasm();
            }
            ig.igEnd();
        }

        pub fn saveSettings(self: *Self, settings: *ui_settings.Settings) void {
            _ = settings.add(self.title, self.open);
        }

        pub fn loadSettings(self: *Self, settings: *const ui_settings.Settings) void {
            self.open = settings.isOpen(self.title);
        }
    };
}
