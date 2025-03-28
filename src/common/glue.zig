//! host bindings

pub const Rect = struct {
    x: i32 = 0,
    y: i32 = 0,
    width: i32 = 0,
    height: i32 = 0,
};

pub const Dim = struct {
    width: i32 = 0,
    height: i32 = 0,
};

/// display orientation
pub const DisplayOrientation = enum {
    Landscape,
    Portrait,
};

/// describe emulator display info back to the host
pub const DisplayInfo = struct {
    /// framebuffer properties
    fb: struct {
        /// framebuffer dimensions in pixels
        dim: Dim,
        /// slice to the actual framebuffer pixels
        buffer: ?union(enum) {
            Palette8: []const u8,
            Rgba8: []const u32,
        },
    },
    /// the visible area of the framebuffer
    view: Rect,
    /// optional color palette (always in RGBA8 format)
    palette: ?[]const u32,
    /// display orientation
    orientation: DisplayOrientation,
};
