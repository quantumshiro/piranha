//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");
const testing = std.testing;

// Re-export common modules
pub const crypto = @import("common/crypto.zig");
pub const signature = @import("common/signature.zig");
pub const cell = @import("common/cell.zig");
pub const net = @import("common/net.zig");
pub const ntor = @import("common/ntor.zig");

pub export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}
