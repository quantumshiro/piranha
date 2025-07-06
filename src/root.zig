//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");
const testing = std.testing;

// Re-export common modules
pub const crypto = @import("crypto");
pub const signature = @import("signature");
pub const cell = @import("cell");
pub const net = @import("net");
pub const ntor = @import("ntor");

pub export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}
