const std = @import("std");
const cli = @import("client/cli.zig");

pub fn main() !void {
    try cli.runCli();
}