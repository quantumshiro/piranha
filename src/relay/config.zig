const std = @import("std");
const testing = std.testing;

pub const RelayConfig = struct {
    listen_addr: []const u8,
    cert_path: []const u8,
    key_path: []const u8,
    max_circuits: u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) RelayConfig {
        return RelayConfig{
            .listen_addr = "",
            .cert_path = "",
            .key_path = "",
            .max_circuits = 1024,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RelayConfig) void {
        if (self.listen_addr.len > 0) self.allocator.free(self.listen_addr);
        if (self.cert_path.len > 0) self.allocator.free(self.cert_path);
        if (self.key_path.len > 0) self.allocator.free(self.key_path);
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, file_path: []const u8) !RelayConfig {
        const file = std.fs.cwd().openFile(file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                std.log.err("Config file not found: {s}", .{file_path});
                return err;
            },
            else => return err,
        };
        defer file.close();

        const file_size = try file.getEndPos();
        const contents = try allocator.alloc(u8, file_size);
        defer allocator.free(contents);
        _ = try file.readAll(contents);

        return try parseFromJson(allocator, contents);
    }

    pub fn parseFromJson(allocator: std.mem.Allocator, json_data: []const u8) !RelayConfig {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_data, .{});
        defer parsed.deinit();

        const root = parsed.value.object;

        var config = RelayConfig.init(allocator);

        if (root.get("listen_addr")) |addr_value| {
            if (addr_value == .string) {
                config.listen_addr = try allocator.dupe(u8, addr_value.string);
            }
        }

        if (root.get("cert_path")) |cert_value| {
            if (cert_value == .string) {
                config.cert_path = try allocator.dupe(u8, cert_value.string);
            }
        }

        if (root.get("key_path")) |key_value| {
            if (key_value == .string) {
                config.key_path = try allocator.dupe(u8, key_value.string);
            }
        }

        if (root.get("max_circuits")) |max_circuits_value| {
            if (max_circuits_value == .integer) {
                config.max_circuits = @intCast(max_circuits_value.integer);
            }
        }

        return config;
    }

    pub fn validate(self: *const RelayConfig) !void {
        if (self.listen_addr.len == 0) {
            return error.MissingListenAddress;
        }

        if (std.mem.indexOf(u8, self.listen_addr, ":") == null) {
            return error.InvalidListenAddress;
        }

        if (self.max_circuits == 0) {
            return error.InvalidMaxCircuits;
        }
    }

    pub fn getListenPort(self: *const RelayConfig) !u16 {
        const colon_pos = std.mem.lastIndexOf(u8, self.listen_addr, ":") orelse return error.InvalidListenAddress;
        const port_str = self.listen_addr[colon_pos + 1 ..];
        return try std.fmt.parseInt(u16, port_str, 10);
    }

    pub fn getListenHost(self: *const RelayConfig, allocator: std.mem.Allocator) ![]u8 {
        const colon_pos = std.mem.lastIndexOf(u8, self.listen_addr, ":") orelse return error.InvalidListenAddress;
        return try allocator.dupe(u8, self.listen_addr[0..colon_pos]);
    }

    pub fn hasTls(self: *const RelayConfig) bool {
        return self.cert_path.len > 0 and self.key_path.len > 0;
    }
};

test "RelayConfig JSON parsing" {
    const allocator = testing.allocator;

    const json_data =
        \\{
        \\  "listen_addr": "0.0.0.0:9001",
        \\  "cert_path": "/etc/tor-zig/relay.crt",
        \\  "key_path": "/etc/tor-zig/relay.key",
        \\  "max_circuits": 1024
        \\}
    ;

    var config = try RelayConfig.parseFromJson(allocator, json_data);
    defer config.deinit();

    try testing.expectEqualStrings("0.0.0.0:9001", config.listen_addr);
    try testing.expectEqualStrings("/etc/tor-zig/relay.crt", config.cert_path);
    try testing.expectEqualStrings("/etc/tor-zig/relay.key", config.key_path);
    try testing.expectEqual(@as(u32, 1024), config.max_circuits);
}

test "RelayConfig validation" {
    const allocator = testing.allocator;

    var valid_config = RelayConfig{
        .listen_addr = try allocator.dupe(u8, "127.0.0.1:9001"),
        .cert_path = try allocator.dupe(u8, "/tmp/cert.crt"),
        .key_path = try allocator.dupe(u8, "/tmp/key.key"),
        .max_circuits = 512,
        .allocator = allocator,
    };
    defer valid_config.deinit();

    try valid_config.validate();

    const port = try valid_config.getListenPort();
    try testing.expectEqual(@as(u16, 9001), port);

    const host = try valid_config.getListenHost(allocator);
    defer allocator.free(host);
    try testing.expectEqualStrings("127.0.0.1", host);

    try testing.expect(valid_config.hasTls());
}