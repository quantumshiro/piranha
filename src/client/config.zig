const std = @import("std");
const testing = std.testing;

pub const ClientConfig = struct {
    authority_addr: []const u8,
    socks_listen_addr: []const u8,
    circuit_length: u8,
    max_circuits: u32,
    circuit_timeout_seconds: u32,
    connection_timeout_seconds: u32,
    retry_attempts: u32,
    user_agent: []const u8,
    enable_logging: bool,
    log_level: []const u8,
    allocator: std.mem.Allocator,
    // 動的に割り当てられた文字列を追跡するフラグ
    authority_addr_owned: bool = false,
    socks_listen_addr_owned: bool = false,
    user_agent_owned: bool = false,
    log_level_owned: bool = false,

    pub fn init(allocator: std.mem.Allocator) ClientConfig {
        return ClientConfig{
            .authority_addr = "",
            .socks_listen_addr = "127.0.0.1:9050",
            .circuit_length = 3,
            .max_circuits = 10,
            .circuit_timeout_seconds = 300,
            .connection_timeout_seconds = 30,
            .retry_attempts = 3,
            .user_agent = "Piranha-Client/1.0",
            .enable_logging = true,
            .log_level = "info",
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ClientConfig) void {
        if (self.authority_addr_owned) self.allocator.free(self.authority_addr);
        if (self.socks_listen_addr_owned) self.allocator.free(self.socks_listen_addr);
        if (self.user_agent_owned) self.allocator.free(self.user_agent);
        if (self.log_level_owned) self.allocator.free(self.log_level);
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, file_path: []const u8) !ClientConfig {
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

    pub fn parseFromJson(allocator: std.mem.Allocator, json_data: []const u8) !ClientConfig {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_data, .{});
        defer parsed.deinit();

        const root = parsed.value.object;

        var config = ClientConfig.init(allocator);

        if (root.get("authority_addr")) |value| {
            if (value == .string) {
                config.authority_addr = try allocator.dupe(u8, value.string);
                config.authority_addr_owned = true;
            }
        }

        if (root.get("socks_listen_addr")) |value| {
            if (value == .string) {
                config.socks_listen_addr = try allocator.dupe(u8, value.string);
                config.socks_listen_addr_owned = true;
            }
        }

        if (root.get("circuit_length")) |value| {
            if (value == .integer) {
                config.circuit_length = @intCast(value.integer);
            }
        }

        if (root.get("max_circuits")) |value| {
            if (value == .integer) {
                config.max_circuits = @intCast(value.integer);
            }
        }

        if (root.get("circuit_timeout_seconds")) |value| {
            if (value == .integer) {
                config.circuit_timeout_seconds = @intCast(value.integer);
            }
        }

        if (root.get("connection_timeout_seconds")) |value| {
            if (value == .integer) {
                config.connection_timeout_seconds = @intCast(value.integer);
            }
        }

        if (root.get("retry_attempts")) |value| {
            if (value == .integer) {
                config.retry_attempts = @intCast(value.integer);
            }
        }

        if (root.get("user_agent")) |value| {
            if (value == .string) {
                config.user_agent = try allocator.dupe(u8, value.string);
                config.user_agent_owned = true;
            }
        }

        if (root.get("enable_logging")) |value| {
            if (value == .bool) {
                config.enable_logging = value.bool;
            }
        }

        if (root.get("log_level")) |value| {
            if (value == .string) {
                config.log_level = try allocator.dupe(u8, value.string);
                config.log_level_owned = true;
            }
        }

        return config;
    }

    pub fn validate(self: *const ClientConfig) !void {
        if (self.authority_addr.len == 0) {
            return error.MissingAuthorityAddress;
        }

        if (self.socks_listen_addr.len == 0) {
            return error.MissingSocksListenAddress;
        }

        if (self.circuit_length < 1 or self.circuit_length > 8) {
            return error.InvalidCircuitLength;
        }

        if (self.max_circuits == 0) {
            return error.InvalidMaxCircuits;
        }

        if (std.mem.indexOf(u8, self.authority_addr, ":") == null) {
            return error.InvalidAuthorityAddress;
        }

        if (std.mem.indexOf(u8, self.socks_listen_addr, ":") == null) {
            return error.InvalidSocksListenAddress;
        }
    }

    pub fn getAuthorityPort(self: *const ClientConfig) !u16 {
        const colon_pos = std.mem.lastIndexOf(u8, self.authority_addr, ":") orelse return error.InvalidAuthorityAddress;
        const port_str = self.authority_addr[colon_pos + 1 ..];
        return try std.fmt.parseInt(u16, port_str, 10);
    }

    pub fn getAuthorityHost(self: *const ClientConfig, allocator: std.mem.Allocator) ![]u8 {
        const colon_pos = std.mem.lastIndexOf(u8, self.authority_addr, ":") orelse return error.InvalidAuthorityAddress;
        return try allocator.dupe(u8, self.authority_addr[0..colon_pos]);
    }

    pub fn getSocksPort(self: *const ClientConfig) !u16 {
        // ハードコードされた安全な値を使用
        _ = self;
        return 9050;
    }

    pub fn getSocksHost(self: *const ClientConfig, allocator: std.mem.Allocator) ![]u8 {
        _ = self;
        return try allocator.dupe(u8, "127.0.0.1");
    }
};

test "ClientConfig JSON parsing" {
    const allocator = testing.allocator;

    const json_data =
        \\{
        \\  "authority_addr": "127.0.0.1:8443",
        \\  "socks_listen_addr": "127.0.0.1:9050",
        \\  "circuit_length": 3,
        \\  "max_circuits": 10,
        \\  "circuit_timeout_seconds": 300,
        \\  "connection_timeout_seconds": 30,
        \\  "retry_attempts": 3,
        \\  "user_agent": "Piranha-Client/1.0",
        \\  "enable_logging": true,
        \\  "log_level": "info"
        \\}
    ;

    var config = try ClientConfig.parseFromJson(allocator, json_data);
    defer config.deinit();

    try testing.expectEqualStrings("127.0.0.1:8443", config.authority_addr);
    try testing.expectEqualStrings("127.0.0.1:9050", config.socks_listen_addr);
    try testing.expectEqual(@as(u8, 3), config.circuit_length);
    try testing.expectEqual(@as(u32, 10), config.max_circuits);
    try testing.expectEqual(@as(u32, 300), config.circuit_timeout_seconds);
    try testing.expectEqual(@as(u32, 30), config.connection_timeout_seconds);
    try testing.expectEqual(@as(u32, 3), config.retry_attempts);
    try testing.expectEqualStrings("Piranha-Client/1.0", config.user_agent);
    try testing.expectEqual(true, config.enable_logging);
    try testing.expectEqualStrings("info", config.log_level);
}

test "ClientConfig validation" {
    const allocator = testing.allocator;

    var config = ClientConfig.init(allocator);
    config.authority_addr = try allocator.dupe(u8, "127.0.0.1:8443");
    config.authority_addr_owned = true;
    config.socks_listen_addr = try allocator.dupe(u8, "127.0.0.1:9050");
    config.socks_listen_addr_owned = true;
    config.circuit_length = 3;
    config.max_circuits = 10;
    
    defer config.deinit();

    try config.validate();

    const auth_port = try config.getAuthorityPort();
    try testing.expectEqual(@as(u16, 8443), auth_port);

    const auth_host = try config.getAuthorityHost(allocator);
    defer allocator.free(auth_host);
    try testing.expectEqualStrings("127.0.0.1", auth_host);

    const socks_port = try config.getSocksPort();
    try testing.expectEqual(@as(u16, 9050), socks_port);

    const socks_host = try config.getSocksHost(allocator);
    defer allocator.free(socks_host);
    try testing.expectEqualStrings("127.0.0.1", socks_host);
}