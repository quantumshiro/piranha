const std = @import("std");
const testing = std.testing;

pub const AuthorityConfig = struct {
    listen_addr: []const u8,
    cert_path: []const u8,
    key_path: []const u8,
    sig_key_path: []const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) AuthorityConfig {
        return AuthorityConfig{
            .listen_addr = "",
            .cert_path = "",
            .key_path = "",
            .sig_key_path = "",
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AuthorityConfig) void {
        if (self.listen_addr.len > 0) self.allocator.free(self.listen_addr);
        if (self.cert_path.len > 0) self.allocator.free(self.cert_path);
        if (self.key_path.len > 0) self.allocator.free(self.key_path);
        if (self.sig_key_path.len > 0) self.allocator.free(self.sig_key_path);
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, file_path: []const u8) !AuthorityConfig {
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

    pub fn parseFromJson(allocator: std.mem.Allocator, json_data: []const u8) !AuthorityConfig {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_data, .{});
        defer parsed.deinit();

        const root = parsed.value.object;

        var config = AuthorityConfig.init(allocator);

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

        if (root.get("sig_key_path")) |sig_key_value| {
            if (sig_key_value == .string) {
                config.sig_key_path = try allocator.dupe(u8, sig_key_value.string);
            }
        }

        return config;
    }

    pub fn toJson(self: *const AuthorityConfig, allocator: std.mem.Allocator) ![]u8 {
        var json_obj = std.json.ObjectMap.init(allocator);
        defer json_obj.deinit();

        try json_obj.put("listen_addr", std.json.Value{ .string = self.listen_addr });
        try json_obj.put("cert_path", std.json.Value{ .string = self.cert_path });
        try json_obj.put("key_path", std.json.Value{ .string = self.key_path });
        try json_obj.put("sig_key_path", std.json.Value{ .string = self.sig_key_path });

        const value = std.json.Value{ .object = json_obj };
        return try std.json.stringifyAlloc(allocator, value, .{ .whitespace = .indent_2 });
    }

    pub fn saveToFile(self: *const AuthorityConfig, file_path: []const u8) !void {
        const json_str = try self.toJson(self.allocator);
        defer self.allocator.free(json_str);

        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        try file.writeAll(json_str);
    }

    pub fn validate(self: *const AuthorityConfig) !void {
        if (self.listen_addr.len == 0) {
            return error.MissingListenAddress;
        }

        if (self.cert_path.len == 0) {
            return error.MissingCertPath;
        }

        if (self.key_path.len == 0) {
            return error.MissingKeyPath;
        }

        if (self.sig_key_path.len == 0) {
            return error.MissingSignatureKeyPath;
        }

        if (std.mem.indexOf(u8, self.listen_addr, ":") == null) {
            return error.InvalidListenAddress;
        }
    }

    pub fn getListenPort(self: *const AuthorityConfig) !u16 {
        const colon_pos = std.mem.lastIndexOf(u8, self.listen_addr, ":") orelse return error.InvalidListenAddress;
        const port_str = self.listen_addr[colon_pos + 1 ..];
        return try std.fmt.parseInt(u16, port_str, 10);
    }

    pub fn getListenHost(self: *const AuthorityConfig, allocator: std.mem.Allocator) ![]u8 {
        const colon_pos = std.mem.lastIndexOf(u8, self.listen_addr, ":") orelse return error.InvalidListenAddress;
        return try allocator.dupe(u8, self.listen_addr[0..colon_pos]);
    }
};

test "AuthorityConfig JSON parsing" {
    const allocator = testing.allocator;

    const json_data =
        \\{
        \\  "listen_addr": "0.0.0.0:8443",
        \\  "cert_path": "/etc/tor-zig/authority.crt",
        \\  "key_path": "/etc/tor-zig/authority.key",
        \\  "sig_key_path": "/etc/tor-zig/authority-sign.ed25519"
        \\}
    ;

    var config = try AuthorityConfig.parseFromJson(allocator, json_data);
    defer config.deinit();

    try testing.expectEqualStrings("0.0.0.0:8443", config.listen_addr);
    try testing.expectEqualStrings("/etc/tor-zig/authority.crt", config.cert_path);
    try testing.expectEqualStrings("/etc/tor-zig/authority.key", config.key_path);
    try testing.expectEqualStrings("/etc/tor-zig/authority-sign.ed25519", config.sig_key_path);
}

test "AuthorityConfig validation" {
    const allocator = testing.allocator;

    var valid_config = AuthorityConfig{
        .listen_addr = try allocator.dupe(u8, "127.0.0.1:8443"),
        .cert_path = try allocator.dupe(u8, "/tmp/cert.crt"),
        .key_path = try allocator.dupe(u8, "/tmp/key.key"),
        .sig_key_path = try allocator.dupe(u8, "/tmp/sig.ed25519"),
        .allocator = allocator,
    };
    defer valid_config.deinit();

    try valid_config.validate();

    const port = try valid_config.getListenPort();
    try testing.expectEqual(@as(u16, 8443), port);

    const host = try valid_config.getListenHost(allocator);
    defer allocator.free(host);
    try testing.expectEqualStrings("127.0.0.1", host);
}

test "AuthorityConfig JSON serialization" {
    const allocator = testing.allocator;

    var config = AuthorityConfig{
        .listen_addr = try allocator.dupe(u8, "0.0.0.0:9030"),
        .cert_path = try allocator.dupe(u8, "/etc/certs/authority.crt"),
        .key_path = try allocator.dupe(u8, "/etc/keys/authority.key"),
        .sig_key_path = try allocator.dupe(u8, "/etc/keys/authority-sign.ed25519"),
        .allocator = allocator,
    };
    defer config.deinit();

    const json_str = try config.toJson(allocator);
    defer allocator.free(json_str);

    try testing.expect(std.mem.indexOf(u8, json_str, "0.0.0.0:9030") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "/etc/certs/authority.crt") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "/etc/keys/authority.key") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "/etc/keys/authority-sign.ed25519") != null);
}