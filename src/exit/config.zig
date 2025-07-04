const std = @import("std");
const testing = std.testing;

pub const ExitPolicy = struct {
    host: []const u8,
    port: u16,
    
    pub fn init(allocator: std.mem.Allocator, policy_str: []const u8) !ExitPolicy {
        // Parse "0.0.0.0/0:80" format
        const colon_pos = std.mem.lastIndexOf(u8, policy_str, ":") orelse return error.InvalidExitPolicy;
        const host_part = policy_str[0..colon_pos];
        const port_str = policy_str[colon_pos + 1..];
        
        const port = try std.fmt.parseInt(u16, port_str, 10);
        const host = try allocator.dupe(u8, host_part);
        
        return ExitPolicy{
            .host = host,
            .port = port,
        };
    }
    
    pub fn deinit(self: *ExitPolicy, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
    }
    
    pub fn matches(self: *const ExitPolicy, target_host: []const u8, target_port: u16) bool {
        // Simple wildcard matching for "0.0.0.0/0" (allow all)
        if (std.mem.eql(u8, self.host, "0.0.0.0/0")) {
            return self.port == target_port;
        }
        
        // Exact host matching
        return std.mem.eql(u8, self.host, target_host) and self.port == target_port;
    }
};

pub const ExitConfig = struct {
    listen_addr: []const u8,
    max_circuits: u32,
    tls_enabled: bool,
    exit_policies: []ExitPolicy,
    timeout_seconds: u32,
    max_connections: u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ExitConfig {
        return ExitConfig{
            .listen_addr = "",
            .max_circuits = 1024,
            .tls_enabled = false,
            .exit_policies = &[_]ExitPolicy{},
            .timeout_seconds = 30,
            .max_connections = 100,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ExitConfig) void {
        if (self.listen_addr.len > 0) self.allocator.free(self.listen_addr);
        
        for (self.exit_policies) |*policy| {
            policy.deinit(self.allocator);
        }
        if (self.exit_policies.len > 0) {
            self.allocator.free(self.exit_policies);
        }
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, file_path: []const u8) !ExitConfig {
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

    pub fn parseFromJson(allocator: std.mem.Allocator, json_data: []const u8) !ExitConfig {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_data, .{});
        defer parsed.deinit();

        const root = parsed.value.object;

        var config = ExitConfig.init(allocator);

        if (root.get("listen_addr")) |addr_value| {
            if (addr_value == .string) {
                config.listen_addr = try allocator.dupe(u8, addr_value.string);
            }
        }

        if (root.get("max_circuits")) |max_circuits_value| {
            if (max_circuits_value == .integer) {
                config.max_circuits = @intCast(max_circuits_value.integer);
            }
        }

        if (root.get("tls_enabled")) |tls_value| {
            if (tls_value == .bool) {
                config.tls_enabled = tls_value.bool;
            }
        }

        if (root.get("timeout_seconds")) |timeout_value| {
            if (timeout_value == .integer) {
                config.timeout_seconds = @intCast(timeout_value.integer);
            }
        }

        if (root.get("max_connections")) |max_conn_value| {
            if (max_conn_value == .integer) {
                config.max_connections = @intCast(max_conn_value.integer);
            }
        }

        if (root.get("exit_policy")) |policy_array| {
            if (policy_array == .array) {
                var policies = try allocator.alloc(ExitPolicy, policy_array.array.items.len);
                for (policy_array.array.items, 0..) |policy_value, i| {
                    if (policy_value == .string) {
                        policies[i] = try ExitPolicy.init(allocator, policy_value.string);
                    }
                }
                config.exit_policies = policies;
            }
        }

        return config;
    }

    pub fn validate(self: *const ExitConfig) !void {
        if (self.listen_addr.len == 0) {
            return error.MissingListenAddress;
        }

        if (std.mem.indexOf(u8, self.listen_addr, ":") == null) {
            return error.InvalidListenAddress;
        }

        if (self.max_circuits == 0) {
            return error.InvalidMaxCircuits;
        }

        if (self.exit_policies.len == 0) {
            return error.NoExitPolicies;
        }
    }

    pub fn getListenPort(self: *const ExitConfig) !u16 {
        const colon_pos = std.mem.lastIndexOf(u8, self.listen_addr, ":") orelse return error.InvalidListenAddress;
        const port_str = self.listen_addr[colon_pos + 1 ..];
        return try std.fmt.parseInt(u16, port_str, 10);
    }

    pub fn getListenHost(self: *const ExitConfig, allocator: std.mem.Allocator) ![]u8 {
        const colon_pos = std.mem.lastIndexOf(u8, self.listen_addr, ":") orelse return error.InvalidListenAddress;
        return try allocator.dupe(u8, self.listen_addr[0..colon_pos]);
    }

    pub fn isAllowed(self: *const ExitConfig, target_host: []const u8, target_port: u16) bool {
        for (self.exit_policies) |*policy| {
            if (policy.matches(target_host, target_port)) {
                return true;
            }
        }
        return false;
    }
};

test "ExitConfig JSON parsing" {
    const allocator = testing.allocator;

    const json_data =
        \\{
        \\  "listen_addr": "0.0.0.0:9003",
        \\  "max_circuits": 1024,
        \\  "tls_enabled": false,
        \\  "exit_policy": [
        \\    "0.0.0.0/0:80",
        \\    "0.0.0.0/0:443"
        \\  ],
        \\  "timeout_seconds": 30,
        \\  "max_connections": 100
        \\}
    ;

    var config = try ExitConfig.parseFromJson(allocator, json_data);
    defer config.deinit();

    try testing.expectEqualStrings("0.0.0.0:9003", config.listen_addr);
    try testing.expectEqual(@as(u32, 1024), config.max_circuits);
    try testing.expectEqual(false, config.tls_enabled);
    try testing.expectEqual(@as(u32, 30), config.timeout_seconds);
    try testing.expectEqual(@as(u32, 100), config.max_connections);
    try testing.expectEqual(@as(usize, 2), config.exit_policies.len);
}

test "ExitConfig validation and policy checking" {
    const allocator = testing.allocator;

    var config = ExitConfig.init(allocator);
    config.listen_addr = try allocator.dupe(u8, "127.0.0.1:9003");
    
    var policies = try allocator.alloc(ExitPolicy, 2);
    policies[0] = try ExitPolicy.init(allocator, "0.0.0.0/0:80");
    policies[1] = try ExitPolicy.init(allocator, "0.0.0.0/0:443");
    config.exit_policies = policies;
    
    defer config.deinit();

    try config.validate();

    const port = try config.getListenPort();
    try testing.expectEqual(@as(u16, 9003), port);

    const host = try config.getListenHost(allocator);
    defer allocator.free(host);
    try testing.expectEqualStrings("127.0.0.1", host);

    // Test exit policy matching
    try testing.expect(config.isAllowed("example.com", 80));
    try testing.expect(config.isAllowed("example.com", 443));
    try testing.expect(!config.isAllowed("example.com", 22));
}