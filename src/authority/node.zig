const std = @import("std");
const testing = std.testing;

pub const NodeFlags = packed struct {
    exit: bool = false,
    guard: bool = false,
    stable: bool = false,
    fast: bool = false,
    valid: bool = false,
    running: bool = false,
    _padding: u2 = 0,
};

pub const NodeInfo = struct {
    nickname: []const u8,
    identity_key: [32]u8,
    onion_key: [32]u8,
    address: []const u8,
    or_port: u16,
    dir_port: u16,
    flags: NodeFlags,
    bandwidth: u64,
    published: i64,
    uptime: u64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, nickname: []const u8, address: []const u8) !NodeInfo {
        return NodeInfo{
            .nickname = try allocator.dupe(u8, nickname),
            .identity_key = [_]u8{0} ** 32,
            .onion_key = [_]u8{0} ** 32,
            .address = try allocator.dupe(u8, address),
            .or_port = 9001,
            .dir_port = 9030,
            .flags = NodeFlags{},
            .bandwidth = 0,
            .published = std.time.timestamp(),
            .uptime = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *NodeInfo) void {
        self.allocator.free(self.nickname);
        self.allocator.free(self.address);
    }

    pub fn clone(self: *const NodeInfo, allocator: std.mem.Allocator) !NodeInfo {
        return NodeInfo{
            .nickname = try allocator.dupe(u8, self.nickname),
            .identity_key = self.identity_key,
            .onion_key = self.onion_key,
            .address = try allocator.dupe(u8, self.address),
            .or_port = self.or_port,
            .dir_port = self.dir_port,
            .flags = self.flags,
            .bandwidth = self.bandwidth,
            .published = self.published,
            .uptime = self.uptime,
            .allocator = allocator,
        };
    }

    pub fn setFlags(self: *NodeInfo, flags: NodeFlags) void {
        self.flags = flags;
    }

    pub fn hasFlag(self: *const NodeInfo, flag_name: []const u8) bool {
        if (std.mem.eql(u8, flag_name, "Exit")) return self.flags.exit;
        if (std.mem.eql(u8, flag_name, "Guard")) return self.flags.guard;
        if (std.mem.eql(u8, flag_name, "Stable")) return self.flags.stable;
        if (std.mem.eql(u8, flag_name, "Fast")) return self.flags.fast;
        if (std.mem.eql(u8, flag_name, "Valid")) return self.flags.valid;
        if (std.mem.eql(u8, flag_name, "Running")) return self.flags.running;
        return false;
    }

    pub fn toJson(self: *const NodeInfo, allocator: std.mem.Allocator) ![]u8 {
        var json_str = std.ArrayList(u8).init(allocator);
        const writer = json_str.writer();
        
        try writer.writeAll("{");
        try writer.print("\"nickname\":\"{s}\",", .{self.nickname});
        try writer.print("\"address\":\"{s}\",", .{self.address});
        try writer.print("\"or_port\":{d},", .{self.or_port});
        try writer.print("\"dir_port\":{d},", .{self.dir_port});
        try writer.print("\"bandwidth\":{d},", .{self.bandwidth});
        try writer.print("\"published\":{d},", .{self.published});
        try writer.print("\"uptime\":{d},", .{self.uptime});
        
        try writer.writeAll("\"flags\":{");
        try writer.print("\"exit\":{},", .{self.flags.exit});
        try writer.print("\"guard\":{},", .{self.flags.guard});
        try writer.print("\"stable\":{},", .{self.flags.stable});
        try writer.print("\"fast\":{},", .{self.flags.fast});
        try writer.print("\"valid\":{},", .{self.flags.valid});
        try writer.print("\"running\":{}", .{self.flags.running});
        try writer.writeAll("},");
        
        try writer.print("\"identity_key\":\"{x}\",", .{std.fmt.fmtSliceHexLower(&self.identity_key)});
        try writer.print("\"onion_key\":\"{x}\"", .{std.fmt.fmtSliceHexLower(&self.onion_key)});
        try writer.writeAll("}");
        
        return try json_str.toOwnedSlice();
    }
};

pub const NodeRegistry = struct {
    nodes: std.HashMap([]const u8, NodeInfo, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) NodeRegistry {
        return NodeRegistry{
            .nodes = std.HashMap([]const u8, NodeInfo, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *NodeRegistry) void {
        var iterator = self.nodes.iterator();
        while (iterator.next()) |entry| {
            var node = entry.value_ptr;
            node.deinit();
            self.allocator.free(entry.key_ptr.*);
        }
        self.nodes.deinit();
    }

    pub fn addNode(self: *NodeRegistry, node: NodeInfo) !void {
        const key = try self.allocator.dupe(u8, node.nickname);
        const result = try self.nodes.getOrPut(key);
        if (result.found_existing) {
            self.allocator.free(key);
            result.value_ptr.deinit();
        }
        result.value_ptr.* = node;
    }

    pub fn removeNode(self: *NodeRegistry, nickname: []const u8) void {
        if (self.nodes.fetchRemove(nickname)) |kv| {
            var node = kv.value;
            node.deinit();
            self.allocator.free(kv.key);
        }
    }

    pub fn getNode(self: *NodeRegistry, nickname: []const u8) ?*NodeInfo {
        return self.nodes.getPtr(nickname);
    }

    pub fn getNodeCount(self: *const NodeRegistry) usize {
        return self.nodes.count();
    }

    pub fn getNodesWithFlag(self: *NodeRegistry, allocator: std.mem.Allocator, flag_name: []const u8) ![]NodeInfo {
        var matching_nodes = std.ArrayList(NodeInfo).init(allocator);
        defer matching_nodes.deinit();

        var iterator = self.nodes.iterator();
        while (iterator.next()) |entry| {
            const node = entry.value_ptr;
            if (node.hasFlag(flag_name)) {
                try matching_nodes.append(try node.clone(allocator));
            }
        }

        return try matching_nodes.toOwnedSlice();
    }

    pub fn toJson(self: *NodeRegistry, allocator: std.mem.Allocator) ![]u8 {
        var json_str = std.ArrayList(u8).init(allocator);
        const writer = json_str.writer();
        
        try writer.writeAll("[");
        
        var iterator = self.nodes.iterator();
        var first = true;
        while (iterator.next()) |entry| {
            if (!first) try writer.writeAll(",");
            first = false;
            
            const node = entry.value_ptr;
            const node_json = try node.toJson(allocator);
            defer allocator.free(node_json);
            try writer.writeAll(node_json);
        }
        
        try writer.writeAll("]");
        return try json_str.toOwnedSlice();
    }
};

test "NodeInfo creation and basic operations" {
    const allocator = testing.allocator;
    
    var node = try NodeInfo.init(allocator, "TestRelay", "192.168.1.100");
    defer node.deinit();
    
    try testing.expectEqualStrings("TestRelay", node.nickname);
    try testing.expectEqualStrings("192.168.1.100", node.address);
    try testing.expectEqual(@as(u16, 9001), node.or_port);
    
    node.setFlags(NodeFlags{ .valid = true, .running = true, .stable = true });
    try testing.expect(node.hasFlag("Valid"));
    try testing.expect(node.hasFlag("Running"));
    try testing.expect(node.hasFlag("Stable"));
    try testing.expect(!node.hasFlag("Exit"));
}

test "NodeRegistry operations" {
    const allocator = testing.allocator;
    
    var registry = NodeRegistry.init(allocator);
    defer registry.deinit();
    
    var node1 = try NodeInfo.init(allocator, "Relay1", "10.0.0.1");
    var node2 = try NodeInfo.init(allocator, "Relay2", "10.0.0.2");
    
    node1.setFlags(NodeFlags{ .valid = true, .running = true, .guard = true });
    node2.setFlags(NodeFlags{ .valid = true, .running = true, .exit = true });
    
    try registry.addNode(node1);
    try registry.addNode(node2);
    
    try testing.expectEqual(@as(usize, 2), registry.getNodeCount());
    
    const found_node = registry.getNode("Relay1");
    try testing.expect(found_node != null);
    try testing.expectEqualStrings("Relay1", found_node.?.nickname);
    
    const guard_nodes = try registry.getNodesWithFlag(allocator, "Guard");
    defer {
        for (guard_nodes) |*node| {
            node.deinit();
        }
        allocator.free(guard_nodes);
    }
    try testing.expectEqual(@as(usize, 1), guard_nodes.len);
    try testing.expectEqualStrings("Relay1", guard_nodes[0].nickname);
}

test "JSON serialization" {
    const allocator = testing.allocator;
    
    var node = try NodeInfo.init(allocator, "JSONTest", "203.0.113.42");
    defer node.deinit();
    
    node.setFlags(NodeFlags{ .valid = true, .running = true, .fast = true });
    node.bandwidth = 1000000;
    
    const json_str = try node.toJson(allocator);
    defer allocator.free(json_str);
    
    try testing.expect(std.mem.indexOf(u8, json_str, "JSONTest") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "203.0.113.42") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "1000000") != null);
}