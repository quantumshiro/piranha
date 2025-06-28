const std = @import("std");
const testing = std.testing;
const NodeInfo = @import("node.zig").NodeInfo;
const NodeRegistry = @import("node.zig").NodeRegistry;
const AuthorityConfig = @import("config.zig").AuthorityConfig;
const signature_module = @import("../common/signature.zig");
const SignatureManager = signature_module.SignatureManager;
const signatureToHex = signature_module.signatureToHex;
const hexToSignature = signature_module.hexToSignature;
const verifySignature = signature_module.verifySignature;
const PUBLIC_KEY_SIZE = signature_module.PUBLIC_KEY_SIZE;

pub const DirectoryAuthority = struct {
    config: AuthorityConfig,
    registry: NodeRegistry,
    consensus_version: u32,
    last_consensus_time: i64,
    signature_manager: SignatureManager,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: AuthorityConfig) DirectoryAuthority {
        return DirectoryAuthority{
            .config = config,
            .registry = NodeRegistry.init(allocator),
            .consensus_version = 1,
            .last_consensus_time = std.time.timestamp(),
            .signature_manager = SignatureManager.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DirectoryAuthority) void {
        self.registry.deinit();
        self.config.deinit();
    }

    pub fn loadSigningKey(self: *DirectoryAuthority) !void {
        try self.signature_manager.loadFromFile(self.config.sig_key_path);
    }

    pub fn generateSigningKey(self: *DirectoryAuthority) void {
        self.signature_manager.generateNew();
    }

    pub fn saveSigningKey(self: *DirectoryAuthority) !void {
        try self.signature_manager.saveToFile(self.config.sig_key_path);
    }

    pub fn addNode(self: *DirectoryAuthority, node: NodeInfo) !void {
        try self.registry.addNode(node);
        self.updateConsensus();
    }

    pub fn removeNode(self: *DirectoryAuthority, nickname: []const u8) void {
        self.registry.removeNode(nickname);
        self.updateConsensus();
    }

    pub fn getNode(self: *DirectoryAuthority, nickname: []const u8) ?*NodeInfo {
        return self.registry.getNode(nickname);
    }

    pub fn getNodeCount(self: *const DirectoryAuthority) usize {
        return self.registry.getNodeCount();
    }

    pub fn generateConsensus(self: *DirectoryAuthority) ![]u8 {
        var json_str = std.ArrayList(u8).init(self.allocator);
        const writer = json_str.writer();
        
        try writer.writeAll("{");
        try writer.print("\"version\":{d},", .{self.consensus_version});
        try writer.print("\"timestamp\":{d},", .{self.last_consensus_time});
        try writer.print("\"node_count\":{d},", .{self.registry.getNodeCount()});
        
        try writer.writeAll("\"nodes\":");
        const nodes_json = try self.registry.toJson(self.allocator);
        defer self.allocator.free(nodes_json);
        try writer.writeAll(nodes_json);
        
        try writer.writeAll("}");
        return try json_str.toOwnedSlice();
    }

    pub fn generateSignedConsensus(self: *DirectoryAuthority) ![]u8 {
        const consensus_data = try self.generateConsensus();
        defer self.allocator.free(consensus_data);
        
        const signature = try self.signature_manager.signData(consensus_data);
        const public_key = try self.signature_manager.getPublicKey();
        
        const sig_hex = try signatureToHex(self.allocator, signature);
        defer self.allocator.free(sig_hex);
        
        var signed_json = std.ArrayList(u8).init(self.allocator);
        const writer = signed_json.writer();
        
        try writer.writeAll("{");
        try writer.writeAll("\"consensus\":");
        try writer.writeAll(consensus_data);
        try writer.writeAll(",");
        try writer.print("\"signature\":\"{s}\",", .{sig_hex});
        try writer.print("\"public_key\":\"{x}\",", .{std.fmt.fmtSliceHexLower(&public_key)});
        try writer.print("\"signed_at\":{d}", .{std.time.timestamp()});
        try writer.writeAll("}");
        
        return try signed_json.toOwnedSlice();
    }

    pub fn verifySignedConsensus(allocator: std.mem.Allocator, signed_consensus_json: []const u8) !bool {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, signed_consensus_json, .{});
        defer parsed.deinit();
        
        const root = parsed.value.object;
        
        const consensus_value = root.get("consensus") orelse return false;
        const signature_hex = root.get("signature") orelse return false;
        const public_key_hex = root.get("public_key") orelse return false;
        
        if (consensus_value != .object) return false;
        if (signature_hex != .string) return false;
        if (public_key_hex != .string) return false;
        
        // Reconstruct consensus JSON
        const consensus_json = try std.json.stringifyAlloc(allocator, consensus_value, .{});
        defer allocator.free(consensus_json);
        
        // Parse signature and public key
        const signature = hexToSignature(signature_hex.string) catch return false;
        
        if (public_key_hex.string.len != PUBLIC_KEY_SIZE * 2) return false;
        var public_key: [PUBLIC_KEY_SIZE]u8 = undefined;
        for (0..PUBLIC_KEY_SIZE) |i| {
            const hex_byte = public_key_hex.string[i * 2..i * 2 + 2];
            public_key[i] = std.fmt.parseInt(u8, hex_byte, 16) catch return false;
        }
        
        return verifySignature(public_key, consensus_json, signature);
    }

    pub fn extractConsensusFromSigned(allocator: std.mem.Allocator, signed_consensus_json: []const u8) ![]u8 {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, signed_consensus_json, .{});
        defer parsed.deinit();
        
        const root = parsed.value.object;
        const consensus_value = root.get("consensus") orelse return error.InvalidFormat;
        
        return try std.json.stringifyAlloc(allocator, consensus_value, .{});
    }

    pub fn getNodesWithFlag(self: *DirectoryAuthority, flag_name: []const u8) ![]NodeInfo {
        return try self.registry.getNodesWithFlag(self.allocator, flag_name);
    }

    pub fn updateConsensus(self: *DirectoryAuthority) void {
        self.consensus_version += 1;
        self.last_consensus_time = std.time.timestamp();
    }

    pub fn getConsensusInfo(self: *const DirectoryAuthority) struct {
        version: u32,
        timestamp: i64,
        node_count: usize,
    } {
        return .{
            .version = self.consensus_version,
            .timestamp = self.last_consensus_time,
            .node_count = self.registry.getNodeCount(),
        };
    }

    pub fn validateNode(self: *DirectoryAuthority, nickname: []const u8) bool {
        _ = self;
        
        if (nickname.len == 0 or nickname.len > 19) return false;
        
        for (nickname) |c| {
            if (!std.ascii.isAlphanumeric(c)) return false;
        }
        
        return true;
    }

    pub fn exportToFile(self: *DirectoryAuthority, file_path: []const u8) !void {
        const consensus = try self.generateConsensus();
        defer self.allocator.free(consensus);

        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        try file.writeAll(consensus);
    }
};

test "DirectoryAuthority basic operations" {
    const allocator = testing.allocator;

    const json_config =
        \\{
        \\  "listen_addr": "127.0.0.1:8443",
        \\  "cert_path": "/tmp/authority.crt",
        \\  "key_path": "/tmp/authority.key",
        \\  "sig_key_path": "/tmp/authority-sign.ed25519"
        \\}
    ;

    const config = try AuthorityConfig.parseFromJson(allocator, json_config);
    var authority = DirectoryAuthority.init(allocator, config);
    defer authority.deinit();

    try testing.expectEqual(@as(usize, 0), authority.getNodeCount());

    const node1 = try NodeInfo.init(allocator, "TestRelay1", "192.168.1.10");
    const node2 = try NodeInfo.init(allocator, "TestRelay2", "192.168.1.20");

    try authority.addNode(node1);
    try authority.addNode(node2);

    try testing.expectEqual(@as(usize, 2), authority.getNodeCount());

    const found_node = authority.getNode("TestRelay1");
    try testing.expect(found_node != null);
    try testing.expectEqualStrings("TestRelay1", found_node.?.nickname);
}

test "DirectoryAuthority consensus generation" {
    const allocator = testing.allocator;

    const json_config =
        \\{
        \\  "listen_addr": "127.0.0.1:8443",
        \\  "cert_path": "/tmp/authority.crt",
        \\  "key_path": "/tmp/authority.key",
        \\  "sig_key_path": "/tmp/authority-sign.ed25519"
        \\}
    ;

    const config = try AuthorityConfig.parseFromJson(allocator, json_config);
    var authority = DirectoryAuthority.init(allocator, config);
    defer authority.deinit();

    const node = try NodeInfo.init(allocator, "ConsensusTest", "10.0.0.1");
    try authority.addNode(node);

    const consensus = try authority.generateConsensus();
    defer allocator.free(consensus);

    try testing.expect(std.mem.indexOf(u8, consensus, "ConsensusTest") != null);
    try testing.expect(std.mem.indexOf(u8, consensus, "10.0.0.1") != null);
    try testing.expect(std.mem.indexOf(u8, consensus, "\"node_count\":1") != null);
}

test "DirectoryAuthority node validation" {
    const allocator = testing.allocator;

    const json_config =
        \\{
        \\  "listen_addr": "127.0.0.1:8443",
        \\  "cert_path": "/tmp/authority.crt",
        \\  "key_path": "/tmp/authority.key",
        \\  "sig_key_path": "/tmp/authority-sign.ed25519"
        \\}
    ;

    const config = try AuthorityConfig.parseFromJson(allocator, json_config);
    var authority = DirectoryAuthority.init(allocator, config);
    defer authority.deinit();

    try testing.expect(authority.validateNode("ValidRelay123"));
    try testing.expect(!authority.validateNode("Invalid-Relay"));
    try testing.expect(!authority.validateNode(""));
    try testing.expect(!authority.validateNode("TooLongRelayNameThatExceedsLimit"));
}

test "DirectoryAuthority signed consensus" {
    const allocator = testing.allocator;

    const json_config =
        \\{
        \\  "listen_addr": "127.0.0.1:8443",
        \\  "cert_path": "/tmp/authority.crt",
        \\  "key_path": "/tmp/authority.key",
        \\  "sig_key_path": "/tmp/authority-sign.ed25519"
        \\}
    ;

    const config = try AuthorityConfig.parseFromJson(allocator, json_config);
    var authority = DirectoryAuthority.init(allocator, config);
    defer authority.deinit();

    // Generate signing key
    authority.generateSigningKey();

    // Add a test node
    const node = try NodeInfo.init(allocator, "SignedTest", "10.0.0.100");
    try authority.addNode(node);

    // Generate signed consensus
    const signed_consensus = try authority.generateSignedConsensus();
    defer allocator.free(signed_consensus);

    // Verify the signed consensus
    const is_valid = try DirectoryAuthority.verifySignedConsensus(allocator, signed_consensus);
    try testing.expect(is_valid);

    // Extract and verify consensus content
    const extracted_consensus = try DirectoryAuthority.extractConsensusFromSigned(allocator, signed_consensus);
    defer allocator.free(extracted_consensus);

    try testing.expect(std.mem.indexOf(u8, extracted_consensus, "SignedTest") != null);
    try testing.expect(std.mem.indexOf(u8, extracted_consensus, "10.0.0.100") != null);
}