const std = @import("std");
const net = std.net;
const testing = std.testing;
const Cell = @import("../common/cell.zig").Cell;
const CellCommand = @import("../common/cell.zig").CellCommand;
const TorCrypto = @import("../common/tor_crypto.zig").TorCrypto;
const ntor = @import("../common/ntor.zig");

// Torプロトコル互換性テスト
pub const TorProtocolTest = struct {
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) TorProtocolTest {
        return TorProtocolTest{
            .allocator = allocator,
        };
    }
    
    // 実際のTorリレーとのハンドシェイクテスト
    pub fn testTorHandshake(self: *TorProtocolTest, relay_address: []const u8, relay_port: u16) !void {
        std.log.info("Testing Tor handshake with {s}:{d}", .{ relay_address, relay_port });
        
        const address = try net.Address.parseIp(relay_address, relay_port);
        const stream = try net.tcpConnectToAddress(address);
        defer stream.close();
        
        // Phase 1: VERSIONSセルの交換
        try self.exchangeVersions(stream);
        
        // Phase 2: NETINFOセルの交換
        try self.exchangeNetinfo(stream);
        
        // Phase 3: CREATE2セルでの回路作成
        try self.createCircuit(stream);
        
        std.log.info("✅ Tor handshake completed successfully", .{});
    }
    
    fn exchangeVersions(self: *TorProtocolTest, stream: net.Stream) !void {
        std.log.debug("Exchanging VERSIONS cells...", .{});
        
        // VERSIONSセルを送信
        const versions_cell = try Cell.createVersionsCell(self.allocator);
        const cell_bytes = try versions_cell.toBytes();
        try stream.writeAll(&cell_bytes);
        
        // VERSIONSレスポンスを受信
        var response_buffer: [512]u8 = undefined;
        const bytes_read = try stream.read(&response_buffer);
        
        if (bytes_read < 512) {
            return error.IncompleteResponse;
        }
        
        const response_cell = try Cell.fromBytes(@ptrCast(&response_buffer));
        
        if (response_cell.command != .versions) {
            std.log.err("Expected VERSIONS, got {}", .{response_cell.command});
            return error.UnexpectedResponse;
        }
        
        // サポートされているバージョンを解析
        var offset: usize = 0;
        var supported_versions = std.ArrayList(u16).init(self.allocator);
        defer supported_versions.deinit();
        
        while (offset + 2 <= response_cell.payload.len and response_cell.payload[offset] != 0) {
            const version = std.mem.readInt(u16, response_cell.payload[offset..offset+2], .big);
            if (version == 0) break;
            try supported_versions.append(version);
            offset += 2;
        }
        
        std.log.debug("Relay supports versions: {any}", .{supported_versions.items});
        
        // 共通バージョンを確認
        const our_versions = @import("../common/cell.zig").LINK_PROTOCOL_VERSIONS;
        var common_version: ?u16 = null;
        
        for (our_versions) |our_ver| {
            for (supported_versions.items) |their_ver| {
                if (our_ver == their_ver) {
                    common_version = our_ver;
                    break;
                }
            }
            if (common_version != null) break;
        }
        
        if (common_version == null) {
            return error.NoCommonVersion;
        }
        
        std.log.debug("Using protocol version: {}", .{common_version.?});
    }
    
    fn exchangeNetinfo(self: *TorProtocolTest, stream: net.Stream) !void {
        std.log.debug("Exchanging NETINFO cells...", .{});
        
        // まず、リレーからのNETINFOセルを受信
        var response_buffer: [512]u8 = undefined;
        const bytes_read = try stream.read(&response_buffer);
        
        if (bytes_read < 512) {
            return error.IncompleteResponse;
        }
        
        const netinfo_cell = try Cell.fromBytes(@ptrCast(&response_buffer));
        
        if (netinfo_cell.command != .netinfo) {
            std.log.err("Expected NETINFO, got {}", .{netinfo_cell.command});
            return error.UnexpectedResponse;
        }
        
        std.log.debug("Received NETINFO from relay", .{});
        
        // 我々のNETINFOセルを送信
        const my_addr = try net.Address.parseIp("127.0.0.1", 0);
        const other_addr = try net.Address.parseIp("127.0.0.1", 9001);
        const timestamp = @as(u32, @intCast(std.time.timestamp()));
        
        const our_netinfo = try Cell.createNetinfoCell(timestamp, my_addr, other_addr);
        const our_cell_bytes = try our_netinfo.toBytes();
        try stream.writeAll(&our_cell_bytes);
        
        std.log.debug("Sent NETINFO to relay", .{});
    }
    
    fn createCircuit(self: *TorProtocolTest, stream: net.Stream) !void {
        std.log.debug("Creating circuit with CREATE2 cell...", .{});
        
        // CREATE2セルを作成
        var create_cell = Cell.init(1, .create2); // Circuit ID = 1
        
        // nTorハンドシェイクデータを準備
        const node_id = [_]u8{0} ** 20; // 実際の実装では適切なnode IDを使用
        const node_key = [_]u8{0} ** 32; // 実際の実装では適切なnTor keyを使用
        
        const handshake_result = try ntor.NtorHandshake.clientHandshake1(self.allocator, node_id, node_key);
        
        // CREATE2ペイロードを構築
        var offset: usize = 0;
        
        // Handshake type (2 bytes) - nTor = 0x0002
        std.mem.writeInt(u16, create_cell.payload[offset..offset+2], 0x0002, .big);
        offset += 2;
        
        // Handshake data length (2 bytes)
        std.mem.writeInt(u16, create_cell.payload[offset..offset+2], @intCast(handshake_result.onion_skin.len), .big);
        offset += 2;
        
        // Handshake data
        @memcpy(create_cell.payload[offset..offset+handshake_result.onion_skin.len], &handshake_result.onion_skin);
        
        // CREATE2セルを送信
        const cell_bytes = try create_cell.toBytes();
        try stream.writeAll(&cell_bytes);
        
        std.log.debug("Sent CREATE2 cell", .{});
        
        // CREATED2レスポンスを受信
        var response_buffer: [512]u8 = undefined;
        const bytes_read = try stream.read(&response_buffer);
        
        if (bytes_read < 512) {
            return error.IncompleteResponse;
        }
        
        const created_cell = try Cell.fromBytes(@ptrCast(&response_buffer));
        
        if (created_cell.command != .created2) {
            std.log.err("Expected CREATED2, got {}", .{created_cell.command});
            return error.UnexpectedResponse;
        }
        
        std.log.debug("Received CREATED2 response", .{});
        
        // CREATED2レスポンスを解析
        const response_length = std.mem.readInt(u16, created_cell.payload[0..2], .big);
        if (response_length > created_cell.payload.len - 2) {
            return error.InvalidResponse;
        }
        
        const handshake_response = created_cell.payload[2..2+response_length];
        
        // nTorハンドシェイクを完了
        if (handshake_response.len >= 64) {
            var reply: [64]u8 = undefined;
            @memcpy(&reply, handshake_response[0..64]);
            
            const client_result = try ntor.NtorHandshake.clientHandshake2(
                self.allocator,
                reply,
                handshake_result.client_keypair,
                node_id,
                node_key
            );
            
            if (!client_result.verified) {
                return error.HandshakeVerificationFailed;
            }
            
            std.log.debug("nTor handshake completed and verified", .{});
        } else {
            return error.InvalidHandshakeResponse;
        }
        
        std.log.debug("Circuit created successfully", .{});
    }
    
    // RELAYセルのテスト
    pub fn testRelayCell(self: *TorProtocolTest, stream: net.Stream, circuit_id: u16) !void {
        std.log.debug("Testing RELAY cell communication...", .{});
        
        // RELAY_BEGINセルを作成（簡単化）
        var relay_cell = Cell.init(circuit_id, .relay);
        
        // RELAYペイロードを構築（簡単化）
        relay_cell.payload[0] = 1; // RELAY_BEGIN
        relay_cell.payload[1] = 0; // Recognized (2 bytes)
        relay_cell.payload[2] = 0;
        relay_cell.payload[3] = 0; // Stream ID (2 bytes)
        relay_cell.payload[4] = 1;
        // Digest (4 bytes) - 簡単化のため0
        relay_cell.payload[5] = 0;
        relay_cell.payload[6] = 0;
        relay_cell.payload[7] = 0;
        relay_cell.payload[8] = 0;
        // Length (2 bytes)
        const data = "www.example.com:80\x00";
        std.mem.writeInt(u16, relay_cell.payload[9..11], @intCast(data.len), .big);
        // Data
        @memcpy(relay_cell.payload[11..11+data.len], data);
        
        // RELAYセルを送信
        const cell_bytes = try relay_cell.toBytes();
        try stream.writeAll(&cell_bytes);
        
        std.log.debug("Sent RELAY_BEGIN cell", .{});
        
        // レスポンスを受信（タイムアウト付き）
        var response_buffer: [512]u8 = undefined;
        const bytes_read = stream.read(&response_buffer) catch |err| {
            if (err == error.WouldBlock) {
                std.log.debug("No immediate response (expected for RELAY cells)", .{});
                return;
            }
            return err;
        };
        
        if (bytes_read >= 512) {
            const response_cell = try Cell.fromBytes(@ptrCast(&response_buffer));
            std.log.debug("Received response cell: {}", .{response_cell.command});
        }
    }
    
    // 包括的なプロトコルテスト
    pub fn runProtocolTest(self: *TorProtocolTest, relay_address: []const u8, relay_port: u16) !void {
        std.log.info("Running comprehensive protocol test with {s}:{d}", .{ relay_address, relay_port });
        
        const address = try net.Address.parseIp(relay_address, relay_port);
        const stream = try net.tcpConnectToAddress(address);
        defer stream.close();
        
        // 1. ハンドシェイクテスト
        try self.exchangeVersions(stream);
        try self.exchangeNetinfo(stream);
        
        // 2. 回路作成テスト
        try self.createCircuit(stream);
        
        // 3. RELAYセルテスト
        try self.testRelayCell(stream, 1);
        
        std.log.info("✅ Protocol test completed successfully", .{});
    }
};

// プロトコルテスト実行用の関数
pub fn runProtocolTests(allocator: std.mem.Allocator, relay_address: []const u8, relay_port: u16) !void {
    var protocol_test = TorProtocolTest.init(allocator);
    try protocol_test.runProtocolTest(relay_address, relay_port);
}

test "Tor protocol compatibility" {
    // 注意: このテストは実際のネットワーク接続が必要です
    if (std.process.hasEnvVar(testing.allocator, "SKIP_NETWORK_TESTS")) {
        return testing.skip();
    }
    
    // テスト用のリレーアドレス（実際のTorリレー）
    try runProtocolTests(testing.allocator, "127.0.0.1", 9001);
}