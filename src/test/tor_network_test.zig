const std = @import("std");
const net = std.net;
const testing = std.testing;
const DirectoryClient = @import("../client/directory.zig").DirectoryClient;
const ClientConfig = @import("../client/config.zig").ClientConfig;
const CircuitBuilder = @import("../client/builder.zig").CircuitBuilder;
const CircuitManager = @import("../client/circuit.zig").CircuitManager;
const NodeSelector = @import("../client/circuit.zig").NodeSelector;
const Cell = @import("../common/cell.zig").Cell;
const TorDirectory = @import("../common/tor_directory.zig").TorDirectory;

// 実際のTorネットワークテスト
pub const TorNetworkTest = struct {
    allocator: std.mem.Allocator,
    config: ClientConfig,
    
    // 実際のTor Directory Authority のアドレス
    const REAL_TOR_AUTHORITIES = [_][]const u8{
        "128.31.0.39:9131",     // moria1
        "86.59.21.38:80",       // tor26
        "194.109.206.212:80",   // dizum
        "131.188.40.189:80",    // gabelmoo
        "193.23.244.244:80",    // dannenberg
        "171.25.193.9:443",     // longclaw
        "154.35.175.225:80",    // bastet
        "199.58.81.140:80",     // faravahar
    };
    
    pub fn init(allocator: std.mem.Allocator) TorNetworkTest {
        var config = ClientConfig.init(allocator);
        config.connection_timeout_seconds = 30;
        config.retry_attempts = 3;
        
        return TorNetworkTest{
            .allocator = allocator,
            .config = config,
        };
    }
    
    pub fn deinit(self: *TorNetworkTest) void {
        self.config.deinit();
    }
    
    // 実際のTor Authority への接続テスト
    pub fn testAuthorityConnection(self: *TorNetworkTest) !void {
        std.log.info("Testing connection to real Tor authorities...", .{});
        
        var successful_connections: usize = 0;
        
        for (REAL_TOR_AUTHORITIES) |authority_addr| {
            std.log.info("Testing connection to {s}...", .{authority_addr});
            
            const result = self.testSingleAuthority(authority_addr);
            if (result) {
                successful_connections += 1;
                std.log.info("✅ Successfully connected to {s}", .{authority_addr});
            } else |err| {
                std.log.warn("❌ Failed to connect to {s}: {}", .{ authority_addr, err });
            }
        }
        
        std.log.info("Connected to {}/{} authorities", .{ successful_connections, REAL_TOR_AUTHORITIES.len });
        
        if (successful_connections == 0) {
            return error.NoAuthorityConnections;
        }
    }
    
    fn testSingleAuthority(self: *TorNetworkTest, authority_addr: []const u8) !void {
        // 設定を更新
        if (self.config.authority_addr_owned) {
            self.allocator.free(self.config.authority_addr);
        }
        self.config.authority_addr = try self.allocator.dupe(u8, authority_addr);
        self.config.authority_addr_owned = true;
        
        // Directory Client を作成
        var directory_client = DirectoryClient.init(self.allocator, &self.config);
        defer directory_client.deinit();
        
        // 実際のコンセンサス文書を取得
        var directory = try directory_client.fetchDirectoryWithRetry();
        defer directory.deinit();
        
        // 基本的な検証
        if (!directory.isValid()) {
            return error.InvalidDirectory;
        }
        
        if (directory.nodes.len == 0) {
            return error.EmptyDirectory;
        }
        
        std.log.debug("Retrieved directory with {} nodes", .{directory.nodes.len});
    }
    
    // 実際のTorリレーへの接続テスト
    pub fn testRelayConnection(self: *TorNetworkTest) !void {
        std.log.info("Testing connection to real Tor relays...", .{});
        
        // まず、コンセンサス文書を取得
        self.config.authority_addr = try self.allocator.dupe(u8, REAL_TOR_AUTHORITIES[0]);
        self.config.authority_addr_owned = true;
        
        var directory_client = DirectoryClient.init(self.allocator, &self.config);
        defer directory_client.deinit();
        
        var directory = try directory_client.fetchDirectoryWithRetry();
        defer directory.deinit();
        
        // 有効なガードノードを探す
        var guard_nodes = std.ArrayList(@TypeOf(directory.nodes[0])).init(self.allocator);
        defer guard_nodes.deinit();
        
        for (directory.nodes) |node| {
            if (node.flags.valid and node.flags.running and node.flags.guard) {
                try guard_nodes.append(node);
                if (guard_nodes.items.len >= 5) break; // 最初の5つのガードノードをテスト
            }
        }
        
        if (guard_nodes.items.len == 0) {
            return error.NoGuardNodes;
        }
        
        std.log.info("Found {} guard nodes, testing connections...", .{guard_nodes.items.len});
        
        var successful_connections: usize = 0;
        
        for (guard_nodes.items) |node| {
            std.log.info("Testing connection to relay {s} ({s}:{d})...", .{ node.nickname, node.address, node.port });
            
            const result = self.testSingleRelay(node);
            if (result) {
                successful_connections += 1;
                std.log.info("✅ Successfully connected to relay {s}", .{node.nickname});
            } else |err| {
                std.log.warn("❌ Failed to connect to relay {s}: {}", .{ node.nickname, err });
            }
        }
        
        std.log.info("Connected to {}/{} relays", .{ successful_connections, guard_nodes.items.len });
        
        if (successful_connections == 0) {
            return error.NoRelayConnections;
        }
    }
    
    fn testSingleRelay(self: *TorNetworkTest, node: anytype) !void {
        // リレーへのTCP接続をテスト
        const address = net.Address.parseIp(node.address, node.port) catch |err| {
            std.log.err("Failed to parse address {s}:{d}: {}", .{ node.address, node.port, err });
            return err;
        };
        
        const stream = net.tcpConnectToAddress(address) catch |err| {
            return err;
        };
        defer stream.close();
        
        // VERSIONSセルを送信
        const versions_cell = try Cell.createVersionsCell(self.allocator);
        const cell_bytes = try versions_cell.toBytes();
        
        try stream.writeAll(&cell_bytes);
        
        // レスポンスを読み取り
        var response_buffer: [512]u8 = undefined;
        const bytes_read = try stream.read(&response_buffer);
        
        if (bytes_read < 3) {
            return error.InvalidResponse;
        }
        
        // レスポンスセルを解析
        const response_cell = try Cell.fromBytes(@ptrCast(&response_buffer));
        
        if (response_cell.command != .versions) {
            return error.UnexpectedResponse;
        }
        
        std.log.debug("Received VERSIONS response from {s}", .{node.nickname});
    }
    
    // 実際のTorネットワークでの回路構築テスト
    pub fn testCircuitBuilding(self: *TorNetworkTest) !void {
        std.log.info("Testing circuit building on real Tor network...", .{});
        
        // コンセンサス文書を取得
        self.config.authority_addr = try self.allocator.dupe(u8, REAL_TOR_AUTHORITIES[0]);
        self.config.authority_addr_owned = true;
        
        var directory_client = DirectoryClient.init(self.allocator, &self.config);
        defer directory_client.deinit();
        
        var directory = try directory_client.fetchDirectoryWithRetry();
        defer directory.deinit();
        
        // ノード選択器を設定
        var node_selector = NodeSelector.init(self.allocator);
        defer node_selector.deinit();
        
        try node_selector.updateNodes(directory.nodes);
        
        // 回路管理器を作成
        var circuit_manager = CircuitManager.init(self.allocator);
        defer circuit_manager.deinit();
        
        // 回路構築器を作成
        var circuit_builder = CircuitBuilder.init(self.allocator, &self.config, &circuit_manager, &node_selector);
        defer circuit_builder.deinit();
        
        // 実際の回路構築を試行
        std.log.info("Attempting to build circuit...", .{});
        
        const circuit_id = circuit_builder.buildCircuit() catch |err| {
            std.log.err("Failed to build circuit: {}", .{err});
            return err;
        };
        
        std.log.info("✅ Successfully built circuit {}", .{circuit_id});
        
        // 回路の状態を確認
        const circuit = circuit_manager.getCircuit(circuit_id) orelse return error.CircuitNotFound;
        
        if (!circuit.isReady()) {
            return error.CircuitNotReady;
        }
        
        std.log.info("Circuit {} is ready with {} hops", .{ circuit_id, circuit.hops.items.len });
    }
    
    // HTTPSリクエストのテスト（Tor経由）
    pub fn testHttpsRequest(self: *TorNetworkTest) !void {
        _ = self;
        std.log.info("Testing HTTPS request through Tor...", .{});
        
        // 注意: これは簡単化されたテストです
        // 実際の実装では、SOCKS5プロキシを通じてHTTPSリクエストを送信します
        
        std.log.info("HTTPS request test would be implemented here", .{});
        std.log.info("This requires a complete SOCKS5 proxy integration", .{});
    }
    
    // ネットワーク遅延とパフォーマンスのテスト
    pub fn testNetworkPerformance(self: *TorNetworkTest) !void {
        std.log.info("Testing network performance...", .{});
        
        const start_time = std.time.nanoTimestamp();
        
        // Authority への接続時間を測定
        try self.testAuthorityConnection();
        
        const end_time = std.time.nanoTimestamp();
        const duration_ms = @divTrunc(end_time - start_time, std.time.ns_per_ms);
        
        std.log.info("Authority connection test completed in {}ms", .{duration_ms});
        
        if (duration_ms > 30000) { // 30秒以上
            std.log.warn("Authority connection is slow: {}ms", .{duration_ms});
        }
    }
    
    // 包括的なネットワークテスト
    pub fn runFullNetworkTest(self: *TorNetworkTest) !void {
        std.log.info("=== Starting Full Tor Network Test ===", .{});
        
        // 1. Authority 接続テスト
        std.log.info("Phase 1: Testing authority connections...", .{});
        try self.testAuthorityConnection();
        
        // 2. リレー接続テスト
        std.log.info("Phase 2: Testing relay connections...", .{});
        try self.testRelayConnection();
        
        // 3. 回路構築テスト
        std.log.info("Phase 3: Testing circuit building...", .{});
        try self.testCircuitBuilding();
        
        // 4. パフォーマンステスト
        std.log.info("Phase 4: Testing network performance...", .{});
        try self.testNetworkPerformance();
        
        std.log.info("=== Full Tor Network Test Completed Successfully! ===", .{});
    }
};

// テスト実行用の関数
pub fn runNetworkTests(allocator: std.mem.Allocator) !void {
    var network_test = TorNetworkTest.init(allocator);
    defer network_test.deinit();
    
    try network_test.runFullNetworkTest();
}

test "Tor network connectivity" {
    // 注意: このテストは実際のネットワーク接続が必要です
    // CI環境では無効化される可能性があります
    
    if (std.process.hasEnvVar(testing.allocator, "SKIP_NETWORK_TESTS")) {
        return testing.skip();
    }
    
    try runNetworkTests(testing.allocator);
}