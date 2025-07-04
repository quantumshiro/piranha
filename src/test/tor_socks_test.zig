const std = @import("std");
const net = std.net;
const testing = std.testing;
const SocksServer = @import("../client/socks.zig").SocksServer;
const PiranhaClient = @import("../client/main.zig").PiranhaClient;
const ClientConfig = @import("../client/config.zig").ClientConfig;

// 実際のTorネットワークでのSOCKS5テスト
pub const TorSocksTest = struct {
    allocator: std.mem.Allocator,
    client: ?*PiranhaClient = null,
    
    pub fn init(allocator: std.mem.Allocator) TorSocksTest {
        return TorSocksTest{
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *TorSocksTest) void {
        if (self.client) |client| {
            client.deinit();
            self.allocator.destroy(client);
        }
    }
    
    // Piranha Tor Clientを起動
    pub fn startTorClient(self: *TorSocksTest) !void {
        std.log.info("Starting Piranha Tor Client...", .{});
        
        // 設定を作成
        var config = ClientConfig.init(self.allocator);
        config.authority_addr = try self.allocator.dupe(u8, "128.31.0.39:9131"); // moria1
        config.authority_addr_owned = true;
        config.socks_listen_addr = try self.allocator.dupe(u8, "127.0.0.1:9150");
        config.socks_listen_addr_owned = true;
        config.circuit_length = 3;
        config.max_circuits = 5;
        config.connection_timeout_seconds = 30;
        config.retry_attempts = 3;
        
        // クライアントを作成
        self.client = try self.allocator.create(PiranhaClient);
        self.client.?.* = PiranhaClient.init(self.allocator, config);
        
        // バックグラウンドでクライアントを開始
        const client_thread = try std.Thread.spawn(.{}, clientRunner, .{self.client.?});
        client_thread.detach();
        
        // クライアントが起動するまで少し待機
        std.time.sleep(5 * std.time.ns_per_s);
        
        std.log.info("Piranha Tor Client started on 127.0.0.1:9150", .{});
    }
    
    fn clientRunner(client: *PiranhaClient) void {
        client.start() catch |err| {
            std.log.err("Failed to start Tor client: {}", .{err});
        };
    }
    
    // SOCKS5接続テスト
    pub fn testSocksConnection(self: *TorSocksTest) !void {
        std.log.info("Testing SOCKS5 connection...", .{});
        
        const socks_addr = try net.Address.parseIp("127.0.0.1", 9150);
        const socks_stream = net.tcpConnectToAddress(socks_addr) catch |err| {
            std.log.err("Failed to connect to SOCKS proxy: {}", .{err});
            return err;
        };
        defer socks_stream.close();
        
        // SOCKS5認証ネゴシエーション
        try self.socksAuthentication(socks_stream);
        
        // SOCKS5 CONNECTリクエスト
        try self.socksConnect(socks_stream, "httpbin.org", 80);
        
        // HTTPリクエストを送信
        try self.sendHttpRequest(socks_stream);
        
        std.log.info("✅ SOCKS5 connection test passed", .{});
    }
    
    fn socksAuthentication(self: *TorSocksTest, stream: net.Stream) !void {
        _ = self;
        
        // SOCKS5認証リクエスト
        const auth_request = [_]u8{ 0x05, 0x01, 0x00 }; // VER=5, NMETHODS=1, METHOD=0 (no auth)
        try stream.writeAll(&auth_request);
        
        // 認証レスポンス
        var auth_response: [2]u8 = undefined;
        _ = try stream.readAll(&auth_response);
        
        if (auth_response[0] != 0x05 or auth_response[1] != 0x00) {
            return error.SocksAuthFailed;
        }
        
        std.log.debug("SOCKS5 authentication successful", .{});
    }
    
    fn socksConnect(self: *TorSocksTest, stream: net.Stream, hostname: []const u8, port: u16) !void {
        _ = self;
        
        // SOCKS5 CONNECTリクエストを構築
        var connect_request = std.ArrayList(u8).init(self.allocator);
        defer connect_request.deinit();
        
        try connect_request.appendSlice(&[_]u8{ 0x05, 0x01, 0x00, 0x03 }); // VER, CMD=CONNECT, RSV, ATYP=DOMAIN
        try connect_request.append(@intCast(hostname.len)); // Domain length
        try connect_request.appendSlice(hostname); // Domain name
        try connect_request.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u16, port))); // Port
        
        try stream.writeAll(connect_request.items);
        
        // CONNECTレスポンス
        var connect_response: [10]u8 = undefined; // 最小サイズ
        _ = try stream.readAll(&connect_response);
        
        if (connect_response[0] != 0x05 or connect_response[1] != 0x00) {
            std.log.err("SOCKS CONNECT failed: status={}", .{connect_response[1]});
            return error.SocksConnectFailed;
        }
        
        std.log.debug("SOCKS5 CONNECT to {s}:{d} successful", .{ hostname, port });
    }
    
    fn sendHttpRequest(self: *TorSocksTest, stream: net.Stream) !void {
        _ = self;
        
        // HTTPリクエストを送信
        const http_request = 
            "GET /ip HTTP/1.1\r\n" ++
            "Host: httpbin.org\r\n" ++
            "User-Agent: Piranha-Tor-Test/1.0\r\n" ++
            "Connection: close\r\n" ++
            "\r\n";
        
        try stream.writeAll(http_request);
        
        // HTTPレスポンスを受信
        var response_buffer: [4096]u8 = undefined;
        const bytes_read = try stream.read(&response_buffer);
        
        const response = response_buffer[0..bytes_read];
        std.log.debug("HTTP response ({} bytes):\n{s}", .{ bytes_read, response });
        
        // レスポンスの基本検証
        if (!std.mem.startsWith(u8, response, "HTTP/1.1 200")) {
            return error.HttpRequestFailed;
        }
        
        // IPアドレスがTor出口ノードのものかチェック（簡単化）
        if (std.mem.indexOf(u8, response, "\"origin\"") == null) {
            return error.InvalidHttpResponse;
        }
        
        std.log.info("HTTP request through Tor successful", .{});
    }
    
    // 複数サイトへの接続テスト
    pub fn testMultipleSites(self: *TorSocksTest) !void {
        std.log.info("Testing connections to multiple sites...", .{});
        
        const test_sites = [_]struct {
            hostname: []const u8,
            port: u16,
            path: []const u8,
        }{
            .{ .hostname = "httpbin.org", .port = 80, .path = "/ip" },
            .{ .hostname = "icanhazip.com", .port = 80, .path = "/" },
            .{ .hostname = "api.ipify.org", .port = 80, .path = "/" },
        };
        
        for (test_sites) |site| {
            std.log.info("Testing connection to {s}...", .{site.hostname});
            
            const result = self.testSingleSite(site.hostname, site.port, site.path);
            if (result) {
                std.log.info("✅ Successfully connected to {s}", .{site.hostname});
            } else |err| {
                std.log.warn("❌ Failed to connect to {s}: {}", .{ site.hostname, err });
            }
        }
    }
    
    fn testSingleSite(self: *TorSocksTest, hostname: []const u8, port: u16, path: []const u8) !void {
        const socks_addr = try net.Address.parseIp("127.0.0.1", 9150);
        const socks_stream = try net.tcpConnectToAddress(socks_addr);
        defer socks_stream.close();
        
        // SOCKS5ハンドシェイク
        try self.socksAuthentication(socks_stream);
        try self.socksConnect(socks_stream, hostname, port);
        
        // HTTPリクエスト
        const http_request = try std.fmt.allocPrint(self.allocator,
            "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "User-Agent: Piranha-Tor-Test/1.0\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
            .{ path, hostname }
        );
        defer self.allocator.free(http_request);
        
        try socks_stream.writeAll(http_request);
        
        // レスポンス受信
        var response_buffer: [4096]u8 = undefined;
        const bytes_read = try socks_stream.read(&response_buffer);
        
        if (bytes_read == 0) {
            return error.NoResponse;
        }
        
        const response = response_buffer[0..bytes_read];
        if (!std.mem.startsWith(u8, response, "HTTP/1.1 200")) {
            return error.HttpError;
        }
        
        std.log.debug("Response from {s}: {} bytes", .{ hostname, bytes_read });
    }
    
    // パフォーマンステスト
    pub fn testPerformance(self: *TorSocksTest) !void {
        std.log.info("Testing Tor performance...", .{});
        
        const iterations = 5;
        var total_time: i64 = 0;
        
        for (0..iterations) |i| {
            std.log.info("Performance test iteration {}/{}", .{ i + 1, iterations });
            
            const start_time = std.time.nanoTimestamp();
            
            try self.testSingleSite("httpbin.org", 80, "/ip");
            
            const end_time = std.time.nanoTimestamp();
            const duration = end_time - start_time;
            total_time += duration;
            
            const duration_ms = @divTrunc(duration, std.time.ns_per_ms);
            std.log.info("Iteration {} completed in {}ms", .{ i + 1, duration_ms });
        }
        
        const avg_time_ms = @divTrunc(total_time, iterations * std.time.ns_per_ms);
        std.log.info("Average response time: {}ms", .{avg_time_ms});
        
        if (avg_time_ms > 10000) { // 10秒以上
            std.log.warn("Performance is slow: {}ms average", .{avg_time_ms});
        } else {
            std.log.info("✅ Performance test passed", .{});
        }
    }
    
    // 包括的なSOCKSテスト
    pub fn runFullSocksTest(self: *TorSocksTest) !void {
        std.log.info("=== Starting Full SOCKS5 Test ===", .{});
        
        // 1. Torクライアントを起動
        try self.startTorClient();
        
        // 2. 基本的なSOCKS接続テスト
        try self.testSocksConnection();
        
        // 3. 複数サイトへの接続テスト
        try self.testMultipleSites();
        
        // 4. パフォーマンステスト
        try self.testPerformance();
        
        std.log.info("=== Full SOCKS5 Test Completed Successfully! ===", .{});
    }
};

// SOCKS5テスト実行用の関数
pub fn runSocksTests(allocator: std.mem.Allocator) !void {
    var socks_test = TorSocksTest.init(allocator);
    defer socks_test.deinit();
    
    try socks_test.runFullSocksTest();
}

test "Tor SOCKS5 proxy" {
    // 注意: このテストは実際のネットワーク接続が必要です
    if (std.process.hasEnvVar(testing.allocator, "SKIP_NETWORK_TESTS")) {
        return testing.skip();
    }
    
    try runSocksTests(testing.allocator);
}