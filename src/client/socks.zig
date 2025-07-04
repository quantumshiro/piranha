const std = @import("std");
const net = std.net;
const circuit = @import("circuit.zig");
const CircuitManager = circuit.CircuitManager;
const ClientConfig = @import("config.zig").ClientConfig;
const builder = @import("builder.zig");
const CircuitBuilder = builder.CircuitBuilder;
const RelayCommand = builder.RelayCommand;
const RelayCell = builder.RelayCell;

// SOCKS5 コマンド
pub const SocksCommand = enum(u8) {
    connect = 0x01,
    bind = 0x02,
    udp_associate = 0x03,
};

// SOCKS5 アドレスタイプ
pub const SocksAddressType = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
};

// SOCKS5 レスポンスコード
pub const SocksResponse = enum(u8) {
    success = 0x00,
    general_failure = 0x01,
    connection_not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
};

// SOCKS5 リクエスト
pub const SocksRequest = struct {
    command: SocksCommand,
    address_type: SocksAddressType,
    address: []const u8,
    port: u16,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *SocksRequest) void {
        self.allocator.free(self.address);
    }
};

// ストリーム情報
pub const StreamInfo = struct {
    stream_id: circuit.StreamId,
    circuit_id: circuit.CircuitId,
    target_address: []const u8,
    target_port: u16,
    created_at: i64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, stream_id: circuit.StreamId, circuit_id: circuit.CircuitId, address: []const u8, port: u16) !StreamInfo {
        return StreamInfo{
            .stream_id = stream_id,
            .circuit_id = circuit_id,
            .target_address = try allocator.dupe(u8, address),
            .target_port = port,
            .created_at = std.time.timestamp(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *StreamInfo) void {
        self.allocator.free(self.target_address);
    }
};

// SOCKS5 プロキシサーバー
pub const SocksServer = struct {
    config: *const ClientConfig,
    circuit_manager: *CircuitManager,
    circuit_builder: *CircuitBuilder,
    allocator: std.mem.Allocator,
    listener: ?net.Server = null,
    running: bool = false,
    streams: std.AutoHashMap(circuit.StreamId, StreamInfo),
    stream_mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, config: *const ClientConfig, circuit_manager: *CircuitManager, circuit_builder: *CircuitBuilder) SocksServer {
        return SocksServer{
            .config = config,
            .circuit_manager = circuit_manager,
            .circuit_builder = circuit_builder,
            .allocator = allocator,
            .streams = std.AutoHashMap(circuit.StreamId, StreamInfo).init(allocator),
            .stream_mutex = .{},
        };
    }

    pub fn deinit(self: *SocksServer) void {
        self.stop();
        
        // ストリーム情報をクリーンアップ
        self.stream_mutex.lock();
        defer self.stream_mutex.unlock();
        
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.streams.deinit();
    }

    pub fn start(self: *SocksServer) !void {
        std.log.info("Starting SOCKS server...", .{});
        
        const host = self.config.getSocksHost(self.allocator) catch |err| {
            std.log.err("Failed to get SOCKS host: {}", .{err});
            return err;
        };
        defer self.allocator.free(host);
        
        const port = self.config.getSocksPort() catch |err| {
            std.log.err("Failed to get SOCKS port: {}", .{err});
            return err;
        };
        
        std.log.info("SOCKS server will bind to {s}:{d}", .{ host, port });

        const address = net.Address.parseIp(host, port) catch |err| {
            std.log.err("Failed to parse SOCKS listen address: {s}:{d}", .{ host, port });
            return err;
        };

        self.listener = net.Address.listen(address, .{
            .reuse_address = true,
            .reuse_port = true,
        }) catch |err| {
            std.log.err("Failed to bind SOCKS server to {s}:{d}: {}", .{ host, port, err });
            return err;
        };

        self.running = true;
        std.log.info("SOCKS5 proxy listening on {s}:{d}", .{ host, port });

        try self.acceptLoop();
    }

    pub fn stop(self: *SocksServer) void {
        self.running = false;
        if (self.listener) |*listener| {
            listener.deinit();
            self.listener = null;
        }
    }

    fn acceptLoop(self: *SocksServer) !void {
        var connection_count: u32 = 0;

        while (self.running) {
            if (self.listener) |*listener| {
                const connection = listener.accept() catch |err| switch (err) {
                    error.ConnectionAborted => continue,
                    error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => {
                        std.log.warn("File descriptor limit reached, waiting before accepting new connections", .{});
                        std.time.sleep(1000 * std.time.ns_per_ms);
                        continue;
                    },
                    else => {
                        std.log.err("Failed to accept SOCKS connection: {}", .{err});
                        continue;
                    },
                };

                connection_count += 1;
                std.log.debug("Accepted SOCKS connection #{d} from {}", .{ connection_count, connection.address });

                const thread = std.Thread.spawn(.{}, handleSocksConnection, .{ self, connection, connection_count }) catch |err| {
                    std.log.err("Failed to spawn SOCKS handler thread: {}", .{err});
                    connection.stream.close();
                    continue;
                };
                thread.detach();
            }
        }
    }

    fn handleSocksConnection(self: *SocksServer, connection: net.Server.Connection, connection_id: u32) void {
        defer connection.stream.close();

        std.log.debug("Handling SOCKS connection #{d}", .{connection_id});

        self.processSocksHandshake(connection.stream, connection_id) catch |err| {
            std.log.err("SOCKS connection #{d} failed: {}", .{ connection_id, err });
            return;
        };

        std.log.debug("SOCKS connection #{d} closed", .{connection_id});
    }

    fn processSocksHandshake(self: *SocksServer, stream: net.Stream, connection_id: u32) !void {
        // SOCKS5 認証ネゴシエーション
        try self.handleAuthentication(stream);

        // SOCKS5 リクエスト処理
        const request = try self.parseRequest(stream);
        defer {
            var mutable_request = request;
            mutable_request.deinit();
        }

        std.log.info("SOCKS connection #{d}: {} to {s}:{d}", .{ 
            connection_id, 
            request.command, 
            request.address, 
            request.port 
        });

        // 回路を取得または作成
        const circuit_id = self.circuit_manager.getReadyCircuit() orelse {
            std.log.warn("No ready circuits available for SOCKS connection #{d}", .{connection_id});
            try self.sendResponse(stream, .general_failure);
            return;
        };

        // リクエストを処理
        switch (request.command) {
            .connect => try self.handleConnect(stream, request, circuit_id, connection_id),
            .bind, .udp_associate => {
                std.log.warn("SOCKS command not supported: {}", .{request.command});
                try self.sendResponse(stream, .command_not_supported);
            },
        }
    }

    fn handleAuthentication(self: *SocksServer, stream: net.Stream) !void {
        _ = self;
        
        // クライアントからの認証メソッド要求を読み取り
        var auth_request: [2]u8 = undefined;
        _ = try stream.readAll(&auth_request);

        if (auth_request[0] != 0x05) { // SOCKS5
            return error.UnsupportedSocksVersion;
        }

        const num_methods = auth_request[1];
        if (num_methods == 0) {
            return error.NoAuthenticationMethods;
        }

        // 認証メソッドを読み取り（認証なしのみサポート）
        const methods = try std.heap.page_allocator.alloc(u8, num_methods);
        defer std.heap.page_allocator.free(methods);
        _ = try stream.readAll(methods);

        // 認証なし (0x00) をサポート
        var supports_no_auth = false;
        for (methods) |method| {
            if (method == 0x00) {
                supports_no_auth = true;
                break;
            }
        }

        // レスポンスを送信
        const auth_response: [2]u8 = if (supports_no_auth) 
            .{ 0x05, 0x00 } // SOCKS5, 認証なし
        else 
            .{ 0x05, 0xFF }; // SOCKS5, 認証方法なし

        try stream.writeAll(&auth_response);

        if (!supports_no_auth) {
            return error.AuthenticationRequired;
        }
    }

    fn parseRequest(self: *SocksServer, stream: net.Stream) !SocksRequest {
        // SOCKS5 リクエストヘッダーを読み取り
        var header: [4]u8 = undefined;
        _ = try stream.readAll(&header);

        if (header[0] != 0x05) { // SOCKS5
            return error.UnsupportedSocksVersion;
        }

        const command = @as(SocksCommand, @enumFromInt(header[1]));
        // header[2] は予約済み (0x00)
        const address_type = @as(SocksAddressType, @enumFromInt(header[3]));

        // アドレスを読み取り
        var address: []u8 = undefined;
        switch (address_type) {
            .ipv4 => {
                var ipv4_bytes: [4]u8 = undefined;
                _ = try stream.readAll(&ipv4_bytes);
                address = try std.fmt.allocPrint(self.allocator, "{d}.{d}.{d}.{d}", .{
                    ipv4_bytes[0], ipv4_bytes[1], ipv4_bytes[2], ipv4_bytes[3]
                });
            },
            .domain => {
                var domain_len: [1]u8 = undefined;
                _ = try stream.readAll(&domain_len);
                
                const domain_bytes = try self.allocator.alloc(u8, domain_len[0]);
                _ = try stream.readAll(domain_bytes);
                address = domain_bytes;
            },
            .ipv6 => {
                return error.IPv6NotSupported;
            },
        }

        // ポートを読み取り
        var port_bytes: [2]u8 = undefined;
        _ = try stream.readAll(&port_bytes);
        const port = std.mem.readInt(u16, &port_bytes, .big);

        return SocksRequest{
            .command = command,
            .address_type = address_type,
            .address = address,
            .port = port,
            .allocator = self.allocator,
        };
    }

    fn handleConnect(self: *SocksServer, stream: net.Stream, request: SocksRequest, circuit_id: circuit.CircuitId, connection_id: u32) !void {
        std.log.debug("SOCKS connection #{d}: Connecting to {s}:{d} via circuit {d}", .{ connection_id, request.address, request.port, circuit_id });

        // 回路を通じて接続を確立
        const stream_id = self.establishConnection(circuit_id, request.address, request.port) catch |err| {
            std.log.err("Failed to establish connection for SOCKS #{d}: {}", .{ connection_id, err });
            try self.sendResponse(stream, .general_failure);
            return;
        };
        
        // 成功レスポンスを送信
        self.sendResponse(stream, .success) catch |err| {
            std.log.err("Failed to send success response for SOCKS #{d}: {}", .{ connection_id, err });
            self.cleanupStream(stream_id);
            return;
        };
        
        std.log.info("SOCKS connection #{d}: Connected to {s}:{d} via stream {d}", .{ connection_id, request.address, request.port, stream_id });

        // データ転送ループを開始
        self.dataTransferLoop(stream, circuit_id, stream_id, connection_id) catch |err| {
            std.log.err("Data transfer failed for SOCKS #{d}: {}", .{ connection_id, err });
        };
    }

    fn sendResponse(self: *SocksServer, stream: net.Stream, response_code: SocksResponse) !void {
        _ = self;
        
        // SOCKS5 レスポンス: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2)
        const response = [_]u8{
            0x05, // SOCKS5
            @intFromEnum(response_code),
            0x00, // 予約済み
            0x01, // IPv4
            0x00, 0x00, 0x00, 0x00, // バインドアドレス (0.0.0.0)
            0x00, 0x00, // バインドポート (0)
        };

        try stream.writeAll(&response);
    }

    fn establishConnection(self: *SocksServer, circuit_id: circuit.CircuitId, address: []const u8, port: u16) !circuit.StreamId {
        // 新しいストリームIDを生成（0は無効なので1から開始）
        const stream_id: circuit.StreamId = blk: {
            var id: u16 = 1;
            while (id != 0) : (id += 1) {
                self.stream_mutex.lock();
                const exists = self.streams.contains(id);
                self.stream_mutex.unlock();
                if (!exists) break :blk id;
            }
            return error.NoAvailableStreamId;
        };
        
        std.log.debug("Establishing connection to {s}:{d} via circuit {d}, stream {d}", .{ address, port, circuit_id, stream_id });

        // ストリーム情報を登録
        const stream_info = try StreamInfo.init(self.allocator, stream_id, circuit_id, address, port);
        
        self.stream_mutex.lock();
        defer self.stream_mutex.unlock();
        try self.streams.put(stream_id, stream_info);

        // RELAY_BEGIN セルを送信して接続を確立
        self.sendRelayBegin(circuit_id, stream_id, address, port) catch |err| {
            std.log.err("Failed to send RELAY_BEGIN: {}", .{err});
        };
        
        // TODO: RELAY_CONNECTED レスポンスを待機
        // 現在は簡単化のため、すぐに成功とみなす
        
        return stream_id;
    }

    fn dataTransferLoop(self: *SocksServer, client_stream: net.Stream, circuit_id: circuit.CircuitId, stream_id: circuit.StreamId, connection_id: u32) !void {
        std.log.debug("Starting data transfer loop for SOCKS connection #{d}", .{connection_id});

        var client_to_tor_thread: ?std.Thread = null;
        var tor_to_client_thread: ?std.Thread = null;
        
        defer {
            if (client_to_tor_thread) |thread| thread.join();
            if (tor_to_client_thread) |thread| thread.join();
        }

        // クライアント -> Tor 方向のデータ転送スレッド
        const client_to_tor_context = ClientToTorContext{
            .socks_server = self,
            .client_stream = client_stream,
            .circuit_id = circuit_id,
            .stream_id = stream_id,
            .connection_id = connection_id,
        };

        client_to_tor_thread = std.Thread.spawn(.{}, clientToTorTransfer, .{client_to_tor_context}) catch |err| {
            std.log.err("Failed to spawn client->tor transfer thread: {}", .{err});
            return err;
        };

        // Tor -> クライアント 方向のデータ転送スレッド
        const tor_to_client_context = TorToClientContext{
            .socks_server = self,
            .client_stream = client_stream,
            .circuit_id = circuit_id,
            .stream_id = stream_id,
            .connection_id = connection_id,
        };

        tor_to_client_thread = std.Thread.spawn(.{}, torToClientTransfer, .{tor_to_client_context}) catch |err| {
            std.log.err("Failed to spawn tor->client transfer thread: {}", .{err});
            return err;
        };

        // どちらかのスレッドが終了するまで待機
        if (client_to_tor_thread) |thread| thread.join();
        if (tor_to_client_thread) |thread| thread.join();

        std.log.debug("Data transfer loop ended for SOCKS connection #{d}", .{connection_id});
        
        // ストリームをクリーンアップ
        self.cleanupStream(stream_id);
    }

    fn cleanupStream(self: *SocksServer, stream_id: circuit.StreamId) void {
        self.stream_mutex.lock();
        defer self.stream_mutex.unlock();
        
        if (self.streams.fetchRemove(stream_id)) |entry| {
            var stream_info = entry.value;
            stream_info.deinit();
            std.log.debug("Cleaned up stream {d}", .{stream_id});
        }
    }

    // RELAY_BEGIN セルを送信して接続を確立
    fn sendRelayBegin(self: *SocksServer, circuit_id: circuit.CircuitId, stream_id: circuit.StreamId, address: []const u8, port: u16) !void {
        std.log.debug("Sending RELAY_BEGIN to {s}:{d} via circuit {d}, stream {d}", .{ address, port, circuit_id, stream_id });
        
        // RELAY_BEGIN ペイロードを作成: "address:port\0"
        const begin_payload = try std.fmt.allocPrint(self.allocator, "{s}:{d}\x00", .{ address, port });
        defer self.allocator.free(begin_payload);
        
        // TODO: 実際のCircuitBuilderのsendRelayCellを呼び出す
        // circuit_builder.sendRelayCell(circuit_id, @intFromEnum(RelayCommand.relay_begin), stream_id, begin_payload);
    }
};

// データ転送コンテキスト
const ClientToTorContext = struct {
    socks_server: *SocksServer,
    client_stream: net.Stream,
    circuit_id: circuit.CircuitId,
    stream_id: circuit.StreamId,
    connection_id: u32,
};

const TorToClientContext = struct {
    socks_server: *SocksServer,
    client_stream: net.Stream,
    circuit_id: circuit.CircuitId,
    stream_id: circuit.StreamId,
    connection_id: u32,
};

// クライアント -> Tor データ転送
fn clientToTorTransfer(context: ClientToTorContext) !void {
    std.log.debug("Client->Tor transfer started for connection #{d}", .{context.connection_id});
    
    var buffer: [4096]u8 = undefined;
    
    while (true) {
        const bytes_read = context.client_stream.read(&buffer) catch |err| {
            if (err == error.EndOfStream) {
                std.log.debug("Client closed connection #{d}", .{context.connection_id});
                break;
            }
            std.log.err("Error reading from client #{d}: {}", .{ context.connection_id, err });
            break;
        };

        if (bytes_read == 0) break;

        std.log.debug("Client->Tor: {d} bytes from connection #{d}", .{ bytes_read, context.connection_id });

        // RELAY_DATA セルとして回路に送信
        const relay_cell = RelayCell.init(.relay_data, context.stream_id, buffer[0..bytes_read]);
        const cell_bytes = try relay_cell.toBytes(context.socks_server.allocator);
        defer context.socks_server.allocator.free(cell_bytes);
        
        try context.socks_server.circuit_builder.sendRelayCell(context.circuit_id, @intFromEnum(RelayCommand.relay_data), context.stream_id, buffer[0..bytes_read]);
    }

    std.log.debug("Client->Tor transfer ended for connection #{d}", .{context.connection_id});
}

// Tor -> クライアント データ転送
fn torToClientTransfer(context: TorToClientContext) !void {
    std.log.debug("Tor->Client transfer started for connection #{d}", .{context.connection_id});
    
    while (true) {
        // 回路からRELAY_DATAセルを受信
        const relay_cell = context.socks_server.circuit_builder.receiveRelayCell(context.circuit_id) catch |err| {
            std.log.err("Failed to receive data from circuit: {}", .{err});
            break;
        };
        
        if (relay_cell.command == .relay_data and relay_cell.stream_id == context.stream_id) {
            _ = try context.client_stream.writeAll(relay_cell.data);
        }

        if (relay_cell.data.len == 0) {
            std.log.debug("Tor connection closed for connection #{d}", .{context.connection_id});
            break;
        }

        std.log.debug("Tor->Client: {d} bytes to connection #{d}", .{ relay_cell.data.len, context.connection_id });

        context.client_stream.writeAll(relay_cell.data) catch |err| {
            std.log.err("Error writing to client #{d}: {}", .{ context.connection_id, err });
            break;
        };
    }

    std.log.debug("Tor->Client transfer ended for connection #{d}", .{context.connection_id});
}

    // 回路にデータを送信
    fn sendDataToCircuit(self: *SocksServer, circuit_id: circuit.CircuitId, stream_id: circuit.StreamId, data: []const u8) !void {
        std.log.debug("Sending {d} bytes to circuit {d}, stream {d}", .{ data.len, circuit_id, stream_id });
        
        // RELAY_DATA セルを作成して送信
        const relay_cell = RelayCell.init(.relay_data, stream_id, data);
        const cell_bytes = try relay_cell.toBytes(self.allocator);
        defer self.allocator.free(cell_bytes);
        
        try self.circuit_builder.sendRelayCell(circuit_id, cell_bytes);
        // circuit_builder.sendRelayCell(circuit_id, @intFromEnum(RelayCommand.relay_data), stream_id, data);
    }

    // 回路からデータを受信
    fn receiveDataFromCircuit(self: *SocksServer, circuit_id: circuit.CircuitId, stream_id: circuit.StreamId) ![]const u8 {
        std.log.debug("Receiving data from circuit {d}, stream {d}", .{ circuit_id, stream_id });
        
        // RELAY セルを受信
        const relay_cell = try self.circuit_builder.receiveRelayCell(circuit_id);
        if (relay_cell.command == .relay_data and relay_cell.stream_id == stream_id) {
            return relay_cell.data;
        }
        // const relay_cell = circuit_builder.receiveRelayCell(circuit_id);
        // if (relay_cell.command == .relay_data and relay_cell.stream_id == stream_id) {
        //     return relay_cell.data;
        // }
        
        // プレースホルダー: 空のデータを返す（接続終了をシミュレート）
        return &[_]u8{};
    }

    // RELAY_BEGIN セルを送信して接続を確立
    fn sendRelayBegin(self: *SocksServer, circuit_id: circuit.CircuitId, stream_id: circuit.StreamId, address: []const u8, port: u16) !void {
        std.log.debug("Sending RELAY_BEGIN to {s}:{d} via circuit {d}, stream {d}", .{ address, port, circuit_id, stream_id });
        
        // RELAY_BEGIN ペイロードを作成: "address:port\0"
        const begin_payload = try std.fmt.allocPrint(self.allocator, "{s}:{d}\x00", .{ address, port });
        defer self.allocator.free(begin_payload);
        
        // TODO: 実際のCircuitBuilderのsendRelayCellを呼び出す
        // circuit_builder.sendRelayCell(circuit_id, @intFromEnum(RelayCommand.relay_begin), stream_id, begin_payload);
    }

test "SOCKS5 server creation" {
    const allocator = std.testing.allocator;

    var config = ClientConfig.init(allocator);
    config.socks_listen_addr = try allocator.dupe(u8, "127.0.0.1:9050");
    config.socks_listen_addr_owned = true;
    defer config.deinit();

    var circuit_manager = CircuitManager.init(allocator);
    defer circuit_manager.deinit();

    // テスト用のCircuitBuilderを作成
    var node_selector = circuit.NodeSelector.init(allocator);
    defer node_selector.deinit();
    
    var circuit_builder = CircuitBuilder.init(allocator, &config, &circuit_manager, &node_selector);
    defer circuit_builder.deinit();

    var server = SocksServer.init(allocator, &config, &circuit_manager, &circuit_builder);
    defer server.deinit();

    try std.testing.expect(!server.running);
    try std.testing.expect(server.listener == null);
    try std.testing.expectEqual(@as(usize, 0), server.streams.count());
}

test "SOCKS5 stream management" {
    const allocator = std.testing.allocator;

    var config = ClientConfig.init(allocator);
    config.socks_listen_addr = try allocator.dupe(u8, "127.0.0.1:9050");
    config.socks_listen_addr_owned = true;
    defer config.deinit();

    var circuit_manager = CircuitManager.init(allocator);
    defer circuit_manager.deinit();

    // テスト用のCircuitBuilderを作成
    var node_selector = circuit.NodeSelector.init(allocator);
    defer node_selector.deinit();
    
    var circuit_builder = CircuitBuilder.init(allocator, &config, &circuit_manager, &node_selector);
    defer circuit_builder.deinit();

    var server = SocksServer.init(allocator, &config, &circuit_manager, &circuit_builder);
    defer server.deinit();

    // ストリーム作成テスト
    const stream_id = try server.establishConnection(1, "example.com", 80);
    try std.testing.expect(stream_id > 0);
    try std.testing.expectEqual(@as(usize, 1), server.streams.count());

    // ストリームクリーンアップテスト
    server.cleanupStream(stream_id);
    try std.testing.expectEqual(@as(usize, 0), server.streams.count());
}