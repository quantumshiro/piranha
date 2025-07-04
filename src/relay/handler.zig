const std = @import("std");
const net = std.net;
const lib = @import("piranha_lib");
const Cell = lib.cell.Cell;
const CellCommand = lib.cell.CellCommand;
const CELL_SIZE = lib.cell.CELL_SIZE;
const RelayConfig = @import("config.zig").RelayConfig;

pub const CircuitId = u16;

// RELAYセルのコマンド
pub const RelayCommand = enum(u8) {
    relay_begin = 1,
    relay_data = 2,
    relay_end = 3,
    relay_connected = 4,
    relay_sendme = 5,
    relay_extend = 6,
    relay_extended = 7,
    relay_truncate = 8,
    relay_truncated = 9,
    relay_drop = 10,
    relay_resolve = 11,
    relay_resolved = 12,
    _,
};

// RELAYセルのペイロード構造
const RelayPayload = struct {
    command: RelayCommand,
    recognized: u16,  // 常に0
    stream_id: u16,
    digest: [4]u8,    // MAC digest
    length: u16,
    data: []const u8,

    const HEADER_SIZE = 11; // command(1) + recognized(2) + stream_id(2) + digest(4) + length(2)

    pub fn parse(payload: []const u8) !RelayPayload {
        if (payload.len < HEADER_SIZE) {
            return error.InvalidRelayPayload;
        }

        const command = @as(RelayCommand, @enumFromInt(payload[0]));
        const recognized = std.mem.readInt(u16, payload[1..3], .big);
        const stream_id = std.mem.readInt(u16, payload[3..5], .big);
        var digest: [4]u8 = undefined;
        @memcpy(&digest, payload[5..9]);
        const length = std.mem.readInt(u16, payload[9..11], .big);

        if (payload.len < HEADER_SIZE + length) {
            return error.InvalidRelayPayload;
        }

        return RelayPayload{
            .command = command,
            .recognized = recognized,
            .stream_id = stream_id,
            .digest = digest,
            .length = length,
            .data = payload[HEADER_SIZE..HEADER_SIZE + length],
        };
    }

    pub fn serialize(self: *const RelayPayload, buffer: []u8) !usize {
        if (buffer.len < HEADER_SIZE + self.data.len) {
            return error.BufferTooSmall;
        }

        buffer[0] = @intFromEnum(self.command);
        std.mem.writeInt(u16, buffer[1..3], self.recognized, .big);
        std.mem.writeInt(u16, buffer[3..5], self.stream_id, .big);
        @memcpy(buffer[5..9], &self.digest);
        std.mem.writeInt(u16, buffer[9..11], @intCast(self.data.len), .big);
        @memcpy(buffer[HEADER_SIZE..HEADER_SIZE + self.data.len], self.data);

        return HEADER_SIZE + self.data.len;
    }
};

// ストリーム情報
const StreamInfo = struct {
    stream_id: u16,
    target_addr: []const u8,
    connection: ?net.Stream = null,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, stream_id: u16, target_addr: []const u8) !StreamInfo {
        return StreamInfo{
            .stream_id = stream_id,
            .target_addr = try allocator.dupe(u8, target_addr),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *StreamInfo) void {
        if (self.connection) |conn| {
            conn.close();
        }
        self.allocator.free(self.target_addr);
    }
};

// セッション情報を保持する構造体
const Session = struct {
    circ_id: CircuitId,
    forward_key: [16]u8,        // ntor forward encryption key
    backward_key: [16]u8,       // ntor backward encryption key
    forward_digest: [20]u8,     // ntor forward digest key
    backward_digest: [20]u8,    // ntor backward digest key
    next_hop_addr: []const u8,  // 後続ノードの "ip:port"
    streams: std.AutoHashMap(u16, StreamInfo), // stream_id -> StreamInfo
    is_exit_node: bool,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, circ_id: CircuitId, ntor_keys: lib.ntor.NtorKeys, next_hop_addr: []const u8) !Session {
        return Session{
            .circ_id = circ_id,
            .forward_key = ntor_keys.forward_key,
            .backward_key = ntor_keys.backward_key,
            .forward_digest = ntor_keys.forward_digest,
            .backward_digest = ntor_keys.backward_digest,
            .next_hop_addr = try allocator.dupe(u8, next_hop_addr),
            .streams = std.AutoHashMap(u16, StreamInfo).init(allocator),
            .is_exit_node = std.mem.eql(u8, next_hop_addr, "exit"), // "exit"の場合は出口ノード
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Session) void {
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.streams.deinit();
        self.allocator.free(self.next_hop_addr);
    }
};

// CellReader - セルを読み込むためのヘルパー
pub const CellReader = struct {
    stream: net.Stream,

    pub fn init(stream: net.Stream) CellReader {
        return CellReader{ .stream = stream };
    }

    pub fn readCell(self: *CellReader) !Cell {
        var buffer: [CELL_SIZE]u8 = undefined;
        const bytes_read = try self.stream.readAll(&buffer);
        if (bytes_read != CELL_SIZE) {
            return error.IncompleteCell;
        }
        return try Cell.fromBytes(&buffer);
    }
};

// CellWriter - セルを書き込むためのヘルパー
pub const CellWriter = struct {
    stream: net.Stream,

    pub fn init(stream: net.Stream) CellWriter {
        return CellWriter{ .stream = stream };
    }

    pub fn writeCell(self: *CellWriter, cell: *const Cell) !void {
        const bytes = try cell.toBytes();
        try self.stream.writeAll(&bytes);
    }
};

// セッション管理用のグローバル変数
var sessions: std.AutoHashMap(CircuitId, Session) = undefined;
var sessions_mutex: std.Thread.Mutex = std.Thread.Mutex{};
var sessions_initialized: bool = false;

pub fn initSessions(allocator: std.mem.Allocator) void {
    sessions_mutex.lock();
    defer sessions_mutex.unlock();
    
    if (!sessions_initialized) {
        sessions = std.AutoHashMap(CircuitId, Session).init(allocator);
        sessions_initialized = true;
    }
}

pub fn deinitSessions() void {
    sessions_mutex.lock();
    defer sessions_mutex.unlock();
    
    if (sessions_initialized) {
        var iterator = sessions.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        sessions.deinit();
        sessions_initialized = false;
    }
}

// メイン接続ハンドラー
pub fn handleClient(stream: net.Stream, config: *const RelayConfig, allocator: std.mem.Allocator) !void {
    _ = config; // 将来の使用のため
    
    var reader = CellReader.init(stream);
    var writer = CellWriter.init(stream);

    std.log.debug("Starting client handler", .{});

    while (true) {
        const cell = reader.readCell() catch |err| switch (err) {
            error.IncompleteCell, error.EndOfStream => {
                std.log.debug("Client disconnected", .{});
                break;
            },
            else => {
                std.log.err("Error reading cell: {}", .{err});
                break;
            },
        };

        std.log.debug("Received cell: circuit_id={}, command={}", .{ cell.circuit_id, cell.command });

        switch (cell.command) {
            .create => try handleCreate(cell, &writer, allocator),
            .create2 => try handleCreate2(cell, &writer, allocator),
            .relay => try handleRelay(cell, &writer, allocator),
            .destroy => try handleDestroy(cell, allocator),
            .padding => {
                // パディングセルは無視
                std.log.debug("Received padding cell", .{});
            },
            else => {
                std.log.warn("Unknown cell command: {}", .{cell.command});
                // 無効なタイプは無視
            },
        }
    }

    std.log.debug("Client handler finished", .{});
}

// CREATE セルの処理
fn handleCreate(cell: Cell, writer: *CellWriter, allocator: std.mem.Allocator) !void {
    std.log.debug("Handling CREATE cell for circuit {}", .{cell.circuit_id});

    // 1. クライアントの公開鍵を取り出す (ペイロードの最初の32バイト)
    if (cell.payload.len < 32) {
        std.log.err("CREATE cell payload too short: {} bytes", .{cell.payload.len});
        return error.InvalidCreateCell;
    }

    var client_public_key: [32]u8 = undefined;
    @memcpy(&client_public_key, cell.payload[0..32]);

    std.log.debug("Extracted client public key from CREATE cell", .{});

    // 2. サーバー側のX25519キーペアを生成
    const server_keypair = lib.crypto.X25519KeyPair.generate() catch |err| {
        std.log.err("Failed to generate server keypair: {}", .{err});
        return err;
    };

    // 3. X25519で共有鍵を計算
    const shared_secret = server_keypair.computeSharedSecret(client_public_key) catch |err| {
        std.log.err("Failed to compute shared secret: {}", .{err});
        return err;
    };

    // 4. 共有秘密から暗号化キーとMACキーを導出
    const keys = lib.crypto.deriveKeys(shared_secret, "tor-circuit-keys");

    std.log.debug("Computed shared secret and derived keys for circuit {}", .{cell.circuit_id});

    // 5. セッションを作成 (暗号化キーとMACキーを保存)
    const legacy_keys = lib.ntor.NtorKeys{
        .forward_key = keys.encryption_key[0..16].*,
        .backward_key = keys.encryption_key[16..32].*,
        .forward_digest = keys.mac_key[0..20].*,
        .backward_digest = keys.mac_key[12..32].*,
    };
    const session = try Session.init(allocator, cell.circuit_id, legacy_keys, "127.0.0.1:9002");

    // 6. セッションを保存
    sessions_mutex.lock();
    defer sessions_mutex.unlock();
    try sessions.put(cell.circuit_id, session);

    // 7. CREATED セルを返送 (サーバーの公開鍵を含む)
    var response = Cell.init(cell.circuit_id, .created);
    
    // サーバーの公開鍵をペイロードに設定
    @memcpy(response.payload[0..32], &server_keypair.public_key);
    
    // 残りのペイロードはゼロで埋める
    @memset(response.payload[32..], 0);

    try writer.writeCell(&response);
    std.log.debug("Sent CREATED cell with server public key for circuit {}", .{cell.circuit_id});
}

// CREATE2 セルの処理 (ntor handshake)
fn handleCreate2(cell: Cell, writer: *CellWriter, allocator: std.mem.Allocator) !void {
    std.log.debug("Handling CREATE2 cell for circuit {}", .{cell.circuit_id});

    // CREATE2 ペイロード構造: HTYPE(2) + HLEN(2) + HDATA(HLEN)
    if (cell.payload.len < 4) {
        std.log.err("CREATE2 cell payload too short: {} bytes", .{cell.payload.len});
        return error.InvalidCreate2Cell;
    }

    const htype = std.mem.readInt(u16, cell.payload[0..2], .big);
    const hlen = std.mem.readInt(u16, cell.payload[2..4], .big);

    if (htype != 2) { // ntor handshake type
        std.log.err("Unsupported handshake type: {}", .{htype});
        return error.UnsupportedHandshakeType;
    }

    if (hlen != lib.ntor.NTOR_ONIONSKIN_LEN) {
        std.log.err("Invalid ntor onion skin length: {}", .{hlen});
        return error.InvalidOnionSkinLength;
    }

    if (cell.payload.len < 4 + hlen) {
        std.log.err("CREATE2 cell payload too short for onion skin: {} bytes", .{cell.payload.len});
        return error.InvalidCreate2Cell;
    }

    // ntor onion skinを抽出
    var onion_skin_data: [lib.ntor.NTOR_ONIONSKIN_LEN]u8 = undefined;
    @memcpy(&onion_skin_data, cell.payload[4..4 + lib.ntor.NTOR_ONIONSKIN_LEN]);
    const onion_skin = lib.ntor.NtorOnionSkin.deserialize(&onion_skin_data);

    std.log.debug("Extracted ntor onion skin from CREATE2 cell", .{});

    // サーバーのntor keypairを生成 (実際の実装では永続的なキーを使用)
    const server_ntor_keypair = try lib.ntor.NtorKeyPair.generate();
    const server_identity_key = [_]u8{0x42} ** 32; // ダミーのidentity key

    // ntor handshakeを処理
    const server_result = lib.ntor.server_process_onion_skin(
        &onion_skin,
        server_identity_key,
        &server_ntor_keypair,
        allocator
    ) catch |err| {
        std.log.err("Failed to process ntor onion skin: {}", .{err});
        return err;
    };

    std.log.debug("Processed ntor handshake for circuit {}", .{cell.circuit_id});

    // セッションを作成
    const session = try Session.init(allocator, cell.circuit_id, server_result.keys, "exit");

    // セッションを保存
    sessions_mutex.lock();
    defer sessions_mutex.unlock();
    try sessions.put(cell.circuit_id, session);

    // CREATED2 セルを返送
    var response = Cell.init(cell.circuit_id, .created2);
    
    // CREATED2 ペイロード構造: HLEN(2) + HDATA(HLEN)
    const reply_data = server_result.reply.serialize();
    std.mem.writeInt(u16, response.payload[0..2], lib.ntor.NTOR_REPLY_LEN, .big);
    @memcpy(response.payload[2..2 + lib.ntor.NTOR_REPLY_LEN], &reply_data);
    
    // 残りのペイロードはゼロで埋める
    @memset(response.payload[2 + lib.ntor.NTOR_REPLY_LEN..], 0);

    try writer.writeCell(&response);
    std.log.debug("Sent CREATED2 cell with ntor reply for circuit {}", .{cell.circuit_id});
}

// RELAY セルの処理
fn handleRelay(cell: Cell, writer: *CellWriter, allocator: std.mem.Allocator) !void {
    std.log.debug("Handling RELAY cell for circuit {}", .{cell.circuit_id});

    // 1. 該当セッションを取り出し
    sessions_mutex.lock();
    const session_opt = sessions.getPtr(cell.circuit_id);
    sessions_mutex.unlock();

    if (session_opt == null) {
        std.log.warn("No session found for circuit {}", .{cell.circuit_id});
        return;
    }

    const session = session_opt.?;

    // 2. AES-CTR で 1 レイヤ復号
    var decrypted_payload: [CELL_SIZE - 3]u8 = undefined; // セルサイズ - ヘッダー
    @memcpy(&decrypted_payload, &cell.payload);

    // ntorキーを32バイトに拡張してAES-256で使用
    var aes_key: [32]u8 = undefined;
    @memcpy(aes_key[0..16], &session.backward_key);
    @memcpy(aes_key[16..32], &session.backward_key); // 簡略化: 実際にはより適切な拡張が必要
    
    const aes = lib.crypto.AesCtr.init(aes_key);
    const iv = [_]u8{0} ** 16; // 簡略化: 実際にはカウンターを使用
    try aes.decrypt(&decrypted_payload, iv, &decrypted_payload);

    std.log.debug("Decrypted RELAY cell payload", .{});

    // 3. ペイロード先頭の "コマンド" をチェック
    const relay_payload = RelayPayload.parse(&decrypted_payload) catch |err| {
        std.log.err("Failed to parse RELAY payload: {}", .{err});
        return;
    };

    std.log.debug("RELAY command: {}, stream_id: {}", .{ relay_payload.command, relay_payload.stream_id });

    // 4. コマンドに応じて処理
    switch (relay_payload.command) {
        .relay_begin => try handleRelayBegin(session, relay_payload, writer, allocator),
        .relay_data => try handleRelayData(session, relay_payload, writer, allocator),
        .relay_end => try handleRelayEnd(session, relay_payload, writer, allocator),
        else => {
            std.log.warn("Unsupported RELAY command: {}", .{relay_payload.command});
        },
    }
}

// RELAY_BEGIN の処理
fn handleRelayBegin(session: *Session, relay_payload: RelayPayload, writer: *CellWriter, allocator: std.mem.Allocator) !void {
    std.log.debug("Handling RELAY_BEGIN for stream {}", .{relay_payload.stream_id});

    // データから接続先アドレスを取得 (例: "example.com:80")
    const target_addr = std.mem.sliceTo(relay_payload.data, 0);
    std.log.debug("Target address: {s}", .{target_addr});

    if (session.is_exit_node) {
        // 出口ノードの場合: 最終サーバへ接続
        try connectToTarget(session, relay_payload.stream_id, target_addr, writer, allocator);
    } else {
        // 中継ノードの場合: 次ホップへ転送
        try forwardToNextHop(session, relay_payload, writer, allocator);
    }
}

// RELAY_DATA の処理
fn handleRelayData(session: *Session, relay_payload: RelayPayload, writer: *CellWriter, allocator: std.mem.Allocator) !void {
    std.log.debug("Handling RELAY_DATA for stream {}", .{relay_payload.stream_id});

    if (session.is_exit_node) {
        // 出口ノードの場合: 最終サーバへデータ送信
        try sendDataToTarget(session, relay_payload, writer, allocator);
    } else {
        // 中継ノードの場合: 次ホップへ転送
        try forwardToNextHop(session, relay_payload, writer, allocator);
    }
}

// RELAY_END の処理
fn handleRelayEnd(session: *Session, relay_payload: RelayPayload, writer: *CellWriter, allocator: std.mem.Allocator) !void {
    _ = writer;
    _ = allocator;
    std.log.debug("Handling RELAY_END for stream {}", .{relay_payload.stream_id});

    // ストリームを閉じる
    if (session.streams.fetchRemove(relay_payload.stream_id)) |entry| {
        var stream_info = entry.value;
        stream_info.deinit();
        std.log.debug("Closed stream {}", .{relay_payload.stream_id});
    }
}

// 最終サーバへの接続
fn connectToTarget(session: *Session, stream_id: u16, target_addr: []const u8, writer: *CellWriter, allocator: std.mem.Allocator) !void {
    std.log.debug("Connecting to target: {s}", .{target_addr});

    // アドレスをパース (例: "example.com:80")
    const colon_pos = std.mem.lastIndexOf(u8, target_addr, ":") orelse {
        std.log.err("Invalid target address format: {s}", .{target_addr});
        return sendRelayConnected(session.circ_id, stream_id, false, writer);
    };

    const host = target_addr[0..colon_pos];
    const port_str = target_addr[colon_pos + 1 ..];
    const port = std.fmt.parseInt(u16, port_str, 10) catch {
        std.log.err("Invalid port in target address: {s}", .{target_addr});
        return sendRelayConnected(session.circ_id, stream_id, false, writer);
    };

    // 接続試行
    const address = net.Address.resolveIp(host, port) catch {
        std.log.err("Failed to resolve address: {s}:{d}", .{ host, port });
        return sendRelayConnected(session.circ_id, stream_id, false, writer);
    };

    const connection = net.tcpConnectToAddress(address) catch {
        std.log.err("Failed to connect to {s}:{d}", .{ host, port });
        return sendRelayConnected(session.circ_id, stream_id, false, writer);
    };

    // ストリーム情報を保存
    var stream_info = try StreamInfo.init(allocator, stream_id, target_addr);
    stream_info.connection = connection;
    try session.streams.put(stream_id, stream_info);

    std.log.debug("Successfully connected to {s}:{d}", .{ host, port });
    try sendRelayConnected(session.circ_id, stream_id, true, writer);
}

// 最終サーバへのデータ送信
fn sendDataToTarget(session: *Session, relay_payload: RelayPayload, writer: *CellWriter, allocator: std.mem.Allocator) !void {
    _ = allocator;
    
    const stream_info = session.streams.getPtr(relay_payload.stream_id) orelse {
        std.log.warn("No stream found for stream_id {}", .{relay_payload.stream_id});
        return;
    };

    if (stream_info.connection) |connection| {
        // データを最終サーバに送信
        connection.writeAll(relay_payload.data) catch |err| {
            std.log.err("Failed to send data to target: {}", .{err});
            return;
        };

        std.log.debug("Sent {} bytes to target server", .{relay_payload.data.len});

        // 応答を読み取り、クライアントに返送 (簡略化)
        var response_buffer: [4096]u8 = undefined;
        const bytes_read = connection.read(&response_buffer) catch |err| {
            std.log.err("Failed to read response from target: {}", .{err});
            return;
        };

        if (bytes_read > 0) {
            try sendRelayData(session.circ_id, relay_payload.stream_id, response_buffer[0..bytes_read], writer);
        }
    }
}

// 次ホップへの転送
fn forwardToNextHop(session: *Session, relay_payload: RelayPayload, writer: *CellWriter, allocator: std.mem.Allocator) !void {
    _ = session;
    _ = relay_payload;
    _ = writer;
    _ = allocator;
    // TODO: 次ホップへの転送を実装
    std.log.debug("Forwarding to next hop (not implemented)", .{});
}

// RELAY_CONNECTED セルの送信
fn sendRelayConnected(circuit_id: CircuitId, stream_id: u16, success: bool, writer: *CellWriter) !void {
    var response = Cell.init(circuit_id, .relay);
    
    // RELAY_CONNECTED ペイロードを構築
    response.payload[0] = @intFromEnum(RelayCommand.relay_connected);
    std.mem.writeInt(u16, response.payload[1..3], 0, .big); // recognized
    std.mem.writeInt(u16, response.payload[3..5], stream_id, .big);
    @memset(response.payload[5..9], 0); // digest
    std.mem.writeInt(u16, response.payload[9..11], 0, .big); // length
    
    if (!success) {
        response.payload[11] = 1; // エラーコード
    }

    // TODO: 暗号化してから送信
    try writer.writeCell(&response);
    std.log.debug("Sent RELAY_CONNECTED for stream {} (success: {})", .{ stream_id, success });
}

// RELAY_DATA セルの送信
fn sendRelayData(circuit_id: CircuitId, stream_id: u16, data: []const u8, writer: *CellWriter) !void {
    var response = Cell.init(circuit_id, .relay);
    
    // RELAY_DATA ペイロードを構築
    response.payload[0] = @intFromEnum(RelayCommand.relay_data);
    std.mem.writeInt(u16, response.payload[1..3], 0, .big); // recognized
    std.mem.writeInt(u16, response.payload[3..5], stream_id, .big);
    @memset(response.payload[5..9], 0); // digest
    std.mem.writeInt(u16, response.payload[9..11], @intCast(data.len), .big);
    
    const max_data_len = response.payload.len - 11;
    const copy_len = @min(data.len, max_data_len);
    @memcpy(response.payload[11..11 + copy_len], data[0..copy_len]);

    // TODO: 暗号化してから送信
    try writer.writeCell(&response);
    std.log.debug("Sent RELAY_DATA for stream {} ({} bytes)", .{ stream_id, copy_len });
}

// DESTROY セルの処理
fn handleDestroy(cell: Cell, allocator: std.mem.Allocator) !void {
    _ = allocator;
    std.log.debug("Handling DESTROY cell for circuit {}", .{cell.circuit_id});

    // セッションを削除
    sessions_mutex.lock();
    defer sessions_mutex.unlock();
    
    if (sessions.fetchRemove(cell.circuit_id)) |entry| {
        var session = entry.value;
        session.deinit();
        std.log.debug("Destroyed circuit {}", .{cell.circuit_id});
    } else {
        std.log.warn("Attempted to destroy non-existent circuit {}", .{cell.circuit_id});
    }
}

test "CellReader and CellWriter" {
    // テスト用のメモリストリーム
    var buffer: [CELL_SIZE]u8 = undefined;
    _ = std.io.fixedBufferStream(&buffer);
    
    // テスト用のネットワークストリームを模擬
    // 実際のテストでは適切なモックが必要
}

test "Session management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    initSessions(allocator);
    defer deinitSessions();
    
    const ntor_keys = lib.ntor.NtorKeys{
        .forward_key = [_]u8{0x01} ** 16,
        .backward_key = [_]u8{0x02} ** 16,
        .forward_digest = [_]u8{0x03} ** 20,
        .backward_digest = [_]u8{0x04} ** 20,
    };
    var session = try Session.init(allocator, 123, ntor_keys, "127.0.0.1:9002");
    defer session.deinit();
    
    sessions_mutex.lock();
    try sessions.put(123, session);
    sessions_mutex.unlock();
    
    sessions_mutex.lock();
    const retrieved = sessions.get(123);
    sessions_mutex.unlock();
    
    try testing.expect(retrieved != null);
    try testing.expect(retrieved.?.circ_id == 123);
    try testing.expectEqualSlices(u8, &ntor_keys.forward_key, &retrieved.?.forward_key);
    try testing.expectEqualSlices(u8, &ntor_keys.backward_key, &retrieved.?.backward_key);
}