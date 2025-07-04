const std = @import("std");
const net = std.net;
const lib = @import("piranha_lib");
const Cell = lib.cell.Cell;
const CellCommand = lib.cell.CellCommand;
const CELL_SIZE = lib.cell.CELL_SIZE;
const crypto = lib.crypto;
const ntor = lib.ntor;
const ExitConfig = @import("config.zig").ExitConfig;

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

// Exit ノードのセッション情報
const ExitSession = struct {
    circuit_id: CircuitId,
    shared_key: [32]u8,
    dest_host: []const u8,
    dest_port: u16,
    dest_connection: ?net.Stream,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, circuit_id: CircuitId, shared_key: [32]u8, dest_host: []const u8, dest_port: u16) !ExitSession {
        const host_copy = try allocator.dupe(u8, dest_host);
        return ExitSession{
            .circuit_id = circuit_id,
            .shared_key = shared_key,
            .dest_host = host_copy,
            .dest_port = dest_port,
            .dest_connection = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ExitSession) void {
        if (self.dest_connection) |conn| {
            conn.close();
        }
        self.allocator.free(self.dest_host);
    }

    pub fn connectToDestination(self: *ExitSession) !void {
        if (self.dest_connection != null) {
            return; // Already connected
        }

        const address = net.Address.parseIp(self.dest_host, self.dest_port) catch |err| {
            std.log.err("Failed to parse destination address {s}:{d}: {}", .{ self.dest_host, self.dest_port, err });
            return err;
        };

        self.dest_connection = net.tcpConnectToAddress(address) catch |err| {
            std.log.err("Failed to connect to {s}:{d}: {}", .{ self.dest_host, self.dest_port, err });
            return err;
        };

        std.log.info("Connected to destination {s}:{d}", .{ self.dest_host, self.dest_port });
    }
};

// グローバルセッション管理
var sessions_mutex: std.Thread.Mutex = .{};
var sessions: std.AutoHashMap(CircuitId, ExitSession) = undefined;
var sessions_initialized = false;

pub fn initSessions(allocator: std.mem.Allocator) void {
    sessions_mutex.lock();
    defer sessions_mutex.unlock();
    
    if (!sessions_initialized) {
        sessions = std.AutoHashMap(CircuitId, ExitSession).init(allocator);
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

// メインのクライアントハンドラー
pub fn handleClient(stream: net.Stream, config: *const ExitConfig, allocator: std.mem.Allocator) !void {
    defer stream.close();
    
    std.log.info("Exit node handling new client connection", .{});
    
    var buffer: [CELL_SIZE]u8 = undefined;
    
    while (true) {
        const bytes_read = stream.read(&buffer) catch |err| switch (err) {
            error.ConnectionResetByPeer => {
                std.log.debug("Client disconnected", .{});
                break;
            },
            else => {
                std.log.err("Error reading from client: {}", .{err});
                break;
            },
        };
        
        if (bytes_read == 0) break;
        if (bytes_read != CELL_SIZE) {
            std.log.warn("Received incomplete cell: {} bytes", .{bytes_read});
            continue;
        }
        
        const cell = Cell.fromBytes(&buffer) catch |err| {
            std.log.err("Failed to parse cell: {}", .{err});
            continue;
        };
        
        switch (cell.command) {
            .create => try handleCreate(cell, stream, config, allocator),
            .relay => try handleRelay(cell, stream, config, allocator),
            .destroy => try handleDestroy(cell, allocator),
            else => {
                std.log.warn("Unhandled cell command: {}", .{cell.command});
            },
        }
    }
}

// CREATE セルの処理
fn handleCreate(cell: Cell, stream: net.Stream, config: *const ExitConfig, allocator: std.mem.Allocator) !void {
    std.log.debug("Processing CREATE cell for circuit {}", .{cell.circuit_id});
    
    // ペイロード解析: [ client_pk (32B) | dest_addr_len (1B) | dest_addr (nB) | port (2B) ]
    if (cell.payload.len < 35) { // 32 + 1 + 1 + 2 minimum
        std.log.err("CREATE cell payload too short");
        return;
    }
    
    const client_pk = cell.payload[0..32];
    const addr_len = cell.payload[32];
    
    if (cell.payload.len < 35 + addr_len) {
        std.log.err("CREATE cell payload incomplete");
        return;
    }
    
    const dest_addr = cell.payload[33..33 + addr_len];
    const dest_port = std.mem.readInt(u16, cell.payload[33 + addr_len..35 + addr_len][0..2], .big);
    
    std.log.info("CREATE request for destination {s}:{d}", .{ dest_addr, dest_port });
    
    // Exit ポリシーチェック
    if (!config.isAllowed(dest_addr, dest_port)) {
        std.log.warn("Connection to {s}:{d} denied by exit policy", .{ dest_addr, dest_port });
        return; // ポリシー違反は黙殺
    }
    
    // X25519 DH 握手
    const our_keypair = crypto.X25519KeyPair.generate() catch |err| {
        std.log.err("Failed to generate X25519 keypair: {}", .{err});
        return;
    };
    
    var client_pk_array: [32]u8 = undefined;
    @memcpy(&client_pk_array, client_pk);
    
    const shared_secret = our_keypair.computeSharedSecret(client_pk_array) catch |err| {
        std.log.err("Failed to compute shared secret: {}", .{err});
        return;
    };
    
    // セッション登録
    sessions_mutex.lock();
    defer sessions_mutex.unlock();
    
    const session = ExitSession.init(allocator, cell.circuit_id, shared_secret, dest_addr, dest_port) catch |err| {
        std.log.err("Failed to create session: {}", .{err});
        return;
    };
    
    sessions.put(cell.circuit_id, session) catch |err| {
        std.log.err("Failed to store session: {}", .{err});
        return;
    };
    
    // CREATED セル返送
    var response_cell = Cell.init(cell.circuit_id, .created);
    @memcpy(response_cell.payload[0..32], &our_keypair.public_key);
    
    const response_bytes = response_cell.toBytes() catch |err| {
        std.log.err("Failed to serialize CREATED cell: {}", .{err});
        return;
    };
    
    stream.writeAll(&response_bytes) catch |err| {
        std.log.err("Failed to send CREATED cell: {}", .{err});
        return;
    };
    
    std.log.debug("Sent CREATED cell for circuit {}", .{cell.circuit_id});
}

// RELAY セルの処理
fn handleRelay(cell: Cell, stream: net.Stream, config: *const ExitConfig, allocator: std.mem.Allocator) !void {
    _ = config;
    
    std.log.debug("Processing RELAY cell for circuit {}", .{cell.circuit_id});
    
    sessions_mutex.lock();
    const session_ptr = sessions.getPtr(cell.circuit_id);
    sessions_mutex.unlock();
    
    if (session_ptr == null) {
        std.log.warn("No session found for circuit {}", .{cell.circuit_id});
        return;
    }
    
    const session = session_ptr.?;
    
    // 1レイヤ復号
    var decrypted_payload: [lib.cell.PAYLOAD_SIZE]u8 = undefined;
    const aes = crypto.AesCtr.init(session.shared_key);
    const iv = [_]u8{0} ** crypto.IV_SIZE; // 簡単化のため固定IV
    
    aes.decrypt(cell.payload[0..lib.cell.PAYLOAD_SIZE], iv, &decrypted_payload) catch |err| {
        std.log.err("Failed to decrypt RELAY cell: {}", .{err});
        return;
    };
    
    const relay_payload = RelayPayload.parse(&decrypted_payload) catch |err| {
        std.log.err("Failed to parse RELAY payload: {}", .{err});
        return;
    };
    
    switch (relay_payload.command) {
        .relay_begin => try handleRelayBegin(session, relay_payload, stream, allocator),
        .relay_data => try handleRelayData(session, relay_payload, stream, allocator),
        .relay_end => try handleRelayEnd(session, relay_payload, allocator),
        else => {
            std.log.warn("Unhandled RELAY command: {}", .{relay_payload.command});
        },
    }
}

// RELAY_BEGIN の処理
fn handleRelayBegin(session: *ExitSession, relay_payload: RelayPayload, stream: net.Stream, allocator: std.mem.Allocator) !void {
    _ = allocator;
    
    std.log.debug("Processing RELAY_BEGIN for stream {}", .{relay_payload.stream_id});
    
    // 宛先への接続を確立
    session.connectToDestination() catch |err| {
        std.log.err("Failed to connect to destination: {}", .{err});
        
        // RELAY_END を送信して接続失敗を通知
        try sendRelayEnd(session, relay_payload.stream_id, stream);
        return;
    };
    
    // RELAY_CONNECTED を送信
    try sendRelayConnected(session, relay_payload.stream_id, stream);
}

// RELAY_DATA の処理
fn handleRelayData(session: *ExitSession, relay_payload: RelayPayload, stream: net.Stream, allocator: std.mem.Allocator) !void {
    _ = allocator;
    
    std.log.debug("Processing RELAY_DATA for stream {} ({} bytes)", .{ relay_payload.stream_id, relay_payload.data.len });
    
    if (session.dest_connection == null) {
        std.log.warn("No destination connection for RELAY_DATA", .{});
        return;
    }
    
    // データを宛先に転送
    session.dest_connection.?.writeAll(relay_payload.data) catch |err| {
        std.log.err("Failed to write to destination: {}", .{err});
        try sendRelayEnd(session, relay_payload.stream_id, stream);
        return;
    };
    
    // 宛先からの応答を読み取り
    var response_buffer: [4096]u8 = undefined;
    const bytes_read = session.dest_connection.?.read(&response_buffer) catch |err| {
        std.log.err("Failed to read from destination: {}", .{err});
        try sendRelayEnd(session, relay_payload.stream_id, stream);
        return;
    };
    
    if (bytes_read > 0) {
        // 応答をRELAY_DATAとして送り返す
        try sendRelayData(session, relay_payload.stream_id, response_buffer[0..bytes_read], stream);
    }
}

// RELAY_END の処理
fn handleRelayEnd(session: *ExitSession, relay_payload: RelayPayload, allocator: std.mem.Allocator) !void {
    _ = allocator;
    
    std.log.debug("Processing RELAY_END for stream {}", .{relay_payload.stream_id});
    
    if (session.dest_connection) |conn| {
        conn.close();
        session.dest_connection = null;
    }
}

// DESTROY セルの処理
fn handleDestroy(cell: Cell, allocator: std.mem.Allocator) !void {
    _ = allocator;
    
    std.log.debug("Processing DESTROY cell for circuit {}", .{cell.circuit_id});
    
    sessions_mutex.lock();
    defer sessions_mutex.unlock();
    
    if (sessions.fetchRemove(cell.circuit_id)) |entry| {
        var session = entry.value;
        session.deinit();
        std.log.debug("Destroyed circuit {}", .{cell.circuit_id});
    }
}

// RELAY_CONNECTED セルの送信
fn sendRelayConnected(session: *ExitSession, stream_id: u16, stream: net.Stream) !void {
    var payload_buffer: [lib.cell.PAYLOAD_SIZE]u8 = undefined;
    
    const relay_payload = RelayPayload{
        .command = .relay_connected,
        .recognized = 0,
        .stream_id = stream_id,
        .digest = [_]u8{0} ** 4,
        .length = 0,
        .data = &[_]u8{},
    };
    
    const payload_len = try relay_payload.serialize(&payload_buffer);
    
    // 暗号化
    var encrypted_payload: [lib.cell.PAYLOAD_SIZE]u8 = undefined;
    const aes = crypto.AesCtr.init(session.shared_key);
    const iv = [_]u8{0} ** crypto.IV_SIZE;
    
    try aes.encrypt(payload_buffer[0..payload_len], iv, encrypted_payload[0..payload_len]);
    
    // RELAY セルとして送信
    var response_cell = Cell.init(session.circuit_id, .relay);
    @memcpy(response_cell.payload[0..payload_len], encrypted_payload[0..payload_len]);
    
    const response_bytes = try response_cell.toBytes();
    try stream.writeAll(&response_bytes);
    
    std.log.debug("Sent RELAY_CONNECTED for stream {}", .{stream_id});
}

// RELAY_DATA セルの送信
fn sendRelayData(session: *ExitSession, stream_id: u16, data: []const u8, stream: net.Stream) !void {
    var payload_buffer: [lib.cell.PAYLOAD_SIZE]u8 = undefined;
    
    const relay_payload = RelayPayload{
        .command = .relay_data,
        .recognized = 0,
        .stream_id = stream_id,
        .digest = [_]u8{0} ** 4,
        .length = @intCast(data.len),
        .data = data,
    };
    
    const payload_len = try relay_payload.serialize(&payload_buffer);
    
    // 暗号化
    var encrypted_payload: [lib.cell.PAYLOAD_SIZE]u8 = undefined;
    const aes = crypto.AesCtr.init(session.shared_key);
    const iv = [_]u8{0} ** crypto.IV_SIZE;
    
    try aes.encrypt(payload_buffer[0..payload_len], iv, encrypted_payload[0..payload_len]);
    
    // RELAY セルとして送信
    var response_cell = Cell.init(session.circuit_id, .relay);
    @memcpy(response_cell.payload[0..payload_len], encrypted_payload[0..payload_len]);
    
    const response_bytes = try response_cell.toBytes();
    try stream.writeAll(&response_bytes);
    
    std.log.debug("Sent RELAY_DATA for stream {} ({} bytes)", .{ stream_id, data.len });
}

// RELAY_END セルの送信
fn sendRelayEnd(session: *ExitSession, stream_id: u16, stream: net.Stream) !void {
    var payload_buffer: [lib.cell.PAYLOAD_SIZE]u8 = undefined;
    
    const relay_payload = RelayPayload{
        .command = .relay_end,
        .recognized = 0,
        .stream_id = stream_id,
        .digest = [_]u8{0} ** 4,
        .length = 0,
        .data = &[_]u8{},
    };
    
    const payload_len = try relay_payload.serialize(&payload_buffer);
    
    // 暗号化
    var encrypted_payload: [lib.cell.PAYLOAD_SIZE]u8 = undefined;
    const aes = crypto.AesCtr.init(session.shared_key);
    const iv = [_]u8{0} ** crypto.IV_SIZE;
    
    try aes.encrypt(payload_buffer[0..payload_len], iv, encrypted_payload[0..payload_len]);
    
    // RELAY セルとして送信
    var response_cell = Cell.init(session.circuit_id, .relay);
    @memcpy(response_cell.payload[0..payload_len], encrypted_payload[0..payload_len]);
    
    const response_bytes = try response_cell.toBytes();
    try stream.writeAll(&response_bytes);
    
    std.log.debug("Sent RELAY_END for stream {}", .{stream_id});
}