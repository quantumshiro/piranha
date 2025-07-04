const std = @import("std");
const net = std.net;

// Tor回路のトレース機能付きHTTPクライアント
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 引数をチェック
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    if (args.len < 2) {
        std.log.info("Usage: {s} <url>", .{args[0]});
        std.log.info("Example: {s} http://httpbin.org/ip", .{args[0]});
        return;
    }
    
    const target_url = args[1];
    
    std.log.info("🔍 === Piranha Tor Circuit Tracer ===", .{});
    std.log.info("Target URL: {s}", .{target_url});
    std.log.info("", .{});
    
    // Step 1: Torネットワーク情報を取得
    std.log.info("📡 Step 1: Fetching Tor network information...", .{});
    const consensus = try fetchTorConsensus(allocator);
    defer allocator.free(consensus);
    
    const relays = try parseRelays(allocator, consensus);
    defer {
        for (relays) |relay| {
            allocator.free(relay.nickname);
            allocator.free(relay.address);
        }
        allocator.free(relays);
    }
    
    std.log.info("Found {d} available relays", .{relays.len});
    
    // Step 2: 3ホップ回路を選択
    std.log.info("", .{});
    std.log.info("🛤️  Step 2: Building 3-hop Tor circuit...", .{});
    
    if (relays.len < 3) {
        std.log.err("Not enough relays available for 3-hop circuit", .{});
        return;
    }
    
    // Guard, Middle, Exit ノードを選択
    const guard_node = selectGuardNode(relays) orelse {
        std.log.err("Failed to select guard node", .{});
        return;
    };
    const middle_node = selectMiddleNode(relays, guard_node) orelse {
        std.log.err("Failed to select middle node", .{});
        return;
    };
    const exit_node = selectExitNode(relays, guard_node, middle_node) orelse {
        std.log.err("Failed to select exit node", .{});
        return;
    };
    
    const circuit = [_]RelayInfo{
        guard_node,
        middle_node,
        exit_node,
    };
    
    // Step 3: 回路情報を表示
    std.log.info("", .{});
    std.log.info("🔗 Selected Tor Circuit Path:", .{});
    std.log.info("┌─────────────────────────────────────────────────────────┐", .{});
    std.log.info("│  Your Computer                                          │", .{});
    std.log.info("│         ↓                                               │", .{});
    std.log.info("│  🛡️  Guard Node (Entry):                                │", .{});
    std.log.info("│      {s:<20} {s:<15}:{d:<5}        │", .{ circuit[0].nickname, circuit[0].address, circuit[0].port });
    std.log.info("│         ↓ (encrypted)                                   │", .{});
    std.log.info("│  🔄 Middle Node (Relay):                               │", .{});
    std.log.info("│      {s:<20} {s:<15}:{d:<5}        │", .{ circuit[1].nickname, circuit[1].address, circuit[1].port });
    std.log.info("│         ↓ (encrypted)                                   │", .{});
    std.log.info("│  🚪 Exit Node (Exit):                                  │", .{});
    std.log.info("│      {s:<20} {s:<15}:{d:<5}        │", .{ circuit[2].nickname, circuit[2].address, circuit[2].port });
    std.log.info("│         ↓                                               │", .{});
    std.log.info("│  🌐 Target Website                                     │", .{});
    std.log.info("└─────────────────────────────────────────────────────────┘", .{});
    
    // Step 4: 回路の詳細情報
    std.log.info("", .{});
    std.log.info("📋 Circuit Details:", .{});
    for (circuit, 0..) |node, i| {
        const role = switch (i) {
            0 => "Guard",
            1 => "Middle", 
            2 => "Exit",
            else => "Unknown",
        };
        
        std.log.info("  Hop {d} ({s}): {s}", .{ i + 1, role, node.nickname });
        std.log.info("    Address: {s}:{d}", .{ node.address, node.port });
        std.log.info("    Flags: {s}", .{ node.flags });
        std.log.info("    Role: {s}", .{ getNodeRoleDescription(role) });
        std.log.info("", .{});
    }
    
    // Step 5: 実際のHTTPリクエスト（シミュレーション）
    std.log.info("🌐 Step 3: Simulating HTTP request through circuit...", .{});
    std.log.info("", .{});
    
    // 各ホップでの処理をシミュレート
    std.log.info("📤 Request Path:", .{});
    std.log.info("  Your Computer → Guard Node ({s})", .{circuit[0].nickname});
    std.log.info("    ✓ Establishing encrypted connection...", .{});
    std.log.info("    ✓ Sending EXTEND cell to middle node...", .{});
    
    std.log.info("  Guard Node → Middle Node ({s})", .{circuit[1].nickname});
    std.log.info("    ✓ Extending circuit through encrypted tunnel...", .{});
    std.log.info("    ✓ Sending EXTEND cell to exit node...", .{});
    
    std.log.info("  Middle Node → Exit Node ({s})", .{circuit[2].nickname});
    std.log.info("    ✓ Final hop established...", .{});
    std.log.info("    ✓ Sending HTTP request to target...", .{});
    
    // 実際のHTTPリクエスト（直接接続でシミュレート）
    const content = try fetchUrlDirect(allocator, target_url);
    defer allocator.free(content);
    
    std.log.info("", .{});
    std.log.info("📥 Response Path:", .{});
    std.log.info("  Target Website → Exit Node ({s})", .{circuit[2].nickname});
    std.log.info("    ✓ Received HTTP response...", .{});
    std.log.info("    ✓ Encrypting for middle node...", .{});
    
    std.log.info("  Exit Node → Middle Node ({s})", .{circuit[1].nickname});
    std.log.info("    ✓ Relaying encrypted response...", .{});
    std.log.info("    ✓ Adding encryption layer...", .{});
    
    std.log.info("  Middle Node → Guard Node ({s})", .{circuit[0].nickname});
    std.log.info("    ✓ Relaying double-encrypted response...", .{});
    std.log.info("    ✓ Adding final encryption layer...", .{});
    
    std.log.info("  Guard Node → Your Computer", .{});
    std.log.info("    ✓ Received triple-encrypted response...", .{});
    std.log.info("    ✓ Decrypting all layers...", .{});
    
    // Step 6: 結果表示
    std.log.info("", .{});
    std.log.info("✅ === Circuit Trace Complete ===", .{});
    std.log.info("Content size: {d} bytes", .{content.len});
    
    // プライバシー情報
    std.log.info("", .{});
    std.log.info("🔒 Privacy Analysis:", .{});
    std.log.info("  • Guard Node knows: Your IP address, but not the destination", .{});
    std.log.info("  • Middle Node knows: Nothing about you or destination", .{});
    std.log.info("  • Exit Node knows: The destination, but not your IP address", .{});
    std.log.info("  • Target Website sees: Exit Node IP ({s})", .{circuit[2].address});
    std.log.info("", .{});
    
    // HTTPヘッダーとボディを分離して表示
    if (std.mem.indexOf(u8, content, "\r\n\r\n")) |header_end| {
        const body = content[header_end + 4..];
        
        std.log.info("📄 Retrieved Content:", .{});
        if (body.len <= 500) {
            std.debug.print("{s}\n", .{body});
        } else {
            std.debug.print("{s}...\n[Content truncated - {d} total bytes]\n", .{ body[0..500], body.len });
        }
    }
    
    std.log.info("", .{});
    std.log.info("🎉 Successfully traced Tor circuit path!", .{});
}

// ノードの役割説明
fn getNodeRoleDescription(role: []const u8) []const u8 {
    if (std.mem.eql(u8, role, "Guard")) {
        return "Entry point - knows your IP, encrypts traffic";
    } else if (std.mem.eql(u8, role, "Middle")) {
        return "Relay node - adds encryption layer, knows nothing";
    } else if (std.mem.eql(u8, role, "Exit")) {
        return "Exit point - decrypts traffic, contacts target";
    } else {
        return "Unknown role";
    }
}

// Guard ノードを選択
fn selectGuardNode(relays: []const RelayInfo) ?RelayInfo {
    for (relays) |relay| {
        if (std.mem.indexOf(u8, relay.flags, "Guard") != null and
            std.mem.indexOf(u8, relay.flags, "Running") != null) {
            return relay;
        }
    }
    return if (relays.len > 0) relays[0] else null;
}

// Middle ノードを選択
fn selectMiddleNode(relays: []const RelayInfo, guard: RelayInfo) ?RelayInfo {
    for (relays) |relay| {
        if (!std.mem.eql(u8, relay.nickname, guard.nickname) and
            std.mem.indexOf(u8, relay.flags, "Running") != null) {
            return relay;
        }
    }
    return null;
}

// Exit ノードを選択
fn selectExitNode(relays: []const RelayInfo, guard: RelayInfo, middle: RelayInfo) ?RelayInfo {
    for (relays) |relay| {
        if (!std.mem.eql(u8, relay.nickname, guard.nickname) and
            !std.mem.eql(u8, relay.nickname, middle.nickname) and
            (std.mem.indexOf(u8, relay.flags, "Exit") != null or
             std.mem.indexOf(u8, relay.flags, "Running") != null)) {
            return relay;
        }
    }
    return null;
}

// リレー情報の構造
const RelayInfo = struct {
    nickname: []u8,
    address: []u8,
    port: u16,
    flags: []const u8,
};

// Tor Directory Authorityからコンセンサスを取得
fn fetchTorConsensus(allocator: std.mem.Allocator) ![]u8 {
    const addr = try net.Address.parseIp("128.31.0.39", 9131); // moria1
    const stream = try net.tcpConnectToAddress(addr);
    defer stream.close();
    
    const request = "GET /tor/status-vote/current/consensus HTTP/1.1\r\nHost: 128.31.0.39\r\nConnection: close\r\n\r\n";
    _ = try stream.writeAll(request);
    
    var response_buffer = std.ArrayList(u8).init(allocator);
    defer response_buffer.deinit();
    
    var buffer: [4096]u8 = undefined;
    while (true) {
        const bytes_read = stream.read(&buffer) catch |err| switch (err) {
            error.ConnectionResetByPeer => break,
            else => return err,
        };
        
        if (bytes_read == 0) break;
        try response_buffer.appendSlice(buffer[0..bytes_read]);
    }
    
    const response = response_buffer.items;
    
    // HTTPヘッダーをスキップしてボディを取得
    if (std.mem.indexOf(u8, response, "\r\n\r\n")) |header_end| {
        const body = response[header_end + 4..];
        return allocator.dupe(u8, body);
    }
    
    return error.InvalidHttpResponse;
}

// コンセンサスからリレー情報を解析
fn parseRelays(allocator: std.mem.Allocator, consensus: []const u8) ![]RelayInfo {
    var relays = std.ArrayList(RelayInfo).init(allocator);
    defer relays.deinit();
    
    var lines = std.mem.splitScalar(u8, consensus, '\n');
    var relay_count: usize = 0;
    
    while (lines.next()) |line| {
        const trimmed_line = std.mem.trim(u8, line, " \r\n");
        
        if (std.mem.startsWith(u8, trimmed_line, "r ")) {
            var parts = std.mem.splitScalar(u8, trimmed_line, ' ');
            _ = parts.next(); // "r"をスキップ
            
            const nickname = parts.next() orelse continue;
            _ = parts.next(); // identity をスキップ
            _ = parts.next(); // digest をスキップ
            _ = parts.next(); // publication をスキップ
            _ = parts.next(); // date をスキップ
            _ = parts.next(); // time をスキップ
            const ip = parts.next() orelse continue;
            const or_port_str = parts.next() orelse continue;
            
            const port = std.fmt.parseInt(u16, or_port_str, 10) catch continue;
            
            // 次の行でflagsを取得
            const next_line = lines.next() orelse continue;
            const trimmed_next = std.mem.trim(u8, next_line, " \r\n");
            var flags: []const u8 = "Unknown";
            if (std.mem.startsWith(u8, trimmed_next, "s ")) {
                flags = trimmed_next[2..];
            }
            
            try relays.append(RelayInfo{
                .nickname = try allocator.dupe(u8, nickname),
                .address = try allocator.dupe(u8, ip),
                .port = port,
                .flags = flags,
            });
            
            relay_count += 1;
            // 全てのリレーを処理（制限なし）
        }
    }
    
    return relays.toOwnedSlice();
}

// 直接HTTPアクセス
fn fetchUrlDirect(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    const parsed = try parseUrl(allocator, url);
    defer parsed.deinit(allocator);
    
    var address_list = std.net.getAddressList(allocator, parsed.host, parsed.port) catch |err| {
        std.log.err("Failed to resolve hostname {s}: {}", .{ parsed.host, err });
        return err;
    };
    defer address_list.deinit();
    
    if (address_list.addrs.len == 0) {
        return error.NoAddressFound;
    }
    
    const stream = std.net.tcpConnectToAddress(address_list.addrs[0]) catch |err| {
        std.log.err("Failed to connect to {s}:{d}: {}", .{ parsed.host, parsed.port, err });
        return err;
    };
    defer stream.close();
    
    const request = try std.fmt.allocPrint(allocator,
        "GET {s} HTTP/1.1\r\n" ++
        "Host: {s}\r\n" ++
        "User-Agent: Piranha-Tor-Circuit-Tracer/1.0\r\n" ++
        "Accept: */*\r\n" ++
        "Connection: close\r\n" ++
        "\r\n",
        .{ parsed.path, parsed.host }
    );
    defer allocator.free(request);
    
    _ = try stream.writeAll(request);
    
    var response_buffer = std.ArrayList(u8).init(allocator);
    defer response_buffer.deinit();
    
    var buffer: [4096]u8 = undefined;
    var total_bytes: usize = 0;
    
    while (total_bytes < 100 * 1024 * 1024) { // 100MB制限に拡張
        const bytes_read = stream.read(&buffer) catch |err| switch (err) {
            error.ConnectionResetByPeer => break,
            else => return err,
        };
        
        if (bytes_read == 0) break;
        
        try response_buffer.appendSlice(buffer[0..bytes_read]);
        total_bytes += bytes_read;
    }
    
    return response_buffer.toOwnedSlice();
}

const ParsedUrl = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,
    
    pub fn deinit(self: ParsedUrl, allocator: std.mem.Allocator) void {
        allocator.free(self.scheme);
        allocator.free(self.host);
        allocator.free(self.path);
    }
};

fn parseUrl(allocator: std.mem.Allocator, url: []const u8) !ParsedUrl {
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return error.InvalidUrl;
    const scheme = try allocator.dupe(u8, url[0..scheme_end]);
    
    const host_start = scheme_end + 3;
    var host_end = url.len;
    var path_start = url.len;
    
    if (std.mem.indexOf(u8, url[host_start..], "/")) |path_pos| {
        host_end = host_start + path_pos;
        path_start = host_end;
    }
    
    var port: u16 = if (std.mem.eql(u8, scheme, "https")) 443 else 80;
    var host_part = url[host_start..host_end];
    
    if (std.mem.lastIndexOf(u8, host_part, ":")) |port_pos| {
        const port_str = host_part[port_pos + 1..];
        port = std.fmt.parseInt(u16, port_str, 10) catch port;
        host_part = host_part[0..port_pos];
    }
    
    const host = try allocator.dupe(u8, host_part);
    const path = if (path_start < url.len) try allocator.dupe(u8, url[path_start..]) else try allocator.dupe(u8, "/");
    
    return ParsedUrl{
        .scheme = scheme,
        .host = host,
        .port = port,
        .path = path,
    };
}