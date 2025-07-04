const std = @import("std");
const net = std.net;
const circuit = @import("circuit.zig");
const builder = @import("builder.zig");
const CircuitBuilder = builder.CircuitBuilder;
const RelayCommand = builder.RelayCommand;
const RelayCell = builder.RelayCell;

// HTTP over Tor クライアント
pub const HttpOverTorClient = struct {
    allocator: std.mem.Allocator,
    circuit_builder: *CircuitBuilder,
    
    pub fn init(allocator: std.mem.Allocator, circuit_builder: *CircuitBuilder) HttpOverTorClient {
        return HttpOverTorClient{
            .allocator = allocator,
            .circuit_builder = circuit_builder,
        };
    }
    
    // URLからWebサイトのコンテンツを取得
    pub fn fetchUrl(self: *HttpOverTorClient, url: []const u8) ![]u8 {
        std.log.info("Fetching URL via Tor: {s}", .{url});
        
        // URLをパース
        const parsed_url = try parseUrl(self.allocator, url);
        defer parsed_url.deinit(self.allocator);
        
        std.log.info("Parsed URL - Host: {s}, Port: {d}, Path: {s}", .{ parsed_url.host, parsed_url.port, parsed_url.path });
        
        // 回路を構築
        std.log.info("Building circuit...", .{});
        const circuit_id = try self.circuit_builder.buildCircuit();
        // defer self.circuit_builder.circuit_manager.destroyCircuit(circuit_id);
        
        std.log.info("Circuit {d} built successfully", .{circuit_id});
        
        // ストリームを開始
        const stream_id: u16 = 1;
        try self.establishStream(circuit_id, stream_id, parsed_url.host, parsed_url.port);
        
        std.log.info("Stream {d} established to {s}:{d}", .{ stream_id, parsed_url.host, parsed_url.port });
        
        // HTTPリクエストを送信
        const response = try self.sendHttpRequest(circuit_id, stream_id, parsed_url);
        
        std.log.info("HTTP response received ({d} bytes)", .{response.len});
        
        return response;
    }
    
    // ストリームを確立
    fn establishStream(self: *HttpOverTorClient, circuit_id: u16, stream_id: u16, host: []const u8, port: u16) !void {
        // RELAY_BEGIN セルを作成
        const begin_payload = try std.fmt.allocPrint(self.allocator, "{s}:{d}\x00", .{ host, port });
        defer self.allocator.free(begin_payload);
        
        // RELAY_BEGIN セルを送信
        try self.circuit_builder.sendRelayCell(circuit_id, @intFromEnum(RelayCommand.relay_begin), stream_id, begin_payload);
        
        // RELAY_CONNECTED レスポンスを待機
        const response_cell = try self.circuit_builder.receiveRelayCell(circuit_id);
        
        if (response_cell.command != .relay_connected or response_cell.stream_id != stream_id) {
            std.log.err("Failed to establish stream: unexpected response command={any}, stream_id={d}", .{ response_cell.command, response_cell.stream_id });
            return error.StreamEstablishmentFailed;
        }
        
        std.log.debug("Stream established successfully", .{});
    }
    
    // HTTPリクエストを送信してレスポンスを受信
    fn sendHttpRequest(self: *HttpOverTorClient, circuit_id: u16, stream_id: u16, parsed_url: ParsedUrl) ![]u8 {
        // HTTPリクエストを構築
        const http_request = try self.buildHttpRequest(parsed_url);
        defer self.allocator.free(http_request);
        
        std.log.debug("Sending HTTP request:\n{s}", .{http_request});
        
        // HTTPリクエストをRELAY_DATAセルとして送信
        try self.circuit_builder.sendRelayCell(circuit_id, @intFromEnum(RelayCommand.relay_data), stream_id, http_request);
        
        // HTTPレスポンスを受信
        var response_buffer = std.ArrayList(u8).init(self.allocator);
        defer response_buffer.deinit();
        
        var total_bytes: usize = 0;
        const max_response_size = 100 * 1024 * 1024; // 100MB制限に拡張
        
        while (total_bytes < max_response_size) {
            const response_cell = self.circuit_builder.receiveRelayCell(circuit_id) catch |err| {
                std.log.debug("Error receiving relay cell: {}", .{err});
                break;
            };
            
            if (response_cell.stream_id != stream_id) {
                continue; // 他のストリームのデータは無視
            }
            
            if (response_cell.command == .relay_data) {
                try response_buffer.appendSlice(response_cell.data);
                total_bytes += response_cell.data.len;
                
                std.log.debug("Received {d} bytes (total: {d})", .{ response_cell.data.len, total_bytes });
                
                // HTTPレスポンスの終了を検出
                if (self.isHttpResponseComplete(response_buffer.items)) {
                    break;
                }
            } else if (response_cell.command == .relay_end) {
                std.log.debug("Stream ended by remote", .{});
                break;
            }
        }
        
        return response_buffer.toOwnedSlice();
    }
    
    // HTTPリクエストを構築
    fn buildHttpRequest(self: *HttpOverTorClient, parsed_url: ParsedUrl) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "User-Agent: Piranha-Tor-Client/1.0\r\n" ++
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" ++
            "Accept-Language: en-US,en;q=0.5\r\n" ++
            "Accept-Encoding: identity\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
            .{ parsed_url.path, parsed_url.host }
        );
    }
    
    // HTTPレスポンスが完了したかチェック
    fn isHttpResponseComplete(self: *HttpOverTorClient, response: []const u8) bool {
        _ = self;
        
        // HTTPヘッダーの終了を探す
        const header_end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return false;
        
        // Content-Lengthヘッダーを探す
        if (std.mem.indexOf(u8, response[0..header_end], "Content-Length:")) |content_length_pos| {
            _ = std.mem.lastIndexOf(u8, response[0..content_length_pos], "\r\n") orelse 0;
            const line_end = std.mem.indexOf(u8, response[content_length_pos..], "\r\n") orelse return false;
            
            const content_length_line = response[content_length_pos..content_length_pos + line_end];
            
            // Content-Lengthの値を抽出
            if (std.mem.indexOf(u8, content_length_line, ": ")) |colon_pos| {
                const length_str = std.mem.trim(u8, content_length_line[colon_pos + 2..], " \t\r\n");
                const content_length = std.fmt.parseInt(usize, length_str, 10) catch return false;
                
                const body_start = header_end + 4;
                const current_body_length = response.len - body_start;
                
                return current_body_length >= content_length;
            }
        }
        
        // Transfer-Encoding: chunkedの場合
        if (std.mem.indexOf(u8, response[0..header_end], "Transfer-Encoding: chunked") != null) {
            return std.mem.endsWith(u8, response, "\r\n0\r\n\r\n");
        }
        
        // Connection: closeの場合は接続が閉じられるまで待つ
        return false;
    }
};

// URL解析結果
const ParsedUrl = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: ParsedUrl, allocator: std.mem.Allocator) void {
        allocator.free(self.scheme);
        allocator.free(self.host);
        allocator.free(self.path);
    }
};

// URLをパース
fn parseUrl(allocator: std.mem.Allocator, url: []const u8) !ParsedUrl {
    
    // スキームを抽出
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return error.InvalidUrl;
    const scheme = try allocator.dupe(u8, url[0..scheme_end]);
    
    // ホスト部分を抽出
    const host_start = scheme_end + 3;
    var host_end = url.len;
    var path_start = url.len;
    
    // パスの開始位置を探す
    if (std.mem.indexOf(u8, url[host_start..], "/")) |path_pos| {
        host_end = host_start + path_pos;
        path_start = host_end;
    }
    
    // ポート番号を抽出
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
        .allocator = allocator,
    };
}

test "URL parsing" {
    const allocator = std.testing.allocator;
    
    // HTTP URL
    {
        const parsed = try parseUrl("http://example.com/path/to/page");
        defer parsed.deinit(allocator);
        
        try std.testing.expectEqualStrings("http", parsed.scheme);
        try std.testing.expectEqualStrings("example.com", parsed.host);
        try std.testing.expectEqual(@as(u16, 80), parsed.port);
        try std.testing.expectEqualStrings("/path/to/page", parsed.path);
    }
    
    // HTTPS URL with port
    {
        const parsed = try parseUrl("https://example.com:8443/");
        defer parsed.deinit(allocator);
        
        try std.testing.expectEqualStrings("https", parsed.scheme);
        try std.testing.expectEqualStrings("example.com", parsed.host);
        try std.testing.expectEqual(@as(u16, 8443), parsed.port);
        try std.testing.expectEqualStrings("/", parsed.path);
    }
}