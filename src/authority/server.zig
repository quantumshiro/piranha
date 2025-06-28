const std = @import("std");
const testing = std.testing;
const http = std.http;
const net = std.net;
// const DirectoryAuthority = @import("directory.zig").DirectoryAuthority;
const AuthorityConfig = @import("config.zig").AuthorityConfig;
const NodeInfo = @import("node.zig").NodeInfo;
// Import common modules 
const signature_mod = @import("signature");

// Import signature utilities from common module
pub const SIGNATURE_SIZE = signature_mod.SIGNATURE_SIZE;
pub const PUBLIC_KEY_SIZE = signature_mod.PUBLIC_KEY_SIZE;
pub const PRIVATE_KEY_SIZE = signature_mod.PRIVATE_KEY_SIZE;
pub const Ed25519KeyPair = signature_mod.Ed25519KeyPair;
pub const SignatureManager = signature_mod.SignatureManager;

pub const RegistrationRequest = struct {
    type: []const u8,
    nickname: []const u8,
    address: []const u8,
    pubkey_b64: []const u8,
    signature: []const u8,
    
    pub fn fromJson(allocator: std.mem.Allocator, json_data: []const u8) !RegistrationRequest {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_data, .{});
        defer parsed.deinit();
        
        const root = parsed.value.object;
        
        const type_val = root.get("type") orelse return error.MissingType;
        const nickname_val = root.get("nickname") orelse return error.MissingNickname;
        const address_val = root.get("address") orelse return error.MissingAddress;
        const pubkey_val = root.get("pubkey_b64") orelse return error.MissingPubkey;
        const signature_val = root.get("signature") orelse return error.MissingSignature;
        
        if (type_val != .string or nickname_val != .string or address_val != .string or 
            pubkey_val != .string or signature_val != .string) {
            return error.InvalidDataTypes;
        }
        
        return RegistrationRequest{
            .type = try allocator.dupe(u8, type_val.string),
            .nickname = try allocator.dupe(u8, nickname_val.string),
            .address = try allocator.dupe(u8, address_val.string),
            .pubkey_b64 = try allocator.dupe(u8, pubkey_val.string),
            .signature = try allocator.dupe(u8, signature_val.string),
        };
    }
    
    pub fn deinit(self: *RegistrationRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.type);
        allocator.free(self.nickname);
        allocator.free(self.address);
        allocator.free(self.pubkey_b64);
        allocator.free(self.signature);
    }
    
    pub fn validate(self: *const RegistrationRequest) !void {
        if (self.nickname.len == 0 or self.nickname.len > 19) {
            return error.InvalidNickname;
        }
        
        if (self.address.len == 0 or self.address.len > 255) {
            return error.InvalidAddress;
        }
        
        if (self.pubkey_b64.len == 0) {
            return error.InvalidPubkey;
        }
        
        if (self.signature.len == 0) {
            return error.InvalidSignature;
        }
        
        if (!std.mem.eql(u8, self.type, "relay") and !std.mem.eql(u8, self.type, "exit")) {
            return error.InvalidType;
        }
    }
};

pub const ServerError = error{
    StartupFailed,
    InvalidRequest,
    NotFound,
    MethodNotAllowed,
    InternalServerError,
    Unauthorized,
};

pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    OPTIONS,
    
    pub fn fromString(method_str: []const u8) ?HttpMethod {
        if (std.mem.eql(u8, method_str, "GET")) return .GET;
        if (std.mem.eql(u8, method_str, "POST")) return .POST;
        if (std.mem.eql(u8, method_str, "PUT")) return .PUT;
        if (std.mem.eql(u8, method_str, "DELETE")) return .DELETE;
        if (std.mem.eql(u8, method_str, "OPTIONS")) return .OPTIONS;
        return null;
    }
};

pub const HttpRequest = struct {
    method: HttpMethod,
    path: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, method: HttpMethod, path: []const u8, body: []const u8) !HttpRequest {
        return HttpRequest{
            .method = method,
            .path = try allocator.dupe(u8, path),
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = try allocator.dupe(u8, body),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *HttpRequest) void {
        self.allocator.free(self.path);
        self.allocator.free(self.body);
        
        var iterator = self.headers.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
    }
    
    pub fn addHeader(self: *HttpRequest, name: []const u8, value: []const u8) !void {
        const name_owned = try self.allocator.dupe(u8, name);
        const value_owned = try self.allocator.dupe(u8, value);
        try self.headers.put(name_owned, value_owned);
    }
    
    pub fn getHeader(self: *const HttpRequest, name: []const u8) ?[]const u8 {
        return self.headers.get(name);
    }
};

pub const HttpResponse = struct {
    status_code: u16,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, status_code: u16) HttpResponse {
        return HttpResponse{
            .status_code = status_code,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *HttpResponse) void {
        if (self.body.len > 0) {
            self.allocator.free(self.body);
        }
        
        var iterator = self.headers.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
    }
    
    pub fn setHeader(self: *HttpResponse, name: []const u8, value: []const u8) !void {
        const name_owned = try self.allocator.dupe(u8, name);
        const value_owned = try self.allocator.dupe(u8, value);
        try self.headers.put(name_owned, value_owned);
    }
    
    pub fn setBody(self: *HttpResponse, body: []const u8) !void {
        if (self.body.len > 0) {
            self.allocator.free(self.body);
        }
        self.body = try self.allocator.dupe(u8, body);
    }
    
    pub fn setJsonBody(self: *HttpResponse, json_data: []const u8) !void {
        try self.setHeader("Content-Type", "application/json");
        try self.setBody(json_data);
    }
    
    pub fn toBytes(self: *const HttpResponse) ![]u8 {
        var response_lines = std.ArrayList([]const u8).init(self.allocator);
        defer response_lines.deinit();
        
        // Status line
        const status_line = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 {d} {s}", .{ self.status_code, getStatusText(self.status_code) });
        try response_lines.append(status_line);
        
        // Headers
        var header_iterator = self.headers.iterator();
        while (header_iterator.next()) |entry| {
            const header_line = try std.fmt.allocPrint(self.allocator, "{s}: {s}", .{ entry.key_ptr.*, entry.value_ptr.* });
            try response_lines.append(header_line);
        }
        
        // Content-Length header
        const content_length = try std.fmt.allocPrint(self.allocator, "Content-Length: {d}", .{self.body.len});
        try response_lines.append(content_length);
        
        // Empty line before body
        try response_lines.append(try self.allocator.dupe(u8, ""));
        
        // Calculate total size
        var total_size: usize = self.body.len;
        for (response_lines.items) |line| {
            total_size += line.len + 2; // +2 for CRLF
        }
        
        var result = try self.allocator.alloc(u8, total_size);
        var offset: usize = 0;
        
        for (response_lines.items) |line| {
            @memcpy(result[offset..offset + line.len], line);
            offset += line.len;
            result[offset] = '\r';
            result[offset + 1] = '\n';
            offset += 2;
            self.allocator.free(line);
        }
        
        @memcpy(result[offset..offset + self.body.len], self.body);
        
        return result;
    }
    
    fn getStatusText(status_code: u16) []const u8 {
        return switch (status_code) {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            else => "Unknown",
        };
    }
};

// Real DirectoryAuthority implementation
pub const DirectoryAuthority = struct {
    config: AuthorityConfig,
    nodes: std.ArrayList(NodeInfo),
    consensus_version: u32,
    last_consensus_time: i64,
    signature_manager: SignatureManager,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: AuthorityConfig) DirectoryAuthority {
        return DirectoryAuthority{
            .config = config,
            .nodes = std.ArrayList(NodeInfo).init(allocator),
            .consensus_version = 1,
            .last_consensus_time = std.time.timestamp(),
            .signature_manager = SignatureManager.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DirectoryAuthority) void {
        for (self.nodes.items) |*node| {
            node.deinit();
        }
        self.nodes.deinit();
    }
    
    pub fn getConsensusInfo(self: *const DirectoryAuthority) struct {
        version: u32,
        timestamp: i64,
        node_count: usize,
    } {
        return .{
            .version = self.consensus_version,
            .timestamp = std.time.timestamp(),
            .node_count = self.nodes.items.len,
        };
    }
    
    pub fn generateConsensus(self: *const DirectoryAuthority) ![]u8 {
        const version_str = try std.fmt.allocPrint(self.allocator, "{d}", .{self.consensus_version});
        defer self.allocator.free(version_str);
        
        const timestamp_str = try std.fmt.allocPrint(self.allocator, "{d}", .{std.time.timestamp()});
        defer self.allocator.free(timestamp_str);

        var consensus_json = std.ArrayList(u8).init(self.allocator);
        defer consensus_json.deinit();

        try consensus_json.appendSlice("{\"version\":");
        try consensus_json.appendSlice(version_str);
        try consensus_json.appendSlice(",\"timestamp\":");
        try consensus_json.appendSlice(timestamp_str);
        try consensus_json.appendSlice(",\"nodes\":[");

        for (self.nodes.items, 0..) |node, i| {
            const node_json = try node.toJson(self.allocator);
            defer self.allocator.free(node_json);
            
            try consensus_json.appendSlice(node_json);
            if (i < self.nodes.items.len - 1) {
                try consensus_json.appendSlice(",");
            }
        }

        try consensus_json.appendSlice("]}");
        return try consensus_json.toOwnedSlice();
    }
    
    pub fn generateSignedConsensus(self: *const DirectoryAuthority) ![]u8 {
        const consensus_data = try self.generateConsensus();
        defer self.allocator.free(consensus_data);
        
        const signature = self.signature_manager.signData(consensus_data) catch |err| switch (err) {
            error.NoKeyLoaded => {
                // Return unsigned consensus if no key loaded
                return try self.allocator.dupe(u8, consensus_data);
            },
            else => return err,
        };
        
        // Convert signature to hex
        var sig_hex: [SIGNATURE_SIZE * 2]u8 = undefined;
        _ = try std.fmt.bufPrint(&sig_hex, "{x}", .{std.fmt.fmtSliceHexLower(&signature)});
        
        // Create signed JSON
        const signed_json = try std.fmt.allocPrint(self.allocator, 
            "{{\"consensus\":{s},\"signature\":\"{s}\"}}", 
            .{ consensus_data, sig_hex });
        
        return signed_json;
    }
    
    pub fn validateNode(self: *const DirectoryAuthority, nickname: []const u8) bool {
        _ = self;
        return nickname.len > 0 and nickname.len <= 19;
    }
    
    pub fn addNode(self: *DirectoryAuthority, node: NodeInfo) !void {
        // Check for duplicate nicknames
        for (self.nodes.items) |existing_node| {
            if (std.mem.eql(u8, existing_node.nickname, node.nickname)) {
                return error.DuplicateNickname;
            }
        }
        
        try self.nodes.append(node);
    }
    
    pub fn getNodeCount(self: *const DirectoryAuthority) usize {
        return self.nodes.items.len;
    }

    pub fn loadSigningKey(self: *DirectoryAuthority) !void {
        try self.signature_manager.loadFromFile(self.config.sig_key_path);
    }

    pub fn generateSigningKey(self: *DirectoryAuthority) void {
        self.signature_manager.generateNew();
    }

    pub fn saveSigningKey(self: *const DirectoryAuthority) !void {
        try self.signature_manager.saveToFile(self.config.sig_key_path);
    }
    
    const registry = struct {
        pub fn toJson(allocator: std.mem.Allocator, nodes: []const NodeInfo) ![]u8 {
            var json = std.ArrayList(u8).init(allocator);
            defer json.deinit();

            try json.appendSlice("[");
            for (nodes, 0..) |node, i| {
                const node_json = try node.toJson(allocator);
                defer allocator.free(node_json);
                
                try json.appendSlice(node_json);
                if (i < nodes.len - 1) {
                    try json.appendSlice(",");
                }
            }
            try json.appendSlice("]");
            
            return try json.toOwnedSlice();
        }
    };
};

pub const NodeStore = struct {
    nodes: std.ArrayList(NodeInfo),
    allocator: std.mem.Allocator,
    storage_file: []const u8,
    
    pub fn init(allocator: std.mem.Allocator, storage_file: []const u8) NodeStore {
        return NodeStore{
            .nodes = std.ArrayList(NodeInfo).init(allocator),
            .allocator = allocator,
            .storage_file = storage_file,
        };
    }
    
    pub fn deinit(self: *NodeStore) void {
        for (self.nodes.items) |*node| {
            node.deinit();
        }
        self.nodes.deinit();
    }
    
    pub fn addNode(self: *NodeStore, node: NodeInfo) !void {
        try self.nodes.append(node);
        try self.saveToFile();
    }
    
    pub fn saveToFile(self: *NodeStore) !void {
        const file = try std.fs.cwd().createFile(self.storage_file, .{});
        defer file.close();
        
        try file.writeAll("[\n");
        for (self.nodes.items, 0..) |node, i| {
            const node_json = try node.toJson(self.allocator);
            defer self.allocator.free(node_json);
            
            try file.writeAll("  ");
            try file.writeAll(node_json);
            if (i < self.nodes.items.len - 1) {
                try file.writeAll(",");
            }
            try file.writeAll("\n");
        }
        try file.writeAll("]\n");
    }
    
    pub fn loadFromFile(self: *NodeStore) !void {
        const file = std.fs.cwd().openFile(self.storage_file, .{}) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer file.close();
        
        const file_size = try file.getEndPos();
        const contents = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(contents);
        
        _ = try file.readAll(contents);
        
        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, contents, .{});
        defer parsed.deinit();
        
        if (parsed.value != .array) return;
        
        for (parsed.value.array.items) |item| {
            if (item != .object) continue;
            
            const obj = item.object;
            const nickname = obj.get("nickname") orelse continue;
            const address = obj.get("address") orelse continue;
            
            if (nickname != .string or address != .string) continue;
            
            const node = try NodeInfo.init(self.allocator, nickname.string, address.string);
            try self.nodes.append(node);
        }
    }
};

// Directory structure for /directory endpoint
pub const Directory = struct {
    timestamp: []const u8,
    nodes: []const NodeInfo,
    
    pub fn toJson(self: *const Directory, allocator: std.mem.Allocator) ![]u8 {
        var json = std.ArrayList(u8).init(allocator);
        defer json.deinit();
        
        try json.appendSlice("{\"timestamp\":\"");
        try json.appendSlice(self.timestamp);
        try json.appendSlice("\",\"nodes\":[");
        
        for (self.nodes, 0..) |node, i| {
            const node_json = try node.toJson(allocator);
            defer allocator.free(node_json);
            
            try json.appendSlice(node_json);
            if (i < self.nodes.len - 1) {
                try json.appendSlice(",");
            }
        }
        
        try json.appendSlice("]}");
        return try json.toOwnedSlice();
    }
};

fn generateISO8601Timestamp(allocator: std.mem.Allocator) ![]u8 {
    const timestamp = std.time.timestamp();
    const seconds = @as(u64, @intCast(timestamp));
    
    // Convert Unix timestamp to calendar date/time
    const SECONDS_PER_DAY = 86400;
    const seconds_in_day = seconds % SECONDS_PER_DAY;
    
    // Simple approximation for demonstration (should use proper calendar calculation)
    // This is a simplified version - in production, use std.time formatting
    const year = 2024; // Hardcoded for now - in real implementation calculate properly
    const month = 6;
    const day = 29;
    
    const hours = seconds_in_day / 3600;
    const minutes = (seconds_in_day % 3600) / 60;
    const secs = seconds_in_day % 60;
    
    return try std.fmt.allocPrint(allocator, "{d:04}-{d:02}-{d:02}T{d:02}:{d:02}:{d:02}Z", 
        .{ year, month, day, hours, minutes, secs });
}

fn decodeBase64(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, decoded_len);
    try decoder.decode(decoded, encoded);
    return decoded;
}

fn verifySignature(allocator: std.mem.Allocator, message: []const u8, signature_hex: []const u8, pubkey: []const u8) !bool {
    _ = allocator;
    
    if (signature_hex.len != 128) return false; // Ed25519 signature is 64 bytes = 128 hex chars
    if (pubkey.len != 32) return false; // Ed25519 public key is 32 bytes
    
    // Convert hex signature to bytes
    var signature: [SIGNATURE_SIZE]u8 = undefined;
    for (0..SIGNATURE_SIZE) |i| {
        const hex_byte = signature_hex[i * 2..i * 2 + 2];
        signature[i] = std.fmt.parseInt(u8, hex_byte, 16) catch return false;
    }
    
    // Use our Ed25519 verification implementation
    var pubkey_array: [PUBLIC_KEY_SIZE]u8 = undefined;
    @memcpy(&pubkey_array, pubkey);
    
    return Ed25519KeyPair.verify(pubkey_array, message, signature);
}

pub const AuthorityHttpServer = struct {
    authority: *DirectoryAuthority,
    allocator: std.mem.Allocator,
    running: bool,
    node_store: NodeStore,
    
    pub fn init(allocator: std.mem.Allocator, authority: *DirectoryAuthority) AuthorityHttpServer {
        var node_store = NodeStore.init(allocator, "data/registered_nodes.json");
        node_store.loadFromFile() catch |err| {
            std.log.warn("Failed to load nodes from file: {}", .{err});
        };
        
        return AuthorityHttpServer{
            .authority = authority,
            .allocator = allocator,
            .running = false,
            .node_store = node_store,
        };
    }
    
    pub fn deinit(self: *AuthorityHttpServer) void {
        self.node_store.deinit();
    }
    
    pub fn start(self: *AuthorityHttpServer) !void {
        const host = try self.authority.config.getListenHost(self.allocator);
        defer self.allocator.free(host);
        const port = try self.authority.config.getListenPort();
        
        const address = try net.Address.parseIp(host, port);
        var server = address.listen(.{ .reuse_address = true }) catch |err| switch (err) {
            error.AddressInUse, error.PermissionDenied => return ServerError.StartupFailed,
            else => return err,
        };
        defer server.deinit();
        
        std.log.info("Directory Authority HTTP server listening on {s}:{d}", .{ host, port });
        self.running = true;
        
        while (self.running) {
            const connection = server.accept() catch |err| {
                std.log.err("Failed to accept connection: {}", .{err});
                continue;
            };
            
            self.handleConnection(connection) catch |err| {
                std.log.err("Failed to handle connection: {}", .{err});
            };
        }
    }
    
    pub fn stop(self: *AuthorityHttpServer) void {
        self.running = false;
    }
    
    fn handleConnection(self: *AuthorityHttpServer, connection: net.Server.Connection) !void {
        defer connection.stream.close();
        
        var buffer: [8192]u8 = undefined;
        const bytes_read = try connection.stream.read(&buffer);
        
        if (bytes_read == 0) return;
        
        const request_data = buffer[0..bytes_read];
        var request = self.parseRequest(request_data) catch |err| {
            try self.sendErrorResponse(connection.stream, 400, "Bad Request");
            return err;
        };
        defer request.deinit();
        
        var response = self.routeRequest(&request) catch |err| {
            try self.sendErrorResponse(connection.stream, 500, "Internal Server Error");
            return err;
        };
        defer response.deinit();
        
        const response_bytes = try response.toBytes();
        defer self.allocator.free(response_bytes);
        
        _ = try connection.stream.writeAll(response_bytes);
    }
    
    fn parseRequest(self: *AuthorityHttpServer, data: []const u8) !HttpRequest {
        var lines = std.mem.splitSequence(u8, data, "\r\n");
        
        const request_line = lines.next() orelse return ServerError.InvalidRequest;
        var request_parts = std.mem.splitScalar(u8, request_line, ' ');
        
        const method_str = request_parts.next() orelse return ServerError.InvalidRequest;
        const path = request_parts.next() orelse return ServerError.InvalidRequest;
        _ = request_parts.next() orelse return ServerError.InvalidRequest;
        
        const method = HttpMethod.fromString(method_str) orelse return ServerError.InvalidRequest;
        
        var request = try HttpRequest.init(self.allocator, method, path, "");
        
        // Parse headers
        while (lines.next()) |line| {
            if (line.len == 0) break; // Empty line indicates start of body
            
            if (std.mem.indexOf(u8, line, ":")) |colon_pos| {
                const header_name = std.mem.trim(u8, line[0..colon_pos], " \t");
                const header_value = std.mem.trim(u8, line[colon_pos + 1..], " \t");
                try request.addHeader(header_name, header_value);
            }
        }
        
        // Parse body (if any)
        var remaining_body = std.ArrayList(u8).init(self.allocator);
        defer remaining_body.deinit();
        
        while (lines.next()) |line| {
            try remaining_body.appendSlice(line);
            try remaining_body.appendSlice("\r\n");
        }
        
        if (remaining_body.items.len > 0) {
            if (request.body.len > 0) {
                self.allocator.free(request.body);
            }
            request.body = try remaining_body.toOwnedSlice();
        }
        
        return request;
    }
    
    fn routeRequest(self: *AuthorityHttpServer, request: *const HttpRequest) !HttpResponse {
        // CORS headers for all responses
        var response = HttpResponse.init(self.allocator, 200);
        try response.setHeader("Access-Control-Allow-Origin", "*");
        try response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        try response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        
        // Handle OPTIONS requests (CORS preflight)
        if (request.method == .OPTIONS) {
            return response;
        }
        
        // Route to appropriate handler
        std.log.info("Routing request to path: '{s}'", .{request.path});
        if (std.mem.eql(u8, request.path, "/status")) {
            return self.handleStatus(request);
        } else if (std.mem.eql(u8, request.path, "/consensus")) {
            return self.handleConsensus(request);
        } else if (std.mem.eql(u8, request.path, "/consensus/signed")) {
            return self.handleSignedConsensus(request);
        } else if (std.mem.eql(u8, request.path, "/directory")) {
            return self.handleDirectory(request);
        } else if (std.mem.eql(u8, request.path, "/register")) {
            return self.handleRegister(request);
        } else if (std.mem.startsWith(u8, request.path, "/nodes")) {
            return self.handleNodes(request);
        }
        
        // 404 Not Found
        response.deinit();
        var not_found = HttpResponse.init(self.allocator, 404);
        try not_found.setJsonBody("{\"error\": \"Not Found\"}");
        return not_found;
    }
    
    fn handleStatus(self: *AuthorityHttpServer, request: *const HttpRequest) !HttpResponse {
        _ = request;
        
        var response = HttpResponse.init(self.allocator, 200);
        
        const consensus_info = self.authority.getConsensusInfo();
        const status_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"status\": \"running\", \"version\": {d}, \"timestamp\": {d}, \"node_count\": {d}}}",
            .{ consensus_info.version, consensus_info.timestamp, consensus_info.node_count }
        );
        defer self.allocator.free(status_json);
        
        try response.setJsonBody(status_json);
        return response;
    }
    
    fn handleConsensus(self: *AuthorityHttpServer, request: *const HttpRequest) !HttpResponse {
        if (request.method != .GET) {
            var response = HttpResponse.init(self.allocator, 405);
            try response.setJsonBody("{\"error\": \"Method Not Allowed\"}");
            return response;
        }
        
        const consensus = try self.authority.generateConsensus();
        defer self.allocator.free(consensus);
        
        var response = HttpResponse.init(self.allocator, 200);
        try response.setJsonBody(consensus);
        return response;
    }
    
    fn handleSignedConsensus(self: *AuthorityHttpServer, request: *const HttpRequest) !HttpResponse {
        if (request.method != .GET) {
            var response = HttpResponse.init(self.allocator, 405);
            try response.setJsonBody("{\"error\": \"Method Not Allowed\"}");
            return response;
        }
        
        const signed_consensus = try self.authority.generateSignedConsensus();
        defer self.allocator.free(signed_consensus);
        
        var response = HttpResponse.init(self.allocator, 200);
        try response.setJsonBody(signed_consensus);
        return response;
    }
    
    fn handleDirectory(self: *AuthorityHttpServer, request: *const HttpRequest) !HttpResponse {
        if (request.method != .GET) {
            var response = HttpResponse.init(self.allocator, 405);
            try response.setJsonBody("{\"error\": \"Method Not Allowed\"}");
            return response;
        }
        
        // Generate ISO8601 timestamp
        const timestamp = try generateISO8601Timestamp(self.allocator);
        defer self.allocator.free(timestamp);
        
        // Create Directory structure
        const directory = Directory{
            .timestamp = timestamp,
            .nodes = self.authority.nodes.items,
        };
        
        // Generate Directory JSON
        const directory_json = try directory.toJson(self.allocator);
        defer self.allocator.free(directory_json);
        
        // Sign the Directory JSON
        const signature = self.authority.signature_manager.signData(directory_json) catch |err| switch (err) {
            error.NoKeyLoaded => {
                var response = HttpResponse.init(self.allocator, 500);
                try response.setJsonBody("{\"error\": \"Signing key not loaded\"}");
                return response;
            },
            else => return err,
        };
        
        // Convert signature to hex
        var sig_hex: [SIGNATURE_SIZE * 2]u8 = undefined;
        _ = try std.fmt.bufPrint(&sig_hex, "{x}", .{std.fmt.fmtSliceHexLower(&signature)});
        
        // Create response with custom header
        var response = HttpResponse.init(self.allocator, 200);
        try response.setJsonBody(directory_json);
        try response.setHeader("X-Directory-Signature", &sig_hex);
        
        return response;
    }
    
    fn handleNodes(self: *AuthorityHttpServer, request: *const HttpRequest) !HttpResponse {
        if (std.mem.eql(u8, request.path, "/nodes")) {
            if (request.method == .GET) {
                return self.handleGetNodes(request);
            } else if (request.method == .POST) {
                return self.handleRegisterNode(request);
            }
        }
        
        var response = HttpResponse.init(self.allocator, 404);
        try response.setJsonBody("{\"error\": \"Not Found\"}");
        return response;
    }
    
    fn handleGetNodes(self: *AuthorityHttpServer, request: *const HttpRequest) !HttpResponse {
        _ = request;
        
        const nodes_json = try DirectoryAuthority.registry.toJson(self.allocator, self.authority.nodes.items);
        defer self.allocator.free(nodes_json);
        
        var response = HttpResponse.init(self.allocator, 200);
        try response.setJsonBody(nodes_json);
        return response;
    }
    
    fn handleRegister(self: *AuthorityHttpServer, request: *const HttpRequest) !HttpResponse {
        if (request.method != .POST) {
            var response = HttpResponse.init(self.allocator, 405);
            try response.setJsonBody("{\"error\": \"Method Not Allowed\"}");
            return response;
        }
        
        if (request.body.len == 0) {
            var response = HttpResponse.init(self.allocator, 400);
            try response.setJsonBody("{\"error\": \"Request body required\"}");
            return response;
        }
        
        // Parse and validate registration request
        var registration_req = RegistrationRequest.fromJson(self.allocator, request.body) catch |err| {
            var response = HttpResponse.init(self.allocator, 400);
            const error_msg = switch (err) {
                error.MissingType => "{\"error\": \"Missing 'type' field\"}",
                error.MissingNickname => "{\"error\": \"Missing 'nickname' field\"}",
                error.MissingAddress => "{\"error\": \"Missing 'address' field\"}",
                error.MissingPubkey => "{\"error\": \"Missing 'pubkey_b64' field\"}",
                error.MissingSignature => "{\"error\": \"Missing 'signature' field\"}",
                error.InvalidDataTypes => "{\"error\": \"Invalid data types in request\"}",
                else => "{\"error\": \"Invalid JSON format\"}",
            };
            try response.setJsonBody(error_msg);
            return response;
        };
        defer registration_req.deinit(self.allocator);
        
        // Validate request fields
        registration_req.validate() catch |err| {
            var response = HttpResponse.init(self.allocator, 400);
            const error_msg = switch (err) {
                error.InvalidNickname => "{\"error\": \"Invalid nickname: must be 1-19 characters\"}",
                error.InvalidAddress => "{\"error\": \"Invalid address: must be 1-255 characters\"}",
                error.InvalidPubkey => "{\"error\": \"Invalid public key\"}",
                error.InvalidSignature => "{\"error\": \"Invalid signature\"}",
                error.InvalidType => "{\"error\": \"Invalid type: must be 'relay' or 'exit'\"}",
            };
            try response.setJsonBody(error_msg);
            return response;
        };
        
        // Decode Base64 public key
        const pubkey = decodeBase64(self.allocator, registration_req.pubkey_b64) catch {
            var response = HttpResponse.init(self.allocator, 400);
            try response.setJsonBody("{\"error\": \"Invalid Base64 public key\"}");
            return response;
        };
        defer self.allocator.free(pubkey);
        
        // Create message for signature verification
        const message = try std.fmt.allocPrint(
            self.allocator,
            "{s}:{s}:{s}",
            .{ registration_req.type, registration_req.nickname, registration_req.address }
        );
        defer self.allocator.free(message);
        
        // Verify signature
        const signature_valid = verifySignature(
            self.allocator,
            message,
            registration_req.signature,
            pubkey
        ) catch false;
        
        if (!signature_valid) {
            var response = HttpResponse.init(self.allocator, 401);
            try response.setJsonBody("{\"error\": \"Invalid signature\"}");
            return response;
        }
        
        // Create and store node
        var node = try NodeInfo.init(self.allocator, registration_req.nickname, registration_req.address);
        
        // Set node flags based on type
        if (std.mem.eql(u8, registration_req.type, "exit")) {
            node.setFlags(.{ .valid = true, .running = true, .exit = true });
        } else {
            node.setFlags(.{ .valid = true, .running = true });
        }
        
        // Add to both memory and persistent storage
        try self.authority.addNode(node);
        try self.node_store.addNode(node);
        
        std.log.info("Registered new node: {s} at {s} (type: {s})", .{ 
            registration_req.nickname, 
            registration_req.address, 
            registration_req.type 
        });
        
        var response = HttpResponse.init(self.allocator, 201);
        const success_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"status\": \"registered\", \"nickname\": \"{s}\", \"address\": \"{s}\"}}",
            .{ registration_req.nickname, registration_req.address }
        );
        defer self.allocator.free(success_json);
        
        try response.setJsonBody(success_json);
        return response;
    }
    
    fn handleRegisterNode(self: *AuthorityHttpServer, request: *const HttpRequest) !HttpResponse {
        if (request.body.len == 0) {
            var response = HttpResponse.init(self.allocator, 400);
            try response.setJsonBody("{\"error\": \"Request body required\"}");
            return response;
        }
        
        // Parse JSON request body (simplified)
        // In production, use proper JSON parser
        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, request.body, .{});
        defer parsed.deinit();
        
        const root = parsed.value.object;
        const nickname = root.get("nickname") orelse {
            var response = HttpResponse.init(self.allocator, 400);
            try response.setJsonBody("{\"error\": \"Missing nickname\"}");
            return response;
        };
        const address = root.get("address") orelse {
            var response = HttpResponse.init(self.allocator, 400);
            try response.setJsonBody("{\"error\": \"Missing address\"}");
            return response;
        };
        
        if (nickname != .string or address != .string) {
            var response = HttpResponse.init(self.allocator, 400);
            try response.setJsonBody("{\"error\": \"Invalid data types\"}");
            return response;
        }
        
        // Validate node nickname
        if (!self.authority.validateNode(nickname.string)) {
            var response = HttpResponse.init(self.allocator, 400);
            try response.setJsonBody("{\"error\": \"Invalid nickname\"}");
            return response;
        }
        
        // Create and add node
        const node = try NodeInfo.init(self.allocator, nickname.string, address.string);
        try self.authority.addNode(node);
        
        var response = HttpResponse.init(self.allocator, 201);
        try response.setJsonBody("{\"status\": \"registered\"}");
        return response;
    }
    
    fn sendErrorResponse(self: *AuthorityHttpServer, stream: net.Stream, status_code: u16, message: []const u8) !void {
        var response = HttpResponse.init(self.allocator, status_code);
        defer response.deinit();
        
        const error_json = try std.fmt.allocPrint(self.allocator, "{{\"error\": \"{s}\"}}", .{message});
        defer self.allocator.free(error_json);
        
        try response.setJsonBody(error_json);
        
        const response_bytes = try response.toBytes();
        defer self.allocator.free(response_bytes);
        
        _ = try stream.writeAll(response_bytes);
    }
};

test "HTTP request parsing" {
    const allocator = testing.allocator;
    
    const raw_request = "GET /status HTTP/1.1\r\nHost: localhost:8443\r\nUser-Agent: curl/7.68.0\r\n\r\n";
    
    var server = AuthorityHttpServer{
        .authority = undefined,
        .allocator = allocator,
        .running = false,
    };
    
    var request = try server.parseRequest(raw_request);
    defer request.deinit();
    
    try testing.expectEqual(HttpMethod.GET, request.method);
    try testing.expectEqualStrings("/status", request.path);
    try testing.expectEqualStrings("localhost:8443", request.getHeader("Host").?);
}

test "HTTP response generation" {
    const allocator = testing.allocator;
    
    var response = HttpResponse.init(allocator, 200);
    defer response.deinit();
    
    try response.setHeader("Content-Type", "application/json");
    try response.setBody("{\"status\": \"ok\"}");
    
    const response_bytes = try response.toBytes();
    defer allocator.free(response_bytes);
    
    try testing.expect(std.mem.indexOf(u8, response_bytes, "HTTP/1.1 200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, response_bytes, "Content-Type: application/json") != null);
    try testing.expect(std.mem.indexOf(u8, response_bytes, "{\"status\": \"ok\"}") != null);
}