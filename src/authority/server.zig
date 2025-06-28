const std = @import("std");
const testing = std.testing;
const http = std.http;
const net = std.net;
// const DirectoryAuthority = @import("directory.zig").DirectoryAuthority;
const AuthorityConfig = @import("config.zig").AuthorityConfig;
const NodeInfo = @import("node.zig").NodeInfo;

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

// Mock DirectoryAuthority for testing
const MockDirectoryAuthority = struct {
    config: AuthorityConfig,
    node_count: usize = 0,
    
    pub fn getConsensusInfo(self: *const MockDirectoryAuthority) struct {
        version: u32,
        timestamp: i64,
        node_count: usize,
    } {
        _ = self;
        return .{
            .version = 1,
            .timestamp = std.time.timestamp(),
            .node_count = 0,
        };
    }
    
    pub fn generateConsensus(self: *const MockDirectoryAuthority) ![]u8 {
        _ = self;
        return "{}";
    }
    
    pub fn generateSignedConsensus(self: *const MockDirectoryAuthority) ![]u8 {
        _ = self;
        return "{}";
    }
    
    pub fn validateNode(self: *const MockDirectoryAuthority, nickname: []const u8) bool {
        _ = self;
        return nickname.len > 0 and nickname.len <= 19;
    }
    
    pub fn addNode(self: *MockDirectoryAuthority, node: NodeInfo) !void {
        _ = node;
        self.node_count += 1;
    }
    
    const registry = struct {
        pub fn toJson(allocator: std.mem.Allocator) ![]u8 {
            _ = allocator;
            return "[]";
        }
    };
};

pub const AuthorityHttpServer = struct {
    authority: *MockDirectoryAuthority,
    allocator: std.mem.Allocator,
    running: bool,
    
    pub fn init(allocator: std.mem.Allocator, authority: *MockDirectoryAuthority) AuthorityHttpServer {
        return AuthorityHttpServer{
            .authority = authority,
            .allocator = allocator,
            .running = false,
        };
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
        if (std.mem.eql(u8, request.path, "/status")) {
            return self.handleStatus(request);
        } else if (std.mem.eql(u8, request.path, "/consensus")) {
            return self.handleConsensus(request);
        } else if (std.mem.eql(u8, request.path, "/consensus/signed")) {
            return self.handleSignedConsensus(request);
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
        
        const nodes_json = try MockDirectoryAuthority.registry.toJson(self.allocator);
        defer self.allocator.free(nodes_json);
        
        var response = HttpResponse.init(self.allocator, 200);
        try response.setJsonBody(nodes_json);
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