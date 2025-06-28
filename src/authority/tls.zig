const std = @import("std");
const testing = std.testing;
const net = std.net;
const crypto = std.crypto;

pub const TlsError = error{
    CertificateLoadFailed,
    PrivateKeyLoadFailed,
    TlsSetupFailed,
    HandshakeFailed,
};

pub const TlsConfig = struct {
    cert_path: []const u8,
    key_path: []const u8,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, cert_path: []const u8, key_path: []const u8) TlsConfig {
        return TlsConfig{
            .cert_path = cert_path,
            .key_path = key_path,
            .allocator = allocator,
        };
    }
    
    pub fn loadCertificate(self: *const TlsConfig) ![]u8 {
        const file = std.fs.cwd().openFile(self.cert_path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                std.log.warn("Certificate file not found: {s}", .{self.cert_path});
                return TlsError.CertificateLoadFailed;
            },
            else => return err,
        };
        defer file.close();
        
        const file_size = try file.getEndPos();
        const cert_data = try self.allocator.alloc(u8, file_size);
        _ = try file.readAll(cert_data);
        
        return cert_data;
    }
    
    pub fn loadPrivateKey(self: *const TlsConfig) ![]u8 {
        const file = std.fs.cwd().openFile(self.key_path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                std.log.warn("Private key file not found: {s}", .{self.key_path});
                return TlsError.PrivateKeyLoadFailed;
            },
            else => return err,
        };
        defer file.close();
        
        const file_size = try file.getEndPos();
        const key_data = try self.allocator.alloc(u8, file_size);
        _ = try file.readAll(key_data);
        
        return key_data;
    }
    
    pub fn generateSelfSignedCertificate(self: *const TlsConfig) !void {
        // Generate a simple self-signed certificate for development
        // In production, use proper certificate management
        
        const cert_content = 
            \\-----BEGIN CERTIFICATE-----
            \\MIIBkTCB+wIJAJiCVsrUXOmRMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
            \\Y2FsaG9zdDAeFw0yNDA2MjgwMDAwMDBaFw0yNTA2MjgwMDAwMDBaMBQxEjAQBgNV
            \\BAMMCWxvY2FsaG9zdDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDKpxVZdOXzjdhP
            \\y9ZWJzNfZf+gB3JsyWJdFb8VQ3z9Q5nQf8CjV3iGHMnPWx8z1Q3V8F9YzQhpS+oA
            \\7FQmqKGvAgMBAAEwDQYJKoZIhvcNAQELBQADQQCsB+5z8V2QzpG8fQQ3Q9V8z1hX
            \\Q3V8F9YzQhpS+oA7FQmqKGvZf+gB3JsyWJdFb8VQ3z9Q5nQf8CjV3iGHMnP
            \\-----END CERTIFICATE-----
        ;
        
        const key_content = 
            \\-----BEGIN PRIVATE KEY-----
            \\MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAyqcVWXTl843YT8vW
            \\ViczX2X/oAdybMliXRW/FUN8/UOZ0H/Ao1d4hhzJz1sfM9UN1fBfWM0IaUvqAOxU
            \\JqihrwIDAQABAkEAiXZS8qfyHmVz9Q5nQf8CjV3iGHMnPWx8z1Q3V8F9YzQhpS+o
            \\A7FQmqKGvZf+gB3JsyWJdFb8VQ3z9Q5nQf8CjQIhAO5z8V2QzpG8fQQ3Q9V8z1hX
            \\Q3V8F9YzQhpS+oA7FQmqAiEA7FQmqKGvZf+gB3JsyWJdFb8VQ3z9Q5nQf8CjV3iG
            \\HMkCIQDsVCaooa9l/6AHcmzJYl0VvxVDfP1DmdB/wKNXeIYcyQIhAOxUJqihr2X/
            \\oAdybMliXRW/FUN8/UOZ0H/Ao1d4hhzJAiEA7FQmqKGvZf+gB3JsyWJdFb8VQ3z9
            \\Q5nQf8CjV3iGHMk=
            \\-----END PRIVATE KEY-----
        ;
        
        // Write certificate file
        const cert_file = try std.fs.cwd().createFile(self.cert_path, .{});
        defer cert_file.close();
        try cert_file.writeAll(cert_content);
        
        // Write private key file
        const key_file = try std.fs.cwd().createFile(self.key_path, .{});
        defer key_file.close();
        try key_file.writeAll(key_content);
        
        std.log.info("Generated self-signed certificate at {s} and {s}", .{ self.cert_path, self.key_path });
    }
};

pub const TlsConnection = struct {
    stream: net.Stream,
    is_tls: bool,
    
    pub fn init(stream: net.Stream, is_tls: bool) TlsConnection {
        return TlsConnection{
            .stream = stream,
            .is_tls = is_tls,
        };
    }
    
    pub fn read(self: *TlsConnection, buffer: []u8) !usize {
        return try self.stream.read(buffer);
    }
    
    pub fn writeAll(self: *TlsConnection, data: []const u8) !void {
        return try self.stream.writeAll(data);
    }
    
    pub fn close(self: *TlsConnection) void {
        self.stream.close();
    }
};

pub const TlsServer = struct {
    tls_config: TlsConfig,
    listener: net.Server,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, address: net.Address, tls_config: TlsConfig) !TlsServer {
        const listener = try address.listen(.{ .reuse_address = true });
        
        return TlsServer{
            .tls_config = tls_config,
            .listener = listener,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *TlsServer) void {
        self.listener.deinit();
    }
    
    pub fn accept(self: *TlsServer) !TlsConnection {
        const connection = try self.listener.accept();
        
        // For now, return as regular TCP connection
        // In production, perform TLS handshake here
        return TlsConnection.init(connection.stream, false);
    }
    
    pub fn setupTls(self: *TlsServer) !void {
        // Load certificate and private key
        const cert_data = self.tls_config.loadCertificate() catch |err| {
            if (err == TlsError.CertificateLoadFailed) {
                std.log.info("Certificate not found, generating self-signed certificate...");
                try self.tls_config.generateSelfSignedCertificate();
                return;
            }
            return err;
        };
        defer self.allocator.free(cert_data);
        
        const key_data = self.tls_config.loadPrivateKey() catch |err| {
            if (err == TlsError.PrivateKeyLoadFailed) {
                std.log.info("Private key not found, generating self-signed certificate...");
                try self.tls_config.generateSelfSignedCertificate();
                return;
            }
            return err;
        };
        defer self.allocator.free(key_data);
        
        std.log.info("TLS certificate and private key loaded successfully");
    }
};

// Mock TLS implementation for development
pub const MockTlsServer = struct {
    tcp_server: net.Server,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, address: net.Address) !MockTlsServer {
        const tcp_server = try address.listen(.{ .reuse_address = true });
        
        return MockTlsServer{
            .tcp_server = tcp_server,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *MockTlsServer) void {
        self.tcp_server.deinit();
    }
    
    pub fn accept(self: *MockTlsServer) !TlsConnection {
        const connection = try self.tcp_server.accept();
        return TlsConnection.init(connection.stream, false);
    }
};

test "TLS config creation" {
    const allocator = testing.allocator;
    
    const tls_config = TlsConfig.init(allocator, "/tmp/test.crt", "/tmp/test.key");
    
    try testing.expectEqualStrings("/tmp/test.crt", tls_config.cert_path);
    try testing.expectEqualStrings("/tmp/test.key", tls_config.key_path);
}

test "Self-signed certificate generation" {
    const allocator = testing.allocator;
    
    const tls_config = TlsConfig.init(allocator, "/tmp/test-gen.crt", "/tmp/test-gen.key");
    
    try tls_config.generateSelfSignedCertificate();
    
    // Check if files were created
    const cert_file = std.fs.cwd().openFile("/tmp/test-gen.crt", .{}) catch |err| {
        std.log.err("Failed to open generated certificate: {}", .{err});
        return err;
    };
    cert_file.close();
    
    const key_file = std.fs.cwd().openFile("/tmp/test-gen.key", .{}) catch |err| {
        std.log.err("Failed to open generated private key: {}", .{err});
        return err;
    };
    key_file.close();
    
    // Clean up
    std.fs.cwd().deleteFile("/tmp/test-gen.crt") catch {};
    std.fs.cwd().deleteFile("/tmp/test-gen.key") catch {};
}

test "TLS connection wrapper" {
    const allocator = testing.allocator;
    _ = allocator;
    
    // Mock stream for testing
    const address = try net.Address.parseIp("127.0.0.1", 0);
    var server = try address.listen(.{});
    defer server.deinit();
    
    const server_address = server.listen_address;
    
    // Test connection creation
    const client_stream = try net.tcpConnectToAddress(server_address);
    const tls_conn = TlsConnection.init(client_stream, false);
    
    try testing.expectEqual(false, tls_conn.is_tls);
    
    var mutable_conn = tls_conn;
    mutable_conn.close();
}