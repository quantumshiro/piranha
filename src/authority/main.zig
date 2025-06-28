const std = @import("std");
const AuthorityConfig = @import("config.zig").AuthorityConfig;
const AuthorityHttpServer = @import("server.zig").AuthorityHttpServer;
const DirectoryAuthority = @import("server.zig").DirectoryAuthority;
const TlsConfig = @import("tls.zig").TlsConfig;
const NodeInfo = @import("node.zig").NodeInfo;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("Starting Piranha Directory Authority...", .{});

    // Load configuration
    var config = AuthorityConfig.loadFromFile(allocator, "config/authority.json") catch |err| switch (err) {
        error.FileNotFound => blk: {
            std.log.warn("Config file not found, using defaults", .{});
            var default_config = AuthorityConfig.init(allocator);
            default_config.listen_addr = try allocator.dupe(u8, "0.0.0.0:8443");
            default_config.cert_path = try allocator.dupe(u8, "/tmp/authority.crt");
            default_config.key_path = try allocator.dupe(u8, "/tmp/authority.key");
            default_config.sig_key_path = try allocator.dupe(u8, "/tmp/authority-sign.ed25519");
            
            // Save default config
            try default_config.saveToFile("config/authority.json");
            break :blk default_config;
        },
        else => return err,
    };

    try config.validate();
    std.log.info("Configuration loaded successfully", .{});

    // Initialize Directory Authority
    var authority = DirectoryAuthority.init(allocator, config);
    defer authority.deinit();

    // Load or generate signing key
    authority.loadSigningKey() catch |err| switch (err) {
        error.FileNotFound => {
            std.log.info("Signing key not found, generating new key...", .{});
            authority.generateSigningKey();
            try authority.saveSigningKey();
        },
        else => return err,
    };

    std.log.info("Signing key loaded successfully", .{});

    // Add some example nodes for testing
    try addExampleNodes(&authority, allocator);

    // Setup TLS configuration
    const tls_config = TlsConfig.init(allocator, config.cert_path, config.key_path);
    
    // Generate self-signed certificate if needed
    tls_config.generateSelfSignedCertificate() catch |err| {
        std.log.warn("Failed to setup TLS certificate: {}", .{err});
    };

    // Start HTTP server
    var http_server = AuthorityHttpServer.init(allocator, &authority);
    
    std.log.info("Directory Authority ready", .{});
    std.log.info("Available endpoints:", .{});
    std.log.info("  GET  /status           - Server status", .{});
    std.log.info("  GET  /consensus        - Current consensus", .{});
    std.log.info("  GET  /consensus/signed - Signed consensus", .{});
    std.log.info("  GET  /directory        - Directory with ISO8601 timestamp and signature", .{});
    std.log.info("  GET  /nodes            - List all nodes", .{});
    std.log.info("  POST /nodes            - Register new node", .{});
    std.log.info("  POST /register         - Register node with signature verification", .{});

    try http_server.start();
}

fn addExampleNodes(authority: *DirectoryAuthority, allocator: std.mem.Allocator) !void {
    std.log.info("Adding example nodes...", .{});

    var node1 = try NodeInfo.init(allocator, "ExampleRelay1", "192.168.1.100");
    node1.setFlags(.{ .valid = true, .running = true, .stable = true });
    node1.bandwidth = 1000000; // 1 MB/s
    try authority.addNode(node1);

    var node2 = try NodeInfo.init(allocator, "ExampleRelay2", "192.168.1.101");
    node2.setFlags(.{ .valid = true, .running = true, .fast = true });
    node2.bandwidth = 2000000; // 2 MB/s
    try authority.addNode(node2);

    var node3 = try NodeInfo.init(allocator, "ExampleExit", "10.0.0.50");
    node3.setFlags(.{ .valid = true, .running = true, .exit = true });
    node3.bandwidth = 500000; // 500 KB/s
    try authority.addNode(node3);

    std.log.info("Added {} example nodes", .{authority.getNodeCount()});
}