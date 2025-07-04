const std = @import("std");
const net = std.net;
const ExitConfig = @import("config.zig").ExitConfig;
const handler = @import("handler.zig");

pub const ExitServer = struct {
    config: ExitConfig,
    allocator: std.mem.Allocator,
    listener: ?net.Server = null,
    running: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: ExitConfig) ExitServer {
        return ExitServer{
            .config = config,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ExitServer) void {
        self.stop();
        handler.deinitSessions();
        self.config.deinit();
    }

    pub fn start(self: *ExitServer) !void {
        try self.config.validate();

        // セッション管理を初期化
        handler.initSessions(self.allocator);

        const host = try self.config.getListenHost(self.allocator);
        defer self.allocator.free(host);
        const port = try self.config.getListenPort();

        const address = net.Address.parseIp(host, port) catch |err| {
            std.log.err("Failed to parse listen address: {s}:{d}", .{ host, port });
            return err;
        };

        self.listener = net.Address.listen(address, .{
            .reuse_address = true,
            .reuse_port = true,
        }) catch |err| {
            std.log.err("Failed to bind to {s}:{d}: {}", .{ host, port, err });
            return err;
        };

        self.running = true;
        std.log.info("Exit server listening on {s}:{d}", .{ host, port });
        std.log.info("Exit policies enabled for {} rules", .{self.config.exit_policies.len});
        
        for (self.config.exit_policies) |policy| {
            std.log.info("  Allow: {s}:{d}", .{ policy.host, policy.port });
        }

        if (self.config.tls_enabled) {
            std.log.info("TLS enabled", .{});
        } else {
            std.log.info("TLS disabled - running in plain TCP mode", .{});
        }

        try self.acceptLoop();
    }

    pub fn stop(self: *ExitServer) void {
        self.running = false;
        if (self.listener) |*listener| {
            listener.deinit();
            self.listener = null;
        }
    }

    fn acceptLoop(self: *ExitServer) !void {
        var connection_count: u32 = 0;

        while (self.running) {
            if (self.listener) |*listener| {
                const connection = listener.accept() catch |err| switch (err) {
                    error.ConnectionAborted => continue,
                    error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => {
                        std.log.warn("File descriptor limit reached, waiting before accepting new connections", .{});
                        std.time.sleep(1000 * std.time.ns_per_ms); // Wait 1 second
                        continue;
                    },
                    else => {
                        std.log.err("Failed to accept connection: {}", .{err});
                        continue;
                    },
                };

                connection_count += 1;
                
                // Check connection limit
                if (connection_count > self.config.max_connections) {
                    std.log.warn("Connection limit reached, rejecting connection #{d}", .{connection_count});
                    connection.stream.close();
                    connection_count -= 1;
                    continue;
                }

                std.log.debug("Accepted connection #{d} from {}", .{ connection_count, connection.address });

                // Handle connection asynchronously
                const thread = std.Thread.spawn(.{}, handleConnectionWrapper, .{ self, connection, connection_count }) catch |err| {
                    std.log.err("Failed to spawn handler thread: {}", .{err});
                    connection.stream.close();
                    connection_count -= 1;
                    continue;
                };
                thread.detach(); // Let the thread run independently
            }
        }
    }

    fn handleConnectionWrapper(self: *ExitServer, connection: net.Server.Connection, connection_id: u32) void {
        defer connection.stream.close();

        std.log.debug("Handling exit connection #{d}", .{connection_id});

        // Use the exit handler
        handler.handleClient(connection.stream, &self.config, self.allocator) catch |err| {
            std.log.err("Exit connection #{d} handler failed: {}", .{ connection_id, err });
            return;
        };

        std.log.debug("Exit connection #{d} closed", .{connection_id});
    }
};

pub fn loadExitConfig(allocator: std.mem.Allocator, config_path: []const u8) !ExitConfig {
    return ExitConfig.loadFromFile(allocator, config_path);
}

pub fn runExitServer(allocator: std.mem.Allocator, config_path: []const u8) !void {
    const config = try loadExitConfig(allocator, config_path);
    var server = ExitServer.init(allocator, config);
    defer server.deinit();

    try server.start();
}

// Exit ノード専用のメイン関数
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const config_path = if (args.len >= 2) args[1] else "config/exit.json";
    
    std.log.info("Starting Piranha Exit Node with config: {s}", .{config_path});
    
    // Load and validate configuration
    _ = loadExitConfig(allocator, config_path) catch |err| {
        std.log.err("Failed to load exit config from {s}: {}", .{ config_path, err });
        return;
    };
    
    // Start the exit server
    runExitServer(allocator, config_path) catch |err| {
        std.log.err("Failed to start exit server: {}", .{err});
        return;
    };
}

test "ExitServer initialization" {
    const allocator = std.testing.allocator;

    var config = ExitConfig.init(allocator);
    config.listen_addr = try allocator.dupe(u8, "127.0.0.1:9003");
    config.max_circuits = 512;

    var server = ExitServer.init(allocator, config);
    defer server.deinit();

    try std.testing.expect(!server.running);
    try std.testing.expect(server.listener == null);
}