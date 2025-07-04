const std = @import("std");
const net = std.net;
const RelayConfig = @import("config.zig").RelayConfig;
const handler = @import("handler.zig");

pub const RelayServer = struct {
    config: RelayConfig,
    allocator: std.mem.Allocator,
    listener: ?net.Server = null,
    running: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: RelayConfig) RelayServer {
        return RelayServer{
            .config = config,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RelayServer) void {
        self.stop();
        handler.deinitSessions();
        self.config.deinit();
    }

    pub fn start(self: *RelayServer) !void {
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
        std.log.info("Relay server listening on {s}:{d}", .{ host, port });

        if (self.config.hasTls()) {
            std.log.info("TLS enabled with cert: {s}, key: {s}", .{ self.config.cert_path, self.config.key_path });
        } else {
            std.log.info("TLS disabled - running in plain TCP mode", .{});
        }

        try self.acceptLoop();
    }

    pub fn stop(self: *RelayServer) void {
        self.running = false;
        if (self.listener) |*listener| {
            listener.deinit();
            self.listener = null;
        }
    }

    fn acceptLoop(self: *RelayServer) !void {
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
                std.log.debug("Accepted connection #{d} from {}", .{ connection_count, connection.address });

                // Handle connection asynchronously using the new handler
                const thread = std.Thread.spawn(.{}, handleConnectionWrapper, .{ self, connection, connection_count }) catch |err| {
                    std.log.err("Failed to spawn handler thread: {}", .{err});
                    connection.stream.close();
                    continue;
                };
                thread.detach(); // Let the thread run independently
            }
        }
    }

    fn handleConnectionWrapper(self: *RelayServer, connection: net.Server.Connection, connection_id: u32) void {
        defer connection.stream.close();

        std.log.debug("Handling connection #{d} with new handler", .{connection_id});

        // Use the new handler
        handler.handleClient(connection.stream, &self.config, self.allocator) catch |err| {
            std.log.err("Connection #{d} handler failed: {}", .{ connection_id, err });
            return;
        };

        std.log.debug("Connection #{d} closed", .{connection_id});
    }
};

pub fn loadRelayConfig(allocator: std.mem.Allocator, config_path: []const u8) !RelayConfig {
    return RelayConfig.loadFromFile(allocator, config_path);
}

pub fn runRelayServer(allocator: std.mem.Allocator, config_path: []const u8) !void {
    const config = try loadRelayConfig(allocator, config_path);
    var server = RelayServer.init(allocator, config);
    defer server.deinit();

    try server.start();
}

test "RelayServer initialization" {
    const allocator = std.testing.allocator;

    var config = RelayConfig.init(allocator);
    config.listen_addr = try allocator.dupe(u8, "127.0.0.1:9001");
    config.max_circuits = 512;

    var server = RelayServer.init(allocator, config);
    defer server.deinit();

    try std.testing.expect(!server.running);
    try std.testing.expect(server.listener == null);
}