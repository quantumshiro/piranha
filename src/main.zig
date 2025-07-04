//! By convention, main.zig is where your main function lives in the case that
//! you are building an executable. If you are making a library, the convention
//! is to delete this file and start with root.zig instead.

const RelayConfig = @import("relay/config.zig").RelayConfig;
const RelayServer = @import("relay/main.zig").RelayServer;
const runRelayServer = @import("relay/main.zig").runRelayServer;

const ExitConfig = @import("exit/config.zig").ExitConfig;
const ExitServer = @import("exit/main.zig").ExitServer;
const runExitServer = @import("exit/main.zig").runExitServer;

const ClientConfig = @import("client/config.zig").ClientConfig;
const PiranhaClient = @import("client/main.zig").PiranhaClient;
const runClient = @import("client/main.zig").runClient;

/// Utility function to load relay configuration from JSON file
pub fn loadRelayConfigFromJson(allocator: std.mem.Allocator, config_path: []const u8) !RelayConfig {
    return RelayConfig.loadFromFile(allocator, config_path);
}

/// Utility function to start a relay server with given configuration
pub fn startRelayServer(allocator: std.mem.Allocator, config: RelayConfig) !void {
    var server = RelayServer.init(allocator, config);
    defer server.deinit();
    
    try server.start();
}

/// Utility function to load exit configuration from JSON file
pub fn loadExitConfigFromJson(allocator: std.mem.Allocator, config_path: []const u8) !ExitConfig {
    return ExitConfig.loadFromFile(allocator, config_path);
}

/// Utility function to start an exit server with given configuration
pub fn startExitServer(allocator: std.mem.Allocator, config: ExitConfig) !void {
    var server = ExitServer.init(allocator, config);
    defer server.deinit();
    
    try server.start();
}

/// Utility function to load client configuration from JSON file
pub fn loadClientConfigFromJson(allocator: std.mem.Allocator, config_path: []const u8) !ClientConfig {
    return ClientConfig.loadFromFile(allocator, config_path);
}

/// Utility function to start a client with given configuration
pub fn startClient(allocator: std.mem.Allocator, config: ClientConfig) !void {
    var client = PiranhaClient.init(allocator, config);
    defer client.deinit();
    
    try client.start();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.log.info("Usage: {s} <mode> [config_path]", .{args[0]});
        std.log.info("Modes:", .{});
        std.log.info("  relay [config_path]  - Run as relay server (default: config/relay.json)", .{});
        std.log.info("  exit [config_path]   - Run as exit node (default: config/exit.json)", .{});
        std.log.info("  client [config_path] - Run as client proxy (default: config/client.json)", .{});
        return;
    }

    const mode = args[1];

    if (std.mem.eql(u8, mode, "relay")) {
        const config_path = if (args.len >= 3) args[2] else "config/relay.json";
        
        std.log.info("Starting relay server with config: {s}", .{config_path});
        
        // Load and validate configuration
        const config = loadRelayConfigFromJson(allocator, config_path) catch |err| {
            std.log.err("Failed to load relay config from {s}: {}", .{ config_path, err });
            return;
        };
        
        // Start the relay server
        startRelayServer(allocator, config) catch |err| {
            std.log.err("Failed to start relay server: {}", .{err});
            return;
        };
    } else if (std.mem.eql(u8, mode, "exit")) {
        const config_path = if (args.len >= 3) args[2] else "config/exit.json";
        
        std.log.info("Starting exit node with config: {s}", .{config_path});
        
        // Load and validate configuration
        const config = loadExitConfigFromJson(allocator, config_path) catch |err| {
            std.log.err("Failed to load exit config from {s}: {}", .{ config_path, err });
            return;
        };
        
        // Start the exit server
        startExitServer(allocator, config) catch |err| {
            std.log.err("Failed to start exit server: {}", .{err});
            return;
        };
    } else if (std.mem.eql(u8, mode, "client")) {
        const config_path = if (args.len >= 3) args[2] else "config/client.json";
        
        std.log.info("Starting client proxy with config: {s}", .{config_path});
        
        // Load and validate configuration
        const config = loadClientConfigFromJson(allocator, config_path) catch |err| {
            std.log.err("Failed to load client config from {s}: {}", .{ config_path, err });
            return;
        };
        
        // Start the client
        startClient(allocator, config) catch |err| {
            std.log.err("Failed to start client: {}", .{err});
            return;
        };
    } else {
        std.log.err("Unknown mode: {s}", .{mode});
        return;
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // Try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "use other module" {
    try std.testing.expectEqual(@as(i32, 150), lib.add(100, 50));
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}

const std = @import("std");

/// This imports the separate module containing `root.zig`. Take a look in `build.zig` for details.
const lib = @import("piranha_lib");
