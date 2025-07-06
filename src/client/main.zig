const std = @import("std");
const ClientConfig = @import("config.zig").ClientConfig;
const DirectoryClient = @import("directory.zig").DirectoryClient;
const SocksServer = @import("socks.zig").SocksServer;
const CircuitBuilder = @import("builder.zig").CircuitBuilder;
const circuit = @import("circuit.zig");
const CircuitManager = circuit.CircuitManager;
const NodeSelector = circuit.NodeSelector;
const fetch = @import("fetch.zig");
const TorHttpClient = fetch.TorHttpClient;

pub const PiranhaClient = struct {
    config: ClientConfig,
    allocator: std.mem.Allocator,
    circuit_manager: *CircuitManager,
    node_selector: *NodeSelector,
    directory_client: DirectoryClient,
    socks_server: SocksServer,
    circuit_builder: CircuitBuilder,
    http_client: TorHttpClient,
    running: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: ClientConfig) PiranhaClient {
        // ヒープにマネージャーを作成してポインタを保持
        const circuit_manager = allocator.create(CircuitManager) catch unreachable;
        circuit_manager.* = CircuitManager.init(allocator);
        
        const node_selector = allocator.create(NodeSelector) catch unreachable;
        node_selector.* = NodeSelector.init(allocator);
        
        // まず、設定値を保存してからポインタを渡す
        const config_ptr = &config;
        
        const directory_client = DirectoryClient.init(allocator, config_ptr);
        var circuit_builder = CircuitBuilder.init(allocator, config_ptr, circuit_manager, node_selector);
        
        // デバッグ: CircuitBuilderの設定値を確認
        std.log.debug("CircuitBuilder config circuit_length: {}", .{circuit_builder.config.circuit_length});
        
        const socks_server = SocksServer.init(allocator, config_ptr, circuit_manager, &circuit_builder);
        const http_client = TorHttpClient.init(allocator, &circuit_builder, circuit_manager);

        var client = PiranhaClient{
            .config = config,
            .allocator = allocator,
            .circuit_manager = circuit_manager,
            .node_selector = node_selector,
            .directory_client = directory_client,
            .socks_server = socks_server,
            .circuit_builder = circuit_builder,
            .http_client = http_client,
        };
        
        // CircuitBuilderの設定参照を修正
        client.circuit_builder.config = &client.config;
        
        return client;
    }

    pub fn deinit(self: *PiranhaClient) void {
        self.stop();
        self.circuit_builder.deinit();
        self.circuit_manager.deinit();
        self.allocator.destroy(self.circuit_manager);
        self.node_selector.deinit();
        self.allocator.destroy(self.node_selector);
        self.directory_client.deinit();
        self.socks_server.deinit();
        self.config.deinit();
    }

    pub fn start(self: *PiranhaClient) !void {
        try self.config.validate();

        std.log.info("Starting Piranha Client...", .{});
        std.log.info("Authority: {s}", .{self.config.authority_addr});
        std.log.info("SOCKS proxy: {s}", .{self.config.socks_listen_addr});
        std.log.info("Circuit length: {}", .{self.config.circuit_length});
        std.log.info("Max circuits: {}", .{self.config.max_circuits});

        self.running = true;

        // 初期ディレクトリ取得（リトライ付き）
        std.log.info("Fetching initial directory...", .{});
        var initial_directory = self.directory_client.fetchDirectoryWithRetry() catch |err| {
            std.log.err("Failed to fetch initial directory after retries: {}", .{err});
            return err;
        };
        defer initial_directory.deinit();

        if (!initial_directory.isValid()) {
            std.log.err("Received invalid directory from authority", .{});
            return error.InvalidDirectory;
        }

        try self.node_selector.updateNodes(initial_directory.nodes);
        std.log.info("Initial directory loaded with {} nodes (consensus method: {})", .{ 
            initial_directory.nodes.len, 
            initial_directory.consensus_method 
        });

        // バックグラウンドタスクを開始（段階的回路構築）
        try self.startBackgroundTasks();

        // SOCKS サーバーを開始（メインスレッドで実行）
        // try self.socks_server.start(); // 一時的に無効化
        std.log.info("SOCKS server disabled for this demo", .{});
    }

    pub fn stop(self: *PiranhaClient) void {
        self.running = false;
        self.socks_server.stop();
    }

    // URLをTor経由でfetchする機能
    pub fn fetchUrl(self: *PiranhaClient, url: []const u8) ![]u8 {
        if (!self.running) {
            return error.ClientNotRunning;
        }
        
        std.log.info("Fetching URL via Tor: {s}", .{url});
        
        // 回路が利用可能か確認
        const circuit_count = self.circuit_manager.getCircuitCount();
        if (circuit_count == 0) {
            std.log.warn("No circuits available, attempting to build one...", .{});
            _ = try self.circuit_builder.buildCircuit();
        }
        
        return try self.http_client.fetchUrl(url);
    }

    // 段階的な回路構築（簡単版）
    fn buildSimpleCircuit(self: *PiranhaClient, hops: u8) !u16 {
        std.log.info("Building simple {}-hop circuit...", .{hops});
        
        // 回路IDを作成
        const circuit_id = try self.circuit_manager.createCircuit();
        std.log.debug("Created circuit {} for {}-hop build", .{ circuit_id, hops });
        
        // 段階1: 回路作成のみ（実際の接続は後で実装）
        if (hops == 1) {
            std.log.info("Stage 1: Circuit {} created (1-hop simulation)", .{circuit_id});
            
            // 回路を準備完了としてマーク
            if (self.circuit_manager.getCircuit(circuit_id)) |circuit_ptr| {
                circuit_ptr.markReady();
                std.log.info("Circuit {} marked as ready", .{circuit_id});
            }
            
            return circuit_id;
        }
        
        // 段階2以降は後で実装
        std.log.warn("Stage {}: Not yet implemented, simulating success", .{hops});
        
        if (self.circuit_manager.getCircuit(circuit_id)) |circuit_ptr| {
            circuit_ptr.markReady();
        }
        
        return circuit_id;
    }

    fn startBackgroundTasks(self: *PiranhaClient) !void {
        std.log.info("Starting background tasks (gradual circuit building)...", .{});
        
        // Directory更新タスクのみ開始（回路構築は段階的に）
        const directory_thread = std.Thread.spawn(.{}, directoryUpdateTask, .{self}) catch |err| {
            std.log.err("Failed to spawn directory update task: {}", .{err});
            return err;
        };
        directory_thread.detach();
        std.log.info("Directory update task started", .{});

        // 段階的回路構築タスク
        const circuit_thread = std.Thread.spawn(.{}, circuitBuildTask, .{self}) catch |err| {
            std.log.err("Failed to spawn circuit build task: {}", .{err});
            return err;
        };
        circuit_thread.detach();
        std.log.info("Circuit build task started", .{});

        std.log.info("Background tasks started", .{});
    }

    fn directoryUpdateTask(self: *PiranhaClient) void {
        std.log.info("Directory update task started", .{});
        
        while (self.running) {
            std.time.sleep(60 * std.time.ns_per_s); // 60秒間隔

            if (!self.running) break;

            std.log.debug("Updating directory...", .{});
            const directory = self.directory_client.fetchDirectoryWithRetry() catch |err| {
                std.log.err("Failed to update directory after retries: {}", .{err});
                continue;
            };
            defer @constCast(&directory).deinit();

            if (!directory.isValid()) {
                std.log.warn("Received invalid directory, skipping update", .{});
                continue;
            }

            self.node_selector.updateNodes(directory.nodes) catch |err| {
                std.log.err("Failed to update node selector: {}", .{err});
                continue;
            };

            std.log.debug("Directory updated successfully ({} nodes)", .{directory.nodes.len});
        }

        std.log.info("Directory update task stopped", .{});
    }

    fn circuitBuildTask(self: *PiranhaClient) void {
        std.log.info("Circuit build task started", .{});

        // 初期回路を構築
        std.time.sleep(2 * std.time.ns_per_s); // ディレクトリ更新を待つ

        while (self.running) {
            const current_circuits = self.circuit_manager.getCircuitCount();
            
            if (current_circuits < self.config.max_circuits) {
                std.log.debug("Building new circuit ({}/{})", .{ current_circuits, self.config.max_circuits });
                
                _ = self.circuit_builder.buildCircuit() catch |err| {
                    std.log.err("Failed to build circuit: {}", .{err});
                    std.time.sleep(5 * std.time.ns_per_s);
                    continue;
                };

                std.log.info("Circuit built successfully ({}/{})", .{ 
                    self.circuit_manager.getCircuitCount(), 
                    self.config.max_circuits 
                });
            }

            // 期限切れの回路をクリーンアップ
            self.circuit_manager.cleanupExpiredCircuits(self.config.circuit_timeout_seconds);

            std.time.sleep(10 * std.time.ns_per_s);
        }

        std.log.info("Circuit build task stopped", .{});
    }
};

pub fn loadClientConfig(allocator: std.mem.Allocator, config_path: []const u8) !ClientConfig {
    return ClientConfig.loadFromFile(allocator, config_path);
}

pub fn runClient(allocator: std.mem.Allocator, config_path: []const u8) !void {
    const config = try loadClientConfig(allocator, config_path);
    var client = PiranhaClient.init(allocator, config);
    defer client.deinit();

    try client.start();
}

// URLフェッチ専用関数
pub fn fetchOnly(allocator: std.mem.Allocator, config_path: []const u8, url: []const u8) !void {
    _ = config_path; // ハードコードされた設定を使用
    
    // ハードコードされた設定を使用
    var config = ClientConfig.init(allocator);
    config.authority_addr = try allocator.dupe(u8, "128.31.0.39:9131");
    config.authority_addr_owned = true;
    config.socks_listen_addr = try allocator.dupe(u8, "127.0.0.1:9050");
    config.socks_listen_addr_owned = true;
    config.circuit_length = 3;
    config.max_circuits = 3;
    config.circuit_timeout_seconds = 600;
    config.connection_timeout_seconds = 30;
    config.retry_attempts = 3;
    config.user_agent = try allocator.dupe(u8, "Piranha-Tor-Client/1.0");
    config.user_agent_owned = true;
    config.enable_logging = true;
    config.log_level = try allocator.dupe(u8, "info");
    config.log_level_owned = true;
    
    var client = PiranhaClient.init(allocator, config);
    defer client.deinit();

    std.log.info("Initializing Tor client for URL fetch...", .{});
    
    // 簡単な初期化（SOCKSサーバーを開始せずにディレクトリのみ取得）
    try client.config.validate();
    
    // デバッグ: 設定値を確認
    std.log.debug("Config circuit_length: {}", .{client.config.circuit_length});
    std.log.debug("Config max_circuits: {}", .{client.config.max_circuits});
    
    // 初期ディレクトリ取得
    var initial_directory = client.directory_client.fetchDirectoryWithRetry() catch |err| {
        std.log.err("Failed to fetch initial directory: {}", .{err});
        return err;
    };
    defer initial_directory.deinit();

    if (!initial_directory.isValid()) {
        std.log.err("Received invalid directory from authority", .{});
        return error.InvalidDirectory;
    }

    try client.node_selector.updateNodes(initial_directory.nodes);
    std.log.info("Directory loaded with {} nodes", .{initial_directory.nodes.len});
    
    // クライアントを実行状態にマーク
    client.running = true;
    
    // URLをフェッチ
    const response = try client.fetchUrl(url);
    defer allocator.free(response);
    
    // レスポンスを出力
    std.log.info("Response received ({} bytes):", .{response.len});
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll(response);
}

// クライアント専用のメイン関数
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len >= 3 and std.mem.eql(u8, args[1], "fetch")) {
        // fetch コマンド: zig run src/client/main.zig -- fetch <URL>
        const url = args[2];
        const config_path = if (args.len >= 4) args[3] else "config/client.json";
        
        std.log.info("Fetching URL via Tor: {s}", .{url});
        try fetchOnly(allocator, config_path, url);
        return;
    }

    const config_path = if (args.len >= 2) args[1] else "config/client.json";
    
    std.log.info("Starting Piranha Client with config: {s}", .{config_path});
    
    // 設定を読み込み
    _ = loadClientConfig(allocator, config_path) catch |err| {
        std.log.err("Failed to load client config from {s}: {}", .{ config_path, err });
        return;
    };
    
    // クライアントを開始
    runClient(allocator, config_path) catch |err| {
        std.log.err("Failed to start client: {}", .{err});
        return;
    };
}

test "PiranhaClient initialization" {
    const allocator = std.testing.allocator;

    var config = ClientConfig.init(allocator);
    config.authority_addr = try allocator.dupe(u8, "127.0.0.1:8443");
    config.authority_addr_owned = true;
    config.socks_listen_addr = try allocator.dupe(u8, "127.0.0.1:9050");
    config.socks_listen_addr_owned = true;
    config.circuit_length = 3;
    config.max_circuits = 5;

    var client = PiranhaClient.init(allocator, config);
    defer client.deinit();

    try std.testing.expect(!client.running);
    try std.testing.expect(client.config.circuit_length == 3);
    try std.testing.expect(client.config.max_circuits == 5);
}