const std = @import("std");
const TorHttpClient = @import("fetch.zig").TorHttpClient;
const CircuitBuilder = @import("builder.zig").CircuitBuilder;
const CircuitManager = @import("circuit.zig").CircuitManager;
const NodeSelector = @import("circuit.zig").NodeSelector;
const ClientConfig = @import("config.zig").ClientConfig;
const DirectoryClient = @import("directory.zig").DirectoryClient;

// CLI引数の構造
pub const CliArgs = struct {
    url: ?[]const u8 = null,
    output_file: ?[]const u8 = null,
    verbose: bool = false,
    help: bool = false,
    
    pub fn parse(allocator: std.mem.Allocator) !CliArgs {
        const args = try std.process.argsAlloc(allocator);
        defer std.process.argsFree(allocator, args);
        
        var cli_args = CliArgs{};
        
        var i: usize = 1; // Skip program name
        while (i < args.len) {
            const arg = args[i];
            
            if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
                cli_args.help = true;
            } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
                cli_args.verbose = true;
            } else if (std.mem.eql(u8, arg, "--output") or std.mem.eql(u8, arg, "-o")) {
                if (i + 1 >= args.len) {
                    std.log.err("--output requires a filename", .{});
                    return error.InvalidArguments;
                }
                i += 1;
                cli_args.output_file = try allocator.dupe(u8, args[i]);
            } else if (std.mem.startsWith(u8, arg, "http://") or std.mem.startsWith(u8, arg, "https://")) {
                cli_args.url = try allocator.dupe(u8, arg);
            } else if (std.mem.indexOf(u8, arg, ".") != null) {
                // IP address or domain name - convert to HTTP URL
                const url = try std.fmt.allocPrint(allocator, "http://{s}", .{arg});
                cli_args.url = url;
            } else {
                std.log.err("Unknown argument: {s}", .{arg});
                return error.InvalidArguments;
            }
            
            i += 1;
        }
        
        return cli_args;
    }
    
    pub fn deinit(self: *CliArgs, allocator: std.mem.Allocator) void {
        if (self.url) |url| allocator.free(url);
        if (self.output_file) |file| allocator.free(file);
    }
    
    pub fn printHelp() void {
        std.log.info("Piranha Tor Client - Web Fetcher", .{});
        std.log.info("", .{});
        std.log.info("Usage:", .{});
        std.log.info("  piranha-fetch [OPTIONS] <URL|IP|DOMAIN>", .{});
        std.log.info("", .{});
        std.log.info("Arguments:", .{});
        std.log.info("  <URL>        Full URL (http://example.com/path)", .{});
        std.log.info("  <IP>         IP address (192.168.1.1)", .{});
        std.log.info("  <DOMAIN>     Domain name (example.com)", .{});
        std.log.info("", .{});
        std.log.info("Options:", .{});
        std.log.info("  -h, --help       Show this help message", .{});
        std.log.info("  -v, --verbose    Enable verbose logging", .{});
        std.log.info("  -o, --output     Save response to file", .{});
        std.log.info("", .{});
        std.log.info("Examples:", .{});
        std.log.info("  piranha-fetch http://example.com", .{});
        std.log.info("  piranha-fetch https://httpbin.org/ip", .{});
        std.log.info("  piranha-fetch example.com", .{});
        std.log.info("  piranha-fetch 93.184.216.34", .{});
        std.log.info("  piranha-fetch -o response.html http://example.com", .{});
    }
};

// メインのCLI実行関数
pub fn runCli() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // CLI引数をパース
    var cli_args = CliArgs.parse(allocator) catch |err| switch (err) {
        error.InvalidArguments => {
            CliArgs.printHelp();
            std.process.exit(1);
        },
        else => return err,
    };
    defer cli_args.deinit(allocator);
    
    // ヘルプ表示
    if (cli_args.help) {
        CliArgs.printHelp();
        return;
    }
    
    // URLが指定されていない場合
    if (cli_args.url == null) {
        std.log.err("No URL specified. Use --help for usage information.", .{});
        std.process.exit(1);
    }
    
    // ログレベル設定
    if (cli_args.verbose) {
        // Verbose mode - show debug logs
        std.log.info("Verbose mode enabled", .{});
    }
    
    const url = cli_args.url.?;
    std.log.info("=== Piranha Tor Client - Web Fetcher ===", .{});
    std.log.info("Target URL: {s}", .{url});
    std.log.info("", .{});
    
    // Tor クライアントを初期化
    std.log.info("Initializing Tor client...", .{});
    
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
    defer config.deinit();
    
    var circuit_manager = CircuitManager.init(allocator);
    defer circuit_manager.deinit();
    
    var node_selector = NodeSelector.init(allocator);
    defer node_selector.deinit();
    
    var circuit_builder = CircuitBuilder.init(allocator, &config, &circuit_manager, &node_selector);
    
    // ディレクトリサーバーからノードリストを取得
    var directory_client = DirectoryClient.init(allocator, &config);
    defer directory_client.deinit();
    
    std.log.info("Fetching Tor directory from real authorities...", .{});
    var initial_directory = directory_client.fetchDirectoryWithRetry() catch |err| {
        std.log.err("Failed to fetch initial directory: {}", .{err});
        std.process.exit(1);
    };
    defer initial_directory.deinit();
    
    try node_selector.updateNodes(initial_directory.nodes);
    std.log.info("Directory loaded with {} nodes", .{initial_directory.nodes.len});
    
    var http_client = TorHttpClient.init(allocator, &circuit_builder, &circuit_manager);
    
    // 回路を構築
    std.log.info("Building Tor circuit...", .{});
    _ = circuit_builder.buildCircuit() catch |err| {
        std.log.err("Failed to build circuit: {}", .{err});
        std.process.exit(1);
    };
    
    // Webサイトのコンテンツを取得
    std.log.info("Fetching content via Tor network...", .{});
    const start_time = std.time.nanoTimestamp();
    
    const content = http_client.fetchUrl(url) catch |err| {
        std.log.err("Failed to fetch URL: {}", .{err});
        std.process.exit(1);
    };
    defer allocator.free(content);
    
    const end_time = std.time.nanoTimestamp();
    const duration_ms = @divTrunc(end_time - start_time, std.time.ns_per_ms);
    
    std.log.info("", .{});
    std.log.info("=== Fetch Complete ===", .{});
    std.log.info("Content size: {d} bytes", .{content.len});
    std.log.info("Fetch time: {d}ms", .{duration_ms});
    std.log.info("", .{});
    
    // 出力処理
    if (cli_args.output_file) |output_file| {
        // ファイルに保存
        const file = std.fs.cwd().createFile(output_file, .{}) catch |err| {
            std.log.err("Failed to create output file '{s}': {}", .{ output_file, err });
            std.process.exit(1);
        };
        defer file.close();
        
        file.writeAll(content) catch |err| {
            std.log.err("Failed to write to output file: {}", .{err});
            std.process.exit(1);
        };
        
        std.log.info("Content saved to: {s}", .{output_file});
    } else {
        // 標準出力に表示
        std.log.info("=== Content ===", .{});
        std.debug.print("{s}\n", .{content});
    }
    
    std.log.info("", .{});
    std.log.info("🎉 Successfully fetched content via Tor network!", .{});
}