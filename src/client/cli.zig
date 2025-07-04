const std = @import("std");
const HttpOverTorClient = @import("http_client.zig").HttpOverTorClient;
const CircuitBuilder = @import("builder.zig").CircuitBuilder;
const CircuitManager = @import("circuit.zig").CircuitManager;
const NodeSelector = @import("circuit.zig").NodeSelector;
const ClientConfig = @import("config.zig").ClientConfig;

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
    defer config.deinit();
    
    var circuit_manager = CircuitManager.init(allocator);
    defer circuit_manager.deinit();
    
    var node_selector = NodeSelector.init(allocator);
    defer node_selector.deinit();
    
    var circuit_builder = CircuitBuilder.init(allocator, &config, &circuit_manager, &node_selector);
    defer circuit_builder.deinit();
    
    var http_client = HttpOverTorClient.init(allocator, &circuit_builder);
    
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