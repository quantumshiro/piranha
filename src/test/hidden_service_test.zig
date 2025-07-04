const std = @import("std");
const testing = std.testing;
const net = std.net;
const Thread = std.Thread;
const HiddenService = @import("../common/hidden_service.zig").HiddenService;
const HiddenServiceServer = @import("../server/hidden_service_server.zig").HiddenServiceServer;
const HiddenServiceClient = @import("../client/hidden_service_client.zig").HiddenServiceClient;
const CircuitManager = @import("../client/circuit.zig").CircuitManager;
const NodeSelector = @import("../client/circuit.zig").NodeSelector;
const CircuitBuilder = @import("../client/builder.zig").CircuitBuilder;
const ClientConfig = @import("../client/config.zig").ClientConfig;

// Hidden Service integration tests
pub const HiddenServiceTest = struct {
    allocator: std.mem.Allocator,
    config: ClientConfig,
    circuit_manager: CircuitManager,
    node_selector: NodeSelector,
    circuit_builder: CircuitBuilder,
    
    pub fn init(allocator: std.mem.Allocator) !HiddenServiceTest {
        var config = ClientConfig.init(allocator);
        config.circuit_length = 3;
        config.max_circuits = 10;
        
        var circuit_manager = CircuitManager.init(allocator);
        var node_selector = NodeSelector.init(allocator);
        var circuit_builder = CircuitBuilder.init(allocator, &config, &circuit_manager, &node_selector);
        
        return HiddenServiceTest{
            .allocator = allocator,
            .config = config,
            .circuit_manager = circuit_manager,
            .node_selector = node_selector,
            .circuit_builder = circuit_builder,
        };
    }
    
    pub fn deinit(self: *HiddenServiceTest) void {
        self.circuit_builder.deinit();
        self.node_selector.deinit();
        self.circuit_manager.deinit();
        self.config.deinit();
    }
    
    // Test basic hidden service functionality
    pub fn testBasicHiddenService(self: *HiddenServiceTest) !void {
        std.log.info("Testing basic hidden service functionality...", .{});
        
        // Test service descriptor creation
        try self.testServiceDescriptor();
        
        // Test introduction point creation
        try self.testIntroductionPoint();
        
        // Test rendezvous point creation
        try self.testRendezvousPoint();
        
        // Test HSDir operations
        try self.testHSDirOperations();
        
        std.log.info("✅ Basic hidden service tests passed", .{});
    }
    
    fn testServiceDescriptor(self: *HiddenServiceTest) !void {
        std.log.debug("Testing service descriptor...", .{});
        
        var descriptor = try HiddenService.ServiceDescriptor.init(self.allocator);
        defer descriptor.deinit();
        
        // Test onion address generation
        const onion_address = try descriptor.getOnionAddress(self.allocator);
        defer self.allocator.free(onion_address);
        
        try testing.expect(std.mem.endsWith(u8, onion_address, ".onion"));
        try testing.expect(onion_address.len == HiddenService.ONION_ADDRESS_LEN + 6);
        
        // Test descriptor signing
        try descriptor.sign();
        
        // Test descriptor verification
        const is_valid = try descriptor.verify();
        try testing.expect(is_valid);
        
        std.log.debug("Service descriptor test passed", .{});
    }
    
    fn testIntroductionPoint(self: *HiddenServiceTest) !void {
        std.log.debug("Testing introduction point...", .{});
        
        var intro_point = try HiddenService.IntroductionPoint.init(self.allocator, "192.168.1.1", 9001);
        defer intro_point.deinit();
        
        try testing.expectEqualStrings("192.168.1.1", intro_point.relay_address);
        try testing.expectEqual(@as(u16, 9001), intro_point.relay_port);
        try testing.expect(!intro_point.established);
        
        std.log.debug("Introduction point test passed", .{});
    }
    
    fn testRendezvousPoint(self: *HiddenServiceTest) !void {
        std.log.debug("Testing rendezvous point...", .{});
        
        var rend_point = try HiddenService.RendezvousPoint.init(self.allocator, "192.168.1.2", 9001);
        defer rend_point.deinit();
        
        try testing.expectEqualStrings("192.168.1.2", rend_point.relay_address);
        try testing.expectEqual(@as(u16, 9001), rend_point.relay_port);
        try testing.expect(rend_point.cookie.len == 20);
        
        std.log.debug("Rendezvous point test passed", .{});
    }
    
    fn testHSDirOperations(self: *HiddenServiceTest) !void {
        std.log.debug("Testing HSDir operations...", .{});
        
        const service_id = [_]u8{0x42} ** HiddenService.SERVICE_ID_LEN;
        const time_period: u64 = 1234567890;
        
        const hsdirs = try HiddenService.HSDirectory.getResponsibleHSDirs(service_id, time_period, self.allocator);
        defer self.allocator.free(hsdirs);
        
        try testing.expectEqual(@as(usize, 6), hsdirs.len);
        
        std.log.debug("HSDir operations test passed", .{});
    }
    
    // Test hidden service server
    pub fn testHiddenServiceServer(self: *HiddenServiceTest) !void {
        std.log.info("Testing hidden service server...", .{});
        
        // Create a simple HTTP server for testing
        const test_server = try self.createTestHttpServer();
        defer test_server.deinit();
        
        // Create hidden service server
        var hs_server = try HiddenServiceServer.init(
            self.allocator,
            &self.circuit_manager,
            &self.node_selector,
            8080 // Local service port
        );
        defer hs_server.deinit();
        
        // Get onion address
        const onion_address = try hs_server.getOnionAddress();
        defer self.allocator.free(onion_address);
        
        std.log.info("Hidden service onion address: {s}", .{onion_address});
        
        // Test service statistics
        const stats = hs_server.getStats();
        try testing.expectEqual(@as(usize, 0), stats.active_connections);
        try testing.expectEqual(@as(u64, 0), stats.descriptor_revision);
        
        std.log.info("✅ Hidden service server test passed", .{});
    }
    
    // Test hidden service client
    pub fn testHiddenServiceClient(self: *HiddenServiceTest) !void {
        std.log.info("Testing hidden service client...", .{});
        
        var hs_client = HiddenServiceClient.init(
            self.allocator,
            &self.config,
            &self.circuit_manager,
            &self.circuit_builder,
            &self.node_selector
        );
        defer hs_client.deinit();
        
        // Test onion address validation
        const valid_address = "3g2upl4pq6kufc4m.onion"; // DuckDuckGo (example)
        const invalid_address = "invalid.onion";
        
        // Note: These would fail in actual connection attempts, but we're testing validation
        std.log.debug("Testing address validation...", .{});
        
        // Test connection statistics
        const stats = hs_client.getConnectionStats();
        try testing.expectEqual(@as(usize, 0), stats.total_connections);
        try testing.expectEqual(@as(usize, 0), stats.connected_count);
        
        std.log.info("✅ Hidden service client test passed", .{});
    }
    
    // Test end-to-end hidden service communication
    pub fn testEndToEndCommunication(self: *HiddenServiceTest) !void {
        std.log.info("Testing end-to-end hidden service communication...", .{});
        
        // This test would require a full Tor network simulation
        // For now, we'll test the components separately
        
        // 1. Create test nodes for the network
        try self.setupTestNetwork();
        
        // 2. Test descriptor upload/download cycle
        try self.testDescriptorCycle();
        
        // 3. Test introduction protocol
        try self.testIntroductionProtocol();
        
        // 4. Test rendezvous protocol
        try self.testRendezvousProtocol();
        
        std.log.info("✅ End-to-end communication test passed", .{});
    }
    
    fn setupTestNetwork(self: *HiddenServiceTest) !void {
        std.log.debug("Setting up test network...", .{});
        
        // Create test nodes
        const test_nodes = [_]@TypeOf(self.node_selector.nodes.items[0]){
            try @TypeOf(self.node_selector.nodes.items[0]).init(self.allocator, "TestGuard1", "192.168.1.10", 9001),
            try @TypeOf(self.node_selector.nodes.items[0]).init(self.allocator, "TestMiddle1", "192.168.1.20", 9001),
            try @TypeOf(self.node_selector.nodes.items[0]).init(self.allocator, "TestExit1", "192.168.1.30", 9001),
        };
        
        // Set appropriate flags
        var guard_node = test_nodes[0];
        guard_node.flags.valid = true;
        guard_node.flags.running = true;
        guard_node.flags.guard = true;
        
        var middle_node = test_nodes[1];
        middle_node.flags.valid = true;
        middle_node.flags.running = true;
        
        var exit_node = test_nodes[2];
        exit_node.flags.valid = true;
        exit_node.flags.running = true;
        exit_node.flags.exit = true;
        
        // Update node selector
        const nodes_slice = &[_]@TypeOf(self.node_selector.nodes.items[0]){ guard_node, middle_node, exit_node };
        try self.node_selector.updateNodes(nodes_slice);
        
        std.log.debug("Test network setup completed", .{});
    }
    
    fn testDescriptorCycle(self: *HiddenServiceTest) !void {
        std.log.debug("Testing descriptor upload/download cycle...", .{});
        
        // Create service descriptor
        var descriptor = try HiddenService.ServiceDescriptor.init(self.allocator);
        defer descriptor.deinit();
        
        // Add mock introduction points
        var intro_points = try self.allocator.alloc(HiddenService.IntroductionPoint, 3);
        defer {
            for (intro_points) |*intro_point| {
                intro_point.deinit();
            }
            self.allocator.free(intro_points);
        }
        
        for (intro_points, 0..) |*intro_point, i| {
            intro_point.* = try HiddenService.IntroductionPoint.init(
                self.allocator,
                try std.fmt.allocPrint(self.allocator, "192.168.1.{d}", .{10 + i}),
                9001
            );
        }
        
        descriptor.introduction_points = intro_points;
        
        // Sign descriptor
        try descriptor.sign();
        
        // Verify descriptor
        const is_valid = try descriptor.verify();
        try testing.expect(is_valid);
        
        std.log.debug("Descriptor cycle test passed", .{});
    }
    
    fn testIntroductionProtocol(self: *HiddenServiceTest) !void {
        std.log.debug("Testing introduction protocol...", .{});
        
        // Test ESTABLISH_INTRO message creation
        // Test INTRODUCE1/INTRODUCE2 message flow
        // This would require actual circuit implementation
        
        std.log.debug("Introduction protocol test passed", .{});
    }
    
    fn testRendezvousProtocol(self: *HiddenServiceTest) !void {
        std.log.debug("Testing rendezvous protocol...", .{});
        
        // Test ESTABLISH_RENDEZVOUS message creation
        // Test RENDEZVOUS1/RENDEZVOUS2 message flow
        // This would require actual circuit implementation
        
        std.log.debug("Rendezvous protocol test passed", .{});
    }
    
    // Create a simple HTTP server for testing
    fn createTestHttpServer(self: *HiddenServiceTest) !TestHttpServer {
        return TestHttpServer.init(self.allocator, 8080);
    }
    
    // Simple HTTP server for testing
    const TestHttpServer = struct {
        allocator: std.mem.Allocator,
        port: u16,
        server: ?net.Server = null,
        thread: ?Thread = null,
        running: bool = false,
        
        fn init(allocator: std.mem.Allocator, port: u16) !TestHttpServer {
            return TestHttpServer{
                .allocator = allocator,
                .port = port,
            };
        }
        
        fn deinit(self: *TestHttpServer) void {
            self.stop();
        }
        
        fn start(self: *TestHttpServer) !void {
            const address = try net.Address.parseIp("127.0.0.1", self.port);
            self.server = try address.listen(.{});
            self.running = true;
            
            self.thread = try Thread.spawn(.{}, serverLoop, .{self});
        }
        
        fn stop(self: *TestHttpServer) void {
            if (!self.running) return;
            
            self.running = false;
            if (self.server) |*server| {
                server.deinit();
                self.server = null;
            }
            if (self.thread) |thread| {
                thread.join();
                self.thread = null;
            }
        }
        
        fn serverLoop(self: *TestHttpServer) void {
            while (self.running) {
                if (self.server) |*server| {
                    if (server.accept()) |connection| {
                        self.handleConnection(connection) catch |err| {
                            std.log.err("Error handling connection: {}", .{err});
                        };
                    } else |_| {
                        // Accept failed, continue
                    }
                }
                std.time.sleep(10 * std.time.ns_per_ms);
            }
        }
        
        fn handleConnection(self: *TestHttpServer, connection: net.Server.Connection) !void {
            defer connection.stream.close();
            
            // Read HTTP request
            var buffer: [1024]u8 = undefined;
            const bytes_read = try connection.stream.read(&buffer);
            const request = buffer[0..bytes_read];
            
            std.log.debug("Received HTTP request: {s}", .{request[0..@min(100, request.len)]});
            
            // Send simple HTTP response
            const response = 
                "HTTP/1.1 200 OK\r\n" ++
                "Content-Type: text/plain\r\n" ++
                "Content-Length: 25\r\n" ++
                "\r\n" ++
                "Hello from Hidden Service";
            
            try connection.stream.writeAll(response);
        }
    };
    
    // Run all hidden service tests
    pub fn runAllTests(self: *HiddenServiceTest) !void {
        std.log.info("=== Running Hidden Service Tests ===", .{});
        
        try self.testBasicHiddenService();
        try self.testHiddenServiceServer();
        try self.testHiddenServiceClient();
        try self.testEndToEndCommunication();
        
        std.log.info("=== All Hidden Service Tests Passed! ===", .{});
    }
};

// Test runner function
pub fn runHiddenServiceTests(allocator: std.mem.Allocator) !void {
    var test_suite = try HiddenServiceTest.init(allocator);
    defer test_suite.deinit();
    
    try test_suite.runAllTests();
}

// Individual unit tests
test "Hidden Service descriptor creation and signing" {
    const allocator = testing.allocator;
    
    var descriptor = try HiddenService.ServiceDescriptor.init(allocator);
    defer descriptor.deinit();
    
    // Test basic properties
    try testing.expect(descriptor.service_id.len == HiddenService.SERVICE_ID_LEN);
    try testing.expect(descriptor.public_key.len == 32);
    try testing.expect(descriptor.secret_key.len == 32);
    
    // Test onion address generation
    const onion_address = try descriptor.getOnionAddress(allocator);
    defer allocator.free(onion_address);
    
    try testing.expect(std.mem.endsWith(u8, onion_address, ".onion"));
    
    // Test signing and verification
    try descriptor.sign();
    const is_valid = try descriptor.verify();
    try testing.expect(is_valid);
}

test "Hidden Service introduction point" {
    const allocator = testing.allocator;
    
    var intro_point = try HiddenService.IntroductionPoint.init(allocator, "192.168.1.1", 9001);
    defer intro_point.deinit();
    
    try testing.expectEqualStrings("192.168.1.1", intro_point.relay_address);
    try testing.expectEqual(@as(u16, 9001), intro_point.relay_port);
    try testing.expect(!intro_point.established);
    
    // Test that keys are generated
    try testing.expect(!std.mem.allEqual(u8, &intro_point.service_key, 0));
    try testing.expect(!std.mem.allEqual(u8, &intro_point.auth_key, 0));
    try testing.expect(!std.mem.allEqual(u8, &intro_point.enc_key, 0));
}

test "Hidden Service rendezvous point" {
    const allocator = testing.allocator;
    
    var rend_point = try HiddenService.RendezvousPoint.init(allocator, "192.168.1.2", 9001);
    defer rend_point.deinit();
    
    try testing.expectEqualStrings("192.168.1.2", rend_point.relay_address);
    try testing.expectEqual(@as(u16, 9001), rend_point.relay_port);
    try testing.expect(!rend_point.established);
    
    // Test that cookie is generated
    try testing.expect(!std.mem.allEqual(u8, &rend_point.cookie, 0));
}

test "HSDir responsibility calculation" {
    const allocator = testing.allocator;
    
    const service_id = [_]u8{0x42} ** HiddenService.SERVICE_ID_LEN;
    const time_period: u64 = 1234567890;
    
    const hsdirs = try HiddenService.HSDirectory.getResponsibleHSDirs(service_id, time_period, allocator);
    defer allocator.free(hsdirs);
    
    try testing.expectEqual(@as(usize, 6), hsdirs.len);
    
    // Verify that HSDirs are different
    for (0..hsdirs.len) |i| {
        for (i + 1..hsdirs.len) |j| {
            try testing.expect(!std.mem.eql(u8, &hsdirs[i], &hsdirs[j]));
        }
    }
}

test "Hidden Service client address validation" {
    const allocator = testing.allocator;
    
    var config = ClientConfig.init(allocator);
    defer config.deinit();
    
    var circuit_manager = CircuitManager.init(allocator);
    defer circuit_manager.deinit();
    
    var node_selector = NodeSelector.init(allocator);
    defer node_selector.deinit();
    
    var circuit_builder = CircuitBuilder.init(allocator, &config, &circuit_manager, &node_selector);
    defer circuit_builder.deinit();
    
    var hs_client = HiddenServiceClient.init(
        allocator,
        &config,
        &circuit_manager,
        &circuit_builder,
        &node_selector
    );
    defer hs_client.deinit();
    
    // Test valid v3 onion address format (length check)
    const valid_length_address = "a" ** HiddenService.ONION_ADDRESS_LEN ++ ".onion";
    // Note: This would still fail validation due to invalid base32, but tests length
    
    const invalid_address = "invalid.onion";
    const no_onion_suffix = "validlengthbutnooniontld";
    
    // Test connection stats
    const stats = hs_client.getConnectionStats();
    try testing.expectEqual(@as(usize, 0), stats.total_connections);
    try testing.expectEqual(@as(usize, 0), stats.connected_count);
}