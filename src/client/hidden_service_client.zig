const std = @import("std");
const net = std.net;
const ArrayList = std.ArrayList;
const HiddenService = @import("../common/hidden_service.zig").HiddenService;
const CircuitManager = @import("circuit.zig").CircuitManager;
const NodeSelector = @import("circuit.zig").NodeSelector;
const CircuitBuilder = @import("builder.zig").CircuitBuilder;
const Cell = @import("../common/cell.zig").Cell;
const RelayCell = @import("builder.zig").RelayCell;
const RelayCommand = @import("builder.zig").RelayCommand;
const ClientConfig = @import("config.zig").ClientConfig;

// Hidden Service Client implementation
pub const HiddenServiceClient = struct {
    allocator: std.mem.Allocator,
    config: *const ClientConfig,
    circuit_manager: *CircuitManager,
    circuit_builder: *CircuitBuilder,
    node_selector: *NodeSelector,
    active_connections: ArrayList(HiddenConnection),
    
    const HiddenConnection = struct {
        onion_address: []const u8,
        descriptor: ?HiddenService.ServiceDescriptor = null,
        introduction_circuit_id: ?u16 = null,
        rendezvous_point: ?HiddenService.RendezvousPoint = null,
        rendezvous_circuit_id: ?u16 = null,
        connected: bool = false,
        allocator: std.mem.Allocator,
        
        pub fn deinit(self: *HiddenConnection) void {
            self.allocator.free(self.onion_address);
            if (self.descriptor) |*desc| {
                desc.deinit();
            }
            if (self.rendezvous_point) |*rp| {
                rp.deinit();
            }
        }
    };
    
    pub fn init(
        allocator: std.mem.Allocator,
        config: *const ClientConfig,
        circuit_manager: *CircuitManager,
        circuit_builder: *CircuitBuilder,
        node_selector: *NodeSelector
    ) HiddenServiceClient {
        return HiddenServiceClient{
            .allocator = allocator,
            .config = config,
            .circuit_manager = circuit_manager,
            .circuit_builder = circuit_builder,
            .node_selector = node_selector,
            .active_connections = ArrayList(HiddenConnection).init(allocator),
        };
    }
    
    pub fn deinit(self: *HiddenServiceClient) void {
        for (self.active_connections.items) |*connection| {
            connection.deinit();
        }
        self.active_connections.deinit();
    }
    
    // Connect to a hidden service
    pub fn connectToHiddenService(self: *HiddenServiceClient, onion_address: []const u8) !net.Stream {
        std.log.info("Connecting to hidden service: {s}", .{onion_address});
        
        // Validate onion address format
        if (!self.isValidOnionAddress(onion_address)) {
            return error.InvalidOnionAddress;
        }
        
        // Create connection object
        var connection = HiddenConnection{
            .onion_address = try self.allocator.dupe(u8, onion_address),
            .allocator = self.allocator,
        };
        
        // 1. Download service descriptor
        try self.downloadServiceDescriptor(&connection);
        
        // 2. Choose introduction point
        const intro_point = try self.chooseIntroductionPoint(&connection);
        
        // 3. Establish rendezvous point
        try self.establishRendezvousPoint(&connection);
        
        // 4. Send INTRODUCE1 cell
        try self.sendIntroduce1(&connection, intro_point);
        
        // 5. Wait for RENDEZVOUS2 and establish connection
        const stream = try self.waitForRendezvous2(&connection);
        
        // Add to active connections
        try self.active_connections.append(connection);
        
        std.log.info("Successfully connected to hidden service: {s}", .{onion_address});
        return stream;
    }
    
    // Validate onion address format
    fn isValidOnionAddress(self: *HiddenServiceClient, address: []const u8) bool {
        _ = self;
        
        // v3 onion address: 56 characters + ".onion"
        if (address.len != HiddenService.ONION_ADDRESS_LEN + 6) {
            return false;
        }
        
        if (!std.mem.endsWith(u8, address, ".onion")) {
            return false;
        }
        
        // Check base32 encoding
        const base32_part = address[0..HiddenService.ONION_ADDRESS_LEN];
        const base32_alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        
        for (base32_part) |char| {
            if (std.mem.indexOfScalar(u8, base32_alphabet, char) == null) {
                return false;
            }
        }
        
        return true;
    }
    
    // Download service descriptor from HSDirs
    fn downloadServiceDescriptor(self: *HiddenServiceClient, connection: *HiddenConnection) !void {
        std.log.debug("Downloading service descriptor for {s}", .{connection.onion_address});
        
        // Extract service ID from onion address
        const service_id = try self.extractServiceId(connection.onion_address);
        
        // Calculate current time period
        const time_period = @as(u64, @intCast(std.time.timestamp())) / (24 * 60 * 60);
        
        // Get responsible HSDirs
        const hsdirs = try HiddenService.HSDirectory.getResponsibleHSDirs(
            service_id,
            time_period,
            self.allocator
        );
        defer self.allocator.free(hsdirs);
        
        // Try to download from each HSDir
        for (hsdirs) |hsdir_id| {
            // In real implementation, would resolve HSDir ID to actual relay
            const hsdir_address = "127.0.0.1"; // Placeholder
            const hsdir_port: u16 = 9030;
            
            if (HiddenService.HSDirectory.downloadDescriptor(service_id, hsdir_address, hsdir_port, self.allocator)) |descriptor| {
                connection.descriptor = descriptor;
                std.log.debug("Downloaded descriptor from HSDir {}", .{std.fmt.fmtSliceHexLower(&hsdir_id)});
                return;
            } else |err| {
                std.log.debug("Failed to download from HSDir {}: {}", .{ std.fmt.fmtSliceHexLower(&hsdir_id), err });
            }
        }
        
        return error.DescriptorNotFound;
    }
    
    // Extract service ID from onion address
    fn extractServiceId(self: *HiddenServiceClient, onion_address: []const u8) ![HiddenService.SERVICE_ID_LEN]u8 {
        // Remove ".onion" suffix
        const base32_part = onion_address[0..HiddenService.ONION_ADDRESS_LEN];
        
        // Decode base32 to get service ID
        var service_id: [HiddenService.SERVICE_ID_LEN]u8 = undefined;
        
        // Simplified base32 decoding
        const base32_alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        var bits: u32 = 0;
        var bit_count: u8 = 0;
        var output_pos: usize = 0;
        
        for (base32_part) |char| {
            const index = std.mem.indexOfScalar(u8, base32_alphabet, char) orelse return error.InvalidBase32;
            
            bits = (bits << 5) | @as(u32, @intCast(index));
            bit_count += 5;
            
            while (bit_count >= 8 and output_pos < service_id.len) {
                service_id[output_pos] = @intCast((bits >> (bit_count - 8)) & 0xFF);
                output_pos += 1;
                bit_count -= 8;
            }
        }
        
        return service_id;
    }
    
    // Choose an introduction point from the descriptor
    fn chooseIntroductionPoint(self: *HiddenServiceClient, connection: *HiddenConnection) !*HiddenService.IntroductionPoint {
        const descriptor = connection.descriptor orelse return error.NoDescriptor;
        
        if (descriptor.introduction_points.len == 0) {
            return error.NoIntroductionPoints;
        }
        
        // Choose a random introduction point
        const index = std.crypto.random.intRangeAtMost(usize, 0, descriptor.introduction_points.len - 1);
        
        std.log.debug("Chose introduction point {}: {s}:{d}", .{
            index,
            descriptor.introduction_points[index].relay_address,
            descriptor.introduction_points[index].relay_port,
        });
        
        return &descriptor.introduction_points[index];
    }
    
    // Establish rendezvous point
    fn establishRendezvousPoint(self: *HiddenServiceClient, connection: *HiddenConnection) !void {
        std.log.debug("Establishing rendezvous point", .{});
        
        // Choose a relay for rendezvous point
        const middle_node = self.node_selector.selectMiddleNode(&[_]@TypeOf(self.node_selector.nodes.items[0]){}) orelse {
            return error.NoMiddleNodes;
        };
        
        // Create rendezvous point
        connection.rendezvous_point = try HiddenService.RendezvousPoint.init(
            self.allocator,
            middle_node.address,
            middle_node.port
        );
        
        // Build circuit to rendezvous point
        connection.rendezvous_circuit_id = try self.circuit_manager.createCircuit();
        
        // Send ESTABLISH_RENDEZVOUS cell
        try self.sendEstablishRendezvous(connection);
        
        std.log.debug("Rendezvous point established: {s}:{d}", .{
            connection.rendezvous_point.?.relay_address,
            connection.rendezvous_point.?.relay_port,
        });
    }
    
    // Send ESTABLISH_RENDEZVOUS cell
    fn sendEstablishRendezvous(self: *HiddenServiceClient, connection: *HiddenConnection) !void {
        const circuit_id = connection.rendezvous_circuit_id orelse return error.NoRendezvousCircuit;
        const rend_point = &connection.rendezvous_point.? orelse return error.NoRendezvousPoint;
        
        // Create ESTABLISH_RENDEZVOUS payload (just the cookie)
        const payload = &rend_point.cookie;
        
        // Send RELAY cell
        try self.circuit_builder.sendRelayCell(
            circuit_id,
            @intFromEnum(HiddenServiceRelayCommand.relay_command_establish_rendezvous),
            0, // stream_id = 0 for circuit-level commands
            payload
        );
        
        std.log.debug("Sent ESTABLISH_RENDEZVOUS cell", .{});
    }
    
    // Send INTRODUCE1 cell
    fn sendIntroduce1(self: *HiddenServiceClient, connection: *HiddenConnection, intro_point: *HiddenService.IntroductionPoint) !void {
        std.log.debug("Sending INTRODUCE1 cell", .{});
        
        // Build circuit to introduction point
        connection.introduction_circuit_id = try self.circuit_manager.createCircuit();
        
        // Create INTRODUCE1 payload
        const introduce1_payload = try self.createIntroduce1Payload(connection, intro_point);
        defer self.allocator.free(introduce1_payload);
        
        // Send INTRODUCE1 cell
        try self.circuit_builder.sendRelayCell(
            connection.introduction_circuit_id.?,
            @intFromEnum(HiddenServiceRelayCommand.relay_command_introduce1),
            0,
            introduce1_payload
        );
        
        std.log.debug("Sent INTRODUCE1 cell", .{});
    }
    
    // Create INTRODUCE1 payload
    fn createIntroduce1Payload(self: *HiddenServiceClient, connection: *HiddenConnection, intro_point: *HiddenService.IntroductionPoint) ![]u8 {
        var payload = ArrayList(u8).init(self.allocator);
        
        // Legacy key ID (20 bytes) - not used in v3, set to zero
        try payload.appendSlice(&[_]u8{0} ** 20);
        
        // Auth key type (1 byte) - Ed25519
        try payload.append(0x02);
        
        // Auth key length (2 bytes)
        try payload.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u16, 32)));
        
        // Auth key (32 bytes)
        try payload.appendSlice(&intro_point.auth_key);
        
        // Extensions length (2 bytes) - no extensions
        try payload.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u16, 0)));
        
        // Encrypted INTRODUCE2 cell
        const introduce2_cell = try self.createIntroduce2Cell(connection);
        defer self.allocator.free(introduce2_cell);
        
        // Encrypt INTRODUCE2 with introduction point's encryption key
        const encrypted_introduce2 = try self.encryptIntroduce2(introduce2_cell, intro_point);
        defer self.allocator.free(encrypted_introduce2);
        
        // Encrypted data length (2 bytes)
        try payload.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(encrypted_introduce2.len))));
        
        // Encrypted data
        try payload.appendSlice(encrypted_introduce2);
        
        return payload.toOwnedSlice();
    }
    
    // Create INTRODUCE2 cell content
    fn createIntroduce2Cell(self: *HiddenServiceClient, connection: *HiddenConnection) ![]u8 {
        var introduce2 = ArrayList(u8).init(self.allocator);
        
        // Rendezvous cookie (20 bytes)
        const rend_point = &connection.rendezvous_point.?;
        try introduce2.appendSlice(&rend_point.cookie);
        
        // Extension fields length (2 bytes) - no extensions
        try introduce2.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u16, 0)));
        
        // Client public key (32 bytes) - for nTor handshake
        var client_public_key: [32]u8 = undefined;
        std.crypto.random.bytes(&client_public_key);
        try introduce2.appendSlice(&client_public_key);
        
        // Encrypted data for service (simplified)
        const service_data = "RENDEZVOUS_REQUEST";
        try introduce2.appendSlice(service_data);
        
        return introduce2.toOwnedSlice();
    }
    
    // Encrypt INTRODUCE2 cell
    fn encryptIntroduce2(self: *HiddenServiceClient, introduce2_data: []const u8, intro_point: *HiddenService.IntroductionPoint) ![]u8 {
        // Simplified encryption - real implementation would use proper hybrid encryption
        var encrypted = try self.allocator.alloc(u8, introduce2_data.len);
        
        // XOR with introduction point's encryption key (simplified)
        for (introduce2_data, 0..) |byte, i| {
            encrypted[i] = byte ^ intro_point.enc_key[i % 32];
        }
        
        return encrypted;
    }
    
    // Wait for RENDEZVOUS2 cell and establish connection
    fn waitForRendezvous2(self: *HiddenServiceClient, connection: *HiddenConnection) !net.Stream {
        std.log.debug("Waiting for RENDEZVOUS2 cell", .{});
        
        const circuit_id = connection.rendezvous_circuit_id orelse return error.NoRendezvousCircuit;
        
        // Wait for RENDEZVOUS2 cell (simplified)
        const timeout_ms = 30000; // 30 seconds
        const start_time = std.time.milliTimestamp();
        
        while (std.time.milliTimestamp() - start_time < timeout_ms) {
            // Try to receive RENDEZVOUS2 cell
            if (self.receiveRendezvous2(circuit_id)) |rendezvous2_data| {
                defer self.allocator.free(rendezvous2_data);
                
                std.log.debug("Received RENDEZVOUS2 cell", .{});
                
                // Process RENDEZVOUS2 and establish connection
                return try self.processRendezvous2(connection, rendezvous2_data);
            } else |_| {
                // No RENDEZVOUS2 yet, wait a bit
                std.time.sleep(100 * std.time.ns_per_ms);
            }
        }
        
        return error.RendezvousTimeout;
    }
    
    // Receive RENDEZVOUS2 cell (placeholder)
    fn receiveRendezvous2(self: *HiddenServiceClient, circuit_id: u16) ![]u8 {
        _ = self;
        _ = circuit_id;
        
        // Placeholder - would receive actual RENDEZVOUS2 cell
        return error.NoRendezvous2Cell;
    }
    
    // Process RENDEZVOUS2 cell and establish connection
    fn processRendezvous2(self: *HiddenServiceClient, connection: *HiddenConnection, rendezvous2_data: []const u8) !net.Stream {
        std.log.debug("Processing RENDEZVOUS2 cell ({} bytes)", .{rendezvous2_data.len});
        
        // Parse RENDEZVOUS2 cell
        if (rendezvous2_data.len < 32) {
            return error.InvalidRendezvous2;
        }
        
        // Extract handshake data
        const handshake_data = rendezvous2_data[0..32];
        _ = handshake_data;
        
        // Complete nTor handshake (simplified)
        // Real implementation would complete the cryptographic handshake
        
        // Mark connection as established
        connection.connected = true;
        
        // Create a virtual stream representing the hidden service connection
        // In real implementation, this would be a proper Tor stream
        const virtual_stream = try self.createVirtualStream(connection);
        
        std.log.info("Hidden service connection established", .{});
        return virtual_stream;
    }
    
    // Create virtual stream for hidden service connection
    fn createVirtualStream(self: *HiddenServiceClient, connection: *HiddenConnection) !net.Stream {
        _ = self;
        _ = connection;
        
        // Placeholder - would create actual Tor stream
        // For now, return a dummy stream
        return error.NotImplemented;
    }
    
    // Send data through hidden service connection
    pub fn sendData(self: *HiddenServiceClient, onion_address: []const u8, data: []const u8) !void {
        // Find active connection
        for (self.active_connections.items) |*connection| {
            if (std.mem.eql(u8, connection.onion_address, onion_address) and connection.connected) {
                // Send data through rendezvous circuit
                const circuit_id = connection.rendezvous_circuit_id orelse return error.NoCircuit;
                
                try self.circuit_builder.sendRelayCell(
                    circuit_id,
                    @intFromEnum(RelayCommand.relay_data),
                    1, // stream_id
                    data
                );
                
                return;
            }
        }
        
        return error.ConnectionNotFound;
    }
    
    // Receive data from hidden service connection
    pub fn receiveData(self: *HiddenServiceClient, onion_address: []const u8, allocator: std.mem.Allocator) ![]u8 {
        // Find active connection
        for (self.active_connections.items) |*connection| {
            if (std.mem.eql(u8, connection.onion_address, onion_address) and connection.connected) {
                // Receive data from rendezvous circuit
                const circuit_id = connection.rendezvous_circuit_id orelse return error.NoCircuit;
                
                const relay_cell = try self.circuit_builder.receiveRelayCell(circuit_id);
                
                if (relay_cell.command == .relay_data) {
                    return try allocator.dupe(u8, relay_cell.data);
                }
            }
        }
        
        return error.ConnectionNotFound;
    }
    
    // Close hidden service connection
    pub fn closeConnection(self: *HiddenServiceClient, onion_address: []const u8) !void {
        var i: usize = 0;
        while (i < self.active_connections.items.len) {
            if (std.mem.eql(u8, self.active_connections.items[i].onion_address, onion_address)) {
                var connection = self.active_connections.swapRemove(i);
                connection.deinit();
                std.log.info("Closed connection to {s}", .{onion_address});
                return;
            }
            i += 1;
        }
        
        return error.ConnectionNotFound;
    }
    
    // Get connection statistics
    pub fn getConnectionStats(self: *HiddenServiceClient) ConnectionStats {
        var connected_count: usize = 0;
        for (self.active_connections.items) |connection| {
            if (connection.connected) connected_count += 1;
        }
        
        return ConnectionStats{
            .total_connections = self.active_connections.items.len,
            .connected_count = connected_count,
        };
    }
    
    pub const ConnectionStats = struct {
        total_connections: usize,
        connected_count: usize,
    };
};

// Hidden Service relay commands (imported from server)
const HiddenServiceRelayCommand = enum(u8) {
    relay_command_establish_intro = 32,
    relay_command_establish_rendezvous = 33,
    relay_command_introduce1 = 34,
    relay_command_introduce2 = 35,
    relay_command_rendezvous1 = 36,
    relay_command_rendezvous2 = 37,
    relay_command_intro_established = 38,
    relay_command_rendezvous_established = 39,
    relay_command_introduce_ack = 40,
};