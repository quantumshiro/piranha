const std = @import("std");
const testing = std.testing;

// Tor protocol specification compliant cell definition
pub const CELL_SIZE = 512;
pub const HEADER_SIZE = 3;  // Circuit ID (2 bytes) + Command (1 byte)
pub const PAYLOAD_SIZE = CELL_SIZE - HEADER_SIZE;

// Tor protocol specification cell commands
pub const CellCommand = enum(u8) {
    padding = 0,
    create = 1,
    created = 2,
    relay = 3,
    destroy = 4,
    create_fast = 5,
    created_fast = 6,
    versions = 7,
    netinfo = 8,
    relay_early = 9,
    create2 = 10,
    created2 = 11,
    padding_negotiate = 12,
    vpadding = 128,
    certs = 129,
    auth_challenge = 130,
    authenticate = 131,
    authorize = 132,
    _,
};

// Tor protocol version
pub const TOR_PROTOCOL_VERSION = 4;

// Link protocol versions
pub const LINK_PROTOCOL_VERSIONS = [_]u16{ 3, 4, 5 };

// Variable-length cell commands (for link protocol)
pub const VARIABLE_LENGTH_COMMANDS = [_]CellCommand{
    .versions, .vpadding, .certs, .auth_challenge, .authenticate, .authorize
};

pub const Cell = struct {
    circuit_id: u16,
    command: CellCommand,
    payload: [PAYLOAD_SIZE]u8,

    pub fn init(circuit_id: u16, command: CellCommand) Cell {
        return Cell{
            .circuit_id = circuit_id,
            .command = command,
            .payload = [_]u8{0} ** PAYLOAD_SIZE,
        };
    }

    pub fn isVariableLength(self: *const Cell) bool {
        for (VARIABLE_LENGTH_COMMANDS) |cmd| {
            if (self.command == cmd) return true;
        }
        return false;
    }

    pub fn serialize(self: *const Cell, writer: anytype) !void {
        try writer.writeInt(u16, self.circuit_id, .big);
        try writer.writeByte(@intFromEnum(self.command));
        try writer.writeAll(&self.payload);
    }

    pub fn deserialize(reader: anytype) !Cell {
        const circuit_id = try reader.readInt(u16, .big);
        const command_byte = try reader.readByte();
        const command = @as(CellCommand, @enumFromInt(command_byte));
        
        var payload = [_]u8{0} ** PAYLOAD_SIZE;
        _ = try reader.readAll(&payload);
        
        return Cell{
            .circuit_id = circuit_id,
            .command = command,
            .payload = payload,
        };
    }

    pub fn toBytes(self: *const Cell) ![CELL_SIZE]u8 {
        var result = [_]u8{0} ** CELL_SIZE;
        var stream = std.io.fixedBufferStream(&result);
        try self.serialize(stream.writer());
        return result;
    }

    pub fn fromBytes(bytes: *const [CELL_SIZE]u8) !Cell {
        var stream = std.io.fixedBufferStream(bytes);
        return try deserialize(stream.reader());
    }

    // Create a VERSIONS cell for link protocol negotiation
    pub fn createVersionsCell(allocator: std.mem.Allocator) !Cell {
        _ = allocator;
        var cell = Cell.init(0, .versions);  // Circuit ID is 0 for VERSIONS
        
        // Encode supported versions
        var offset: usize = 0;
        for (LINK_PROTOCOL_VERSIONS) |version| {
            if (offset + 2 > PAYLOAD_SIZE) break;
            std.mem.writeInt(u16, cell.payload[offset..offset+2][0..2], version, .big);
            offset += 2;
        }
        
        return cell;
    }

    // Create a NETINFO cell
    pub fn createNetinfoCell(timestamp: u32, my_addr: std.net.Address, other_addr: std.net.Address) !Cell {
        var cell = Cell.init(0, .netinfo);  // Circuit ID is 0 for NETINFO
        
        var offset: usize = 0;
        
        // Timestamp (4 bytes)
        std.mem.writeInt(u32, cell.payload[offset..offset+4][0..4], timestamp, .big);
        offset += 4;
        
        // Other's address
        switch (other_addr.any.family) {
            std.posix.AF.INET => {
                cell.payload[offset] = 0x04;  // IPv4
                offset += 1;
                cell.payload[offset] = 4;     // Length
                offset += 1;
                const addr_bytes = @as([*]const u8, @ptrCast(&other_addr.in.sa.addr))[0..4];
                @memcpy(cell.payload[offset..offset+4], addr_bytes);
                offset += 4;
            },
            else => {
                cell.payload[offset] = 0x00;  // Unknown
                offset += 1;
                cell.payload[offset] = 0;     // Length
                offset += 1;
            },
        }
        
        // Number of my addresses (1)
        cell.payload[offset] = 1;
        offset += 1;
        
        // My address
        switch (my_addr.any.family) {
            std.posix.AF.INET => {
                cell.payload[offset] = 0x04;  // IPv4
                offset += 1;
                cell.payload[offset] = 4;     // Length
                offset += 1;
                const addr_bytes = @as([*]const u8, @ptrCast(&my_addr.in.sa.addr))[0..4];
                @memcpy(cell.payload[offset..offset+4], addr_bytes);
                offset += 4;
            },
            else => {
                cell.payload[offset] = 0x00;  // Unknown
                offset += 1;
                cell.payload[offset] = 0;     // Length
                offset += 1;
            },
        }
        
        return cell;
    }
};

// Variable-length cell for link protocol
pub const VarCell = struct {
    circuit_id: u16,
    command: CellCommand,
    length: u16,
    payload: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, circuit_id: u16, command: CellCommand, payload: []const u8) !VarCell {
        const payload_copy = try allocator.dupe(u8, payload);
        return VarCell{
            .circuit_id = circuit_id,
            .command = command,
            .length = @intCast(payload.len),
            .payload = payload_copy,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *VarCell) void {
        self.allocator.free(self.payload);
    }

    pub fn serialize(self: *const VarCell, writer: anytype) !void {
        try writer.writeInt(u16, self.circuit_id, .big);
        try writer.writeByte(@intFromEnum(self.command));
        try writer.writeInt(u16, self.length, .big);
        try writer.writeAll(self.payload);
    }

    pub fn deserialize(allocator: std.mem.Allocator, reader: anytype) !VarCell {
        const circuit_id = try reader.readInt(u16, .big);
        const command_byte = try reader.readByte();
        const command = @as(CellCommand, @enumFromInt(command_byte));
        const length = try reader.readInt(u16, .big);
        
        const payload = try allocator.alloc(u8, length);
        _ = try reader.readAll(payload);
        
        return VarCell{
            .circuit_id = circuit_id,
            .command = command,
            .length = length,
            .payload = payload,
            .allocator = allocator,
        };
    }
};

test "cell creation" {
    const cell = Cell.init(123, .create);
    try testing.expect(cell.circuit_id == 123);
    try testing.expect(cell.command == .create);
    try testing.expect(cell.payload[0] == 0);
}

test "cell serialization and deserialization" {
    var cell = Cell.init(0x1234, .relay);
    cell.payload[0] = 0xAB;
    cell.payload[1] = 0xCD;
    
    const bytes = try cell.toBytes();
    const deserialized = try Cell.fromBytes(&bytes);
    
    try testing.expect(deserialized.circuit_id == 0x1234);
    try testing.expect(deserialized.command == .relay);
    try testing.expect(deserialized.payload[0] == 0xAB);
    try testing.expect(deserialized.payload[1] == 0xCD);
}

test "versions cell creation" {
    const allocator = testing.allocator;
    const cell = try Cell.createVersionsCell(allocator);
    
    try testing.expect(cell.circuit_id == 0);
    try testing.expect(cell.command == .versions);
    
    // Check first version
    const first_version = std.mem.readInt(u16, cell.payload[0..2], .big);
    try testing.expect(first_version == 3);
}

test "netinfo cell creation" {
    const my_addr = try std.net.Address.parseIp("127.0.0.1", 9050);
    const other_addr = try std.net.Address.parseIp("192.168.1.1", 9001);
    const timestamp: u32 = 1234567890;
    
    const cell = try Cell.createNetinfoCell(timestamp, my_addr, other_addr);
    
    try testing.expect(cell.circuit_id == 0);
    try testing.expect(cell.command == .netinfo);
    
    // Check timestamp
    const parsed_timestamp = std.mem.readInt(u32, cell.payload[0..4], .big);
    try testing.expect(parsed_timestamp == timestamp);
}

test "variable length cell" {
    const allocator = testing.allocator;
    const test_payload = "Hello, Tor!";
    
    var var_cell = try VarCell.init(allocator, 0, .versions, test_payload);
    defer var_cell.deinit();
    
    try testing.expect(var_cell.circuit_id == 0);
    try testing.expect(var_cell.command == .versions);
    try testing.expect(var_cell.length == test_payload.len);
    try testing.expectEqualStrings(test_payload, var_cell.payload);
}