const std = @import("std");
const testing = std.testing;

pub const CELL_SIZE = 512;
pub const HEADER_SIZE = 3;
pub const PAYLOAD_SIZE = CELL_SIZE - HEADER_SIZE;

pub const CellCommand = enum(u8) {
    padding = 0,
    create = 1,
    created = 2,
    relay = 3,
    destroy = 4,
    create_fast = 5,
    created_fast = 6,
    relay_early = 9,
    _,
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

test "cell byte array conversion" {
    const cell = Cell.init(0xABCD, .created);
    const bytes = try cell.toBytes();
    
    try testing.expect(bytes.len == CELL_SIZE);
    try testing.expect(bytes[0] == 0xAB);
    try testing.expect(bytes[1] == 0xCD);
    try testing.expect(bytes[2] == @intFromEnum(CellCommand.created));
}