const std = @import("std");
const testing = std.testing;
const net = std.net;
const posix = std.posix;

pub const NetworkError = error{
    ConnectionFailed,
    ConnectionClosed,
    ReadTimeout,
    WriteTimeout,
    InvalidAddress,
    BindFailed,
    ListenFailed,
    AcceptFailed,
};

pub const TcpConnection = struct {
    stream: net.Stream,
    address: net.Address,

    pub fn connect(allocator: std.mem.Allocator, host: []const u8, port: u16) !TcpConnection {
        const address = net.Address.resolveIp(host, port) catch |err| switch (err) {
            error.InvalidIPAddressFormat => {
                const list = try net.getAddressList(allocator, host, port);
                defer list.deinit();
                if (list.addrs.len == 0) return NetworkError.InvalidAddress;
                return TcpConnection.connectToAddress(list.addrs[0]);
            },
            else => return err,
        };
        
        return TcpConnection.connectToAddress(address);
    }

    pub fn connectToAddress(address: net.Address) !TcpConnection {
        const stream = net.tcpConnectToAddress(address) catch |err| switch (err) {
            error.ConnectionRefused, error.NetworkUnreachable, error.HostUnreachable => return NetworkError.ConnectionFailed,
            else => return err,
        };

        return TcpConnection{
            .stream = stream,
            .address = address,
        };
    }

    pub fn close(self: *TcpConnection) void {
        self.stream.close();
    }

    pub fn read(self: *TcpConnection, buffer: []u8) !usize {
        return self.stream.read(buffer) catch |err| switch (err) {
            error.ConnectionResetByPeer, error.BrokenPipe => return NetworkError.ConnectionClosed,
            else => return err,
        };
    }

    pub fn readAll(self: *TcpConnection, buffer: []u8) !void {
        var total_read: usize = 0;
        while (total_read < buffer.len) {
            const bytes_read = try self.read(buffer[total_read..]);
            if (bytes_read == 0) return NetworkError.ConnectionClosed;
            total_read += bytes_read;
        }
    }

    pub fn write(self: *TcpConnection, data: []const u8) !usize {
        return self.stream.write(data) catch |err| switch (err) {
            error.ConnectionResetByPeer, error.BrokenPipe => return NetworkError.ConnectionClosed,
            else => return err,
        };
    }

    pub fn writeAll(self: *TcpConnection, data: []const u8) !void {
        var total_written: usize = 0;
        while (total_written < data.len) {
            const bytes_written = try self.write(data[total_written..]);
            if (bytes_written == 0) return NetworkError.ConnectionClosed;
            total_written += bytes_written;
        }
    }

    pub fn getLocalAddress(self: *TcpConnection) !net.Address {
        return self.stream.getLocalAddress();
    }

    pub fn getRemoteAddress(self: *TcpConnection) net.Address {
        return self.address;
    }
};

pub const TcpServer = struct {
    listener: net.Server,
    address: net.Address,

    pub fn bind(address: net.Address) !TcpServer {
        const listener = net.Address.listen(address, .{
            .reuse_address = true,
        }) catch |err| switch (err) {
            error.AddressInUse, error.PermissionDenied => return NetworkError.BindFailed,
            else => return err,
        };

        return TcpServer{
            .listener = listener,
            .address = address,
        };
    }

    pub fn accept(self: *TcpServer) !TcpConnection {
        const connection = self.listener.accept() catch |err| switch (err) {
            error.SocketNotListening => return NetworkError.AcceptFailed,
            else => return err,
        };

        return TcpConnection{
            .stream = connection.stream,
            .address = connection.address,
        };
    }

    pub fn close(self: *TcpServer) void {
        self.listener.deinit();
    }

    pub fn getLocalAddress(self: *TcpServer) net.Address {
        return self.address;
    }
};

pub const IOUtils = struct {
    pub fn readExactly(reader: anytype, buffer: []u8) !void {
        var total_read: usize = 0;
        while (total_read < buffer.len) {
            const bytes_read = try reader.read(buffer[total_read..]);
            if (bytes_read == 0) return error.UnexpectedEndOfStream;
            total_read += bytes_read;
        }
    }

    pub fn writeExactly(writer: anytype, data: []const u8) !void {
        var total_written: usize = 0;
        while (total_written < data.len) {
            const bytes_written = try writer.write(data[total_written..]);
            if (bytes_written == 0) return error.WriteError;
            total_written += bytes_written;
        }
    }

    pub fn readUntil(reader: anytype, buffer: []u8, delimiter: u8) ![]u8 {
        var pos: usize = 0;
        while (pos < buffer.len) {
            const byte = try reader.readByte();
            buffer[pos] = byte;
            pos += 1;
            if (byte == delimiter) {
                return buffer[0..pos];
            }
        }
        return error.StreamTooLong;
    }

    pub fn readUint16(reader: anytype, endian: std.builtin.Endian) !u16 {
        var buffer: [2]u8 = undefined;
        try readExactly(reader, &buffer);
        return std.mem.readInt(u16, &buffer, endian);
    }

    pub fn readUint32(reader: anytype, endian: std.builtin.Endian) !u32 {
        var buffer: [4]u8 = undefined;
        try readExactly(reader, &buffer);
        return std.mem.readInt(u32, &buffer, endian);
    }

    pub fn writeUint16(writer: anytype, value: u16, endian: std.builtin.Endian) !void {
        var buffer: [2]u8 = undefined;
        std.mem.writeInt(u16, &buffer, value, endian);
        try writeExactly(writer, &buffer);
    }

    pub fn writeUint32(writer: anytype, value: u32, endian: std.builtin.Endian) !void {
        var buffer: [4]u8 = undefined;
        std.mem.writeInt(u32, &buffer, value, endian);
        try writeExactly(writer, &buffer);
    }

    pub fn copyData(reader: anytype, writer: anytype, size: usize) !void {
        var buffer: [4096]u8 = undefined;
        var remaining = size;
        
        while (remaining > 0) {
            const to_read = @min(buffer.len, remaining);
            try readExactly(reader, buffer[0..to_read]);
            try writeExactly(writer, buffer[0..to_read]);
            remaining -= to_read;
        }
    }
};

pub const Buffer = struct {
    data: []u8,
    read_pos: usize,
    write_pos: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, cap: usize) !Buffer {
        const data = try allocator.alloc(u8, cap);
        return Buffer{
            .data = data,
            .read_pos = 0,
            .write_pos = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Buffer) void {
        self.allocator.free(self.data);
    }

    pub fn available(self: *const Buffer) usize {
        return self.write_pos - self.read_pos;
    }

    pub fn capacity(self: *const Buffer) usize {
        return self.data.len;
    }

    pub fn readableSlice(self: *const Buffer) []const u8 {
        return self.data[self.read_pos..self.write_pos];
    }

    pub fn writableSlice(self: *const Buffer) []u8 {
        return self.data[self.write_pos..];
    }

    pub fn consume(self: *Buffer, amount: usize) void {
        self.read_pos = @min(self.read_pos + amount, self.write_pos);
    }

    pub fn produce(self: *Buffer, amount: usize) void {
        self.write_pos = @min(self.write_pos + amount, self.data.len);
    }

    pub fn compact(self: *Buffer) void {
        if (self.read_pos > 0) {
            const available_data = self.available();
            std.mem.copyForwards(u8, self.data[0..available_data], self.data[self.read_pos..self.write_pos]);
            self.read_pos = 0;
            self.write_pos = available_data;
        }
    }

    pub fn clear(self: *Buffer) void {
        self.read_pos = 0;
        self.write_pos = 0;
    }
};

test "TCP connection simulation" {
    const allocator = testing.allocator;
    
    const test_data = "Hello, Tor network!";
    
    var buffer = try Buffer.init(allocator, 1024);
    defer buffer.deinit();
    
    @memcpy(buffer.data[0..test_data.len], test_data);
    buffer.produce(test_data.len);
    
    const readable = buffer.readableSlice();
    try testing.expectEqualSlices(u8, test_data, readable);
    
    buffer.consume(5);
    const remaining = buffer.readableSlice();
    try testing.expectEqualSlices(u8, ", Tor network!", remaining);
}

test "IOUtils integer read/write" {
    const allocator = testing.allocator;
    
    var data = std.ArrayList(u8).init(allocator);
    defer data.deinit();
    
    const writer = data.writer();
    try IOUtils.writeUint16(writer, 0x1234, .big);
    try IOUtils.writeUint32(writer, 0x56789ABC, .big);
    
    var stream = std.io.fixedBufferStream(data.items);
    const reader = stream.reader();
    
    const value16 = try IOUtils.readUint16(reader, .big);
    const value32 = try IOUtils.readUint32(reader, .big);
    
    try testing.expectEqual(@as(u16, 0x1234), value16);
    try testing.expectEqual(@as(u32, 0x56789ABC), value32);
}

test "Buffer operations" {
    const allocator = testing.allocator;
    
    var buffer = try Buffer.init(allocator, 100);
    defer buffer.deinit();
    
    try testing.expectEqual(@as(usize, 0), buffer.available());
    try testing.expectEqual(@as(usize, 100), buffer.capacity());
    
    const test_data = "test data";
    @memcpy(buffer.data[0..test_data.len], test_data);
    buffer.produce(test_data.len);
    
    try testing.expectEqual(@as(usize, 9), buffer.available());
    
    buffer.consume(5);
    try testing.expectEqual(@as(usize, 4), buffer.available());
    
    const readable = buffer.readableSlice();
    try testing.expectEqualSlices(u8, "data", readable);
    
    buffer.compact();
    try testing.expectEqualSlices(u8, "data", buffer.data[0..4]);
    try testing.expectEqual(@as(usize, 0), buffer.read_pos);
    try testing.expectEqual(@as(usize, 4), buffer.write_pos);
}

test "Network address parsing" {
    const loopback = try net.Address.parseIp("127.0.0.1", 8080);
    try testing.expectEqual(@as(u16, 8080), loopback.getPort());
    
    const ipv6 = try net.Address.parseIp("::1", 9050);
    try testing.expectEqual(@as(u16, 9050), ipv6.getPort());
}