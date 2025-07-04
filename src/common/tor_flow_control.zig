const std = @import("std");
const testing = std.testing;

// Tor flow control implementation
pub const TorFlowControl = struct {
    // Tor flow control constants
    pub const CIRCUIT_WINDOW_START = 1000;
    pub const STREAM_WINDOW_START = 500;
    pub const CIRCUIT_WINDOW_INCREMENT = 100;
    pub const STREAM_WINDOW_INCREMENT = 50;
    pub const SENDME_THRESHOLD = 100;

    // Flow control window for circuits
    pub const CircuitWindow = struct {
        package_window: i32,
        deliver_window: i32,
        mutex: std.Thread.Mutex,

        pub fn init() CircuitWindow {
            return CircuitWindow{
                .package_window = CIRCUIT_WINDOW_START,
                .deliver_window = CIRCUIT_WINDOW_START,
                .mutex = .{},
            };
        }

        pub fn canSend(self: *CircuitWindow) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.package_window > 0;
        }

        pub fn sendCell(self: *CircuitWindow) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            if (self.package_window > 0) {
                self.package_window -= 1;
                return true;
            }
            return false;
        }

        pub fn receiveCell(self: *CircuitWindow) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            if (self.deliver_window > 0) {
                self.deliver_window -= 1;
                
                // Send SENDME if window is getting low
                if (self.deliver_window <= CIRCUIT_WINDOW_START - SENDME_THRESHOLD) {
                    return true; // Indicates SENDME should be sent
                }
            }
            return false;
        }

        pub fn receiveSendme(self: *CircuitWindow) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            self.package_window += CIRCUIT_WINDOW_INCREMENT;
            if (self.package_window > CIRCUIT_WINDOW_START) {
                self.package_window = CIRCUIT_WINDOW_START;
            }
        }

        pub fn sendSendme(self: *CircuitWindow) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            self.deliver_window += CIRCUIT_WINDOW_INCREMENT;
            if (self.deliver_window > CIRCUIT_WINDOW_START) {
                self.deliver_window = CIRCUIT_WINDOW_START;
            }
        }

        pub fn getPackageWindow(self: *CircuitWindow) i32 {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.package_window;
        }

        pub fn getDeliverWindow(self: *CircuitWindow) i32 {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.deliver_window;
        }
    };

    // Flow control window for streams
    pub const StreamWindow = struct {
        stream_id: u16,
        package_window: i32,
        deliver_window: i32,
        mutex: std.Thread.Mutex,

        pub fn init(stream_id: u16) StreamWindow {
            return StreamWindow{
                .stream_id = stream_id,
                .package_window = STREAM_WINDOW_START,
                .deliver_window = STREAM_WINDOW_START,
                .mutex = .{},
            };
        }

        pub fn canSend(self: *StreamWindow) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.package_window > 0;
        }

        pub fn sendCell(self: *StreamWindow) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            if (self.package_window > 0) {
                self.package_window -= 1;
                return true;
            }
            return false;
        }

        pub fn receiveCell(self: *StreamWindow) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            if (self.deliver_window > 0) {
                self.deliver_window -= 1;
                
                // Send SENDME if window is getting low
                if (self.deliver_window <= STREAM_WINDOW_START - SENDME_THRESHOLD) {
                    return true; // Indicates SENDME should be sent
                }
            }
            return false;
        }

        pub fn receiveSendme(self: *StreamWindow) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            self.package_window += STREAM_WINDOW_INCREMENT;
            if (self.package_window > STREAM_WINDOW_START) {
                self.package_window = STREAM_WINDOW_START;
            }
        }

        pub fn sendSendme(self: *StreamWindow) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            self.deliver_window += STREAM_WINDOW_INCREMENT;
            if (self.deliver_window > STREAM_WINDOW_START) {
                self.deliver_window = STREAM_WINDOW_START;
            }
        }
    };

    // Flow control manager for multiple streams
    pub const FlowControlManager = struct {
        circuit_window: CircuitWindow,
        stream_windows: std.AutoHashMap(u16, StreamWindow),
        allocator: std.mem.Allocator,
        mutex: std.Thread.Mutex,

        pub fn init(allocator: std.mem.Allocator) FlowControlManager {
            return FlowControlManager{
                .circuit_window = CircuitWindow.init(),
                .stream_windows = std.AutoHashMap(u16, StreamWindow).init(allocator),
                .allocator = allocator,
                .mutex = .{},
            };
        }

        pub fn deinit(self: *FlowControlManager) void {
            self.stream_windows.deinit();
        }

        pub fn addStream(self: *FlowControlManager, stream_id: u16) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            const stream_window = StreamWindow.init(stream_id);
            try self.stream_windows.put(stream_id, stream_window);
        }

        pub fn removeStream(self: *FlowControlManager, stream_id: u16) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            _ = self.stream_windows.remove(stream_id);
        }

        pub fn canSendData(self: *FlowControlManager, stream_id: u16) bool {
            // Check both circuit and stream windows
            if (!self.circuit_window.canSend()) {
                return false;
            }

            self.mutex.lock();
            defer self.mutex.unlock();
            
            if (self.stream_windows.getPtr(stream_id)) |stream_window| {
                return stream_window.canSend();
            }
            
            return false;
        }

        pub fn sendData(self: *FlowControlManager, stream_id: u16) bool {
            // Decrement both circuit and stream windows
            if (!self.circuit_window.sendCell()) {
                return false;
            }

            self.mutex.lock();
            defer self.mutex.unlock();
            
            if (self.stream_windows.getPtr(stream_id)) |stream_window| {
                if (stream_window.sendCell()) {
                    return true;
                } else {
                    // Restore circuit window if stream window failed
                    self.circuit_window.package_window += 1;
                    return false;
                }
            }
            
            return false;
        }

        pub fn receiveData(self: *FlowControlManager, stream_id: u16) struct {
            circuit_sendme: bool,
            stream_sendme: bool,
        } {
            var result = .{ .circuit_sendme = false, .stream_sendme = false };
            
            // Update circuit window
            result.circuit_sendme = self.circuit_window.receiveCell();
            
            // Update stream window
            self.mutex.lock();
            defer self.mutex.unlock();
            
            if (self.stream_windows.getPtr(stream_id)) |stream_window| {
                result.stream_sendme = stream_window.receiveCell();
            }
            
            return result;
        }

        pub fn receiveSendme(self: *FlowControlManager, stream_id: ?u16) void {
            if (stream_id) |sid| {
                // Stream SENDME
                self.mutex.lock();
                defer self.mutex.unlock();
                
                if (self.stream_windows.getPtr(sid)) |stream_window| {
                    stream_window.receiveSendme();
                }
            } else {
                // Circuit SENDME
                self.circuit_window.receiveSendme();
            }
        }

        pub fn getCircuitWindow(self: *FlowControlManager) struct {
            package: i32,
            deliver: i32,
        } {
            return .{
                .package = self.circuit_window.getPackageWindow(),
                .deliver = self.circuit_window.getDeliverWindow(),
            };
        }

        pub fn getStreamWindow(self: *FlowControlManager, stream_id: u16) ?struct {
            package: i32,
            deliver: i32,
        } {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            if (self.stream_windows.getPtr(stream_id)) |stream_window| {
                return .{
                    .package = stream_window.package_window,
                    .deliver = stream_window.deliver_window,
                };
            }
            
            return null;
        }
    };
};

test "circuit window basic operations" {
    var window = TorFlowControl.CircuitWindow.init();
    
    try testing.expect(window.canSend());
    try testing.expect(window.sendCell());
    try testing.expectEqual(@as(i32, TorFlowControl.CIRCUIT_WINDOW_START - 1), window.getPackageWindow());
    
    // Test SENDME
    window.receiveSendme();
    try testing.expectEqual(@as(i32, TorFlowControl.CIRCUIT_WINDOW_START), window.getPackageWindow());
}

test "stream window basic operations" {
    var window = TorFlowControl.StreamWindow.init(42);
    
    try testing.expectEqual(@as(u16, 42), window.stream_id);
    try testing.expect(window.canSend());
    try testing.expect(window.sendCell());
    
    // Test SENDME
    window.receiveSendme();
    try testing.expect(window.package_window <= TorFlowControl.STREAM_WINDOW_START);
}

test "flow control manager" {
    const allocator = testing.allocator;
    var manager = TorFlowControl.FlowControlManager.init(allocator);
    defer manager.deinit();
    
    // Add stream
    try manager.addStream(1);
    
    // Test sending data
    try testing.expect(manager.canSendData(1));
    try testing.expect(manager.sendData(1));
    
    // Test receiving data
    const result = manager.receiveData(1);
    try testing.expect(!result.circuit_sendme); // Should not trigger SENDME yet
    try testing.expect(!result.stream_sendme);  // Should not trigger SENDME yet
    
    // Test SENDME
    manager.receiveSendme(1); // Stream SENDME
    manager.receiveSendme(null); // Circuit SENDME
    
    // Remove stream
    manager.removeStream(1);
    try testing.expect(!manager.canSendData(1)); // Should fail after removal
}