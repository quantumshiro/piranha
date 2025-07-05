const std = @import("std");
const net = std.net;
// const lib = @import("piranha_lib");
// const Cell = lib.cell.Cell;
// const CellCommand = lib.cell.CellCommand;
// const crypto = lib.crypto;
// const ntor = lib.ntor;

pub const CircuitId = u16;
pub const StreamId = u16;

// ノード情報（Directory Authorityから取得）
pub const NodeInfo = struct {
    nickname: []const u8,
    address: []const u8,
    port: u16,
    identity_key: [32]u8,
    ntor_key: [32]u8,
    flags: NodeFlags,
    allocator: std.mem.Allocator,

    pub const NodeFlags = struct {
        valid: bool = false,
        running: bool = false,
        stable: bool = false,
        fast: bool = false,
        guard: bool = false,
        exit: bool = false,
        authority: bool = false,
    };

    pub fn init(allocator: std.mem.Allocator, nickname: []const u8, address: []const u8, port: u16) !NodeInfo {
        return NodeInfo{
            .nickname = try allocator.dupe(u8, nickname),
            .address = try allocator.dupe(u8, address),
            .port = port,
            .identity_key = [_]u8{0} ** 32,
            .ntor_key = [_]u8{0} ** 32,
            .flags = NodeFlags{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *NodeInfo) void {
        self.allocator.free(self.nickname);
        self.allocator.free(self.address);
    }

    pub fn isUsableAsGuard(self: *const NodeInfo) bool {
        return self.flags.valid and self.flags.running and (self.flags.guard or self.flags.stable);
    }

    pub fn isUsableAsMiddle(self: *const NodeInfo) bool {
        return self.flags.valid and self.flags.running;
    }

    pub fn isUsableAsExit(self: *const NodeInfo) bool {
        return self.flags.valid and self.flags.running and self.flags.exit;
    }
};

// 回路内のホップ情報
pub const CircuitHop = struct {
    node: NodeInfo,
    shared_key: [32]u8,
    forward_digest: [20]u8,
    backward_digest: [20]u8,
    connection: ?net.Stream,

    pub fn init(node: NodeInfo) CircuitHop {
        return CircuitHop{
            .node = node,
            .shared_key = [_]u8{0} ** 32,
            .forward_digest = [_]u8{0} ** 20,
            .backward_digest = [_]u8{0} ** 20,
            .connection = null,
        };
    }

    pub fn deinit(self: *CircuitHop) void {
        if (self.connection) |conn| {
            conn.close();
        }
        self.node.deinit();
    }
};

// 回路の状態
pub const CircuitState = enum {
    building,
    ready,
    failed,
    closed,
};

// 回路情報
pub const Circuit = struct {
    id: CircuitId,
    state: CircuitState,
    hops: std.ArrayList(CircuitHop),
    created_at: i64,
    last_used: i64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, id: CircuitId) Circuit {
        const now = std.time.timestamp();
        return Circuit{
            .id = id,
            .state = .building,
            .hops = std.ArrayList(CircuitHop).init(allocator),
            .created_at = now,
            .last_used = now,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Circuit) void {
        for (self.hops.items) |*hop| {
            hop.deinit();
        }
        self.hops.deinit();
    }

    pub fn addHop(self: *Circuit, node: *const NodeInfo) !void {
        // ノードをディープコピーして所有権を移す
        const node_copy = NodeInfo{
            .nickname = try self.allocator.dupe(u8, node.nickname),
            .address = try self.allocator.dupe(u8, node.address),
            .port = node.port,
            .identity_key = node.identity_key,
            .ntor_key = node.ntor_key,
            .flags = node.flags,
            .allocator = self.allocator,
        };
        
        const hop = CircuitHop.init(node_copy);
        try self.hops.append(hop);
    }

    pub fn getLength(self: *const Circuit) usize {
        return self.hops.items.len;
    }

    pub fn getLastHop(self: *Circuit) ?*CircuitHop {
        if (self.hops.items.len == 0) return null;
        return &self.hops.items[self.hops.items.len - 1];
    }

    pub fn getFirstHop(self: *Circuit) ?*CircuitHop {
        if (self.hops.items.len == 0) return null;
        return &self.hops.items[0];
    }

    pub fn isReady(self: *const Circuit) bool {
        return self.state == .ready;
    }

    pub fn markReady(self: *Circuit) void {
        self.state = .ready;
        self.last_used = std.time.timestamp();
    }

    pub fn markFailed(self: *Circuit) void {
        self.state = .failed;
    }

    pub fn markClosed(self: *Circuit) void {
        self.state = .closed;
    }

    pub fn updateLastUsed(self: *Circuit) void {
        self.last_used = std.time.timestamp();
    }

    pub fn isExpired(self: *const Circuit, timeout_seconds: u32) bool {
        const now = std.time.timestamp();
        return (now - self.last_used) > timeout_seconds;
    }
};

// 回路エントリ
const CircuitEntry = struct {
    id: CircuitId,
    circuit: *Circuit,
    
    pub fn deinit(self: *CircuitEntry, allocator: std.mem.Allocator) void {
        self.circuit.deinit();
        allocator.destroy(self.circuit);
    }
};

// 回路管理
pub const CircuitManager = struct {
    circuits: std.ArrayList(CircuitEntry),
    next_circuit_id: CircuitId,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) CircuitManager {
        return CircuitManager{
            .circuits = std.ArrayList(CircuitEntry).init(allocator),
            .next_circuit_id = 1,
            .allocator = allocator,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *CircuitManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.circuits.items) |*entry| {
            entry.deinit(self.allocator);
        }
        self.circuits.deinit();
    }

    pub fn createCircuit(self: *CircuitManager) !CircuitId {
        self.mutex.lock();
        defer self.mutex.unlock();

        // アロケータの有効性をチェック
        if (@intFromPtr(self.allocator.ptr) == 0) {
            std.log.err("CircuitManager allocator is null", .{});
            return error.InvalidAllocator;
        }

        const circuit_id = self.next_circuit_id;
        self.next_circuit_id +%= 1;

        // より安全な方法でヒープに回路を作成
        const circuit = self.allocator.create(Circuit) catch |err| {
            std.log.err("Failed to allocate memory for circuit {}: {}", .{ circuit_id, err });
            return err;
        };
        
        circuit.* = Circuit.init(self.allocator, circuit_id);
        
        const entry = CircuitEntry{
            .id = circuit_id,
            .circuit = circuit,
        };
        
        self.circuits.append(entry) catch |err| {
            // エラーの場合はメモリを解放
            circuit.deinit();
            self.allocator.destroy(circuit);
            return err;
        };

        std.log.debug("Created circuit {}", .{circuit_id});
        return circuit_id;
    }

    pub fn getCircuit(self: *CircuitManager, circuit_id: CircuitId) ?*Circuit {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.circuits.items) |*entry| {
            if (entry.id == circuit_id) {
                return entry.circuit;
            }
        }
        return null;
    }

    pub fn removeCircuit(self: *CircuitManager, circuit_id: CircuitId) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.circuits.items, 0..) |*entry, i| {
            if (entry.id == circuit_id) {
                entry.deinit(self.allocator);
                _ = self.circuits.swapRemove(i);
                std.log.debug("Removed circuit {}", .{circuit_id});
                return;
            }
        }
    }

    pub fn getReadyCircuit(self: *CircuitManager) ?CircuitId {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.circuits.items) |*entry| {
            if (entry.circuit.isReady()) {
                entry.circuit.updateLastUsed();
                return entry.id;
            }
        }
        return null;
    }

    pub fn cleanupExpiredCircuits(self: *CircuitManager, timeout_seconds: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var i: usize = 0;
        while (i < self.circuits.items.len) {
            if (self.circuits.items[i].circuit.isExpired(timeout_seconds)) {
                const circuit_id = self.circuits.items[i].id;
                self.circuits.items[i].deinit(self.allocator);
                _ = self.circuits.swapRemove(i);
                std.log.debug("Cleaned up expired circuit {}", .{circuit_id});
                // インデックスを進めない（swapRemoveで要素が移動するため）
            } else {
                i += 1;
            }
        }
    }

    pub fn getCircuitCount(self: *CircuitManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.circuits.items.len;
    }
};

// ノード選択器
pub const NodeSelector = struct {
    nodes: std.ArrayList(NodeInfo),
    allocator: std.mem.Allocator,
    rng: std.Random.DefaultPrng,

    pub fn init(allocator: std.mem.Allocator) NodeSelector {
        const rng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
        return NodeSelector{
            .nodes = std.ArrayList(NodeInfo).init(allocator),
            .allocator = allocator,
            .rng = rng,
        };
    }

    pub fn deinit(self: *NodeSelector) void {
        for (self.nodes.items) |*node| {
            node.deinit();
        }
        self.nodes.deinit();
    }

    pub fn updateNodes(self: *NodeSelector, new_nodes: []const NodeInfo) !void {
        // Clear existing nodes
        for (self.nodes.items) |*node| {
            node.deinit();
        }
        self.nodes.clearRetainingCapacity();

        // Add new nodes
        for (new_nodes) |node| {
            // ディープコピーを作成
            const node_copy = NodeInfo{
                .nickname = try self.allocator.dupe(u8, node.nickname),
                .address = try self.allocator.dupe(u8, node.address),
                .port = node.port,
                .identity_key = node.identity_key,
                .ntor_key = node.ntor_key,
                .flags = node.flags,
                .allocator = self.allocator,
            };
            try self.nodes.append(node_copy);
        }

        std.log.info("Updated node list: {} nodes available", .{self.nodes.items.len});
    }

    pub fn selectGuardNode(self: *NodeSelector) ?*NodeInfo {
        var candidates = std.ArrayList(*NodeInfo).init(self.allocator);
        defer candidates.deinit();

        // 信頼できるポートのノードを優先的に選択
        const preferred_ports = [_]u16{ 443, 9001, 80, 9030 };
        
        for (preferred_ports) |preferred_port| {
            for (self.nodes.items) |*node| {
                if (node.isUsableAsGuard() and node.port == preferred_port) {
                    // 大きなTorリレーの名前パターンを優先
                    if (std.mem.indexOf(u8, node.nickname, "exit") != null or
                        std.mem.indexOf(u8, node.nickname, "relay") != null or
                        std.mem.indexOf(u8, node.nickname, "tor") != null or
                        std.mem.indexOf(u8, node.nickname, "node") != null) {
                        candidates.append(node) catch continue;
                    }
                }
            }
            if (candidates.items.len >= 10) break; // 十分な候補がある場合は停止
        }
        
        // 候補が少ない場合は、標準的なポートのすべてのガードノードを追加
        if (candidates.items.len < 5) {
            for (self.nodes.items) |*node| {
                if (node.isUsableAsGuard()) {
                    if (node.port == 443 or node.port == 9001 or node.port == 80) {
                        candidates.append(node) catch continue;
                    }
                }
            }
        }

        if (candidates.items.len == 0) {
            std.log.warn("No guard nodes found with common ports, trying all guard nodes", .{});
            // フォールバック：すべてのガードノードを試す
            for (self.nodes.items) |*node| {
                if (node.isUsableAsGuard()) {
                    candidates.append(node) catch continue;
                }
            }
        }

        if (candidates.items.len == 0) return null;

        const index = self.rng.random().uintLessThan(usize, candidates.items.len);
        const selected = candidates.items[index];

        std.log.debug("Selected guard node: {s} ({s}:{d}) from {} candidates", .{
            selected.nickname, selected.address, selected.port, candidates.items.len
        });
        
        // 既存のノードへのポインタを返す（コピーしない）
        return selected;
    }

    pub fn selectMiddleNode(self: *NodeSelector, exclude_nodes: []*const NodeInfo) ?*NodeInfo {
        var candidates = std.ArrayList(*NodeInfo).init(self.allocator);
        defer candidates.deinit();

        node_loop: for (self.nodes.items) |*node| {
            if (!node.isUsableAsMiddle()) continue;

            // Exclude already selected nodes
            for (exclude_nodes) |exclude| {
                if (std.mem.eql(u8, node.nickname, exclude.nickname)) {
                    continue :node_loop;
                }
            }

            candidates.append(node) catch continue;
        }

        if (candidates.items.len == 0) return null;

        const index = self.rng.random().uintLessThan(usize, candidates.items.len);
        const selected = candidates.items[index];

        std.log.debug("Selected middle node: {s}", .{selected.nickname});
        
        // 既存のノードへのポインタを返す（コピーしない）
        return selected;
    }

    pub fn selectExitNode(self: *NodeSelector, exclude_nodes: []*const NodeInfo) ?*NodeInfo {
        var candidates = std.ArrayList(*NodeInfo).init(self.allocator);
        defer candidates.deinit();

        node_loop: for (self.nodes.items) |*node| {
            if (!node.isUsableAsExit()) continue;

            // Exclude already selected nodes
            for (exclude_nodes) |exclude| {
                if (std.mem.eql(u8, node.nickname, exclude.nickname)) {
                    continue :node_loop;
                }
            }

            candidates.append(node) catch continue;
        }

        if (candidates.items.len == 0) return null;

        const index = self.rng.random().uintLessThan(usize, candidates.items.len);
        const selected = candidates.items[index];

        std.log.debug("Selected exit node: {s}", .{selected.nickname});
        
        // 既存のノードへのポインタを返す（コピーしない）
        return selected;
    }

    pub fn getNodeCount(self: *const NodeSelector) usize {
        return self.nodes.items.len;
    }
};

test "Circuit creation and management" {
    const allocator = std.testing.allocator;

    var manager = CircuitManager.init(allocator);
    defer manager.deinit();

    const circuit_id = try manager.createCircuit();
    try std.testing.expect(circuit_id > 0);

    const circuit = manager.getCircuit(circuit_id);
    try std.testing.expect(circuit != null);
    try std.testing.expect(circuit.?.state == .building);

    manager.removeCircuit(circuit_id);
    const removed_circuit = manager.getCircuit(circuit_id);
    try std.testing.expect(removed_circuit == null);
}

test "Node selection" {
    const allocator = std.testing.allocator;

    var selector = NodeSelector.init(allocator);
    defer selector.deinit();

    // Create test nodes
    var guard_node = try NodeInfo.init(allocator, "GuardNode", "192.168.1.1", 9001);
    defer guard_node.deinit();
    guard_node.flags.valid = true;
    guard_node.flags.running = true;
    guard_node.flags.guard = true;

    var exit_node = try NodeInfo.init(allocator, "ExitNode", "192.168.1.2", 9001);
    defer exit_node.deinit();
    exit_node.flags.valid = true;
    exit_node.flags.running = true;
    exit_node.flags.exit = true;

    const test_nodes = [_]NodeInfo{ guard_node, exit_node };
    try selector.updateNodes(&test_nodes);

    try std.testing.expectEqual(@as(usize, 2), selector.getNodeCount());

    const selected_guard = selector.selectGuardNode();
    try std.testing.expect(selected_guard != null);
    try std.testing.expectEqualStrings("GuardNode", selected_guard.?.nickname);

    const selected_exit = selector.selectExitNode(&[_]*const NodeInfo{});
    try std.testing.expect(selected_exit != null);
    try std.testing.expectEqualStrings("ExitNode", selected_exit.?.nickname);
}