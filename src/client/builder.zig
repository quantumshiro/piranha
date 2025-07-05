const std = @import("std");
const net = std.net;
const circuit = @import("circuit.zig");
const Circuit = circuit.Circuit;
const CircuitHop = circuit.CircuitHop;
const CircuitManager = circuit.CircuitManager;
const NodeSelector = circuit.NodeSelector;
const NodeInfo = circuit.NodeInfo;
const ClientConfig = @import("config.zig").ClientConfig;

// 回路構築エラー
pub const CircuitBuildError = error{
    NodeSelectionFailed,
    ConnectionFailed,
    HandshakeFailed,
    ExtendFailed,
    InvalidConfig,
    Timeout,
};

// 簡略化されたCircuitBuilder
pub const CircuitBuilder = struct {
    config: *const ClientConfig,
    allocator: std.mem.Allocator,
    circuit_manager: *CircuitManager,
    node_selector: *NodeSelector,

    pub fn init(allocator: std.mem.Allocator, config: *const ClientConfig, circuit_manager: *CircuitManager, node_selector: *NodeSelector) CircuitBuilder {
        return CircuitBuilder{
            .config = config,
            .allocator = allocator,
            .circuit_manager = circuit_manager,
            .node_selector = node_selector,
        };
    }

    pub fn buildCircuit(self: *CircuitBuilder) !u16 {
        std.log.info("🔨 Building new circuit...", .{});
        
        // 回路を作成
        const circuit_id = try self.circuit_manager.createCircuit();
        const circuit_ptr = self.circuit_manager.getCircuit(circuit_id) orelse {
            std.log.err("Failed to retrieve created circuit", .{});
            return CircuitBuildError.NodeSelectionFailed;
        };

        // 設定から回路長を取得（フォールバック付き）
        const circuit_length = if (self.config.circuit_length > 0 and self.config.circuit_length <= 10) 
            self.config.circuit_length 
        else 
            3; // デフォルト値

        std.log.debug("Building circuit with {} hops", .{circuit_length});

        // ノードを選択
        try self.selectNodes(circuit_ptr, circuit_length);
        
        // 回路を確立（デモモード）
        try self.establishCircuit(circuit_ptr);

        return circuit_id;
    }

    fn selectNodes(self: *CircuitBuilder, circuit_ptr: *Circuit, length: u8) !void {
        std.log.info("🎯 Selecting {} nodes from live Tor consensus...", .{length});

        var selected_nodes = std.ArrayList(*const NodeInfo).init(self.allocator);
        defer selected_nodes.deinit();

        // Guard node selection
        const guard_node = self.node_selector.selectGuardNode() orelse {
            std.log.err("No suitable guard nodes available", .{});
            return CircuitBuildError.NodeSelectionFailed;
        };
        try selected_nodes.append(guard_node);
        try circuit_ptr.addHop(guard_node);

        // Middle nodes selection
        var hop_count: u8 = 1;
        while (hop_count < length - 1) {
            const middle_node = self.node_selector.selectMiddleNode(selected_nodes.items) orelse {
                std.log.err("No suitable middle nodes available", .{});
                return CircuitBuildError.NodeSelectionFailed;
            };
            try selected_nodes.append(middle_node);
            try circuit_ptr.addHop(middle_node);
            hop_count += 1;
        }

        // Exit node selection
        if (length > 1) {
            const exit_node = self.node_selector.selectExitNode(selected_nodes.items) orelse {
                std.log.err("No suitable exit nodes available", .{});
                return CircuitBuildError.NodeSelectionFailed;
            };
            try circuit_ptr.addHop(exit_node);
        }

        std.log.info("✅ Selected {} nodes successfully", .{circuit_ptr.hops.items.len});
    }

    fn establishCircuit(self: *CircuitBuilder, circuit_ptr: *Circuit) !void {
        _ = self;
        if (circuit_ptr.hops.items.len == 0) {
            std.log.err("Cannot establish circuit without hops", .{});
            return CircuitBuildError.NodeSelectionFailed;
        }

        std.log.info("🔗 Establishing circuit with real Tor nodes (demonstration mode)", .{});

        // Display the real circuit path we would build
        for (circuit_ptr.hops.items, 0..) |*hop, i| {
            const role = if (i == 0) "Guard" else if (i == circuit_ptr.hops.items.len - 1) "Exit" else "Middle";
            std.log.info("  ✓ {s} Node: {s} ({s}:{d}) - Real Tor relay", .{ role, hop.node.nickname, hop.node.address, hop.node.port });
            // 共有キーを設定（デモ用）
            hop.shared_key = [_]u8{0x42 + @as(u8, @intCast(i))} ** 32;
        }

        // 回路を準備完了にマーク
        circuit_ptr.markReady();
        std.log.info("✅ Circuit {} established successfully (demo mode)", .{circuit_ptr.id});
    }
};