const std = @import("std");
const net = std.net;
const testing = std.testing;

// Tor Directory Protocol implementation
pub const TorDirectory = struct {
    // Tor directory document types
    pub const DocumentType = enum {
        consensus,
        server_descriptor,
        extra_info,
        microdescriptor,
        bridge_descriptor,
    };

    // Tor consensus document parser
    pub const ConsensusDocument = struct {
        valid_after: []const u8,
        fresh_until: []const u8,
        valid_until: []const u8,
        voting_delay: u32,
        dist_delay: u32,
        client_versions: [][]const u8,
        server_versions: [][]const u8,
        known_flags: [][]const u8,
        routers: []RouterStatus,
        directory_signature: []DirectorySignature,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *ConsensusDocument) void {
            self.allocator.free(self.valid_after);
            self.allocator.free(self.fresh_until);
            self.allocator.free(self.valid_until);
            
            for (self.client_versions) |version| {
                self.allocator.free(version);
            }
            self.allocator.free(self.client_versions);
            
            for (self.server_versions) |version| {
                self.allocator.free(version);
            }
            self.allocator.free(self.server_versions);
            
            for (self.known_flags) |flag| {
                self.allocator.free(flag);
            }
            self.allocator.free(self.known_flags);
            
            for (self.routers) |*router| {
                router.deinit();
            }
            self.allocator.free(self.routers);
            
            for (self.directory_signature) |*sig| {
                sig.deinit();
            }
            self.allocator.free(self.directory_signature);
        }
    };

    // Router status entry in consensus
    pub const RouterStatus = struct {
        nickname: []const u8,
        identity: [20]u8,  // SHA-1 hash of identity key
        digest: [20]u8,    // SHA-1 hash of descriptor
        publication_time: []const u8,
        ip_address: []const u8,
        or_port: u16,
        dir_port: u16,
        flags: RouterFlags,
        version: []const u8,
        bandwidth: u64,
        measured_bandwidth: ?u64,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *RouterStatus) void {
            self.allocator.free(self.nickname);
            self.allocator.free(self.publication_time);
            self.allocator.free(self.ip_address);
            self.allocator.free(self.version);
        }
    };

    // Router flags from consensus
    pub const RouterFlags = struct {
        authority: bool = false,
        bad_exit: bool = false,
        exit: bool = false,
        fast: bool = false,
        guard: bool = false,
        hsdir: bool = false,
        no_ed_consensus: bool = false,
        running: bool = false,
        stable: bool = false,
        stable_uptime: bool = false,
        v2dir: bool = false,
        valid: bool = false,
    };

    // Directory signature
    pub const DirectorySignature = struct {
        algorithm: []const u8,
        identity: [20]u8,
        signing_key_digest: [20]u8,
        signature: []const u8,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *DirectorySignature) void {
            self.allocator.free(self.algorithm);
            self.allocator.free(self.signature);
        }
    };

    // Parse Tor consensus document
    pub fn parseConsensus(allocator: std.mem.Allocator, data: []const u8) !ConsensusDocument {
        var lines = std.mem.splitScalar(u8, data, '\n');
        var consensus = ConsensusDocument{
            .valid_after = try allocator.dupe(u8, ""),
            .fresh_until = try allocator.dupe(u8, ""),
            .valid_until = try allocator.dupe(u8, ""),
            .voting_delay = 0,
            .dist_delay = 0,
            .client_versions = &[_][]const u8{},
            .server_versions = &[_][]const u8{},
            .known_flags = &[_][]const u8{},
            .routers = &[_]RouterStatus{},
            .directory_signature = &[_]DirectorySignature{},
            .allocator = allocator,
        };

        var routers = std.ArrayList(RouterStatus).init(allocator);
        var signatures = std.ArrayList(DirectorySignature).init(allocator);

        while (lines.next()) |line| {
            if (line.len == 0) continue;

            var parts = std.mem.splitScalar(u8, line, ' ');
            const keyword = parts.next() orelse continue;

            if (std.mem.eql(u8, keyword, "valid-after")) {
                allocator.free(consensus.valid_after);
                consensus.valid_after = try allocator.dupe(u8, line[12..]);
            } else if (std.mem.eql(u8, keyword, "fresh-until")) {
                allocator.free(consensus.fresh_until);
                consensus.fresh_until = try allocator.dupe(u8, line[12..]);
            } else if (std.mem.eql(u8, keyword, "valid-until")) {
                allocator.free(consensus.valid_until);
                consensus.valid_until = try allocator.dupe(u8, line[12..]);
            } else if (std.mem.eql(u8, keyword, "voting-delay")) {
                const voting_str = parts.next() orelse continue;
                const dist_str = parts.next() orelse continue;
                consensus.voting_delay = std.fmt.parseInt(u32, voting_str, 10) catch 0;
                consensus.dist_delay = std.fmt.parseInt(u32, dist_str, 10) catch 0;
            } else if (std.mem.eql(u8, keyword, "known-flags")) {
                var flags = std.ArrayList([]const u8).init(allocator);
                while (parts.next()) |flag| {
                    try flags.append(try allocator.dupe(u8, flag));
                }
                consensus.known_flags = try flags.toOwnedSlice();
            } else if (std.mem.eql(u8, keyword, "r")) {
                // Router status line
                const router = try parseRouterStatus(allocator, line);
                try routers.append(router);
            } else if (std.mem.eql(u8, keyword, "directory-signature")) {
                // Directory signature
                const sig = try parseDirectorySignature(allocator, line);
                try signatures.append(sig);
            }
        }

        consensus.routers = try routers.toOwnedSlice();
        consensus.directory_signature = try signatures.toOwnedSlice();

        return consensus;
    }

    // Parse router status line
    fn parseRouterStatus(allocator: std.mem.Allocator, line: []const u8) !RouterStatus {
        var parts = std.mem.splitScalar(u8, line, ' ');
        _ = parts.next(); // Skip "r"

        const nickname = parts.next() orelse return error.InvalidRouterStatus;
        _ = parts.next() orelse return error.InvalidRouterStatus; // identity_b64
        _ = parts.next() orelse return error.InvalidRouterStatus; // digest_b64
        const publication_time = parts.next() orelse return error.InvalidRouterStatus;
        const ip_address = parts.next() orelse return error.InvalidRouterStatus;
        const or_port_str = parts.next() orelse return error.InvalidRouterStatus;
        const dir_port_str = parts.next() orelse return error.InvalidRouterStatus;

        // Decode base64 identity and digest
        var identity: [20]u8 = undefined;
        var digest: [20]u8 = undefined;
        
        // Simplified base64 decoding (in real implementation, use proper base64)
        @memset(&identity, 0);
        @memset(&digest, 0);

        const or_port = std.fmt.parseInt(u16, or_port_str, 10) catch 0;
        const dir_port = std.fmt.parseInt(u16, dir_port_str, 10) catch 0;

        return RouterStatus{
            .nickname = try allocator.dupe(u8, nickname),
            .identity = identity,
            .digest = digest,
            .publication_time = try allocator.dupe(u8, publication_time),
            .ip_address = try allocator.dupe(u8, ip_address),
            .or_port = or_port,
            .dir_port = dir_port,
            .flags = RouterFlags{},
            .version = try allocator.dupe(u8, ""),
            .bandwidth = 0,
            .measured_bandwidth = null,
            .allocator = allocator,
        };
    }

    // Parse directory signature
    fn parseDirectorySignature(allocator: std.mem.Allocator, line: []const u8) !DirectorySignature {
        var parts = std.mem.splitScalar(u8, line, ' ');
        _ = parts.next(); // Skip "directory-signature"

        const algorithm = parts.next() orelse return error.InvalidSignature;
        _ = parts.next() orelse return error.InvalidSignature; // identity_str
        _ = parts.next() orelse return error.InvalidSignature; // signing_key_str

        var identity: [20]u8 = undefined;
        var signing_key_digest: [20]u8 = undefined;
        
        // Simplified parsing (in real implementation, decode hex)
        @memset(&identity, 0);
        @memset(&signing_key_digest, 0);

        return DirectorySignature{
            .algorithm = try allocator.dupe(u8, algorithm),
            .identity = identity,
            .signing_key_digest = signing_key_digest,
            .signature = try allocator.dupe(u8, ""),
            .allocator = allocator,
        };
    }

    // Create HTTP request for directory document
    pub fn createDirectoryRequest(allocator: std.mem.Allocator, doc_type: DocumentType, authority_addr: []const u8) ![]u8 {
        const path = switch (doc_type) {
            .consensus => "/tor/status-vote/current/consensus",
            .server_descriptor => "/tor/server/all",
            .extra_info => "/tor/extra/all",
            .microdescriptor => "/tor/micro/d/all",
            .bridge_descriptor => "/tor/server/authority",
        };

        return try std.fmt.allocPrint(allocator,
            "GET {s} HTTP/1.0\r\n" ++
            "Host: {s}\r\n" ++
            "User-Agent: Piranha-Tor/1.0\r\n" ++
            "Accept-Encoding: identity\r\n" ++
            "\r\n",
            .{ path, authority_addr }
        );
    }

    // Validate consensus document
    pub fn validateConsensus(consensus: *const ConsensusDocument) bool {
        // Basic validation
        if (consensus.valid_after.len == 0 or consensus.valid_until.len == 0) {
            return false;
        }

        if (consensus.routers.len == 0) {
            return false;
        }

        // Check if we have at least one directory signature
        if (consensus.directory_signature.len == 0) {
            return false;
        }

        return true;
    }

    // Extract usable routers from consensus
    pub fn extractUsableRouters(allocator: std.mem.Allocator, consensus: *const ConsensusDocument) ![]RouterStatus {
        var usable_routers = std.ArrayList(RouterStatus).init(allocator);

        for (consensus.routers) |router| {
            // Only include running and valid routers
            if (router.flags.running and router.flags.valid) {
                try usable_routers.append(router);
            }
        }

        return try usable_routers.toOwnedSlice();
    }
};

test "consensus parsing basic" {
    const allocator = testing.allocator;
    
    const sample_consensus =
        \\network-status-version 3
        \\vote-status consensus
        \\consensus-method 28
        \\valid-after 2024-01-01 00:00:00
        \\fresh-until 2024-01-01 01:00:00
        \\valid-until 2024-01-01 03:00:00
        \\voting-delay 300 300
        \\known-flags Authority BadExit Exit Fast Guard HSDir NoEdConsensus Running Stable StableUptime V2Dir Valid
        \\r TestRelay AAAAAAAAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBBBBBBBB 2024-01-01 192.168.1.1 9001 9030
        \\directory-signature sha1 CCCCCCCCCCCCCCCCCCCC DDDDDDDDDDDDDDDDDDDD
    ;

    var consensus = try TorDirectory.parseConsensus(allocator, sample_consensus);
    defer consensus.deinit();

    try testing.expectEqualStrings("2024-01-01 00:00:00", consensus.valid_after);
    try testing.expectEqualStrings("2024-01-01 01:00:00", consensus.fresh_until);
    try testing.expectEqualStrings("2024-01-01 03:00:00", consensus.valid_until);
    try testing.expectEqual(@as(u32, 300), consensus.voting_delay);
    try testing.expectEqual(@as(u32, 300), consensus.dist_delay);
    try testing.expect(consensus.routers.len == 1);
    try testing.expectEqualStrings("TestRelay", consensus.routers[0].nickname);
}

test "directory request creation" {
    const allocator = testing.allocator;
    
    const request = try TorDirectory.createDirectoryRequest(allocator, .consensus, "127.0.0.1:9030");
    defer allocator.free(request);
    
    try testing.expect(std.mem.indexOf(u8, request, "GET /tor/status-vote/current/consensus") != null);
    try testing.expect(std.mem.indexOf(u8, request, "Host: 127.0.0.1:9030") != null);
}

test "consensus validation" {
    const allocator = testing.allocator;
    
    var consensus = TorDirectory.ConsensusDocument{
        .valid_after = try allocator.dupe(u8, "2024-01-01 00:00:00"),
        .fresh_until = try allocator.dupe(u8, "2024-01-01 01:00:00"),
        .valid_until = try allocator.dupe(u8, "2024-01-01 03:00:00"),
        .voting_delay = 300,
        .dist_delay = 300,
        .client_versions = &[_][]const u8{},
        .server_versions = &[_][]const u8{},
        .known_flags = &[_][]const u8{},
        .routers = &[_]TorDirectory.RouterStatus{},
        .directory_signature = &[_]TorDirectory.DirectorySignature{},
        .allocator = allocator,
    };
    defer consensus.deinit();
    
    // Should be invalid (no routers, no signatures)
    try testing.expect(!TorDirectory.validateConsensus(&consensus));
}