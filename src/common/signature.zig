const std = @import("std");
const testing = std.testing;
const crypto = std.crypto;

pub const SIGNATURE_SIZE = 64;
pub const PUBLIC_KEY_SIZE = 32;
pub const PRIVATE_KEY_SIZE = 32;
pub const SEED_SIZE = 32;

pub const SignatureError = error{
    InvalidKeyFormat,
    InvalidSignature,
    FileNotFound,
    InvalidKeySize,
    InvalidHexEncoding,
};

pub const Ed25519KeyPair = struct {
    private_key: [PRIVATE_KEY_SIZE]u8,
    public_key: [PUBLIC_KEY_SIZE]u8,

    pub fn generate() Ed25519KeyPair {
        var seed: [SEED_SIZE]u8 = undefined;
        crypto.random.bytes(&seed);
        return fromSeed(seed);
    }

    pub fn fromSeed(seed: [SEED_SIZE]u8) Ed25519KeyPair {
        // Simple derivation - mock implementation for development
        const private_key = seed;
        var public_key: [PUBLIC_KEY_SIZE]u8 = undefined;
        
        // Derive public key from private key (mock)
        for (0..PUBLIC_KEY_SIZE) |i| {
            public_key[i] = private_key[i] ^ 0xFF;
        }
        
        return Ed25519KeyPair{
            .private_key = private_key,
            .public_key = public_key,
        };
    }

    pub fn fromPrivateKey(private_key: [PRIVATE_KEY_SIZE]u8) Ed25519KeyPair {
        return fromSeed(private_key);
    }

    pub fn sign(self: *const Ed25519KeyPair, message: []const u8) [SIGNATURE_SIZE]u8 {
        // Simple mock signature for testing - in production use proper Ed25519
        var signature: [SIGNATURE_SIZE]u8 = undefined;
        
        // Create deterministic "signature" based on message and private key
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.private_key);
        hasher.update(message);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        
        @memcpy(signature[0..32], &hash);
        @memcpy(signature[32..64], &self.private_key);
        
        return signature;
    }

    pub fn verify(_: [PUBLIC_KEY_SIZE]u8, message: []const u8, signature: [SIGNATURE_SIZE]u8) bool {
        // Mock verification - in production use proper Ed25519
        const private_key = signature[32..64];
        
        // Reconstruct the expected signature
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(private_key);
        hasher.update(message);
        var expected_hash: [32]u8 = undefined;
        hasher.final(&expected_hash);
        
        // Check if first 32 bytes match the hash
        return std.mem.eql(u8, signature[0..32], &expected_hash);
    }

    pub fn toHex(self: *const Ed25519KeyPair, allocator: std.mem.Allocator) !struct {
        private_hex: []u8,
        public_hex: []u8,
    } {
        const private_hex = try allocator.alloc(u8, PRIVATE_KEY_SIZE * 2);
        const public_hex = try allocator.alloc(u8, PUBLIC_KEY_SIZE * 2);
        
        _ = try std.fmt.bufPrint(private_hex, "{x}", .{std.fmt.fmtSliceHexLower(&self.private_key)});
        _ = try std.fmt.bufPrint(public_hex, "{x}", .{std.fmt.fmtSliceHexLower(&self.public_key)});
        
        return .{
            .private_hex = private_hex,
            .public_hex = public_hex,
        };
    }
};

pub const SignatureManager = struct {
    key_pair: ?Ed25519KeyPair,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) SignatureManager {
        return SignatureManager{
            .key_pair = null,
            .allocator = allocator,
        };
    }

    pub fn loadFromFile(self: *SignatureManager, file_path: []const u8) !void {
        const file = std.fs.cwd().openFile(file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return SignatureError.FileNotFound,
            else => return err,
        };
        defer file.close();

        const file_size = try file.getEndPos();
        if (file_size < PRIVATE_KEY_SIZE * 2) return SignatureError.InvalidKeySize;

        const contents = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(contents);
        _ = try file.readAll(contents);

        // Remove whitespace
        var cleaned = std.ArrayList(u8).init(self.allocator);
        defer cleaned.deinit();
        
        for (contents) |c| {
            if (!std.ascii.isWhitespace(c)) {
                try cleaned.append(c);
            }
        }

        if (cleaned.items.len < PRIVATE_KEY_SIZE * 2) return SignatureError.InvalidKeySize;

        var private_key: [PRIVATE_KEY_SIZE]u8 = undefined;
        const hex_data = cleaned.items[0..PRIVATE_KEY_SIZE * 2];
        
        for (0..PRIVATE_KEY_SIZE) |i| {
            const hex_byte = hex_data[i * 2..i * 2 + 2];
            private_key[i] = std.fmt.parseInt(u8, hex_byte, 16) catch return SignatureError.InvalidHexEncoding;
        }

        self.key_pair = Ed25519KeyPair.fromPrivateKey(private_key);
    }

    pub fn loadFromHex(self: *SignatureManager, hex_private_key: []const u8) !void {
        if (hex_private_key.len != PRIVATE_KEY_SIZE * 2) return SignatureError.InvalidKeySize;

        var private_key: [PRIVATE_KEY_SIZE]u8 = undefined;
        for (0..PRIVATE_KEY_SIZE) |i| {
            const hex_byte = hex_private_key[i * 2..i * 2 + 2];
            private_key[i] = std.fmt.parseInt(u8, hex_byte, 16) catch return SignatureError.InvalidHexEncoding;
        }

        self.key_pair = Ed25519KeyPair.fromPrivateKey(private_key);
    }

    pub fn generateNew(self: *SignatureManager) void {
        self.key_pair = Ed25519KeyPair.generate();
    }

    pub fn signData(self: *const SignatureManager, data: []const u8) ![SIGNATURE_SIZE]u8 {
        if (self.key_pair == null) return error.NoKeyLoaded;
        return self.key_pair.?.sign(data);
    }

    pub fn getPublicKey(self: *const SignatureManager) ![PUBLIC_KEY_SIZE]u8 {
        if (self.key_pair == null) return error.NoKeyLoaded;
        return self.key_pair.?.public_key;
    }

    pub fn saveToFile(self: *const SignatureManager, file_path: []const u8) !void {
        if (self.key_pair == null) return error.NoKeyLoaded;

        const hex_keys = try self.key_pair.?.toHex(self.allocator);
        defer self.allocator.free(hex_keys.private_hex);
        defer self.allocator.free(hex_keys.public_hex);

        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        try file.writeAll(hex_keys.private_hex);
        try file.writeAll("\n");
    }
};

pub fn signatureToHex(allocator: std.mem.Allocator, signature: [SIGNATURE_SIZE]u8) ![]u8 {
    const hex_sig = try allocator.alloc(u8, SIGNATURE_SIZE * 2);
    _ = try std.fmt.bufPrint(hex_sig, "{x}", .{std.fmt.fmtSliceHexLower(&signature)});
    return hex_sig;
}

pub fn hexToSignature(hex_sig: []const u8) ![SIGNATURE_SIZE]u8 {
    if (hex_sig.len != SIGNATURE_SIZE * 2) return SignatureError.InvalidHexEncoding;

    var signature: [SIGNATURE_SIZE]u8 = undefined;
    for (0..SIGNATURE_SIZE) |i| {
        const hex_byte = hex_sig[i * 2..i * 2 + 2];
        signature[i] = std.fmt.parseInt(u8, hex_byte, 16) catch return SignatureError.InvalidHexEncoding;
    }
    return signature;
}

pub fn verifySignature(public_key: [PUBLIC_KEY_SIZE]u8, message: []const u8, signature: [SIGNATURE_SIZE]u8) bool {
    return Ed25519KeyPair.verify(public_key, message, signature);
}

test "Ed25519 key generation and signing" {
    const allocator = testing.allocator;
    
    const key_pair = Ed25519KeyPair.generate();
    const message = "Test message for signing";
    
    const signature = key_pair.sign(message);
    const is_valid = Ed25519KeyPair.verify(key_pair.public_key, message, signature);
    
    try testing.expect(is_valid);
    
    const wrong_message = "Wrong message";
    const is_invalid = Ed25519KeyPair.verify(key_pair.public_key, wrong_message, signature);
    try testing.expect(!is_invalid);
    
    const hex_keys = try key_pair.toHex(allocator);
    defer allocator.free(hex_keys.private_hex);
    defer allocator.free(hex_keys.public_hex);
    
    try testing.expectEqual(@as(usize, PRIVATE_KEY_SIZE * 2), hex_keys.private_hex.len);
    try testing.expectEqual(@as(usize, PUBLIC_KEY_SIZE * 2), hex_keys.public_hex.len);
}

test "SignatureManager operations" {
    const allocator = testing.allocator;
    
    var manager = SignatureManager.init(allocator);
    
    manager.generateNew();
    
    const message = "Directory consensus data";
    const signature = try manager.signData(message);
    const public_key = try manager.getPublicKey();
    
    const is_valid = verifySignature(public_key, message, signature);
    try testing.expect(is_valid);
}

test "Hex encoding and decoding" {
    const allocator = testing.allocator;
    
    const key_pair = Ed25519KeyPair.generate();
    const message = "Test data";
    const signature = key_pair.sign(message);
    
    const hex_sig = try signatureToHex(allocator, signature);
    defer allocator.free(hex_sig);
    
    const decoded_sig = try hexToSignature(hex_sig);
    
    try testing.expectEqualSlices(u8, &signature, &decoded_sig);
}

test "Key loading from hex" {
    const allocator = testing.allocator;
    
    var manager1 = SignatureManager.init(allocator);
    manager1.generateNew();
    
    const hex_keys = try manager1.key_pair.?.toHex(allocator);
    defer allocator.free(hex_keys.private_hex);
    defer allocator.free(hex_keys.public_hex);
    
    var manager2 = SignatureManager.init(allocator);
    try manager2.loadFromHex(hex_keys.private_hex);
    
    const public_key1 = try manager1.getPublicKey();
    const public_key2 = try manager2.getPublicKey();
    
    try testing.expectEqualSlices(u8, &public_key1, &public_key2);
    
    const message = "Test message";
    const sig1 = try manager1.signData(message);
    const sig2 = try manager2.signData(message);
    
    try testing.expect(verifySignature(public_key1, message, sig1));
    try testing.expect(verifySignature(public_key2, message, sig2));
}