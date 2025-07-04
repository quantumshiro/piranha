const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

// Tor protocol cryptographic functions
pub const TorCrypto = struct {
    // AES-CTR encryption/decryption for Tor relay cells
    pub fn aes_ctr_encrypt(data: []const u8, key: [16]u8, iv: [16]u8, allocator: std.mem.Allocator) ![]u8 {
        var result = try allocator.alloc(u8, data.len);
        
        // Use AES-128-CTR
        var ctx = crypto.core.aes.Aes128.initEnc(key);
        var counter = iv;
        
        var offset: usize = 0;
        while (offset < data.len) {
            // Encrypt counter to get keystream
            var keystream: [16]u8 = undefined;
            ctx.encrypt(&keystream, &counter);
            
            // XOR with data
            const chunk_size = @min(16, data.len - offset);
            for (0..chunk_size) |i| {
                result[offset + i] = data[offset + i] ^ keystream[i];
            }
            
            // Increment counter
            incrementCounter(&counter);
            offset += chunk_size;
        }
        
        return result;
    }
    
    pub fn aes_ctr_decrypt(data: []const u8, key: [16]u8, iv: [16]u8, allocator: std.mem.Allocator) ![]u8 {
        // AES-CTR is symmetric, so decryption is the same as encryption
        return aes_ctr_encrypt(data, key, iv, allocator);
    }
    
    // Tor uses a specific key derivation for relay cells
    pub fn deriveRelayKeys(shared_secret: [32]u8) struct {
        forward_key: [16]u8,
        backward_key: [16]u8,
        forward_digest_key: [20]u8,
        backward_digest_key: [20]u8,
    } {
        var result: @TypeOf(.{
            .forward_key = [_]u8{0} ** 16,
            .backward_key = [_]u8{0} ** 16,
            .forward_digest_key = [_]u8{0} ** 20,
            .backward_digest_key = [_]u8{0} ** 20,
        }) = undefined;
        
        result.forward_key = [_]u8{0} ** 16;
        result.backward_key = [_]u8{0} ** 16;
        result.forward_digest_key = [_]u8{0} ** 20;
        result.backward_digest_key = [_]u8{0} ** 20;
        
        // Simplified key derivation (real Tor uses HKDF)
        // Forward key: first 16 bytes of shared secret
        for (0..16) |i| {
            result.forward_key[i] = shared_secret[i];
        }
        
        // Backward key: next 16 bytes of shared secret  
        for (0..16) |i| {
            result.backward_key[i] = shared_secret[16 + i];
        }
        
        // Digest keys: derived from shared secret using SHA-1
        var hasher = crypto.hash.Sha1.init(.{});
        hasher.update(&shared_secret);
        hasher.update("forward");
        hasher.final(&result.forward_digest_key);
        
        hasher = crypto.hash.Sha1.init(.{});
        hasher.update(&shared_secret);
        hasher.update("backward");
        hasher.final(&result.backward_digest_key);
        
        return result;
    }
    
    // Compute digest for relay cell integrity
    pub fn computeDigest(data: []const u8, digest_key: [20]u8) [4]u8 {
        var hasher = crypto.hash.Sha1.init(.{});
        hasher.update(&digest_key);
        hasher.update(data);
        
        var full_digest: [20]u8 = undefined;
        hasher.final(&full_digest);
        
        // Return first 4 bytes as digest
        var result: [4]u8 = undefined;
        for (0..4) |i| {
            result[i] = full_digest[i];
        }
        return result;
    }
    
    // Increment AES-CTR counter
    fn incrementCounter(counter: *[16]u8) void {
        var carry: u16 = 1;
        var i: usize = 15;
        while (true) {
            carry += counter[i];
            counter[i] = @intCast(carry & 0xFF);
            carry >>= 8;
            if (carry == 0 or i == 0) break;
            if (i > 0) i -= 1 else break;
        }
    }
};

// Tor-specific relay cell encryption
pub const RelayEncryption = struct {
    keys: @TypeOf(TorCrypto.deriveRelayKeys([_]u8{0} ** 32)),
    forward_counter: [16]u8,
    backward_counter: [16]u8,
    
    pub fn init(shared_secret: [32]u8) RelayEncryption {
        return RelayEncryption{
            .keys = TorCrypto.deriveRelayKeys(shared_secret),
            .forward_counter = [_]u8{0} ** 16,
            .backward_counter = [_]u8{0} ** 16,
        };
    }
    
    pub fn encryptForward(self: *RelayEncryption, data: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const encrypted = try TorCrypto.aes_ctr_encrypt(data, self.keys.forward_key, self.forward_counter, allocator);
        TorCrypto.incrementCounter(&self.forward_counter);
        return encrypted;
    }
    
    pub fn decryptBackward(self: *RelayEncryption, data: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const decrypted = try TorCrypto.aes_ctr_decrypt(data, self.keys.backward_key, self.backward_counter, allocator);
        TorCrypto.incrementCounter(&self.backward_counter);
        return decrypted;
    }
    
    pub fn computeForwardDigest(self: *const RelayEncryption, data: []const u8) [4]u8 {
        return TorCrypto.computeDigest(data, self.keys.forward_digest_key);
    }
    
    pub fn computeBackwardDigest(self: *const RelayEncryption, data: []const u8) [4]u8 {
        return TorCrypto.computeDigest(data, self.keys.backward_digest_key);
    }
};

// Onion encryption for multiple hops
pub const OnionEncryption = struct {
    hops: std.ArrayList(RelayEncryption),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) OnionEncryption {
        return OnionEncryption{
            .hops = std.ArrayList(RelayEncryption).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *OnionEncryption) void {
        self.hops.deinit();
    }
    
    pub fn addHop(self: *OnionEncryption, shared_secret: [32]u8) !void {
        const relay_enc = RelayEncryption.init(shared_secret);
        try self.hops.append(relay_enc);
    }
    
    // Encrypt data through all hops (reverse order for onion encryption)
    pub fn encryptOnion(self: *OnionEncryption, data: []const u8) ![]u8 {
        var current_data = try self.allocator.dupe(u8, data);
        
        // Encrypt in reverse order (last hop first)
        var i = self.hops.items.len;
        while (i > 0) {
            i -= 1;
            const encrypted = try self.hops.items[i].encryptForward(current_data, self.allocator);
            self.allocator.free(current_data);
            current_data = encrypted;
        }
        
        return current_data;
    }
    
    // Decrypt data from all hops (forward order)
    pub fn decryptOnion(self: *OnionEncryption, data: []const u8, hop_count: usize) ![]u8 {
        var current_data = try self.allocator.dupe(u8, data);
        
        // Decrypt in forward order
        for (0..@min(hop_count, self.hops.items.len)) |i| {
            const decrypted = try self.hops.items[i].decryptBackward(current_data, self.allocator);
            self.allocator.free(current_data);
            current_data = decrypted;
        }
        
        return current_data;
    }
};

test "AES-CTR encryption/decryption" {
    const allocator = testing.allocator;
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 16;
    const plaintext = "Hello, Tor network!";
    
    const encrypted = try TorCrypto.aes_ctr_encrypt(plaintext, key, iv, allocator);
    defer allocator.free(encrypted);
    
    const decrypted = try TorCrypto.aes_ctr_decrypt(encrypted, key, iv, allocator);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(plaintext, decrypted);
}

test "key derivation" {
    const shared_secret = [_]u8{0x42} ** 32;
    const keys = TorCrypto.deriveRelayKeys(shared_secret);
    
    // Keys should be different
    try testing.expect(!std.mem.eql(u8, &keys.forward_key, &keys.backward_key));
    try testing.expect(!std.mem.eql(u8, &keys.forward_digest_key, &keys.backward_digest_key));
}

test "relay encryption" {
    const allocator = testing.allocator;
    const shared_secret = [_]u8{0x33} ** 32;
    var relay_enc = RelayEncryption.init(shared_secret);
    
    const plaintext = "Secret relay message";
    
    const encrypted = try relay_enc.encryptForward(plaintext, allocator);
    defer allocator.free(encrypted);
    
    // Reset counter for decryption test
    relay_enc.backward_counter = [_]u8{0} ** 16;
    const decrypted = try relay_enc.decryptBackward(encrypted, allocator);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(plaintext, decrypted);
}

test "onion encryption" {
    const allocator = testing.allocator;
    var onion = OnionEncryption.init(allocator);
    defer onion.deinit();
    
    // Add 3 hops
    try onion.addHop([_]u8{0x11} ** 32);
    try onion.addHop([_]u8{0x22} ** 32);
    try onion.addHop([_]u8{0x33} ** 32);
    
    const plaintext = "Multi-hop encrypted message";
    
    const encrypted = try onion.encryptOnion(plaintext);
    defer allocator.free(encrypted);
    
    // Reset counters for decryption
    for (onion.hops.items) |*hop| {
        hop.backward_counter = [_]u8{0} ** 16;
    }
    
    const decrypted = try onion.decryptOnion(encrypted, 3);
    defer allocator.free(decrypted);
    
    try testing.expectEqualStrings(plaintext, decrypted);
}