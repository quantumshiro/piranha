const std = @import("std");
const testing = std.testing;
const crypto = std.crypto;

pub const KEY_SIZE = 32;
pub const IV_SIZE = 16;
pub const HASH_SIZE = 32;

pub const X25519KeyPair = struct {
    secret_key: [32]u8,
    public_key: [32]u8,

    pub fn generate() !X25519KeyPair {
        var secret_key: [32]u8 = undefined;
        crypto.random.bytes(&secret_key);
        
        const public_key = try crypto.dh.X25519.recoverPublicKey(secret_key);
        
        return X25519KeyPair{
            .secret_key = secret_key,
            .public_key = public_key,
        };
    }

    pub fn computeSharedSecret(self: *const X25519KeyPair, other_public_key: [32]u8) ![32]u8 {
        return try crypto.dh.X25519.scalarmult(self.secret_key, other_public_key);
    }
};

pub const AesCtr = struct {
    key: [KEY_SIZE]u8,
    
    pub fn init(key: [KEY_SIZE]u8) AesCtr {
        return AesCtr{ .key = key };
    }
    
    pub fn encrypt(self: *const AesCtr, plaintext: []const u8, iv: [IV_SIZE]u8, ciphertext: []u8) !void {
        if (ciphertext.len < plaintext.len) {
            return error.BufferTooSmall;
        }
        
        const aes = crypto.core.aes.Aes256.initEnc(self.key);
        var counter_block: [16]u8 = iv;
        var offset: usize = 0;
        
        while (offset < plaintext.len) {
            var keystream: [16]u8 = undefined;
            aes.encrypt(&keystream, &counter_block);
            
            const chunk_size = @min(16, plaintext.len - offset);
            for (0..chunk_size) |i| {
                ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
            }
            
            offset += chunk_size;
            incrementCounter(&counter_block);
        }
    }
    
    pub fn decrypt(self: *const AesCtr, ciphertext: []const u8, iv: [IV_SIZE]u8, plaintext: []u8) !void {
        try self.encrypt(ciphertext, iv, plaintext);
    }
    
    fn incrementCounter(counter: *[16]u8) void {
        var i: usize = 15;
        while (true) {
            counter[i] +%= 1;
            if (counter[i] != 0) break;
            if (i == 0) break;
            i -= 1;
        }
    }
};

pub const Sha256 = struct {
    pub fn hash(data: []const u8) [HASH_SIZE]u8 {
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        hasher.update(data);
        return hasher.finalResult();
    }
    
    pub fn hashMultiple(data_parts: []const []const u8) [HASH_SIZE]u8 {
        var hasher = crypto.hash.sha2.Sha256.init(.{});
        for (data_parts) |part| {
            hasher.update(part);
        }
        return hasher.finalResult();
    }
};

pub const Hmac = struct {
    pub fn compute(key: []const u8, message: []const u8) [HASH_SIZE]u8 {
        var hmac = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).init(key);
        hmac.update(message);
        var result: [HASH_SIZE]u8 = undefined;
        hmac.final(&result);
        return result;
    }
    
    pub fn verify(key: []const u8, message: []const u8, expected_mac: [HASH_SIZE]u8) bool {
        const computed_mac = compute(key, message);
        return crypto.utils.timingSafeEql([HASH_SIZE]u8, computed_mac, expected_mac);
    }
};

pub fn deriveKeys(shared_secret: [32]u8, info: []const u8) struct {
    encryption_key: [KEY_SIZE]u8,
    mac_key: [KEY_SIZE]u8,
} {
    const salt = [_]u8{0} ** 32;
    var prk: [32]u8 = undefined;
    
    var hmac = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).init(&salt);
    hmac.update(&shared_secret);
    hmac.final(&prk);
    
    var encryption_key: [KEY_SIZE]u8 = undefined;
    var mac_key: [KEY_SIZE]u8 = undefined;
    
    var hmac1 = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).init(&prk);
    hmac1.update(info);
    hmac1.update(&[_]u8{1});
    hmac1.final(&encryption_key);
    
    var hmac2 = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).init(&prk);
    hmac2.update(&encryption_key);
    hmac2.update(info);
    hmac2.update(&[_]u8{2});
    hmac2.final(&mac_key);
    
    return .{
        .encryption_key = encryption_key,
        .mac_key = mac_key,
    };
}

test "X25519 key generation and exchange" {
    const alice = try X25519KeyPair.generate();
    const bob = try X25519KeyPair.generate();
    
    const alice_shared = try alice.computeSharedSecret(bob.public_key);
    const bob_shared = try bob.computeSharedSecret(alice.public_key);
    
    try testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

test "AES-CTR encryption and decryption" {
    const key = [_]u8{0x01} ** KEY_SIZE;
    const iv = [_]u8{0x02} ** IV_SIZE;
    const plaintext = "Hello, Tor network!";
    
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;
    
    const aes = AesCtr.init(key);
    try aes.encrypt(plaintext, iv, &ciphertext);
    try aes.decrypt(&ciphertext, iv, &decrypted);
    
    try testing.expectEqualSlices(u8, plaintext, &decrypted);
    try testing.expect(!std.mem.eql(u8, plaintext, &ciphertext));
}

test "SHA-256 hashing" {
    const data = "test data";
    const hash1 = Sha256.hash(data);
    const hash2 = Sha256.hash(data);
    
    try testing.expectEqualSlices(u8, &hash1, &hash2);
    
    const different_data = "different data";
    const hash3 = Sha256.hash(different_data);
    try testing.expect(!std.mem.eql(u8, &hash1, &hash3));
}

test "HMAC computation and verification" {
    const key = "secret key";
    const message = "important message";
    
    const mac = Hmac.compute(key, message);
    try testing.expect(Hmac.verify(key, message, mac));
    
    const wrong_key = "wrong key";
    try testing.expect(!Hmac.verify(wrong_key, message, mac));
    
    const wrong_message = "wrong message";
    try testing.expect(!Hmac.verify(key, wrong_message, mac));
}

test "Key derivation" {
    const shared_secret = [_]u8{0x42} ** 32;
    const info = "tor-key-derivation";
    
    const keys = deriveKeys(shared_secret, info);
    
    try testing.expect(!std.mem.eql(u8, &keys.encryption_key, &keys.mac_key));
    try testing.expect(!std.mem.eql(u8, &keys.encryption_key, &shared_secret));
    try testing.expect(!std.mem.eql(u8, &keys.mac_key, &shared_secret));
}

test "Full encryption workflow" {
    const alice = try X25519KeyPair.generate();
    const bob = try X25519KeyPair.generate();
    
    const shared_secret = try alice.computeSharedSecret(bob.public_key);
    const keys = deriveKeys(shared_secret, "test-session");
    
    const plaintext = "This is a secret message for the Tor network!";
    const iv = [_]u8{0x12, 0x34, 0x56, 0x78} ++ [_]u8{0} ** 12;
    
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;
    
    const aes = AesCtr.init(keys.encryption_key);
    try aes.encrypt(plaintext, iv, &ciphertext);
    
    const mac = Hmac.compute(&keys.mac_key, &ciphertext);
    try testing.expect(Hmac.verify(&keys.mac_key, &ciphertext, mac));
    
    try aes.decrypt(&ciphertext, iv, &decrypted);
    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}