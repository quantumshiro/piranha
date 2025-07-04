const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

// ntor handshake constants from Tor specification
const PROTOID = "ntor-curve25519-sha256-1";
const M_EXPAND = "ntor-curve25519-sha256-1:key_expand";
const T_MAC = "ntor-curve25519-sha256-1:mac";
const T_KEY = "ntor-curve25519-sha256-1:key_extract";
const T_VERIFY = "ntor-curve25519-sha256-1:verify";

const SERVER_STR = "Server";
const CLIENT_STR = "Client";

pub const NTOR_ONIONSKIN_LEN = 84;  // CLIENT_PK(32) + NODE_ID(20) + CLIENT_EPHEMERAL_PK(32)
pub const NTOR_REPLY_LEN = 64;      // SERVER_PK(32) + AUTH(32)

pub const NtorKeyPair = struct {
    secret_key: [32]u8,
    public_key: [32]u8,

    pub fn generate() !NtorKeyPair {
        var secret_key: [32]u8 = undefined;
        crypto.random.bytes(&secret_key);
        
        const public_key = try crypto.dh.X25519.recoverPublicKey(secret_key);
        
        return NtorKeyPair{
            .secret_key = secret_key,
            .public_key = public_key,
        };
    }

    pub fn fromSecretKey(secret_key: [32]u8) !NtorKeyPair {
        const public_key = try crypto.dh.X25519.recoverPublicKey(secret_key);
        return NtorKeyPair{
            .secret_key = secret_key,
            .public_key = public_key,
        };
    }
    
    pub fn computeSharedSecret(self: NtorKeyPair, other_public_key: [32]u8) ![32]u8 {
        return crypto.dh.X25519.scalarmult(self.secret_key, other_public_key);
    }
};

pub const NtorOnionSkin = struct {
    node_id: [20]u8,           // SHA-1 hash of server's identity key
    node_key: [32]u8,          // Server's ntor public key
    ephemeral_key: [32]u8,     // Client's ephemeral public key

    pub fn serialize(self: *const NtorOnionSkin) [NTOR_ONIONSKIN_LEN]u8 {
        var result: [NTOR_ONIONSKIN_LEN]u8 = undefined;
        @memcpy(result[0..32], &self.node_key);
        @memcpy(result[32..52], &self.node_id);
        @memcpy(result[52..84], &self.ephemeral_key);
        return result;
    }

    pub fn deserialize(data: *const [NTOR_ONIONSKIN_LEN]u8) NtorOnionSkin {
        var result: NtorOnionSkin = undefined;
        @memcpy(&result.node_key, data[0..32]);
        @memcpy(&result.node_id, data[32..52]);
        @memcpy(&result.ephemeral_key, data[52..84]);
        return result;
    }
};

pub const NtorServerReply = struct {
    server_pk: [32]u8,
    auth: [32]u8,

    pub fn serialize(self: *const NtorServerReply) [NTOR_REPLY_LEN]u8 {
        var result: [NTOR_REPLY_LEN]u8 = undefined;
        @memcpy(result[0..32], &self.server_pk);
        @memcpy(result[32..64], &self.auth);
        return result;
    }

    pub fn deserialize(data: *const [NTOR_REPLY_LEN]u8) NtorServerReply {
        var result: NtorServerReply = undefined;
        @memcpy(&result.server_pk, data[0..32]);
        @memcpy(&result.auth, data[32..64]);
        return result;
    }
};

pub const NtorKeys = struct {
    forward_key: [16]u8,    // Kf - forward encryption key
    backward_key: [16]u8,   // Kb - backward encryption key
    forward_digest: [20]u8, // Df - forward digest key
    backward_digest: [20]u8, // Db - backward digest key
};

// HMAC-SHA256 helper
fn hmac_sha256(key: []const u8, message: []const u8) [32]u8 {
    var hmac = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).init(key);
    hmac.update(message);
    var result: [32]u8 = undefined;
    hmac.final(&result);
    return result;
}

// HKDF-SHA256 expand
fn hkdf_expand(prk: []const u8, info: []const u8, length: usize, output: []u8) void {
    var n: u8 = 1;
    var offset: usize = 0;
    
    while (offset < length) {
        var hmac = crypto.auth.hmac.Hmac(crypto.hash.sha2.Sha256).init(prk);
        if (offset > 0) {
            hmac.update(output[offset - 32..offset]);
        }
        hmac.update(info);
        hmac.update(&[_]u8{n});
        
        var block: [32]u8 = undefined;
        hmac.final(&block);
        
        const copy_len = @min(32, length - offset);
        @memcpy(output[offset..offset + copy_len], block[0..copy_len]);
        
        offset += copy_len;
        n += 1;
    }
}

// ntor key derivation function
fn ntor_kdf(secret_input: []const u8, key_bytes: usize, output: []u8) void {
    // Extract phase: PRK = HMAC-SHA256(salt="ntor-curve25519-sha256-1:key_extract", IKM=secret_input)
    const prk = hmac_sha256(T_KEY, secret_input);
    
    // Expand phase
    hkdf_expand(&prk, M_EXPAND, key_bytes, output);
}

// Client side: create onion skin
pub fn client_create_onion_skin(
    node_id: [20]u8,
    node_key: [32]u8,
    ephemeral_keypair: *const NtorKeyPair
) NtorOnionSkin {
    return NtorOnionSkin{
        .node_id = node_id,
        .node_key = node_key,
        .ephemeral_key = ephemeral_keypair.public_key,
    };
}

// Server side: process onion skin and create reply
pub fn server_process_onion_skin(
    onion_skin: *const NtorOnionSkin,
    server_identity_key: [32]u8,
    server_ntor_keypair: *const NtorKeyPair,
    allocator: std.mem.Allocator
) !struct { reply: NtorServerReply, keys: NtorKeys } {
    _ = allocator;
    _ = server_identity_key;
    
    // Generate ephemeral keypair for this handshake
    const server_ephemeral = try NtorKeyPair.generate();
    
    // Compute shared secrets
    const xy = try crypto.dh.X25519.scalarmult(server_ephemeral.secret_key, onion_skin.ephemeral_key);
    const xb = try crypto.dh.X25519.scalarmult(server_ntor_keypair.secret_key, onion_skin.ephemeral_key);
    
    // Build secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
    var secret_input: [32 + 32 + 20 + 32 + 32 + 32 + PROTOID.len]u8 = undefined;
    var offset: usize = 0;
    
    @memcpy(secret_input[offset..offset + 32], &xy);
    offset += 32;
    @memcpy(secret_input[offset..offset + 32], &xb);
    offset += 32;
    @memcpy(secret_input[offset..offset + 20], &onion_skin.node_id);
    offset += 20;
    @memcpy(secret_input[offset..offset + 32], &server_ntor_keypair.public_key);
    offset += 32;
    @memcpy(secret_input[offset..offset + 32], &onion_skin.ephemeral_key);
    offset += 32;
    @memcpy(secret_input[offset..offset + 32], &server_ephemeral.public_key);
    offset += 32;
    @memcpy(secret_input[offset..offset + PROTOID.len], PROTOID);
    
    // Derive keys: KEY_SEED = H(secret_input, t_key)
    var key_material: [72]u8 = undefined; // 16 + 16 + 20 + 20 = 72 bytes
    ntor_kdf(&secret_input, 72, &key_material);
    
    var keys: NtorKeys = undefined;
    @memcpy(&keys.forward_key, key_material[0..16]);
    @memcpy(&keys.backward_key, key_material[16..32]);
    @memcpy(&keys.forward_digest, key_material[32..52]);
    @memcpy(&keys.backward_digest, key_material[52..72]);
    
    // Compute auth = H(secret_input, t_mac)
    const auth = hmac_sha256(T_MAC, &secret_input);
    
    const reply = NtorServerReply{
        .server_pk = server_ephemeral.public_key,
        .auth = auth,
    };
    
    return .{ .reply = reply, .keys = keys };
}

// Client side: process server reply and derive keys
pub fn client_process_reply(
    reply: *const NtorServerReply,
    node_id: [20]u8,
    node_key: [32]u8,
    ephemeral_keypair: *const NtorKeyPair,
    allocator: std.mem.Allocator
) !NtorKeys {
    _ = allocator;
    
    // Compute shared secrets
    const xy = try crypto.dh.X25519.scalarmult(ephemeral_keypair.secret_key, reply.server_pk);
    const xb = try crypto.dh.X25519.scalarmult(ephemeral_keypair.secret_key, node_key);
    
    // Build secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
    var secret_input: [32 + 32 + 20 + 32 + 32 + 32 + PROTOID.len]u8 = undefined;
    var offset: usize = 0;
    
    @memcpy(secret_input[offset..offset + 32], &xy);
    offset += 32;
    @memcpy(secret_input[offset..offset + 32], &xb);
    offset += 32;
    @memcpy(secret_input[offset..offset + 20], &node_id);
    offset += 20;
    @memcpy(secret_input[offset..offset + 32], &node_key);
    offset += 32;
    @memcpy(secret_input[offset..offset + 32], &ephemeral_keypair.public_key);
    offset += 32;
    @memcpy(secret_input[offset..offset + 32], &reply.server_pk);
    offset += 32;
    @memcpy(secret_input[offset..offset + PROTOID.len], PROTOID);
    
    // Verify auth
    const expected_auth = hmac_sha256(T_MAC, &secret_input);
    if (!crypto.utils.timingSafeEql([32]u8, expected_auth, reply.auth)) {
        return error.AuthenticationFailed;
    }
    
    // Derive keys
    var key_material: [72]u8 = undefined;
    ntor_kdf(&secret_input, 72, &key_material);
    
    var keys: NtorKeys = undefined;
    @memcpy(&keys.forward_key, key_material[0..16]);
    @memcpy(&keys.backward_key, key_material[16..32]);
    @memcpy(&keys.forward_digest, key_material[32..52]);
    @memcpy(&keys.backward_digest, key_material[52..72]);
    
    return keys;
}

test "ntor handshake full flow" {
    const allocator = testing.allocator;
    
    // Setup
    const node_id = [_]u8{0x01} ** 20;
    const server_identity_key = [_]u8{0x02} ** 32;
    const server_ntor_keypair = try NtorKeyPair.generate();
    const client_ephemeral = try NtorKeyPair.generate();
    
    // Client creates onion skin
    const onion_skin = client_create_onion_skin(node_id, server_ntor_keypair.public_key, &client_ephemeral);
    
    // Server processes onion skin
    const server_result = try server_process_onion_skin(&onion_skin, server_identity_key, &server_ntor_keypair, allocator);
    
    // Client processes reply
    const client_keys = try client_process_reply(&server_result.reply, node_id, server_ntor_keypair.public_key, &client_ephemeral, allocator);
    
    // Verify keys match
    try testing.expectEqualSlices(u8, &server_result.keys.forward_key, &client_keys.forward_key);
    try testing.expectEqualSlices(u8, &server_result.keys.backward_key, &client_keys.backward_key);
    try testing.expectEqualSlices(u8, &server_result.keys.forward_digest, &client_keys.forward_digest);
    try testing.expectEqualSlices(u8, &server_result.keys.backward_digest, &client_keys.backward_digest);
}

test "ntor onion skin serialization" {
    const onion_skin = NtorOnionSkin{
        .node_id = [_]u8{0x01} ** 20,
        .node_key = [_]u8{0x02} ** 32,
        .ephemeral_key = [_]u8{0x03} ** 32,
    };
    
    const serialized = onion_skin.serialize();
    const deserialized = NtorOnionSkin.deserialize(&serialized);
    
    try testing.expectEqualSlices(u8, &onion_skin.node_id, &deserialized.node_id);
    try testing.expectEqualSlices(u8, &onion_skin.node_key, &deserialized.node_key);
    try testing.expectEqualSlices(u8, &onion_skin.ephemeral_key, &deserialized.ephemeral_key);
}

test "ntor server reply serialization" {
    const reply = NtorServerReply{
        .server_pk = [_]u8{0x04} ** 32,
        .auth = [_]u8{0x05} ** 32,
    };
    
    const serialized = reply.serialize();
    const deserialized = NtorServerReply.deserialize(&serialized);
    
    try testing.expectEqualSlices(u8, &reply.server_pk, &deserialized.server_pk);
    try testing.expectEqualSlices(u8, &reply.auth, &deserialized.auth);
}