# Piranha - Tor-like Network Implementation in Zig

Piranha is a Tor-like anonymity network implementation written in Zig, featuring a Directory Authority server with comprehensive cryptographic capabilities.

## Project Overview

This project implements core components of an anonymity network similar to Tor, including:
- **Directory Authority Server**: Central coordination point for network nodes
- **Cryptographic Infrastructure**: Ed25519 signatures, AES-CTR encryption, SHA-256 hashing
- **Cell-based Communication**: Fixed-size 512-byte cells for network traffic
- **Node Registration System**: Secure node registration with signature verification

## Architecture

```
src/
├── common/              # Shared cryptographic and networking utilities
│   ├── crypto.zig       # AES-CTR, SHA-256, HMAC, X25519 key exchange
│   ├── signature.zig    # Ed25519 signatures and key management
│   ├── cell.zig         # Tor-style 512-byte cell structure
│   └── net.zig          # TCP connection utilities
├── authority/           # Directory Authority server
│   ├── main.zig         # Server entry point
│   ├── server.zig       # HTTP API server with routing
│   ├── config.zig       # Configuration management
│   ├── node.zig         # Node information and registry
│   ├── directory.zig    # Directory generation and consensus
│   └── tls.zig          # TLS certificate management
└── root.zig             # Module exports
```

## Implemented Features

### Directory Authority Server
- **HTTP API Server**: Complete REST API with CORS support
- **Node Management**: In-memory node registry with persistent JSON storage
- **Cryptographic Signatures**: Ed25519 key generation, signing, and verification
- **Configuration System**: JSON-based configuration with validation

### API Endpoints
- `GET /status` - Server status and node count
- `GET /consensus` - Network consensus with node information
- `GET /consensus/signed` - Cryptographically signed consensus
- `GET /directory` - Directory with ISO8601 timestamp and signature header
- `GET /nodes` - List all registered nodes
- `POST /register` - Secure node registration with signature verification
- `POST /nodes` - Simple node registration (legacy)

### Core Cryptography
- **Ed25519 Signatures**: Complete key pair generation, signing, and verification
- **AES-CTR Encryption**: Symmetric encryption with proper IV handling
- **SHA-256 Hashing**: Cryptographic hash functions
- **HMAC**: Message authentication codes
- **X25519 Key Exchange**: Elliptic curve Diffie-Hellman

### Network Layer
- **Tor Cells**: 512-byte fixed-size cells with command types (CREATE, CREATED, RELAY, DESTROY, etc.)
- **TCP Utilities**: Connection management and I/O helpers
- **TLS Support**: Certificate generation and TLS configuration

### Security Features
- **Signature Verification**: All node registrations require valid Ed25519 signatures
- **Input Validation**: Comprehensive JSON validation and field checking
- **Base64 Encoding**: Public key encoding/decoding
- **Memory Safety**: Proper memory management and cleanup

## Quick Start

### Prerequisites
- Zig 0.13+ (tested with latest version)

### Building
```bash
zig build
```

### Running Directory Authority
```bash
zig build run-authority
```

The server will start on `localhost:8443` with the following endpoints available.

### Configuration
Configuration is loaded from `config/authority.json`:
```json
{
  "listen_addr": "0.0.0.0:8443",
  "cert_path": "/tmp/authority.crt",
  "key_path": "/tmp/authority.key", 
  "sig_key_path": "/tmp/authority-sign.ed25519"
}
```

### Testing API Endpoints
```bash
# Check server status
curl http://localhost:8443/status

# Get network directory with signature
curl -v http://localhost:8443/directory

# Register a new node (requires valid signature)
curl -X POST http://localhost:8443/register \
  -H "Content-Type: application/json" \
  -d '{
    "type": "relay",
    "nickname": "MyRelay", 
    "address": "192.168.1.100",
    "pubkey_b64": "SGVsbG8gV29ybGQgUHVibGljIEtleSAxMjM0NTY3ODkwMTIzNDU2Nzg5MA==",
    "signature": "valid_ed25519_signature_in_hex"
  }'
```

## Development

### Project Structure
- **Modular Design**: Common utilities are shared across components via Zig's module system
- **Build System**: Uses `build.zig` for proper module imports and dependency management
- **Memory Management**: Comprehensive memory safety with proper cleanup
- **Error Handling**: Robust error handling throughout the codebase

### Running Tests
```bash
zig build test
```

## TODO - Planned Features

### Relay Node Implementation
- [ ] **Relay Server**: HTTP/SOCKS proxy functionality
- [ ] **Circuit Building**: Establish encrypted circuits through multiple relays
- [ ] **Cell Processing**: Handle CREATE, EXTEND, RELAY cells
- [ ] **Traffic Routing**: Forward encrypted traffic between circuits

### Enhanced Directory Authority
- [ ] **Consensus Algorithm**: Multi-authority consensus mechanism
- [ ] **Bandwidth Measurement**: Node performance monitoring
- [ ] **Flag Assignment**: Automatic node flag assignment (Guard, Exit, Fast, Stable)
- [ ] **Network Health**: Monitoring and health checks

### Advanced Cryptography
- [ ] **Onion Routing**: Layer encryption for multi-hop circuits
- [ ] **Forward Secrecy**: Perfect forward secrecy in circuit keys
- [ ] **Hidden Services**: Service discovery and connection protocol
- [ ] **Guard Node Selection**: Intelligent guard node algorithm

### Network Features
- [ ] **Circuit Management**: Circuit creation, extension, and teardown
- [ ] **Load Balancing**: Intelligent path selection algorithms
- [ ] **Exit Policies**: Configurable exit node policies
- [ ] **Bridge Support**: Censorship-resistant bridge nodes

### Client Implementation
- [ ] **SOCKS Proxy**: Client-side SOCKS proxy server
- [ ] **Circuit Establishment**: Automated circuit building
- [ ] **Stream Multiplexing**: Multiple TCP streams over single circuit
- [ ] **DNS Resolution**: Anonymous DNS resolution through exit nodes

### Monitoring & Management
- [ ] **Metrics Collection**: Performance and usage statistics
- [ ] **Web Dashboard**: Real-time network monitoring interface
- [ ] **Logging System**: Comprehensive logging with configurable levels
- [ ] **Administrative API**: Network management endpoints

### Security Enhancements
- [ ] **Rate Limiting**: DoS protection and traffic shaping
- [ ] **Circuit Padding**: Traffic analysis resistance
- [ ] **Entry Guards**: Long-term guard node selection
- [ ] **Path Selection**: Advanced path selection algorithms

### Performance & Scalability
- [ ] **Async I/O**: Non-blocking network operations
- [ ] **Connection Pooling**: Efficient connection reuse
- [ ] **Memory Optimization**: Reduced memory footprint
- [ ] **High Throughput**: Optimized for high-traffic scenarios

## Testing & Quality Assurance

### Current Testing
- [x] **Unit Tests**: Core cryptographic functions
- [x] **Integration Tests**: HTTP API endpoints
- [x] **Manual Testing**: Full server functionality

### Planned Testing
- [ ] **Automated Test Suite**: Comprehensive test coverage
- [ ] **Load Testing**: Performance under high load
- [ ] **Security Auditing**: Cryptographic implementation review
- [ ] **Network Simulation**: Multi-node network testing

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Notice

**This is an experimental implementation for educational purposes.** Do not use this in production environments where anonymity is critical. For real anonymity needs, use the official Tor network.

## Acknowledgments

- Inspired by the Tor Project's anonymity research
- Built with the Zig programming language
- Cryptographic algorithms based on industry standards (Ed25519, AES, SHA-256)
