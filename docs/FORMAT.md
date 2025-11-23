# File Format Specification

## Overview

This document describes the encrypted file format used by go-fileencrypt. The format is designed for:
- **Streaming encryption/decryption** of arbitrarily large files
- **Forward compatibility** with future cryptographic algorithms
- **Integrity protection** with authenticated encryption
- **Efficient chunked processing** for memory-constrained environments

## Format Version

**Current Version**: 1.0  
**Algorithm**: AES-256-GCM (Algorithm ID: 1)

## File Structure

```
┌─────────────────────────────────────────────────┐
│                  File Header                     │
│  [3 bytes: "GFE"][1 byte: ver][12 bytes: nonce] │
│  [8 bytes: file size]                           │
├─────────────────────────────────────────────────┤
│                   Chunk 1                        │
│  [4 bytes: chunk size][encrypted data + tag]    │
├─────────────────────────────────────────────────┤
│                   Chunk 2                        │
│  [4 bytes: chunk size][encrypted data + tag]    │
├─────────────────────────────────────────────────┤
│                     ...                          │
├─────────────────────────────────────────────────┤
│                   Chunk N                        │
│  [4 bytes: chunk size][encrypted data + tag]    │
└─────────────────────────────────────────────────┘
```

## Header Format

### Magic Bytes (3 bytes)

- **Offset**: 0
- **Value**: "GFE" (Go File Encrypt)
- **Purpose**: Identifies the file format

### Version (1 byte)

- **Offset**: 3
- **Value**: 0x01
- **Purpose**: File format version number

### Nonce (12 bytes)

- **Offset**: 4
- **Length**: 12 bytes (96 bits)
- **Encoding**: Binary (big-endian)
- **Purpose**: Base nonce for GCM encryption
- **Generation**: Cryptographically random per file
- **Usage**: Incremented for each chunk (nonce_chunk = nonce_base + chunk_index)

**Security Note**: The nonce MUST be unique per encryption operation. Never reuse a nonce with the same key.

### File Size (8 bytes)

- **Offset**: 16
- **Length**: 8 bytes (64 bits)
- **Encoding**: Binary (big-endian, unsigned)
- **Purpose**: Original plaintext file size in bytes
- **Range**: 0 to 2^64-1 bytes (~18.4 exabytes)
- **Security**: Authenticated to prevent truncation attacks

## Chunk Format

Each chunk consists of:

### Chunk Size (4 bytes)

- **Length**: 4 bytes (32 bits)
- **Encoding**: Binary (big-endian, unsigned)
- **Purpose**: Size of encrypted chunk data (including GCM tag)
- **Range**: 17 bytes (1 byte plaintext + 16 byte tag) to 10,485,776 bytes (10MB + 16 bytes)
- **Validation**: Must be ≥17 and ≤10,485,776

### Encrypted Data + Tag

- **Length**: Variable (specified by chunk size field)
- **Composition**: [Encrypted plaintext][16-byte GCM authentication tag]
- **Plaintext Chunk Size**: Default 1MB, configurable (1 byte to 10MB)
- **GCM Tag**: 128 bits (16 bytes) appended by GCM mode
- **Nonce**: Base nonce + chunk index (zero-indexed)

## Algorithm ID (Reserved)

**Note**: Algorithm ID is reserved for future use but not currently stored in files.

Future versions may prepend an algorithm identifier:

```
[1 byte: algorithm ID][12 bytes: nonce][8 bytes: size][chunks...]
```

**Reserved Algorithm IDs:**
- `0x01`: AES-256-GCM (current default)
- `0x02`: ChaCha20-Poly1305 (reserved)
- `0x03`: ML-KEM Hybrid Post-Quantum (reserved)
- `0x04-0xFF`: Reserved for future use

When algorithm IDs are implemented, the library will remain backward compatible with version 1.0 files (no algorithm ID byte).

## Encryption Process

1. **Generate Base Nonce**: 12 random bytes using `crypto/rand`
2. **Write Header**: Write nonce and original file size
3. **Process Chunks**:
   - Read plaintext chunk (up to configured chunk size)
   - Compute chunk nonce: `base_nonce + chunk_index`
   - Encrypt with AES-256-GCM (nonce, plaintext) → ciphertext + tag
   - Write chunk size (4 bytes) + encrypted data + tag

## Decryption Process

1. **Read Header**: Extract nonce and original file size
2. **Process Chunks**:
   - Read chunk size (4 bytes)
   - Read encrypted data + tag (chunk size bytes)
   - Compute chunk nonce: `base_nonce + chunk_index`
   - Decrypt with AES-256-GCM (nonce, ciphertext + tag) → plaintext
   - Verify authentication tag
   - Write plaintext

## Security Properties

### Authentication

- **File Integrity**: File size is authenticated in header
- **Chunk Integrity**: Each chunk has a GCM authentication tag
- **Tamper Detection**: Any modification triggers authentication failure

### Nonce Management

- **Uniqueness**: Base nonce is randomly generated per file
- **No Reuse**: Each chunk uses a unique nonce (base + index)
- **Overflow Protection**: Nonce counter is 96 bits (supports 2^96 chunks)

### Chunk Size Validation

- **Minimum**: 17 bytes (1 byte plaintext + 16 byte GCM tag)
- **Maximum**: 10,485,776 bytes (10MB plaintext + 16 byte tag)
- **Purpose**: Prevents resource exhaustion attacks

## Overhead Calculation

### Per-File Overhead

- **Header**: 24 bytes (3 bytes magic + 1 byte version + 12-byte nonce + 8-byte size)

### Per-Chunk Overhead

- **Chunk Header**: 4 bytes (chunk size field)
- **GCM Tag**: 16 bytes (authentication tag)
- **Total**: 20 bytes per chunk

### Example Overhead

For a 1GB file with 1MB chunks:
- Number of chunks: 1024
- Header overhead: 20 bytes
- Chunk overhead: 1024 × 20 = 20,480 bytes
- **Total overhead**: 20,500 bytes (~0.002%)

## Compatibility

### Backward Compatibility

- **v1.0 files**: Will be supported indefinitely
- **Future versions**: Will detect algorithm ID and use appropriate decryption

### Forward Compatibility

- **Algorithm ID reservation**: Enables future algorithms without format breaking changes
- **Version negotiation**: Not yet implemented (planned for v2.0)

## Implementation Notes

### Streaming Support

The format supports streaming for files larger than available memory:
- Header is fixed size (20 bytes)
- Chunks can be processed individually
- No need to load entire file into memory

### Chunk Size Selection

Trade-offs for chunk size selection:

| Chunk Size | Pros | Cons |
|------------|------|------|
| Small (64KB) | Lower memory usage | Higher overhead, slower |
| Medium (1MB) | Balanced performance | Default choice |
| Large (10MB) | Faster encryption | Higher memory usage |

**Recommendation**: Use default 1MB chunks unless you have specific requirements.

## Error Handling

### Invalid Chunk Size

If chunk size is outside valid range:
- **Error**: "invalid chunk size"
- **Action**: Abort decryption (possible tampering)

### Authentication Failure

If GCM authentication fails:
- **Error**: "authentication failed"
- **Action**: Abort decryption (file has been tampered with)

### Truncated File

If file ends unexpectedly:
- **Error**: "unexpected EOF"
- **Action**: Abort decryption (incomplete encryption or truncation attack)

## Future Enhancements

### Planned (v2.0)

1. **Algorithm ID Byte**: Prepend 1-byte algorithm identifier
2. **Metadata Section**: Optional authenticated metadata (filename, timestamp, etc.)
3. **Compression Support**: Optional compression before encryption
4. **Multi-Key Support**: Support for hybrid encryption (KEMs)

### Under Consideration

1. **Version Negotiation**: Explicit version field for compatibility detection
2. **Header Extensions**: Extensible header format for future fields
3. **Parallel Encryption**: Support for parallel chunk processing
4. **Chunk Index Authentication**: Additional authentication of chunk sequence

## References

- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) - GCM Mode Specification
- [RFC 5116](https://www.rfc-editor.org/rfc/rfc5116) - Authenticated Encryption Interface
- [Go crypto/cipher](https://pkg.go.dev/crypto/cipher) - Go GCM Implementation

## Changelog

- **2025-11-10**: Initial format specification (v1.0)
- **TBD**: Algorithm ID implementation (v2.0)
