# go-fileencrypt

[![CI](https://github.com/gitrgoliveira/go-fileencrypt/workflows/CI/badge.svg)](https://github.com/gitrgoliveira/go-fileencrypt/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/gitrgoliveira/go-fileencrypt)](https://goreportcard.com/report/github.com/gitrgoliveira/go-fileencrypt)
[![GoDoc](https://godoc.org/github.com/gitrgoliveira/go-fileencrypt?status.svg)](https://godoc.org/github.com/gitrgoliveira/go-fileencrypt)

Secure, streaming file encryption and decryption library for Go using AES-256-GCM. Designed for cross-platform use with memory-safe key handling, chunked processing for large files, and support for external libraries to enhance functionality.

> [!WARNING]
> This library ships "as-is" under the Mozilla Public License 2.0 (refer to [LICENSE](LICENSE) for details). While it implements industry-standard cryptographic primitives (AES-256-GCM), **it has not undergone independent security audits**. For production use, especially in security-critical applications, you should:
> - Conduct your own security review or hire a professional security auditor
> - Follow the security best practices outlined in this documentation
> - Stay updated on security advisories and updates
> 
> The author makes no warranties regarding the library's security or fitness for any particular purpose.

## Features

- **Strong Encryption**: AES-256-GCM with authenticated encryption
- **Streaming Support**: Encrypt/decrypt files of any size without loading into memory
- **Cross-Platform**: Works on Linux, macOS, and Windows with platform-specific memory locking
- **Memory Safety**: Secure key handling with explicit memory zeroing
- **Progress Tracking**: Built-in progress callbacks for long operations
- **Context Support**: Cancellation and timeout support for all operations
- **Modern Key Derivation**: **Argon2id (recommended)** and PBKDF2-HMAC-SHA256 support
- **GPU-Resistant**: Argon2id provides superior protection against GPU/ASIC attacks

## Table of contents

- [Installation](#installation)
- [Supported platforms](#supported-platforms)
- [Quick start](#quick-start)
- [Usage examples](#usage-examples)
- [API reference](#api-reference)
- [Security considerations](#security-considerations)
- [Performance](#performance)
- [Documentation](#documentation)
- [Key storage](#key-storage)
- [Thread safety](#thread-safety)
- [Contributing](#contributing)
- [License](#license)

## Installation

```bash
go get github.com/gitrgoliveira/go-fileencrypt
```

**Requirements:**
- Go 1.25 or later

## Supported platforms

This library works across all major operating systems:

- **Linux**: Full support with memory locking using `mlock(2)`
- **macOS**: Full support with memory locking using `mlock(2)`
- **Windows**: Full support (memory locking is no-op)

### Platform-specific features

**Memory Locking:**
- On Unix-based systems (Linux, macOS), the library uses `mlock()` to prevent sensitive data from being swapped to disk
- On Windows, memory locking is a no-op (not implemented)
- All platforms support secure memory zeroing through `secure.Zero()`

**File Permissions:**
- Unix/macOS: Use `0600` permissions for encrypted files (owner read/write only)
- Windows: NTFS ACLs apply; consider restricting access to the current user

**Performance:**
- Performance is consistent across platforms
- The benchmarks in this README use an Apple M1 Pro (ARM64)

## Quick start

### Basic file encryption

```go
package main

import (
       "context"
       "crypto/rand"
       "log"
       "github.com/gitrgoliveira/go-fileencrypt"
       "github.com/gitrgoliveira/go-fileencrypt/secure" // Always import for key zeroing
)

func main() {
       // Generate a random 32-byte key
       key := make([]byte, 32)
       if _, err := rand.Read(key); err != nil {
	       log.Fatal(err)
       }
       defer secure.Zero(key) // Always zero sensitive data
       
       ctx := context.Background()
       
       // Encrypt
       err := fileencrypt.EncryptFile(ctx, "document.pdf", "document.pdf.enc", key)
       if err != nil {
	       log.Fatal(err)
       }
       
       // Decrypt
       err = fileencrypt.DecryptFile(ctx, "document.pdf.enc", "document.pdf", key)
       if err != nil {
	       log.Fatal(err)
       }
}
```

### Password-based encryption

```go
package main

import (
	"context"
	"log"
	
	"github.com/gitrgoliveira/go-fileencrypt"
	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

func main() {
	password := []byte("your-secure-password")
	
	// Generate salt (store this with your encrypted file!)
	salt, err := fileencrypt.GenerateSalt(fileencrypt.DefaultSaltSize)
	if err != nil {
		log.Fatal(err)
	}
	
	// Derive key from password using PBKDF2
	key, err := fileencrypt.DeriveKeyPBKDF2(
		password,
		salt,
		fileencrypt.DefaultPBKDF2Iterations, // 600,000 iterations
		fileencrypt.DefaultKeySize,           // 32 bytes
	)
	if err != nil {
		log.Fatal(err)
	}
	defer secure.Zero(key) // Always zero sensitive data
	
	ctx := context.Background()
	err = fileencrypt.EncryptFile(ctx, "secret.txt", "secret.enc", key)
	if err != nil {
		log.Fatal(err)
	}
}
```

### Stream encryption

```go
// Encrypt from io.Reader to io.Writer
src := bytes.NewReader(plaintext)
var dst bytes.Buffer

err := fileencrypt.EncryptStream(ctx, src, &dst, key)
if err != nil {
	log.Fatal(err)
}

// Decrypt back
encReader := bytes.NewReader(dst.Bytes())
var plainDst bytes.Buffer

err = fileencrypt.DecryptStream(ctx, encReader, &plainDst, key)
if err != nil {
	log.Fatal(err)
}
```

## Usage examples

### Large files with progress tracking

```go
chunkOpt, err := fileencrypt.WithChunkSize(1*1024*1024) // 1MB chunks
if err != nil {
	// handle invalid chunk size (very large or environment-limited)
	// fallback to default chunk size or return error
	// For examples we abort on error
	log.Fatalf("invalid chunk size: %v", err)
}

err = fileencrypt.EncryptFile(ctx, "large_video.mp4", "large_video.enc", key,
	fileencrypt.WithProgress(func(progress float64) {
		// progress is a fraction between 0.0 and 1.0
		fmt.Printf("\rEncrypting: %.1f%%", progress*100)
	}),
	chunkOpt,
)
```

### Context cancellation

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

err := fileencrypt.EncryptFile(ctx, "source.bin", "encrypted.bin", key)
if err == context.DeadlineExceeded {
	log.Println("Encryption timed out")
}
```

For more examples, refer to the `examples/` directory and run them locally:
- `examples/basic/` — Basic encryption/decryption
- `examples/with-password/` — Password-based encryption (PBKDF2)
- `examples/with-argon2/` — Password-based encryption with Argon2id
- `examples/large-files/` — Large files with progress tracking (shows `WithChunkSize` and fractional progress usage)

## API reference

The library exposes the following functions for encryption, decryption, key derivation, and secure memory management.

### Core functions

#### EncryptFile
```go
func EncryptFile(ctx context.Context, srcPath, dstPath string, key []byte, opts ...Option) error
```
Encrypts a file from `srcPath` to `dstPath` using the provided 32-byte key.

**Options:**
- `WithChunkSize(size int)` - Set chunk size (default: `DefaultChunkSize` = 1MB, allowed range: 1 byte to `MaxChunkSize` = 10MB).
- `WithProgress(callback func(float64))` - Progress callback (receives a fraction between `0.0` and `1.0`).

#### DecryptFile
```go
func DecryptFile(ctx context.Context, srcPath, dstPath string, key []byte, opts ...Option) error
```
Decrypts a file from `srcPath` to `dstPath` using the provided key.

#### EncryptStream
```go
func EncryptStream(ctx context.Context, src io.Reader, dst io.Writer, key []byte, opts ...Option) error
```
Encrypts data from an `io.Reader` to an `io.Writer`.

#### DecryptStream
```go
func DecryptStream(ctx context.Context, src io.Reader, dst io.Writer, key []byte, opts ...Option) error
```
Decrypts data from an `io.Reader` to an `io.Writer`.

### Key derivation

#### DeriveKeyPBKDF2
```go
func DeriveKeyPBKDF2(password, salt []byte, iterations, keyLen int) ([]byte, error)
```
Derives an encryption key from a password using PBKDF2-HMAC-SHA256.

**Recommended values:**
- `iterations`: 600,000 (OWASP 2023) or minimum 210,000
- `keyLen`: 32 bytes for AES-256

#### GenerateSalt
```go
func GenerateSalt(size int) ([]byte, error)
```
Generates a cryptographically secure random salt. Recommended size: 32 bytes.

### Secure memory

#### secure.Zero
```go
func Zero(b []byte)
```
Securely zeros a byte slice to prevent key material from remaining in memory.

#### secure.LockMemory / UnlockMemory
```go
func LockMemory(b []byte) error
func UnlockMemory(b []byte) error
```
Lock/unlock memory pages (uses `mlock` on Unix/macOS, no-op on Windows).

## Security considerations

Follow these guidelines to use the library securely.

### Cryptography

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256 bits (32 bytes)
- **Nonce**: 96 bits (12 bytes), randomly generated per file
- **Authentication**: 128-bit GCM tag per chunk
- **Key Derivation**: PBKDF2-HMAC-SHA256 (600,000 iterations default)

### Best practices

**Key Management:**
- Generate keys using `crypto/rand` (cryptographically secure)
- Never hardcode keys in source code
- Use `defer secure.Zero(key)` to clear key material from memory
- Store keys securely (HSM, KMS, or encrypted key storage)
- Use unique keys for different contexts

**Password-Based Encryption:**
- Use strong passwords (minimum 12 characters, mixed complexity)
- Always generate a unique, random salt per encryption
- Store the salt alongside the encrypted file
- Use at least 600,000 PBKDF2 iterations (OWASP 2023)

**File Handling:**
- Validate decrypted data integrity before use
- Use secure file permissions (0600 for sensitive files)
- Delete plaintext securely after encryption (consider `shred` or `srm`)
- Handle authentication failures as potential tampering

**Production Deployment:**
- Run security audits before production use
- Implement proper error handling without leaking sensitive data
- Use context cancellation for long-running operations
- Monitor for security advisories and updates

## Performance

The following tables summarize throughput and overhead measurements.

### Benchmarks

Tested on **Apple M1 Pro**:

| Operation | File Size | Throughput | Time |
|-----------|-----------|------------|---------|
| Encryption | 1 MB | ~949 MB/s | ~1.1 ms |
| Encryption | 10 MB | ~1361 MB/s | ~7.7 ms |
| Encryption | 100 MB | ~1039 MB/s | ~101 ms |
| Encryption | 1 GB | ~235 MB/s | ~4.6 s |
| Decryption | 1 MB | ~1260 MB/s | ~0.8 ms |
| Decryption | 10 MB | ~1362 MB/s | ~7.7 ms |
| Decryption | 100 MB | ~1338 MB/s | ~78 ms |
| Decryption | 1 GB | ~800 MB/s | ~1.3 s |
| PBKDF2 (600k iter) | - | - | ~76 ms |

**Chunk Size Impact** (10MB file):
- 64KB chunks: ~1376 MB/s
- 256KB chunks: ~1478 MB/s
- 1MB chunks: ~1483 MB/s (default, recommended)
- 4MB chunks: ~1409 MB/s

Run benchmarks yourself:
```bash
go test -bench=. ./benchmark -benchtime=10s
```

### File format overhead

- **Header**: 20 bytes (12-byte nonce + 8-byte file size)
- **Per-chunk**: 20 bytes (4-byte size + 16-byte GCM tag)
- **Example**: 1GB file with 1MB chunks = ~20KB overhead (~0.002%)

## Documentation

- [GoDoc](https://godoc.org/github.com/gitrgoliveira/go-fileencrypt) - API documentation
- [File Format Specification](docs/FORMAT.md) - Detailed file format description

## Key storage

Never store keys in plaintext. The following options provide secure key storage:

- **Hardware Security Modules (HSM)**: For production environments
- **Key Management Services (KMS)**: Cloud providers (AWS KMS, Azure Key Vault, and other cloud key management services)
- **Environment Variables**: For development (not recommended for production)
- **Password-based**: Derive from a user password with PBKDF2

### Salt handling

Store the salt alongside the encrypted file. Common approaches include the following:

- Prepend salt to encrypted file: `[32 bytes salt][encrypted data]`
- Store in a separate metadata file: `file.enc` and `file.enc.salt`
- Include in file header (requires custom format)

### Decryption errors

Decryption failures typically indicate one of the following issues:

- Wrong key (authentication failed)
- File corruption or tampering
- Truncated file

Always treat authentication failures as potential security issues.

### Nonce reuse

Each encryption uses a unique random nonce, so encrypting the same file multiple times with the same key produces different output each time. However, for better security, consider using different keys for different files.

### Post-quantum cryptography

The file format reserves algorithm IDs for post-quantum cryptography (ML-KEM hybrid). Refer to [FORMAT.md](docs/FORMAT.md) for details.

## Thread safety

Each encryption/decryption operation is independent and can run concurrently. Do not share keys across goroutines without proper synchronization. Use separate key copies instead.

## Scope

This library encrypts **data at rest** (file encryption). For data in transit, use TLS/HTTPS.

## Environment variables

You can configure runtime behavior with the following environment variables.

### FILEENCRYPT_CHUNKSIZE_LIMIT

You can override the default chunk size limit (10MB) by setting the `FILEENCRYPT_CHUNKSIZE_LIMIT` environment variable. This variable accepts human-readable file sizes, such as `10MB`, `1GB`, etc.

**Example:**

```bash
export FILEENCRYPT_CHUNKSIZE_LIMIT=50MB
```

## Contributing

Contributions are welcome! Please:
1. Open an issue to discuss proposed changes
2. Follow existing code style and conventions
3. Add tests for new functionality
4. Update documentation as needed
5. Run `make validate-all` before submitting

Refer to [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Mozilla Public License 2.0 - refer to [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by [age](https://github.com/FiloSottile/age) and [sops](https://github.com/mozilla/sops)
- Built with Go standard library cryptography
- OWASP password storage guidelines
- NIST SP 800-38D (GCM specification)

