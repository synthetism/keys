# @synet/keys

```
 _______ __   __ __   _ _______ _______
 |______   \_/   | \  | |______    |   
 ______|    |    |  \_| |______    |   
                                       
      _     _ _______ __   __ _______  
      |____/  |______   \_/   |______  
      |    \_ |______    |    ______|  
                                       
version: 1.0.0
description: You are the moment code becomes meaning.
```
> Zero-dependency, secure key generation library for modern cryptographic applications

**Pure blissful keys** - A composable, state-of-the-art key generation library that supports all major cryptographic key types using only Node.js built-in crypto module.

## Features

- **Zero Dependencies** - Uses only Node.js built-in crypto module
- **Multiple Key Types** - RSA, Ed25519, X25519, secp256k1, WireGuard
- **Composable Design** - Pure key generation, no mixed concerns
- **High Performance** - Optimized for speed and security
- **Type Safe** - Full TypeScript support
- **Small Bundle** - Minimal footprint

## Quick Start

```bash
npm install @synet/keys
```

```typescript
import { generateKeyPair, getFingerprint, getShortId } from '@synet/keys';

// Generate different key types
const rsaKeys = generateKeyPair('rsa');
const ed25519Keys = generateKeyPair('ed25519');
const wireguardKeys = generateKeyPair('wireguard');

// Get key fingerprints
const fingerprint = getFingerprint(ed25519Keys.publicKey);
const shortId = getShortId(ed25519Keys.publicKey);
```

## 📚 Supported Key Types

| Type | Description | Use Case |
|------|-------------|----------|
| `rsa` | RSA 2048-bit | Legacy systems, certificates |
| `ed25519` | Ed25519 | Digital signatures, modern crypto |
| `x25519` | Curve25519 | Key exchange, ECDH |
| `secp256k1` | Bitcoin curve | Blockchain, cryptocurrencies |
| `wireguard` | X25519 base64 | VPN, secure tunneling |

## 🔧 API Reference

### `generateKeyPair(type, options?)`

Generates a cryptographic key pair.

```typescript
const keyPair = generateKeyPair('ed25519');
// Returns: { privateKey: string, publicKey: string, type: 'ed25519' }

// With custom format (ed25519, x25519 only)
const base64Keys = generateKeyPair('ed25519', { format: 'base64' });
```

### `getFingerprint(publicKey)`

Generates a 64-character SHA-256 fingerprint.

```typescript
const fingerprint = getFingerprint(publicKey);
// Returns: "a1b2c3d4e5f6..."
```

### `getShortId(publicKey)`

Generates a 16-character short identifier.

```typescript
const shortId = getShortId(publicKey);
// Returns: "a1b2c3d4e5f6a1b2"
```

### `derivePublicKey(privateKey)`

Extracts the public key from a private key (PEM formats only).

```typescript
const publicKey = derivePublicKey(privateKey);
```

## 🎯 Design Principles

- **Single Responsibility** - Only key generation and fingerprinting
- **Zero Dependencies** - Uses only Node.js built-in crypto
- **Composability** - For signing/verification, use `@synet/crypto` (separate package)
- **Type Safety** - Full TypeScript support with strict types
- **Performance** - Optimized for speed and minimal memory usage

## 🛡️ Security

This library uses Node.js built-in crypto module which provides:
- Cryptographically secure random number generation
- Industry-standard key generation algorithms
- No external dependencies to audit or worry about

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Part of the Synet ecosystem** - Building the future of decentralized identity and cryptography.
