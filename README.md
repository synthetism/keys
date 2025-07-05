# @synet/keys

```
 _______ __   __ __   _ _______ _______
 |______   \_/   | \  | |______    |   
 ______|    |    |  \_| |______    |   
                               
      _     _ _______ __   __ _______  
      |____/  |______   \_/   |______  
      |    \_ |______    |    ______|  
                               
version: 1.0.2
description: You are the moment code becomes meaning.
```

> Zero-dependency, secure key generation and management library for modern cryptographic applications

**Pure blissful keys** - A composable, state-of-the-art cryptographic library featuring both low-level key generation and high-level Key units. Uses only Node.js built-in crypto module for maximum security and minimal dependencies.

## Features

- **🔑 Key Unit Architecture** - Self-contained, composable key units with built-in capabilities
- **🔐 Secure by Default** - Internal key generation, private keys never exposed
- **🚀 Zero Dependencies** - Uses only Node.js built-in crypto module
- **🎯 Multiple Key Types** - RSA, Ed25519, X25519, secp256k1, WireGuard
- **🔄 Migration Support** - Easy migration from existing key pairs
- **🏢 Enterprise Ready** - Vault/HSM support through external signers
- **📦 Composable Design** - Pure key operations, clean separation of concerns
- **⚡ High Performance** - Optimized for speed and security
- **🔒 Type Safe** - Full TypeScript support with progressive security
- **📏 Small Bundle** - Minimal footprint, maximum capability

## Quick Start

```bash
npm install @synet/keys
```

### Key Unit (Recommended)

```typescript
import { Key } from '@synet/keys';

// Generate a new key pair (secure default)
const key = Key.generate('ed25519', { name: 'my-key' });

// Use the key
console.log(key.canSign()); // true
const signature = await key.sign('Hello World');
const isValid = await key.verify('Hello World', signature);

// Get help
Key.help(); // Shows all capabilities and usage
```

### Low-Level Key Generation

```typescript
import { generateKeyPair, getFingerprint } from '@synet/keys';

// Generate raw key pairs
const keyPair = generateKeyPair('ed25519');
const fingerprint = getFingerprint(keyPair.publicKey);
```

## Key Unit Architecture

The Key unit is the cornerstone of @synet/keys - a self-contained, composable unit that handles all key operations securely and intelligently.

### Design Principles

- **🛡️ Security First**: Private keys generated internally and never exposed
- **🧩 Self-Contained**: Each key knows its own capabilities and operations
- **🔄 Progressive Security**: From simple keys to enterprise vault/HSM integration
- **📖 Self-Documenting**: Built-in help and capability introspection
- **🎯 Pure Operations**: No side effects, composable with other systems
- **🔒 Type-Safe**: Compile-time verification of key capabilities

### Creation Methods

```typescript
import { Key } from '@synet/keys';

// 1. Generate new key pair (recommended)
const newKey = Key.generate('ed25519', { name: 'my-new-key' });

// 2. Migrate existing key pair
const migratedKey = Key.fromKeyPair('ed25519', existingPub, existingPriv, { 
  name: 'legacy-key',
  source: 'old-system' 
});

// 3. Public-only key (verification only)
const publicKey = Key.createPublic('ed25519', publicKeyHex, { name: 'verify-only' });

// 4. External signer (vault/HSM)
const vaultKey = Key.createWithSigner('ed25519', publicKeyHex, customSigner, { 
  name: 'vault-key' 
});
```

### Key Operations

```typescript
// Check capabilities
console.log(key.canSign());        // true/false
console.log(key.dna.capabilities);  // ['sign', 'verify', 'getPublicKey', ...]

// Sign and verify
const signature = await key.sign('data to sign');
const isValid = await key.verify('data to sign', signature);

// Transform keys
const publicKey = key.toPublicKey();           // Create public-only copy
const vm = key.toVerificationMethod('did:..'); // DID verification method
const exported = key.toJSON();                 // Export (no private key)

// Get information
console.log(key.whoami);           // "Key Unit v1.0.0"
console.log(key.getPublicKey());   // Public key string
key.help();                        // Show all capabilities
```

### Progressive Security Models

#### 1. **Simple Keys** (Generated)

```typescript
const key = Key.generate('ed25519', { name: 'simple-key' });
// ✅ Secure internal generation
// ✅ Can sign and verify
// ✅ Private key protected internally
```

#### 2. **Migrated Keys** (Existing)

```typescript
const key = Key.fromKeyPair('ed25519', existingPub, existingPriv);
// ✅ Easy migration from legacy systems
// ✅ Same security as generated keys
// ✅ Existing key material preserved
```

#### 3. **Public Keys** (Verification Only)

```typescript
const key = Key.createPublic('ed25519', publicKeyHex);
// ✅ Verification only
// ✅ No signing capability
// ✅ Perfect for trust verification
```

#### 4. **Vault Keys** (Enterprise)

```typescript
const vaultSigner = new CustomVaultSigner(config);
const key = Key.createWithSigner('ed25519', publicKeyHex, vaultSigner);
// ✅ Enterprise-grade security
// ✅ Private keys never leave vault/HSM
// ✅ Audit trails and compliance
```

### Self-Documentation

Every Key unit is self-documenting:

```typescript
const key = Key.generate('ed25519');

// Static help (shows all creation methods)
Key.help();

// Instance help (shows this key's capabilities)
key.help();

// Programmatic capabilities
console.log(key.dna);              // Full unit schema
console.log(key.dna.capabilities); // Available methods
console.log(key.whoami);           // Unit identity
```

## 📚 Supported Key Types

| Type          | Description   | Use Case                          | Security   |
| ------------- | ------------- | --------------------------------- | ---------- |
| `ed25519`   | Ed25519 curve | Digital signatures, modern crypto | ⭐⭐⭐⭐⭐ |
| `x25519`    | Curve25519    | Key exchange, ECDH                | ⭐⭐⭐⭐⭐ |
| `rsa`       | RSA 2048-bit  | Legacy systems, certificates      | ⭐⭐⭐⭐   |
| `secp256k1` | Bitcoin curve | Blockchain, cryptocurrencies      | ⭐⭐⭐⭐   |
| `wireguard` | X25519 base64 | VPN, secure tunneling             | ⭐⭐⭐⭐⭐ |

## 🔧 API Reference

### Key Unit API

#### Static Methods

```typescript
// Generate new key pair
Key.generate(type: KeyType, meta?: KeyMeta): Key

// Migrate existing key pair
Key.fromKeyPair(type: KeyType, publicKey: string, privateKey: string, meta?: KeyMeta): Key

// Create public-only key
Key.createPublic(type: KeyType, publicKey: string, meta?: KeyMeta): Key

// Create vault/HSM key
Key.createWithSigner(type: KeyType, publicKey: string, signer: ISigner, meta?: KeyMeta): Key

// Show help
Key.help(): void
```

#### Instance Methods

```typescript
// Core operations
key.canSign(): boolean
key.getPublicKey(): string
key.sign(data: string): Promise<string>
key.verify(data: string, signature: string): Promise<boolean>

// Transformations
key.toPublicKey(): Key
key.toJSON(): KeyExport
key.toVerificationMethod(controller: string): VerificationMethod

// Information
key.help(): void
key.dna: UnitSchema
key.whoami: string
```

#### Properties

```typescript
key.id: string           // Unique key identifier
key.type: KeyType        // Key type (ed25519, rsa, etc.)
key.publicKeyHex: string // Public key material
key.meta: KeyMeta        // Key metadata
key.signer?: ISigner     // External signer (if any)
```

### Low-Level Key Generation API

```typescript
// Generate key pairs
generateKeyPair(type: KeyType, options?: { format?: KeyFormat }): KeyPair

// Key utilities
getFingerprint(publicKey: string): string
getShortId(publicKey: string): string
derivePublicKey(privateKey: string): string
createId(): string
```

## 🚀 Migration Guide

### From Legacy Key Systems

```typescript
// OLD: Direct key handling
const publicKey = 'existing-public-key';
const privateKey = 'existing-private-key';

// NEW: Key unit migration
const key = Key.fromKeyPair('ed25519', publicKey, privateKey, {
  name: 'migrated-from-legacy',
  source: 'legacy-system',
  migratedAt: new Date().toISOString()
});

// Now use with full Key unit benefits
console.log(key.canSign());  // true
key.help();                  // See all capabilities
const signature = await key.sign('data');
```

### From Raw Key Generation

```typescript
// OLD: Raw key generation + manual management
const keyPair = generateKeyPair('ed25519');
// ... manual signing/verification logic

// NEW: Key unit (recommended)
const key = Key.generate('ed25519', { name: 'my-key' });
// All operations built-in, secure by default
```

## 🔒 Security Features

- **Private Key Protection**: Private keys stored internally, never exposed
- **Secure Generation**: Uses Node.js crypto.generateKeyPair() under the hood
- **Memory Safety**: Private keys stored in readonly fields
- **No External Dependencies**: Only Node.js built-in crypto module
- **Audit Ready**: Clean, minimal codebase for security audits
- **Secure by Default**: Safe defaults for all operations

## 🎯 Design Philosophy

### Unit Architecture Benefits

1. **Self-Contained**: Each key is a complete unit with all necessary operations
2. **Self-Documenting**: Built-in help and capability discovery
3. **Composable**: Works seamlessly with other systems and libraries
4. **Secure**: Private keys never exposed, secure by design
5. **Progressive**: Scales from simple to enterprise use cases
6. **Type-Safe**: Full TypeScript support with compile-time verification
7. **Self-evolving:** Only evolves, never breaks. Maintain compatibility with older versions
8. **Self-defending** Protects its own sensitive data, incoming data is validated, private data never exposes.

### Why Not "Key Managers"?

Instead of complex "manager" abstractions, each Key unit is autonomous:

```typescript
// ❌ Complex manager pattern
const keyManager = new KeyManager();
const key = keyManager.getKey('key-id');
await keyManager.sign(key, data);

// ✅ Simple unit pattern
const key = Key.generate('ed25519');
await key.sign(data);
```

## Enterprise Integration

### Vault/HSM Support

```typescript
// Custom vault signer
class VaultSigner implements ISigner {
  constructor(private vault: VaultClient) {}
  
  async sign(data: string): Promise<string> {
    return await this.vault.sign(this.keyId, data);
  }
  
  getPublicKey(): string {
    return this.publicKey;
  }
}

// Use with Key unit
const vaultKey = Key.createWithSigner('ed25519', publicKey, new VaultSigner(vault));
await vaultKey.sign('enterprise data'); // Signed in vault, never exposed
```

### Audit and Compliance

```typescript
const key = Key.generate('ed25519', {
  name: 'compliance-key',
  purpose: 'document-signing',
  compliance: 'SOX',
  auditId: 'AUD-2025-001'
});

// All operations are auditable
console.log(key.meta);        // Metadata for compliance
console.log(key.dna);         // Unit capabilities for auditing
console.log(key.whoami);      // Unit identity and version
```

## Testing

```typescript
import { Key } from '@synet/keys';

describe('Key operations', () => {
  test('should generate and use key', () => {
    const key = Key.generate('ed25519', { name: 'test-key' });
  
    expect(key.canSign()).toBe(true);
    expect(key.type).toBe('ed25519');
    expect(key.meta.name).toBe('test-key');
  });
  
  test('should migrate existing keys', () => {
    const key = Key.fromKeyPair('ed25519', 'pub123', 'priv456');
  
    expect(key.publicKeyHex).toBe('pub123');
    expect(key.canSign()).toBe(true);
  });
});
```

## Performance

The Key unit is optimized for performance:

```typescript
// Generate 100 keys
const startTime = performance.now();
const keys = Array.from({ length: 100 }, () => 
  Key.generate('ed25519', { name: 'perf-test' })
);
const endTime = performance.now();

console.log(`Generated 100 keys in ${endTime - startTime}ms`);
// Typical: ~10-15ms (0.1-0.15ms per key)
```

## 🤔 FAQ

**Q: Should I use Key units or low-level key generation?**
A: Use Key units for most applications. They provide security, documentation, and ease of use. Use low-level generation only when you need raw key material for specific integrations.

**Q: How do I migrate from existing key systems?**
A: Use `Key.fromKeyPair()` to wrap your existing keys in a Key unit. This gives you all the benefits without changing your existing key material.

**Q: Can I use this with hardware security modules (HSMs)?**
A: Yes! Implement the `ISigner` interface and use `Key.createWithSigner()`. Your private keys never leave the HSM.

**Q: Is this compatible with other crypto libraries?**
A: Yes! Key units can export public keys and verification methods for use with any other system. They're designed to be interoperable.

**Q: How do I know what a key can do?**
A: Call `key.help()` or check `key.dna.capabilities`. Every key is self-documenting.

## CredentialKey Interface Compatibility

The Key unit implements the `CredentialKey` interface from `@synet/credential`, enabling seamless integration with credential systems while maintaining loose coupling and version independence.

### What is CredentialKey?

`CredentialKey` is an interface that defines the essential operations needed for credential signing and verification:

```typescript
// From @synet/credential/src/key.ts
interface CredentialKey {
  readonly id: string;
  readonly publicKeyHex: string;
  readonly type: string;
  readonly meta: Record<string, unknown>;
  
  canSign(): boolean;
  getPublicKey(): string;
  sign(data: string): Promise<string>;
  verify(data: string, signature: string): Promise<boolean>;
  toJSON(): object;
  toVerificationMethod(controller: string): object;
}
```

### Automatic Compatibility

All Key units automatically implement `CredentialKey`:

```typescript
import { Key } from '@synet/keys';
import { issueVC } from '@synet/credential';

// Key implements CredentialKey automatically
const key = await Key.generate('ed25519');

// Works seamlessly with credential functions
const credential = await issueVC(
  key, // ← Automatically compatible
  subject,
  type,
  issuerDid
);
```

### Benefits of Interface-Based Design

1. **Version Independence**: Different versions of @synet/keys can coexist
2. **Provider Flexibility**: Use any key provider that implements CredentialKey
3. **Testing**: Easy to mock keys for testing
4. **Loose Coupling**: Credential and key packages evolve independently

### Example: Version Compatibility

```typescript
// Even with different versions, both work
import { Key as KeyV1 } from '@synet/keys@1.0.0';
import { Key as KeyV2 } from '@synet/keys@1.0.1';
import { issueVC } from '@synet/credential';

const keyV1 = await KeyV1.generate('ed25519');
const keyV2 = await KeyV2.generate('ed25519');

// Both work with credential functions
await issueVC(keyV1, subject, type, issuerDid); // ✅
await issueVC(keyV2, subject, type, issuerDid); // ✅
```

### Custom Key Providers

You can implement your own key providers:

```typescript
class MyCustomKey implements CredentialKey {
  // ... implement all interface methods
}

// Works with credential functions
const customKey = new MyCustomKey();
await issueVC(customKey, subject, type, issuerDid); // ✅
```

This design ensures that @synet/keys remains the preferred key provider while allowing maximum flexibility and avoiding version conflicts.
## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Part of the Synet ecosystem** - Building the future of decentralized identity and cryptography with secure, composable, and self-documenting units.
