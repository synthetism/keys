# @synet/keys

```
 _______ __   __ __   _ _______ _______
 |______   \_/   | \  | |______    |   
 ______|    |    |  \_| |______    |   
                             
      _     _ _______ __   __ _______  
      |____/  |______   \_/   |______  
      |    \_ |______    |    ______|  
                             
version: 1.1.0
description: You are the moment code becomes meaning.
```

A composable, [unit-based](https://www.npmjs.com/package/@synet/unit) cryptographic signing system, built on a "signer-first" architecture.

## Supported Algorithms

- **Ed25519**: High-performance elliptic curve signing
- **RSA**: Traditional RSA signing with PKCS1v15 and PSS padding
- **secp256k1**: Bitcoin/Ethereum compatible elliptic curve
- **secp256r1**: NIST P-256 elliptic curve

## Architecture

The package follows a two-unit design based on the unit architecture paradigm:

- **Signer Unit** [🔐]: Primary cryptographic engine that holds private keys and performs signing operations
- **Key Unit** [🔑]: Public-facing unit that can learn signing capabilities from Signer units

Read more about [Unit Architecture](https://github.com/synthetism/unit)

### Design Principles

1. **Signer-First**: Signer is the primary unit that holds private key material and signing logic
2. **Composable**: Key units can learn from any compatible Signer through the teaching/learning pattern
3. **Secure**: Private keys are contained within Signer units, Key units only hold public keys
4. **Self-Contained**: Uses only Node.js crypto, no external dependencies
5. **Unit-Based**: Both follows Unit Architechture, with execute, learn, teach, and capabilities
6. **Static Create Pattern**: All units use private constructor + static create() methods

### Unit Creation Pattern

**CRITICAL**: Both Signer and Key units follow the mandatory static create() pattern:

```typescript
// ✅ CORRECT: Use static create() methods
const signer = Signer.generate('ed25519');
const key = Key.createFromSigner(signer);

// ❌ FORBIDDEN: Direct constructor calls are not allowed
// const signer = new Signer(...); // Won't work - constructor is private
// const key = new Key(...);       // Won't work - constructor is private
```

This architectural pattern ensures:

- **Controlled creation** - Proper validation and error handling
- **Consistent interface** - All units follow the same creation pattern
- **Prevention of invalid states** - Units cannot be created in corrupted states

## Quick Start

### Basic Signing with Signer

```typescript
import { Signer } from '@synet/keys';

// Generate a new signer
const signer = Signer.generate('ed25519');
if (!signer) throw new Error('Failed to generate signer');

// Sign data
const signature = await signer.sign('Hello, World!');
console.log('Signature:', signature);

// Verify signature
const isValid = await signer.verify('Hello, World!', signature);
console.log('Valid:', isValid);

// Get public key
const publicKey = signer.getPublicKey();
console.log('Public Key:', publicKey);
```

### Creating Signer from Existing Keys

```typescript
import { Signer } from '@synet/keys';

// Create signer from existing key material
const signer = Signer.create({
  publicKeyPEM: '-----BEGIN PUBLIC KEY-----...',
  privateKeyPEM: '-----BEGIN PRIVATE KEY-----...',
  keyType: 'ed25519'
});

if (signer) {
  const signature = await signer.sign('Test data');
  console.log('Signature:', signature);
}
```

### Composable Key Units

```typescript
import { Signer, Key } from '@synet/keys';

// Create a signer
const signer = Signer.generate('ed25519');
if (!signer) throw new Error('Failed to generate signer');

// Create a key that learns from the signer
const key = Key.createFromSigner(signer);
if (!key) throw new Error('Failed to create key');

// The key can now sign (learned from signer)
const signature = await key.sign('Hello from key!');
console.log('Key signature:', signature);

// Verify using the key
const isValid = await key.verify('Hello from key!', signature);
console.log('Key verification:', isValid);
```

### Key Learning Pattern

```typescript
import { Signer, Key } from '@synet/keys';

// Create a public-only key
const publicKey = signer.getPublicKey();
const key = Key.createPublic(publicKey, 'ed25519');

// Key can verify but not sign initially
const canVerify = await key.verify(data, signature);
console.log('Can verify:', canVerify);

// Key learns signing from a compatible signer
const learned = await key.learn(signer);
if (learned) {
  // Now the key can sign
  const newSignature = await key.sign('New data');
  console.log('Learned to sign:', newSignature);
}
```

## API Reference

### Signer Class

The primary cryptographic unit that holds private keys and performs signing operations.

#### Static Methods

- `Signer.generate(keyType: KeyType, meta?: Record<string, unknown>): Signer | null`

  - Generate a new signer with a fresh key pair
  - Returns null if generation fails
- `Signer.create(props: SignerProps): Signer | null`

  - Create signer from existing key material
  - Props: `{ publicKeyPEM: string, privateKeyPEM: string, keyType: KeyType, meta?: Record<string, unknown> }`

#### Instance Methods

- `async sign(data: string): Promise<string>`

  - Sign data and return base64 signature
  - Throws error if signing fails
- `async verify(data: string, signature: string): Promise<boolean>`

  - Verify signature against data
  - Returns false if verification fails
- `getPublicKey(): string`

  - Get the public key in PEM format
- `getKeyType(): KeyType`

  - Get the key algorithm type
- `teach(): ISigner`

  - Expose signing capabilities for learning by Key units

#### Unit Methods

- `async execute(instruction: string, context?: Record<string, unknown>): Promise<unknown>`

  - Execute signing operations via unit interface
- `capabilities(): string[]`

  - List available capabilities

### Key Class

A public-facing unit that can learn signing capabilities from Signer units.

#### Static Methods

- `Key.create(publicKeyPEM: string, keyType: KeyType, meta?: Record<string, unknown>): Key | null`

  - Create a public-only key
- `Key.createFromSigner(signer: Signer): Key | null`

  - Create a key that immediately learns from a signer
- `Key.createPublic(publicKeyPEM: string, keyType: KeyType, meta?: Record<string, unknown>): Key | null`

  - Alias for `Key.create()` for clarity

#### Instance Methods

- `async sign(data: string): Promise<string>`

  - Sign data (only available after learning from a signer)
  - Throws error if no signer learned or signing fails
- `async verify(data: string, signature: string): Promise<boolean>`

  - Verify signature against data
  - Always available with public key
- `getPublicKey(): string`

  - Get the public key in PEM format
- `getKeyType(): KeyType`

  - Get the key algorithm type
- `useSigner(signer: Signer): boolean`

  - Learn signing capabilities from a signer
  - Validates public key consistency
  - Returns true if learning successful
- `async learn(teacher: ISigner): Promise<boolean>`

  - Learn from any ISigner implementation
  - Validates public key consistency

#### Unit Methods

- `async execute(instruction: string, context?: Record<string, unknown>): Promise<unknown>`

  - Execute key operations via unit interface
- `capabilities(): string[]`

  - List available capabilities

## Types

### KeyType

Supported cryptographic algorithms:

```typescript
type KeyType = 'ed25519' | 'rsa' | 'secp256k1' | 'secp256r1';
```

### ISigner

Interface for signing implementations:

```typescript
interface ISigner {
  sign(data: string): Promise<string>;
  getPublicKey(): string;
  getAlgorithm?(): string;
}
```

## Error Handling

The package follows a null-return pattern for creation methods and throws errors for operation methods:

- Creation methods (`generate`, `create`, etc.) return `null` on failure
- Operation methods (`sign`, `verify`, etc.) throw errors on failure
- Always check for null returns before using created instances

## Security Considerations

1. **Private Key Protection**: Private keys are only held by Signer units and never exposed
2. **Public Key Validation**: Key units validate public key consistency when learning
3. **Secure Defaults**: All algorithms use secure defaults and best practices
4. **Memory Safety**: Private key material is handled securely within crypto operations

## Testing

Run the test suite:

```bash
cd packages/keys
npm test
```

Run specific test files:

```bash
npm test -- signer.test.ts
npm test -- key.test.ts
npm test -- integration.test.ts
```

## Examples

See the `demo/` directory for complete examples:

- `signer-demo.ts`: Basic signer operations
- `key-learning-demo.ts`: Key learning patterns
- `integration-demo.ts`: Full integration examples

## Development

### Building

```bash
npm run build
```

### Running Demos

```bash
npm run demo:signer
npm run demo:key
npm run demo:integration
```

### Type Checking

```bash
npm run type-check
```

## Legacy Compatibility

The package maintains compatibility with the previous API through the main exports. Legacy code will continue to work while new code can adopt the signer-first pattern.

## License

MIT License - see LICENSE file for details.
