# @synet/keys

```
 _______ __   __ __   _ _______ _______
 |______   \_/   | \  | |______    |   
 ______|    |    |  \_| |______    |   
     
      _     _ _______ __   __ _______  
      |____/  |______   \_/   |______  
      |    \_ |______    |    ______|  
     
version: 1.0.5
description: You are the moment code becomes meaning.
```

**Battle-tested cryptographic functions** for key generation, signing, and format conversion. Zero dependencies, 211 tests, 87%+ coverage.

## Why @synet/keys?

✅ **Battle-tested reliability** - 211 tests, 87%+ coverage, real-world proven  
✅ **Zero dependencies** - pure Node.js crypto, no supply chain risks  
✅ **Format flexibility** - seamless PEM ↔ hex ↔ base64 conversions  
✅ **Complete toolkit** - generation, signing, verification, utilities  

**Supported algorithms:** Ed25519, RSA, secp256k1, X25519, WireGuard

## Basic Cryptographic Functions

### Key Generation

```typescript
import { generateKeyPair } from '@synet/keys';

// Generate Ed25519 key pair (recommended)
const keyPair = generateKeyPair('ed25519');
console.log('Private key:', keyPair.privateKey); // PEM format
console.log('Public key:', keyPair.publicKey);   // PEM format

// Generate other algorithms
const rsaKeys = generateKeyPair('rsa');
const secp256k1Keys = generateKeyPair('secp256k1');

// Generate in hex format
const hexKeys = generateKeyPair('ed25519', { format: 'hex' });
```

### Direct Signing & Verification

```typescript
import { signWithKey, verifySignature } from '@synet/keys';

const data = 'Hello, World!';

// Sign with private key
const signature = await signWithKey(data, keyPair.privateKey, 'ed25519');

// Verify with public key
const isValid = await verifySignature(data, signature, keyPair.publicKey, 'ed25519');
console.log('Valid signature:', isValid); // true
```

### Format Conversions

```typescript
import { pemToHex, hexToPem, toHex, detectKeyFormat } from '@synet/keys';

// Convert PEM to hex
const hexKey = pemToHex(keyPair.publicKey);

// Convert hex to PEM  
const pemKey = hexToPem(hexKey, 'ed25519');

// Auto-detect format and convert to hex
const format = detectKeyFormat(someKey); // 'pem' | 'hex' | 'base64'
const hexFormat = toHex(someKey, 'ed25519'); // always returns hex

// Derive public key from private
import { derivePublicKey } from '@synet/keys';
const publicKey = derivePublicKey(privateKeyPem);
```

### Key Utilities

```typescript
import { getShortId, getFingerprint, isValidKeyPair } from '@synet/keys';

// Get short identifier for UIs
const shortId = getShortId(publicKey); // e.g., "nn3ui8w2"

// Get SHA-256 fingerprint
const fingerprint = getFingerprint(publicKey);

// Validate key pair
const isValid = isValidKeyPair(privateKey, publicKey, 'ed25519');
```
## Signer & Key Units

For advanced use cases, create intelligent units that can teach each other capabilities.

### Basic Signer Usage

```typescript
import { generateKeyPair, Signer } from '@synet/keys';

// Generate keys first
const keyPair = generateKeyPair('ed25519');

// Create signer from keys
const signer = Signer.create(
  keyPair.privateKey,  // required
  keyPair.publicKey,   // required
  'ed25519',
  { purpose: 'documents' }
);

// Use signer
const signature = await signer.sign('Important document');
const isValid = await signer.verify('Important document', signature);

// Get public key
console.log('Public key:', signer.getPublicKey());
```

### Key Units (Public-only)

```typescript
import { Key } from '@synet/keys';

// Create a public-only key
const key = Key.create(keyPair.publicKey, 'ed25519');

// Can verify signatures
const canVerify = await key.verify('Important document', signature);

// Can get key information
console.log('Hex format:', key.getPublicKeyHex());
console.log('Key type:', key.getKeyType());
```

### Teaching & Learning (Advanced)

Keys can learn signing capabilities from Signers without accessing private keys:

```typescript
// Create a signer (holds private key)
const signer = Signer.create(keyPair.privateKey, keyPair.publicKey, 'ed25519');

// Create a public-only key
const publicKey = Key.create(keyPair.publicKey, 'ed25519');

// Key learns signing from signer (no private key transfer!)
const capabilities = signer.teach();
const learned = await publicKey.learn([capabilities]);

if (learned) {
  // Now the key can sign using learned capabilities
  const signature = await publicKey.sign('I can sign now!');
}
```

## Identity Integration Example

Using `@synet/keys` with `@synet/did` for identity systems:

```typescript
import { generateKeyPair, Signer } from '@synet/keys';
import { createDIDKey } from '@synet/did';

// Generate keys for identity
const keyPair = generateKeyPair('ed25519');

// Create signer for signing credentials/documents
const signer = Signer.create(
  keyPair.privateKey,
  keyPair.publicKey,
  'ed25519',
  { purpose: 'identity' }
);

// Create DID from the public key using @synet/did
const did = createDIDKey(keyPair.publicKey, 'ed25519');
console.log('DID:', did); // did:key:z6Mk...

// Sign a document with the identity
const document = JSON.stringify({
  '@context': 'https://w3.org/ns/credentials/v1',
  type: 'VerifiableCredential',
  issuer: did,
  credentialSubject: {
    name: 'Alice Johnson',
    degree: 'Computer Science'
  }
});

const signature = await signer.sign(document);
console.log('Document signed by DID:', did);

// Verify the signature
const isValid = await signer.verify(document, signature);
console.log('Signature valid:', isValid);
```

This shows the typical identity workflow: generate keys → create signer → create DID → sign documents.

## API Reference

### Core Functions (Battle-Tested)

#### Key Generation
```typescript
generateKeyPair(keyType: KeyType, options?: { format?: 'pem' | 'hex' }): KeyPair
isValidKeyPair(privateKey: string, publicKey: string, keyType: KeyType): boolean
derivePublicKey(privateKeyPEM: string): string
```

#### Format Conversion  
```typescript
pemToHex(pemKey: string): string
hexToPem(hexKey: string, keyType: KeyType): string
base64ToHex(base64Key: string): string
detectKeyFormat(key: string): 'pem' | 'hex' | 'base64'
toHex(key: string, keyType: KeyType): string
```

#### Utilities
```typescript
getShortId(publicKey: string): string
getFingerprint(publicKey: string): string  
getKeyAlgorithm(publicKey: string): KeyType
```

#### Direct Signing
```typescript
signWithKey(data: string, privateKeyPEM: string, keyType: KeyType): Promise<string>
verifySignature(data: string, signature: string, publicKeyPEM: string, keyType: KeyType): Promise<boolean>
```

### Intelligent Units

#### Signer Class [🔐] - Holds Private Keys
```typescript
// Creation (requires existing keys)
Signer.create(privateKeyPEM: string, publicKeyPEM: string, keyType: KeyType, meta?: object): Signer | null

// Operations  
signer.sign(data: string): Promise<string>
signer.verify(data: string, signature: string): Promise<boolean>
signer.getPublicKey(): string
signer.getAlgorithm(): KeyType

// Teaching & Key extraction
signer.teach(): TeachingCapabilities
signer.createKey(): Key  // Extract Key unit from Signer

// Unit interface
signer.execute(instruction: string, context?: object): Promise<unknown>
signer.capabilities(): string[]
```

#### Key Class [🔑] - Public Keys + Learning
```typescript
// Creation
Key.create(publicKeyPEM: string, keyType: KeyType, meta?: object): Key | null
Key.createFromSigner(signer: Signer): Key | null

// Operations (verify always available, sign only after learning)
key.verify(data: string, signature: string): Promise<boolean> 
key.sign(data: string): Promise<string>  // Requires learning first
key.getPublicKey(): string
key.getPublicKeyHex(): string
key.getKeyType(): KeyType

// Learning
key.learn(capabilities: TeachingCapabilities[]): Promise<boolean>
key.useSigner(signer: ISigner): boolean
key.teach(): TeachingCapabilities

// Unit interface  
key.execute(instruction: string, context?: object): Promise<unknown>
key.capabilities(): string[]
```

### Types

```typescript
type KeyType = 'ed25519' | 'rsa' | 'secp256k1' | 'secp256r1';

interface KeyPair {
  privateKey: string;    // PEM or hex format
  publicKey: string;     // PEM or hex format  
  type: KeyType;
}

interface ISigner {
  sign(data: string): Promise<string>;
  getPublicKey(): string;
  getAlgorithm?(): string;
}
```

## Installation

```bash
npm install @synet/keys
# For identity examples, also install:
npm install @synet/did
```

## Testing & Development

**Run the 211 tests:**
```bash
cd packages/keys
npm test                    # Run all tests
npm run test:coverage       # With coverage report  
npm test -- signer.test.ts # Specific test file
```

**Production build:**
```bash
npm run build              # TypeScript compilation
npm run prepublishOnly     # Full pipeline: lint + test + build
```

## Error Handling & Safety

- **Creation methods** (`generate`, `create`) return `null` on failure
- **Operation methods** (`sign`, `verify`) throw descriptive errors  
- **Always validate** creation results before using instances
- **Memory safe** private key handling with Node.js crypto
- **Comprehensive validation** on all inputs and key material

```typescript
// Safe creation pattern
const signer = Signer.create(privateKey, publicKey, 'ed25519');
if (!signer) {
  throw new Error('Failed to create signer - invalid key material');
}

// Safe signing with error handling
try {
  const signature = await signer.sign('important data');
  console.log('Signed successfully:', signature);
} catch (error) {
  console.error('Signing failed:', error.message);
}
```

## Why Choose @synet/keys?

✅ **Battle-tested reliability** - 211 tests, 87%+ coverage, real-world proven  
✅ **Zero dependencies** - pure Node.js crypto, no supply chain risks  
✅ **Intelligent architecture** - units that teach each other capabilities safely  
✅ **Identity-first design** - perfect for DIDs, credentials, distributed systems  
✅ **Format flexibility** - seamless PEM ↔ hex ↔ base64 conversions  
✅ **Memory safe** - secure private key handling with comprehensive validation  

**Perfect for:** Identity systems, credential issuance, document signing, distributed apps, DID management, and any application requiring robust cryptographic operations.

---

MIT License - Built with ❤️ by the Synet team
