# @synet/keys

```bash
 _______ __   __ __   _ _______ _______
 |______   \_/   | \  | |______    |   
 ______|    |    |  \_| |______    |   
     
      _     _ _______ __   __ _______  
      |____/  |______   \_/   |______  
      |    \_ |______    |    ______|  
     
version: 1.0.7
```

**Stop fighting with crypto libraries.** Generate keys, sign anything, teach AI agents to handle your entire PKI workflow.

```typescript
import { generateKeyPair, Signer } from '@synet/keys';

// Works exactly like you'd expect
const keys = generateKeyPair('ed25519');
const signer = Signer.create({ 
  privateKeyPEM: keys.privateKey,
  publicKeyPEM: keys.publicKey,
  keyType: 'ed25519'
});
const signature = await signer.sign('Hello World');

// But then it gets interesting...
const smith = Smith.create({ ai });
smith.learn([signer.teach()]); // Now Smith can sign anything
await smith.run("Generate new identity keys, sign all documents in ./contracts");
```

## Why This Exists

You've been there:
- Wrestling with Node's crypto module for basic key operations
- Converting between PEM, hex, base64 formats manually
- Writing the same signing/verification code over and over
- No clean way to use crypto operations with AI agents
- Identity systems that are painful to build

**Then AI agents happened.** And suddenly you need crypto that can teach itself to AI.

This is that library.

## Battle-Tested Foundation

- **211 tests** with 87%+ coverage
- **Zero dependencies** - pure Node.js crypto
- **Production proven** - running in real identity systems
- **Memory safe** - proper private key handling

**Supported:** Ed25519, RSA, secp256k1, X25519, format conversions

## Quick Start

```bash
npm install @synet/keys
```

```typescript
import { generateKeyPair, Signer, signWithKey } from '@synet/keys';

// Option 1: Simple functions (get started fast)
const keys = generateKeyPair('ed25519');
const signature = await signWithKey('data', keys.privateKey, 'ed25519');

// Option 2: Signer approach (more control)
const signer = Signer.create({
  privateKeyPEM: keys.privateKey,
  publicKeyPEM: keys.publicKey,
  keyType: 'ed25519'
});
const sig = await signer.sign('important document');

// Option 3: AI agent approach (magic happens)
const agent = Switch.create({ ai });
agent.learn([signer.teach()]);
await agent.run("Generate company signing keys and sign all legal documents");
```

## Real-World Examples

### Identity Systems That Actually Work
```typescript
import { generateKeyPair, Signer } from '@synet/keys';

// Generate identity keys
const identityKeys = generateKeyPair('ed25519');

// Create secure signer (private keys protected)
const identitySigner = Signer.create({
  privateKeyPEM: identityKeys.privateKey,
  publicKeyPEM: identityKeys.publicKey,
  keyType: 'ed25519',
  secure: true, // Private key access blocked
  metadata: { purpose: 'user-identity' }
});

// Sign user credentials
const credential = {
  userId: 'user123',
  role: 'admin',
  expires: Date.now() + 86400000
};

const signature = await identitySigner.sign(JSON.stringify(credential));
```

### Document Signing Workflows
```typescript
// Contract signing system
const contractSigner = Signer.generate('ed25519', {
  secure: true,
  metadata: { purpose: 'legal-contracts' }
});

// Sign multiple documents
const documents = ['contract-1.pdf', 'contract-2.pdf', 'nda.pdf'];
const signatures = await Promise.all(
  documents.map(doc => contractSigner.sign(doc))
);

// Verification is always available
const isValid = await contractSigner.verify('contract-1.pdf', signatures[0]);
```

### AI Agent Integration
```typescript
import { Smith } from '@synet/agent';

const signer = Signer.generate('ed25519');
const agent = Smith.create({ ai });

// Teach the agent to sign things
agent.learn([signer.teach()]);

// Let AI handle your PKI
await agent.run(`
  1. Generate new signing keys for each department
  2. Sign all pending contracts in ./legal/pending
  3. Create a key management report
  4. Set up automatic key rotation schedule
`);
```
## Features You'll Actually Use

### Smart Key Generation
```typescript
// Recommended: Ed25519 (fast, secure, small)
const keys = generateKeyPair('ed25519');

// Other algorithms when you need them
const rsaKeys = generateKeyPair('rsa');        // Legacy compatibility
const bitcoinKeys = generateKeyPair('secp256k1'); // Blockchain apps

// Different formats
const hexKeys = generateKeyPair('ed25519', { format: 'hex' });
```

### Format Conversion That Works
```typescript
import { pemToHex, hexToPem, detectKeyFormat, toHex } from '@synet/keys';

// Auto-detect and convert
const format = detectKeyFormat(someKey); // 'pem' | 'hex' | 'base64'
const hexKey = toHex(someKey, 'ed25519'); // Always get hex

// Manual conversion
const hex = pemToHex(pemKey);
const pem = hexToPem(hexKey, 'ed25519');

// Derive public from private
const publicKey = derivePublicKey(privateKeyPem);
```

### Key Utilities
```typescript
// Short IDs for UIs
const shortId = getShortId(publicKey); // "nn3ui8w2"

// Fingerprints for verification
const fingerprint = getFingerprint(publicKey);

// Validation
const isValid = isValidKeyPair(privateKey, publicKey, 'ed25519');
```

### Security Features
```typescript
// Secure mode (default) - private keys protected
const secureSigner = Signer.create({
  privateKeyPEM: keys.privateKey,
  publicKeyPEM: keys.publicKey,
  keyType: 'ed25519',
  secure: true  // Default
});

// Private key access blocked
console.log(secureSigner.getPrivateKeyHex()); // null

// Development mode - private keys accessible  
const devSigner = Signer.create({
  privateKeyPEM: keys.privateKey,
  publicKeyPEM: keys.publicKey,
  keyType: 'ed25519',
  secure: false
});

console.log(devSigner.getPrivateKeyHex()); // actual hex key
```

## AI Agent Superpowers

This is where it gets interesting. The Signer follows [Unit Architecture](https://github.com/synthetism/unit), which means:

### Teaching AI Agents
```typescript
const teachingContract = signer.teach();
// Contains: sign, verify methods + schemas

agent.learn([signer.teach()]);
// Agent now knows: "To sign data, call signer.sign with these parameters..."
```

### Capability Learning
```typescript
// Public key can learn signing from signer (without private key!)
const publicKey = Key.create({
  publicKeyPEM: keys.publicKey,
  keyType: 'ed25519'
});

publicKey.learn([signer.teach()]);
// Now publicKey can sign through learned capabilities
const signature = await publicKey.sign('data');
```

### Real Agent Scenarios
```typescript
// Scenario: Legal document workflow
await agent.run(`
  1. Generate signing keys for new client
  2. Sign all contracts in ./legal/pending
  3. Create signature verification manifest
  4. Email signed documents to client
`);

// Scenario: Certificate authority
await agent.run(`
  1. Generate root CA key pair
  2. Create intermediate certificates for each department
  3. Sign employee identity certificates
  4. Set up automatic renewal schedule
`);

// Scenario: Blockchain application
await agent.run(`
  1. Generate secp256k1 wallet keys
  2. Sign transaction for token transfer
  3. Verify signatures on incoming transactions
  4. Generate wallet backup with recovery phrase
`);
```

## Identity Integration Example

Using `@synet/keys` with `@synet/did` for identity systems:

```typescript
import { generateKeyPair, Signer } from '@synet/keys';
import { createDIDKey } from '@synet/did';

// Generate keys for identity
const keyPair = generateKeyPair('ed25519');

// Create signer for signing credentials/documents
const signer = Signer.create({
  privateKeyPEM: keyPair.privateKey,
  publicKeyPEM: keyPair.publicKey,
  keyType: 'ed25519',
  metadata: { purpose: 'identity' }
});

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
pemPrivateKeyToHex(pemKey: string): string  // NEW in v1.0.6
hexPrivateKeyToPem(hexKey: string): string
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

#### Signer Class - Holds Private Keys
```typescript
// Creation (props-based - NEW in v1.0.6)
Signer.create(config: SignerConfig): Signer
Signer.generate(keyType: KeyType, params?: SignerGenerateParams): Signer
Signer.createWithSigner(params: { signer: ISigner; keyType?: KeyType; publicKeyPEM?: string; metadata?: Record<string, unknown> }): Signer | null

// Operations  
signer.sign(data: string): Promise<string>
signer.verify(data: string, signature: string): Promise<boolean>
signer.getPublicKey(): string
signer.getPublicKeyHex(): string | null
signer.getPrivateKeyHex(): string | null  // NEW - security-aware
signer.getAlgorithm(): KeyType

// Teaching & Key extraction
signer.teach(): TeachingCapabilities
signer.createKey(): Key  // Extract Key unit from Signer

// Unit interface
signer.execute(instruction: string, context?: object): Promise<unknown>
signer.capabilities(): string[]
```

#### Key Class - Public Keys + Learning
```typescript
// Creation
Key.create(config: KeyConfig): Key | null
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

interface SignerConfig {
  privateKeyPEM: string;
  publicKeyPEM: string;
  keyType: KeyType;
  secure?: boolean;
  metadata?: Record<string, unknown>;
  isigner?: ISigner;
}

interface SignerGenerateParams {
  secure?: boolean;
  metadata?: Record<string, unknown>;
}

interface KeyConfig {
  publicKeyPEM: string;
  keyType: KeyType;
  metadata?: Record<string, unknown>;
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

**Run the tests:**
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

---

MIT License - Built with ❤️ by the Synet team
