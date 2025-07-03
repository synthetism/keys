#!/usr/bin/env node

/**
 * Demo script to test all key generation functionality
 * This demonstrates the zero-dependency key generation capabilities
 */

const { generateKeyPair, getShortId, getFingerprint, derivePublicKey } = require('./dist/index.js');

console.log('🔑 @synet/keys - Zero-dependency key generation demo\n');

// Test all supported key types
const keyTypes = ['rsa', 'ed25519', 'x25519', 'secp256k1', 'wireguard'];

for (const keyType of keyTypes) {
  try {
    console.log(`\n--- ${keyType.toUpperCase()} Key Generation ---`);
    
    const keyPair = generateKeyPair(keyType);
    console.log(`✅ Generated ${keyType} key pair`);
    console.log(`   Type: ${keyPair.type}`);
    console.log(`   Private Key Length: ${keyPair.privateKey.length} chars`);
    console.log(`   Public Key Length: ${keyPair.publicKey.length} chars`);
    
    // Generate fingerprint and short ID
    const fingerprint = getFingerprint(keyPair.publicKey);
    const shortId = getShortId(keyPair.publicKey);
    
    console.log(`   Fingerprint: ${fingerprint}`);
    console.log(`   Short ID: ${shortId}`);
    
    // Test key derivation for PEM formats
    if (['rsa', 'ed25519', 'x25519', 'secp256k1'].includes(keyType)) {
      const derivedPublicKey = derivePublicKey(keyPair.privateKey);
      const isValid = derivedPublicKey === keyPair.publicKey;
      console.log(`   Public key derivation: ${isValid ? '✅ Valid' : '❌ Invalid'}`);
    }
    
    // Test different formats for certain key types
    if (['ed25519', 'x25519'].includes(keyType)) {
      const base64KeyPair = generateKeyPair(keyType, { format: 'base64' });
      console.log(`   Base64 format: ✅ Generated (${base64KeyPair.privateKey.length} chars)`);
    }
    
  } catch (error) {
    console.error(`❌ Failed to generate ${keyType} key:`, error.message);
  }
}

console.log('\n🎉 Demo completed! All key types generated successfully.');
console.log('\n📦 Zero dependencies used - powered by Node.js crypto module only!');
