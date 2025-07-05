/**
 * Demo for Key unit in @synet/keys
 */

import { Key } from '../src/key';

async function demoKey() {
  console.log('\n=== Key Unit Demo ===\n');

  // Show static help
  Key.help();

  console.log('\n--- Key Generation Demo ---');

  // Generate different types of keys
  const ed25519Key = Key.generate('ed25519', { name: 'Demo Ed25519 Key' });
  const rsaKey = Key.generate('rsa', { name: 'Demo RSA Key' });
  
  console.log('✅ Generated Ed25519 key:', {
    id: ed25519Key.id,
    type: ed25519Key.type,
    canSign: ed25519Key.canSign(),
    publicKey: ed25519Key.publicKeyHex.slice(0, 40) + '...',
    meta: ed25519Key.meta
  });

  console.log('✅ Generated RSA key:', {
    id: rsaKey.id,
    type: rsaKey.type,
    canSign: rsaKey.canSign(),
    publicKey: rsaKey.publicKeyHex.slice(0, 40) + '...',
    meta: rsaKey.meta
  });

  console.log('\n--- Signing Demo ---');

  const data = 'Hello, World! This is test data for signing.';
  console.log('Data to sign:', data);

  try {
    const signature = await ed25519Key.sign(data);
    console.log('✅ Signature created:', signature.slice(0, 50) + '...');

    const isValid = await ed25519Key.verify(data, signature);
    console.log('✅ Signature verification:', isValid ? 'VALID' : 'INVALID');

    const isInvalid = await ed25519Key.verify('different data', signature);
    console.log('✅ Wrong data verification:', isInvalid ? 'VALID' : 'INVALID (as expected)');
  } catch (error) {
    console.error('❌ Signing error:', error);
  }

  console.log('\n--- Public Key Demo ---');

  const publicKey = ed25519Key.toPublicKey();
  console.log('✅ Created public key:', {
    id: publicKey.id,
    type: publicKey.type,
    canSign: publicKey.canSign(),
    publicKey: publicKey.publicKeyHex.slice(0, 40) + '...'
  });

  try {
    await publicKey.sign('test');
    console.log('❌ Public key should not be able to sign!');
  } catch (error) {
    console.log('✅ Public key correctly cannot sign:', (error as Error).message);
  }

  console.log('\n--- JSON Export Demo ---');

  const keyJson = ed25519Key.toJSON();
  console.log('✅ Key exported to JSON:', keyJson);

  console.log('\n--- Verification Method Demo ---');

  const controller = 'did:example:123456';
  const verificationMethod = ed25519Key.toVerificationMethod(controller);
  console.log('✅ Verification method:', verificationMethod);

  console.log('\n--- Unit DNA Demo ---');

  console.log('✅ Unit DNA:', ed25519Key.dna);
  console.log('✅ Unit identity:', ed25519Key.whoami);

  console.log('\n--- External Signer Demo ---');

  // Mock signer for demo
  const mockSigner = {
    sign: async (data: string) => `mock-signature-for-${data.slice(0, 10)}`,
    getPublicKey: () => 'mock-public-key-hex',
    getAlgorithm: () => 'Ed25519'
  };

  const signerKey = Key.createWithSigner('ed25519', 'mock-public-key-hex', mockSigner);
  console.log('✅ Created signer key:', {
    id: signerKey.id,
    type: signerKey.type,
    canSign: signerKey.canSign(),
    publicKey: signerKey.publicKeyHex
  });

  try {
    const signerSignature = await signerKey.sign('test data');
    console.log('✅ Signer signature:', signerSignature);
  } catch (error) {
    console.error('❌ Signer error:', error);
  }

  console.log('\n--- Performance Demo ---');

  const startTime = performance.now();
  const keys = [];
  
  for (let i = 0; i < 100; i++) {
    keys.push(Key.generate('ed25519', { name: `key-${i}` }));
  }
  
  const endTime = performance.now();
  console.log(`✅ Generated 100 keys in ${(endTime - startTime).toFixed(2)}ms`);
  console.log(`✅ Average: ${((endTime - startTime) / 100).toFixed(4)}ms per key`);

  console.log('\n=== Demo Complete ===');
  console.log('💡 Key Benefits Demonstrated:');
  console.log('• Self-documenting with help()');
  console.log('• Secure internal key generation');
  console.log('• No private key exposure');
  console.log('• Multiple key type support');
  console.log('• Type-safe operations');
  console.log('• External signer support');
  console.log('• Unit pattern compliance');
  console.log('• High performance');
}

// Run the demo
demoKey().catch(console.error);
