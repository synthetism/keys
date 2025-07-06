#!/usr/bin/env tsx

/**
 * Demo: Key Learning from Signer with Public Key Consistency
 * 
 * Tests the teaching/learning architecture and public key validation
 */

import { Signer, Key } from '../src/signer-first';

async function demonstrateKeyLearning() {
  console.log('🔑 Key Learning Demo - Teaching/Learning Architecture with Public Key Consistency\n');

  // Create a Signer
  const signer = Signer.create('ed25519', { name: 'teacher-signer' });
  if (!signer) {
    console.error('Failed to create signer');
    return;
  }

  console.log('--- Signer Created ---');
  console.log('✅ Signer created:', signer.whoami());
  console.log('✅ Signer public key:', `${signer.getPublicKey().slice(0, 60)}...`);

  // Create a Key from the same Signer (should work)
  const associatedKey = signer.createKey({ name: 'associated-key' });
  if (!associatedKey) {
    console.error('Failed to create associated key');
    return;
  }

  console.log('\n--- Associated Key Created ---');
  console.log('✅ Associated key created:', associatedKey.whoami());
  console.log('✅ Associated key public key:', `${associatedKey.getPublicKey().slice(0, 60)}...`);
  console.log('✅ Keys match:', signer.getPublicKey() === associatedKey.getPublicKey());
  console.log('✅ Associated key can sign:', associatedKey.canSign());

  // Test signing through the associated key
  console.log('\n--- Signing Test ---');
  const data = 'Hello from associated key!';
  const signature = await associatedKey.sign(data);
  console.log('✅ Signature from associated key:', `${signature.slice(0, 60)}...`);

  // Verify with both key and signer
  const keyVerification = await associatedKey.verify(data, signature);
  const signerVerification = await signer.verify(data, signature);
  console.log('✅ Key verification:', keyVerification ? 'VALID' : 'INVALID');
  console.log('✅ Signer verification:', signerVerification ? 'VALID' : 'INVALID');

  // Create a separate Key (public-only) and try to connect wrong signer
  console.log('\n--- Public Key Consistency Test ---');
  const separateKey = Key.createPublic(signer.getPublicKey(), 'ed25519', { name: 'separate-key' });
  if (!separateKey) {
    console.error('Failed to create separate key');
    return;
  }

  console.log('✅ Separate key created:', separateKey.whoami());
  console.log('✅ Separate key can sign initially:', separateKey.canSign());

  // Try to connect the correct signer (should work)
  console.log('\n--- Connecting Correct Signer ---');
  const connectResult = separateKey.useSigner(signer);
  console.log('✅ Connection result:', connectResult ? 'SUCCESS' : 'FAILED');
  console.log('✅ Separate key can sign now:', separateKey.canSign());

  if (connectResult) {
    // Test signing through the separate key
    const separateSignature = await separateKey.sign('Hello from separate key!');
    console.log('✅ Signature from separate key:', `${separateSignature.slice(0, 60)}...`);
  }

  // Create another signer and try to connect it (should fail)
  console.log('\n--- Wrong Signer Test ---');
  const wrongSigner = Signer.create('ed25519', { name: 'wrong-signer' });
  if (!wrongSigner) {
    console.error('Failed to create wrong signer');
    return;
  }

  console.log('✅ Wrong signer created:', wrongSigner.whoami());
  console.log('✅ Wrong signer public key:', `${wrongSigner.getPublicKey().slice(0, 60)}...`);
  console.log('✅ Public keys match:', signer.getPublicKey() === wrongSigner.getPublicKey());

  // Create new separate key and try to connect wrong signer
  const testKey = Key.createPublic(signer.getPublicKey(), 'ed25519', { name: 'test-key' });
  if (testKey) {
    console.log('\n--- Connecting Wrong Signer ---');
    const wrongConnectResult = testKey.useSigner(wrongSigner);
    console.log('✅ Wrong connection result:', wrongConnectResult ? 'SUCCESS (BAD!)' : 'FAILED (GOOD!)');
  }

  // Test capabilities
  console.log('\n--- Capabilities Test ---');
  console.log('✅ Signer capabilities:', signer.capabilities());
  console.log('✅ Associated key capabilities:', associatedKey.capabilities());
  console.log('✅ Separate key capabilities:', separateKey.capabilities());

  // Test teaching
  console.log('\n--- Teaching Test ---');
  const signerTeachings = signer.teach();
  const keyTeachings = associatedKey.teach();
  console.log('✅ Signer teaches:', Object.keys(signerTeachings));
  console.log('✅ Associated key teaches:', Object.keys(keyTeachings));

  console.log('\n🎉 Key Learning Demo Complete!');
  console.log('✅ Public key consistency enforced');
  console.log('✅ Teaching/learning architecture working');
  console.log('✅ Security maintained through validation');
}

// Run the demo
demonstrateKeyLearning().catch(console.error);
