#!/usr/bin/env tsx

/**
 * Demo: Fully Self-Contained Signer Unit
 * 
 * Shows how the Signer unit can sign and verify data using 
 * built-in cryptographic operations for all supported key types.
 */

import { Signer } from '../src/signer';
import { Key } from '../src/key';

async function demonstrateSignerUnit() {
  console.log('🔐 Signer Unit Demo - Self-Contained Cryptographic Engine\n');

  // Test Ed25519 signing
  console.log('--- Ed25519 Signing ---');
  const ed25519Signer = Signer.generate('ed25519', { name: 'test-ed25519' });
  if (ed25519Signer) {
    console.log('✅ Ed25519 Signer generated:', ed25519Signer.whoami());
    
    const data = 'Hello, cryptographic world!';
    const signature = await ed25519Signer.sign(data);
    console.log('✅ Signature created:', `${signature.slice(0, 60)}...`);
    
    const isValid = await ed25519Signer.verify(data, signature);
    console.log('✅ Signature verification:', isValid ? 'VALID' : 'INVALID');
    
    const isTampered = await ed25519Signer.verify('tampered data', signature);
    console.log('✅ Tampered data verification:', isTampered ? 'VALID' : 'INVALID (as expected)');
  }

  console.log('\n--- RSA Signing ---');
  const rsaSigner = Signer.generate('rsa', { name: 'test-rsa' });
  if (rsaSigner) {
    console.log('✅ RSA Signer generated:', rsaSigner.whoami());
    
    const data = 'RSA signing test data';
    const signature = await rsaSigner.sign(data);
    console.log('✅ RSA Signature created:', `${signature.slice(0, 60)}...`);
    
    const isValid = await rsaSigner.verify(data, signature);
    console.log('✅ RSA Signature verification:', isValid ? 'VALID' : 'INVALID');
  }

  console.log('\n--- secp256k1 Signing ---');
  const secp256k1Signer = Signer.generate('secp256k1', { name: 'test-secp256k1' });
  if (secp256k1Signer) {
    console.log('✅ secp256k1 Signer generated:', secp256k1Signer.whoami());
    
    const data = 'Bitcoin-style signing test';
    const signature = await secp256k1Signer.sign(data);
    console.log('✅ secp256k1 Signature created:', `${signature.slice(0, 60)}...`);
    
    const isValid = await secp256k1Signer.verify(data, signature);
    console.log('✅ secp256k1 Signature verification:', isValid ? 'VALID' : 'INVALID');
  }

  console.log('\n--- Unit Operations ---');
  if (ed25519Signer) {
    console.log('✅ Capabilities:', ed25519Signer.capabilities());
    
    // Test execute
    const publicKey = await ed25519Signer.execute('getPublicKey') as string;
    console.log('✅ Public key via execute:', `${publicKey.slice(0, 60)}...`);
    
    // Test teach
    const teacherCapabilities = ed25519Signer.teach();
    console.log('✅ Taught capabilities:', Object.keys(teacherCapabilities));
    
    // Test JSON export
    const exported = ed25519Signer.toJSON();
    console.log('✅ JSON export (no private key):', {
      id: exported.id,
      type: exported.type,
      canSign: exported.canSign
    });
  }

  console.log('\n--- Key Creation ---');
  if (ed25519Signer) {
    // Create associated Key using proper static method
    const associatedKey = Key.createFromSigner(ed25519Signer, { name: 'associated-key' });
    if (associatedKey) {
      console.log('✅ Associated Key created:', associatedKey.whoami());
      console.log('✅ Key can sign:', associatedKey.canSign());
      
      // Test signing through the key
      const keySignature = await associatedKey.sign('data from key');
      console.log('✅ Key signature:', `${keySignature.slice(0, 60)}...`);
    }
  }

  console.log('\n🎉 Signer Unit Demo Complete!');
  console.log('The Signer is now a fully self-contained cryptographic engine.');
}

// Run the demo
demonstrateSignerUnit().catch(console.error);
