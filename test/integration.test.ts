/**
 * Signer-Key Integration Tests - New 1.0.4 Architecture
 * [🔐🔑] Tests the interaction between Signer and Key units
 * 
 * Focus:
 * - Signer as primary cryptographic engine
 * - Key as clean public-facing unit
 * - Teaching/Learning patterns
 * - Real-world workflows
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Key } from '../src/key';
import { Signer } from '../src/signer';

describe('Signer-Key Integration - New Architecture', () => {
  describe('Basic Integration', () => {
    it('should create compatible Signer and Key', () => {
      // Generate Signer
      const signer = Signer.generate('ed25519', { name: 'test-signer' });
      if (!signer) throw new Error('Failed to generate signer');

      // Create Key from Signer's public material
      const key = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: signer.getAlgorithm() as 'ed25519'
      });
      if (!key) throw new Error('Failed to create key');

      // They should be compatible
      expect(key.publicKeyPEM).toBe(signer.getPublicKey());
      expect(key.keyType).toBe(signer.getAlgorithm());
    });

    it('should support signing with Signer and verification with Key', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      const key = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: signer.getAlgorithm() as 'ed25519'
      });
      if (!key) throw new Error('Failed to create key');

      // Sign with Signer, verify with Key
      const data = 'Hello, world!';
      const signature = await signer.sign(data);
      const isValid = await key.verify(data, signature);

      expect(isValid).toBe(true);
    });

    it('should maintain signature consistency', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      const key = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: signer.getAlgorithm() as 'ed25519'
      });
      if (!key) throw new Error('Failed to create key');

      const data = 'consistent message';
      
      // Multiple signatures should all verify
      const sig1 = await signer.sign(data);
      const sig2 = await signer.sign(data);
      
      expect(await key.verify(data, sig1)).toBe(true);
      expect(await key.verify(data, sig2)).toBe(true);
    });
  });

  describe('Teaching and Learning Patterns', () => {
    it('should support Signer teaching Key', async () => {
      const signer = Signer.generate('ed25519', { role: 'teacher' });
      if (!signer) throw new Error('Failed to generate signer');

      const key = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: signer.getAlgorithm() as 'ed25519',
        meta: { role: 'learner' }
      });
      if (!key) throw new Error('Failed to create key');

      // Get Signer's teachings
      const teachings = signer.teach();
      expect(teachings).toBeDefined();
      expect(teachings.unitId).toBeDefined();
      expect(teachings.capabilities).toBeDefined();

      // Key can learn from Signer
      const learned = await key.learn([teachings]);
      expect(learned).toBe(true);
    });

    it('should support bidirectional teaching', () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      const key = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: signer.getAlgorithm() as 'ed25519'
      });
      if (!key) throw new Error('Failed to create key');

      // Both can teach their capabilities
      const signerTeachings = signer.teach();
      const keyTeachings = key.teach();

      expect(signerTeachings.capabilities).toBeDefined();
      expect(keyTeachings.capabilities).toBeDefined();

      // Signer teaches signing capabilities
      expect(typeof signerTeachings.capabilities.sign).toBe('function');
      expect(typeof signerTeachings.capabilities.verify).toBe('function');

      // Key teaches public info
      expect(typeof keyTeachings.capabilities.getPublicKey).toBe('function');
    });
  });

  describe('Cross-Algorithm Integration', () => {
    const algorithms: Array<'ed25519' | 'rsa' | 'secp256k1'> = ['ed25519', 'rsa', 'secp256k1'];

    for (const algorithm of algorithms) {
      describe(`${algorithm} integration`, () => {
        it(`should work with ${algorithm} Signer and Key`, async () => {
          const signer = Signer.generate(algorithm);
          if (!signer) throw new Error(`Failed to generate ${algorithm} signer`);

          const key = Key.create({
            publicKeyPEM: signer.getPublicKey(),
            keyType: algorithm
          });
          if (!key) throw new Error(`Failed to create ${algorithm} key`);

          // Test integration
          const data = `Testing ${algorithm} integration`;
          const signature = await signer.sign(data);
          const verified = await key.verify(data, signature);

          expect(verified).toBe(true);
          expect(key.keyType).toBe(algorithm);
          expect(signer.getAlgorithm()).toBe(algorithm);
        });

        it(`should support ${algorithm} teaching/learning`, async () => {
          const signer = Signer.generate(algorithm);
          if (!signer) throw new Error(`Failed to generate ${algorithm} signer`);

          const key = Key.create({
            publicKeyPEM: signer.getPublicKey(),
            keyType: algorithm
          });
          if (!key) throw new Error(`Failed to create ${algorithm} key`);

          const teachings = signer.teach();
          const learned = await key.learn([teachings]);

          expect(learned).toBe(true);
        });
      });
    }
  });

  describe('Unit Interface Integration', () => {
    it('should work through Unit execute interface', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      const key = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: signer.getAlgorithm() as 'ed25519'
      });
      if (!key) throw new Error('Failed to create key');

      // Test through execute interface
      const data = 'execute interface test';
      
      // Signer can sign through execute
      const signature = await signer.execute('sign', data);
      expect(typeof signature).toBe('string');

      // Key can verify through execute
      const verified = await key.execute('verify', data, signature);
      expect(verified).toBe(true);

      // Key can get public key through execute
      const publicKey = await key.execute('getPublicKey');
      expect(publicKey).toBe(key.publicKeyPEM);
    });

    it('should list compatible capabilities', () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      const key = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: signer.getAlgorithm() as 'ed25519'
      });
      if (!key) throw new Error('Failed to create key');

      const signerCaps = signer.capabilities();
      const keyCaps = key.capabilities();

      // Signer should have signing capabilities
      expect(signerCaps).toContain('sign');
      expect(signerCaps).toContain('verify');
      expect(signerCaps).toContain('getPublicKey');

      // Key should have verification capabilities
      expect(keyCaps).toContain('verify');
      expect(keyCaps).toContain('getPublicKey');
    });
  });

  describe('Error Handling Integration', () => {
    it('should handle incompatible Signer-Key combinations', async () => {
      // Create two different signers
      const signer1 = Signer.generate('ed25519');
      const signer2 = Signer.generate('ed25519');
      
      if (!signer1 || !signer2) throw new Error('Failed to generate signers');

      // Create key from first signer's public key
      const key = Key.create({
        publicKeyPEM: signer1.getPublicKey(),
        keyType: 'ed25519'
      });
      if (!key) throw new Error('Failed to create key');

      // Sign with second signer (different key)
      const data = 'test data';
      const signature = await signer2.sign(data);

      // Verification should fail (wrong key)
      const verified = await key.verify(data, signature);
      expect(verified).toBe(false);
    });

    it('should handle corrupted signatures', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      const key = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: 'ed25519'
      });
      if (!key) throw new Error('Failed to create key');

      const data = 'test data';
      
      // Create valid signature then corrupt it
      const validSignature = await signer.sign(data);
      const corruptedSignature = validSignature + 'corrupted';

      // Should not throw, just return false
      const verified = await key.verify(data, corruptedSignature);
      expect(verified).toBe(false);
    });
  });

  describe('Real-world Scenarios', () => {
    it('should support document signing workflow', async () => {
      // 1. Authority generates signing key
      const authoritySigner = Signer.generate('rsa', {
        organization: 'Certificate Authority',
        purpose: 'document-signing'
      });
      if (!authoritySigner) throw new Error('Failed to generate authority signer');

      // 2. Public key is distributed for verification
      const publicKey = Key.create({
        publicKeyPEM: authoritySigner.getPublicKey(),
        keyType: 'rsa',
        meta: {
          organization: 'Certificate Authority',
          purpose: 'signature-verification',
          distributed: new Date().toISOString()
        }
      });
      if (!publicKey) throw new Error('Failed to create public key');

      // 3. Authority signs documents
      const document1 = 'Certificate for example.com';
      const document2 = 'Certificate for test.org';
      
      const signature1 = await authoritySigner.sign(document1);
      const signature2 = await authoritySigner.sign(document2);

      // 4. Anyone can verify with public key
      expect(await publicKey.verify(document1, signature1)).toBe(true);
      expect(await publicKey.verify(document2, signature2)).toBe(true);

      // 5. Invalid documents/signatures are rejected
      expect(await publicKey.verify(document1, signature2)).toBe(false);
      expect(await publicKey.verify('forged document', signature1)).toBe(false);
    });

    it('should support multi-party communication', async () => {
      // Create multiple parties
      const alice = Signer.generate('ed25519', { name: 'Alice' });
      const bob = Signer.generate('ed25519', { name: 'Bob' });
      const charlie = Signer.generate('ed25519', { name: 'Charlie' });

      if (!alice || !bob || !charlie) throw new Error('Failed to generate signers');

      // Each party creates public keys for others
      const alicePublicKey = Key.create({
        publicKeyPEM: alice.getPublicKey(),
        keyType: 'ed25519',
        meta: { owner: 'Alice', purpose: 'identity-verification' }
      });

      const bobPublicKey = Key.create({
        publicKeyPEM: bob.getPublicKey(),
        keyType: 'ed25519',
        meta: { owner: 'Bob', purpose: 'identity-verification' }
      });

      if (!alicePublicKey || !bobPublicKey) throw new Error('Failed to create public keys');

      // Alice signs a message
      const message = 'Hello Bob, this is Alice';
      const aliceSignature = await alice.sign(message);

      // Bob can verify Alice's message
      const verifiedByBob = await alicePublicKey.verify(message, aliceSignature);
      expect(verifiedByBob).toBe(true);

      // Bob signs a response
      const response = 'Hello Alice, this is Bob responding';
      const bobSignature = await bob.sign(response);

      // Alice can verify Bob's response
      const verifiedByAlice = await bobPublicKey.verify(response, bobSignature);
      expect(verifiedByAlice).toBe(true);

      // Charlie cannot forge Alice's signature
      const charlieForgedSignature = await charlie.sign(message);
      const charlieForgeVerification = await alicePublicKey.verify(message, charlieForgedSignature);
      expect(charlieForgeVerification).toBe(false);
    });

    it('should handle high-volume operations efficiently', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      const key = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: 'ed25519'
      });
      if (!key) throw new Error('Failed to create key');

      // Test bulk operations
      const messages = Array.from({ length: 10 }, (_, i) => `Message ${i}`);
      
      // Sign all messages
      const signatures = await Promise.all(
        messages.map(msg => signer.sign(msg))
      );

      // Verify all signatures
      const verifications = await Promise.all(
        messages.map((msg, i) => key.verify(msg, signatures[i]))
      );

      // All should be valid
      expect(verifications.every(v => v === true)).toBe(true);
      expect(signatures.length).toBe(messages.length);
    });
  });
});
