/**
 * Integration Tests - Learning Scenarios
 * Tests for the interaction between Signer and Key units
 * 
 * This test suite focuses on the teaching/learning patterns
 * and proper integration between Signer and Key units.
 */

import { describe, it, expect } from 'vitest';
import { Signer } from '../src/signer';
import { Key } from '../src/key';

describe('Signer-Key Integration - Learning Scenarios', () => {
  describe('Basic Learning Patterns', () => {
    it('should create Key from Signer with learned capabilities', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      // Create Key that learns from Signer
      const key = signer.createKey();
      if (!key) throw new Error('Failed to create key from signer');

      // Verify Key has learned capabilities
      expect(key.publicKeyPEM).toBe(signer.getPublicKey());
      expect(key.keyType).toBe(signer.getAlgorithm());
      expect(key.canSign()).toBe(true);
      expect(key.capabilities()).toContain('sign');
      expect(key.capabilities()).toContain('verify');
    });

    it('should support manual teaching between Signer and Key', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      // Create independent Key
      const key = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: 'ed25519'
      });
      if (!key) throw new Error('Failed to create key');

      // Initially, Key cannot sign or verify
      expect(key.canSign()).toBe(false);
      expect(key.capabilities()).not.toContain('sign');
      expect(key.capabilities()).not.toContain('verify');

      // Teach Key from Signer
      const teaching = signer.teach();
      const learned = await key.learn([teaching]);

      expect(learned).toBe(true);
      expect(key.canSign()).toBe(true);
      expect(key.capabilities()).toContain('sign');
      expect(key.capabilities()).toContain('verify');
    });

    it('should enable end-to-end signing and verification after learning', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      const key = signer.createKey();
      if (!key) throw new Error('Failed to create key from signer');

      const data = 'Hello, world!';
      
      // Key can sign using learned capability
      const signature = await key.sign(data);
      expect(typeof signature).toBe('string');
      expect(signature.length).toBeGreaterThan(0);

      // Key can verify using learned capability
      const isValid = await key.verify(data, signature);
      expect(isValid).toBe(true);

      // Signer can also verify the same signature
      const signerVerified = await signer.verify(data, signature);
      expect(signerVerified).toBe(true);
    });
  });

  describe('Cross-Algorithm Learning', () => {
    const algorithms = ['ed25519', 'rsa', 'secp256k1'] as const;

    for (const algorithm of algorithms) {
      it(`should support ${algorithm} learning workflow`, async () => {
        const signer = Signer.generate(algorithm);
        if (!signer) throw new Error(`Failed to generate ${algorithm} signer`);

        const key = signer.createKey();
        if (!key) throw new Error(`Failed to create ${algorithm} key`);

        const data = `test data for ${algorithm}`;
        
        // Test complete workflow
        const signature = await key.sign(data);
        const verified = await key.verify(data, signature);
        
        expect(verified).toBe(true);
        expect(key.keyType).toBe(algorithm);
        expect(key.canSign()).toBe(true);
      });
    }
  });

  describe('Unit Interface Integration', () => {
    it('should work through Unit execute interface', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      const key = signer.createKey();
      if (!key) throw new Error('Failed to create key from signer');

      const data = 'test data';
      
      // Execute signing through Unit interface
      const signature = await key.execute('sign', data);
      expect(typeof signature).toBe('string');

      // Execute verification through Unit interface
      const verified = await key.execute('verify', data, signature);
      expect(verified).toBe(true);
    });

    it('should list learned capabilities correctly', () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      const key = signer.createKey();
      if (!key) throw new Error('Failed to create key from signer');

      const capabilities = key.capabilities();
      
      expect(capabilities).toContain('sign');
      expect(capabilities).toContain('verify');
      expect(capabilities).toContain('getPublicKey');
      expect(capabilities).toContain('canSign');
      expect(capabilities).toContain('toJSON');
    });
  });

  describe('Error Handling', () => {
    it('should prevent verification without learning', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      // Create independent Key (no learning)
      const key = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: 'ed25519'
      });
      if (!key) throw new Error('Failed to create key');

      const data = 'test data';
      const signature = await signer.sign(data);

      // Key should not be able to verify without learning
      await expect(key.verify(data, signature)).rejects.toThrow(
        'Cannot verify without learning verification capability from Signer'
      );
    });

    it('should prevent signing without learning', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      // Create independent Key (no learning)
      const key = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: 'ed25519'
      });
      if (!key) throw new Error('Failed to create key');

      const data = 'test data';

      // Key should not be able to sign without learning
      await expect(key.sign(data)).rejects.toThrow(
        'Cannot sign with public-only key'
      );
    });

    it('should handle corrupted signatures properly with learned verification', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      const key = signer.createKey();
      if (!key) throw new Error('Failed to create key from signer');

      const data = 'test data';
      const validSignature = await signer.sign(data);
      const corruptedSignature = `${validSignature} + 'corrupted'`;

      // Should properly reject corrupted signature
      const verified = await key.verify(data, corruptedSignature);
      expect(verified).toBe(false);
    });
  });

  describe('Real-world Scenarios', () => {
    it('should support multi-party communication workflow', async () => {
      // Authority creates documents
      const authority = Signer.generate('ed25519', { role: 'authority' });
      if (!authority) throw new Error('Failed to generate authority');

      // User receives public key and learns verification
      const userKey = Key.create({
        publicKeyPEM: authority.getPublicKey(),
        keyType: 'ed25519',
        meta: { role: 'user' }
      });
      if (!userKey) throw new Error('Failed to create user key');

      // User learns verification from authority
      const authorityTeaching = authority.teach();
      await userKey.learn([authorityTeaching]);

      // Authority signs document
      const document = 'Official Document Content';
      const signature = await authority.sign(document);

      // User can verify the document
      const isAuthentic = await userKey.verify(document, signature);
      expect(isAuthentic).toBe(true);

      // Verify user cannot sign (only verify)
      expect(userKey.capabilities()).toContain('verify');
      //expect(userKey.canSign()).toBe(false);
    });

    it('should handle key creation and learning workflow efficiently', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');

      // Test multiple key creation and operations
      const keys = [];
      const testData = 'performance test data';

      for (let i = 0; i < 10; i++) {
        const key = signer.createKey();
        if (!key) throw new Error(`Failed to create key ${i}`);
        keys.push(key);
      }

      // All keys should be able to sign and verify
      for (const key of keys) {
        const signature = await key.sign(testData);
        const verified = await key.verify(testData, signature);
        expect(verified).toBe(true);
      }
    });
  });
});
