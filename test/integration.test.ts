/**
 * Integration test file for Signer and Key units in @synet/keys
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Signer, Key } from '../src/index';
import type { KeyType } from '../src/keys';

describe('Signer-Key Integration', () => {
  describe('Basic Integration', () => {
    let signer: Signer;
    let key: Key;

    beforeEach(() => {
      const newSigner = Signer.generate('ed25519');
      if (!newSigner) throw new Error('Failed to generate test signer');
      signer = newSigner;
      
      const newKey = Key.createFromSigner(signer);
      if (!newKey) throw new Error('Failed to create test key');
      key = newKey;
    });

    it('should create compatible signer and key', () => {
      expect(signer.getPublicKey()).toBe(key.getPublicKey());
      expect(signer.getAlgorithm()).toBe(key.type);
    });

    it('should sign and verify with both signer and key', async () => {
      const data = 'Integration test data';
      
      // Sign with signer
      const signerSignature = await signer.sign(data);
      
      // Sign with key
      const keySignature = await key.sign(data);
      
      // Verify signer signature with key
      const signerVerifyWithKey = await key.verify(data, signerSignature);
      
      // Verify key signature with signer
      const keyVerifyWithSigner = await signer.verify(data, keySignature);
      
      expect(signerVerifyWithKey).toBe(true);
      expect(keyVerifyWithSigner).toBe(true);
    });

    it('should have consistent signatures for deterministic algorithms', async () => {
      const data = 'Deterministic test data';
      
      const signerSignature = await signer.sign(data);
      const keySignature = await key.sign(data);
      
      // For ed25519, signatures should be identical
      expect(signerSignature).toBe(keySignature);
    });
  });

  describe('Learning Workflow', () => {
    it('should demonstrate complete learning workflow', async () => {
      // Step 1: Create signer
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');
      
      // Step 2: Create public-only key
      const publicKey = Key.createPublic(signer.getPublicKey(), 'ed25519');
      if (!publicKey) throw new Error('Failed to create public key');
      
      // Step 3: Verify key can't sign initially
      expect(publicKey.canSign()).toBe(false);
      
      // Step 4: Key learns from signer
      const learned = publicKey.useSigner(signer);
      expect(learned).toBe(true);
      
      // Step 5: Verify key can now sign
      expect(publicKey.canSign()).toBe(true);
      
      // Step 6: Test full signing workflow
      const data = 'Learning workflow test';
      const signature = await publicKey.sign(data);
      const isValid = await publicKey.verify(data, signature);
      
      expect(isValid).toBe(true);
      
      // Step 7: Verify signature is compatible with original signer
      const signerVerify = await signer.verify(data, signature);
      expect(signerVerify).toBe(true);
    });

    it('should prevent learning from incompatible signers', async () => {
      // Create two different signers
      const signer1 = Signer.generate('ed25519');
      const signer2 = Signer.generate('ed25519');
      
      if (!signer1 || !signer2) throw new Error('Failed to generate signers');
      
      // Create key from first signer's public key
      const key = Key.createPublic(signer1.getPublicKey(), 'ed25519');
      if (!key) throw new Error('Failed to create key');
      
      // Try to learn from second signer (incompatible)
      const learned = key.useSigner(signer2);
      expect(learned).toBe(false);
      expect(key.canSign()).toBe(false);
    });
  });

  describe('Teaching Pattern', () => {
    it('should demonstrate teaching pattern between units', async () => {
      // Create signer
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');
      
      // Signer teaches its capabilities
      const teachings = signer.teach();
      expect(teachings).toBeDefined();
      expect(typeof teachings.sign).toBe('function');
      expect(typeof teachings.getPublicKey).toBe('function');
      
      // Create key and learn from teachings
      const key = Key.createPublic(signer.getPublicKey(), 'ed25519');
      if (!key) throw new Error('Failed to create key');
      
      const learned = await key.learn([teachings]);
      expect(learned).toBe(true);
      expect(key.canSign()).toBe(true);
      
      // Test that learned capabilities work
      const data = 'Teaching pattern test';
      const signature = await key.sign(data);
      const isValid = await key.verify(data, signature);
      
      expect(isValid).toBe(true);
    });

    it('should handle key teaching its capabilities', async () => {
      // Create key with signing capability
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');
      
      const key = Key.createFromSigner(signer);
      if (!key) throw new Error('Failed to create key');
      
      // Key teaches its capabilities
      const teachings = key.teach();
      expect(teachings).toBeDefined();
      expect(typeof teachings.sign).toBe('function');
      expect(typeof teachings.getPublicKey).toBe('function');
      expect(typeof teachings.canSign).toBe('function');
      
      // Test taught capabilities
      const data = 'Key teaching test';
      const signature = await teachings.sign(data);
      expect(signature).toBeDefined();
      expect(typeof signature).toBe('string');
      
      const publicKey = teachings.getPublicKey();
      expect(publicKey).toBe(key.getPublicKey());
      
      const canSign = teachings.canSign();
      expect(canSign).toBe(true);
    });
  });

  describe('Cross-Algorithm Integration', () => {
    const keyTypes: KeyType[] = ['ed25519', 'rsa', 'secp256k1'];

    keyTypes.forEach(keyType => {
      describe(`${keyType} integration`, () => {
        let signer: Signer;
        let key: Key;

        beforeEach(() => {
          const newSigner = Signer.generate(keyType);
          if (!newSigner) throw new Error(`Failed to generate ${keyType} signer`);
          signer = newSigner;
          
          const newKey = Key.createFromSigner(signer);
          if (!newKey) throw new Error(`Failed to create ${keyType} key`);
          key = newKey;
        });

        it('should work with signer-key integration', async () => {
          const data = `${keyType} integration test`;
          
          // Sign with both units
          const signerSignature = await signer.sign(data);
          const keySignature = await key.sign(data);
          
          // Cross-verify
          const signerVerifyKey = await signer.verify(data, keySignature);
          const keyVerifySigner = await key.verify(data, signerSignature);
          
          expect(signerVerifyKey).toBe(true);
          expect(keyVerifySigner).toBe(true);
        });

        it('should support teaching/learning pattern', async () => {
          // Create public-only key
          const publicOnlyKey = Key.createPublic(signer.getPublicKey(), keyType);
          if (!publicOnlyKey) throw new Error('Failed to create public key');
          
          // Learn from signer
          const learned = publicOnlyKey.useSigner(signer);
          expect(learned).toBe(true);
          
          // Test learned capabilities
          const data = `${keyType} learning test`;
          const signature = await publicOnlyKey.sign(data);
          const isValid = await publicOnlyKey.verify(data, signature);
          
          expect(isValid).toBe(true);
        });
      });
    });
  });

  describe('Unit Interface Integration', () => {
    it('should work through unit execute interface', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');
      
      const key = Key.createFromSigner(signer);
      if (!key) throw new Error('Failed to create key');
      
      const data = 'Unit interface test';
      
      // Execute through signer unit interface
      const signerSignature = await signer.execute('sign', { data });
      const signerVerify = await signer.execute('verify', { data, signature: signerSignature });
      
      // Execute through key unit interface
      const keySignature = await key.execute('sign', { data });
      const keyVerify = await key.execute('verify', { data, signature: keySignature });
      
      expect(signerVerify).toBe(true);
      expect(keyVerify).toBe(true);
      
      // Cross-verify through unit interface
      const crossVerify1 = await signer.execute('verify', { data, signature: keySignature });
      const crossVerify2 = await key.execute('verify', { data, signature: signerSignature });
      
      expect(crossVerify1).toBe(true);
      expect(crossVerify2).toBe(true);
    });

    it('should list compatible capabilities', () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');
      
      const key = Key.createFromSigner(signer);
      if (!key) throw new Error('Failed to create key');
      
      const signerCapabilities = signer.capabilities();
      const keyCapabilities = key.capabilities();
      
      // Both should have signing capabilities
      expect(signerCapabilities).toContain('sign');
      expect(keyCapabilities).toContain('sign');
      
      // Both should have verification capabilities
      expect(signerCapabilities).toContain('verify');
      expect(keyCapabilities).toContain('verify');
      
      // Both should have public key access
      expect(signerCapabilities).toContain('getPublicKey');
      expect(keyCapabilities).toContain('getPublicKey');
    });
  });

  describe('Error Handling Integration', () => {
    it('should handle incompatible signer-key combinations', async () => {
      const signer1 = Signer.generate('ed25519');
      const signer2 = Signer.generate('rsa');
      
      if (!signer1 || !signer2) throw new Error('Failed to generate signers');
      
      // Create key from first signer
      const key = Key.createFromSigner(signer1);
      if (!key) throw new Error('Failed to create key');
      
      // Try to verify RSA signature with Ed25519 key
      const data = 'Cross-algorithm test';
      const rsaSignature = await signer2.sign(data);
      
      const isValid = await key.verify(data, rsaSignature);
      expect(isValid).toBe(false);
    });

    it('should handle corrupted signatures across units', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');
      
      const key = Key.createFromSigner(signer);
      if (!key) throw new Error('Failed to create key');
      
      const data = 'Corruption test';
      const signature = await signer.sign(data);
      const corruptedSignature = signature.slice(0, -5) + 'XXXXX';
      
      // Both units should reject corrupted signature
      const signerVerify = await signer.verify(data, corruptedSignature);
      const keyVerify = await key.verify(data, corruptedSignature);
      
      expect(signerVerify).toBe(false);
      expect(keyVerify).toBe(false);
    });
  });

  describe('Performance Integration', () => {
    it('should handle bulk operations efficiently', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');
      
      const key = Key.createFromSigner(signer);
      if (!key) throw new Error('Failed to create key');
      
      const testData = Array.from({ length: 10 }, (_, i) => `Test data ${i}`);
      
      // Bulk sign and verify
      const signatures = await Promise.all(
        testData.map(data => key.sign(data))
      );
      
      const verifications = await Promise.all(
        testData.map((data, i) => key.verify(data, signatures[i]))
      );
      
      // All verifications should pass
      expect(verifications.every(v => v)).toBe(true);
      
      // Cross-verify with signer
      const crossVerifications = await Promise.all(
        testData.map((data, i) => signer.verify(data, signatures[i]))
      );
      
      expect(crossVerifications.every(v => v)).toBe(true);
    });
  });
});
