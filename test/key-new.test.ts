/**
 * Test file for Key unit in @synet/keys
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Key } from '../src/key';
import { Signer } from '../src/signer';
import type { KeyType } from '../src/keys';

describe('Key Unit', () => {
  describe('Static Methods', () => {
    describe('create', () => {
      let publicKey: string;
      let keyType: KeyType;

      beforeEach(() => {
        const signer = Signer.generate('ed25519');
        if (!signer) throw new Error('Failed to generate test signer');
        
        publicKey = signer.getPublicKey();
        keyType = 'ed25519';
      });

      it('should create a public-only key', () => {
        const key = Key.create({
          publicKeyPEM: publicKey,
          keyType: keyType
        });
        
        expect(key).toBeDefined();
        expect(key?.getPublicKey()).toBe(publicKey);
        expect(key?.type).toBe(keyType);
        expect(key?.canSign()).toBe(false);
      });

      it('should accept metadata', () => {
        const meta = { name: 'test-key', purpose: 'testing' };
        const key = Key.create({
          publicKeyPEM: publicKey,
          keyType: keyType,
          meta
        });
        
        expect(key).toBeDefined();
        expect(key?.metadata).toEqual(meta);
      });

      it('should return null for invalid public key', () => {
        const key = Key.create({
          publicKeyPEM: 'invalid-key',
          keyType: keyType
        });
        
        expect(key).toBeNull();
      });

      it('should return null for missing required fields', () => {
        const key = Key.create({
          publicKeyPEM: '',
          keyType: keyType
        });
        
        expect(key).toBeNull();
      });
    });

    describe('createFromSigner', () => {
      let signer: Signer;

      beforeEach(() => {
        const newSigner = Signer.generate('ed25519');
        if (!newSigner) throw new Error('Failed to generate test signer');
        signer = newSigner;
      });

      it('should create key that learns from signer', () => {
        const key = Key.createFromSigner(signer);
        
        expect(key).toBeDefined();
        expect(key?.getPublicKey()).toBe(signer.getPublicKey());
        expect(key?.type).toBe(signer.getAlgorithm());
        expect(key?.canSign()).toBe(true);
      });

      it('should accept metadata', () => {
        const meta = { name: 'signer-key' };
        const key = Key.createFromSigner(signer, meta);
        
        expect(key).toBeDefined();
        expect(key?.metadata).toEqual(meta);
      });

      it('should return null for invalid signer', () => {
        const key = Key.createFromSigner(null as any);
        
        expect(key).toBeNull();
      });
    });

    describe('createPublic', () => {
      let publicKey: string;
      let keyType: KeyType;

      beforeEach(() => {
        const signer = Signer.generate('ed25519');
        if (!signer) throw new Error('Failed to generate test signer');
        
        publicKey = signer.getPublicKey();
        keyType = 'ed25519';
      });

      it('should create public-only key (alias for create)', () => {
        const key = Key.createPublic(publicKey, keyType);
        
        expect(key).toBeDefined();
        expect(key?.getPublicKey()).toBe(publicKey);
        expect(key?.type).toBe(keyType);
        expect(key?.canSign()).toBe(false);
      });
    });
  });

  describe('Instance Methods', () => {
    let publicKey: string;
    let keyType: KeyType;
    let signer: Signer;

    beforeEach(() => {
      const newSigner = Signer.generate('ed25519');
      if (!newSigner) throw new Error('Failed to generate test signer');
      signer = newSigner;
      publicKey = signer.getPublicKey();
      keyType = 'ed25519';
    });

    describe('Public-only key operations', () => {
      let key: Key;

      beforeEach(() => {
        const newKey = Key.create({
          publicKeyPEM: publicKey,
          keyType: keyType
        });
        if (!newKey) throw new Error('Failed to create test key');
        key = newKey;
      });

      describe('verify', () => {
        it('should verify valid signatures', async () => {
          const data = 'Hello, World!';
          const signature = await signer.sign(data);
          
          const isValid = await key.verify(data, signature);
          expect(isValid).toBe(true);
        });

        it('should reject invalid signatures', async () => {
          const data = 'Hello, World!';
          const invalidSignature = 'invalid-signature';
          
          const isValid = await key.verify(data, invalidSignature);
          expect(isValid).toBe(false);
        });

        it('should reject signatures for different data', async () => {
          const data1 = 'Hello, World!';
          const data2 = 'Goodbye, World!';
          const signature = await signer.sign(data1);
          
          const isValid = await key.verify(data2, signature);
          expect(isValid).toBe(false);
        });
      });

      describe('sign (without signer)', () => {
        it('should throw error when trying to sign without signer', async () => {
          await expect(key.sign('test data')).rejects.toThrow();
        });
      });

      describe('getPublicKey', () => {
        it('should return the public key', () => {
          expect(key.getPublicKey()).toBe(publicKey);
        });
      });

      describe('type property', () => {
        it('should return the key type', () => {
          expect(key.type).toBe(keyType);
        });
      });

      describe('canSign', () => {
        it('should return false for public-only key', () => {
          expect(key.canSign()).toBe(false);
        });
      });
    });

    describe('Key with signer (learning)', () => {
      let key: Key;

      beforeEach(() => {
        const newKey = Key.create({
          publicKeyPEM: publicKey,
          keyType: keyType
        });
        if (!newKey) throw new Error('Failed to create test key');
        key = newKey;
      });

      describe('useSigner', () => {
        it('should learn signing from compatible signer', () => {
          const result = key.useSigner(signer);
          
          expect(result).toBe(true);
          expect(key.canSign()).toBe(true);
        });

        it('should reject incompatible signer (different public key)', () => {
          const otherSigner = Signer.generate('ed25519');
          if (!otherSigner) throw new Error('Failed to generate other signer');
          
          const result = key.useSigner(otherSigner);
          
          expect(result).toBe(false);
          expect(key.canSign()).toBe(false);
        });

        it('should handle null signer gracefully', () => {
          const result = key.useSigner(null as any);
          
          expect(result).toBe(false);
          expect(key.canSign()).toBe(false);
        });
      });

      describe('learn', () => {
        it('should learn from signer capabilities', async () => {
          const teacher = signer.teach();
          
          const result = await key.learn([teacher]);
          
          expect(result).toBe(true);
          expect(key.canSign()).toBe(true);
        });

        it('should reject learning from incompatible signer', async () => {
          const otherSigner = Signer.generate('ed25519');
          if (!otherSigner) throw new Error('Failed to generate other signer');
          
          const teacher = otherSigner.teach();
          
          const result = await key.learn([teacher]);
          
          expect(result).toBe(false);
          expect(key.canSign()).toBe(false);
        });

        it('should handle invalid teacher gracefully', async () => {
          const result = await key.learn([]);
          
          expect(result).toBe(false);
          expect(key.canSign()).toBe(false);
        });
      });

      describe('sign (after learning)', () => {
        beforeEach(() => {
          key.useSigner(signer);
        });

        it('should sign data after learning', async () => {
          const data = 'Hello, World!';
          const signature = await key.sign(data);
          
          expect(signature).toBeDefined();
          expect(typeof signature).toBe('string');
          expect(signature.length).toBeGreaterThan(0);
        });

        it('should produce verifiable signatures', async () => {
          const data = 'Hello, World!';
          const signature = await key.sign(data);
          
          const isValid = await key.verify(data, signature);
          expect(isValid).toBe(true);
        });

        it('should produce same signatures as original signer', async () => {
          const data = 'Hello, World!';
          const keySignature = await key.sign(data);
          const signerSignature = await signer.sign(data);
          
          // For deterministic algorithms, signatures should match
          if (keyType === 'ed25519') {
            expect(keySignature).toBe(signerSignature);
          }
        });
      });
    });

    describe('Key created from signer', () => {
      let key: Key;

      beforeEach(() => {
        const newKey = Key.createFromSigner(signer);
        if (!newKey) throw new Error('Failed to create key from signer');
        key = newKey;
      });

      it('should have signing capability from start', () => {
        expect(key.canSign()).toBe(true);
      });

      it('should sign data immediately', async () => {
        const data = 'Hello, World!';
        const signature = await key.sign(data);
        
        expect(signature).toBeDefined();
        expect(typeof signature).toBe('string');
      });

      it('should verify signatures', async () => {
        const data = 'Hello, World!';
        const signature = await key.sign(data);
        
        const isValid = await key.verify(data, signature);
        expect(isValid).toBe(true);
      });

      it('should have same public key as signer', () => {
        expect(key.getPublicKey()).toBe(signer.getPublicKey());
      });

      it('should have same key type as signer', () => {
        expect(key.type).toBe(signer.getAlgorithm());
      });
    });
  });

  describe('Unit Interface', () => {
    let key: Key;
    let signer: Signer;

    beforeEach(() => {
      const newSigner = Signer.generate('ed25519');
      if (!newSigner) throw new Error('Failed to generate test signer');
      signer = newSigner;
      
      const newKey = Key.createFromSigner(signer);
      if (!newKey) throw new Error('Failed to create test key');
      key = newKey;
    });

    describe('execute', () => {
      it('should execute sign instruction', async () => {
        const result = await key.execute('sign', { data: 'Hello, World!' });
        
        expect(result).toBeDefined();
        expect(typeof result).toBe('string');
      });

      it('should execute verify instruction', async () => {
        const data = 'Hello, World!';
        const signature = await key.sign(data);
        
        const result = await key.execute('verify', { data, signature });
        
        expect(result).toBe(true);
      });

      it('should execute getPublicKey instruction', async () => {
        const result = await key.execute('getPublicKey');
        
        expect(result).toBe(key.getPublicKey());
      });

      it('should execute canSign instruction', async () => {
        const result = await key.execute('canSign');
        
        expect(result).toBe(true);
      });

      it('should throw for unknown instructions', async () => {
        await expect(key.execute('unknown')).rejects.toThrow();
      });
    });

    describe('capabilities', () => {
      it('should return list of capabilities', () => {
        const capabilities = key.capabilities();
        
        expect(capabilities).toBeDefined();
        expect(Array.isArray(capabilities)).toBe(true);
        expect(capabilities).toContain('getPublicKey');
        expect(capabilities).toContain('canSign');
        expect(capabilities).toContain('verify');
        expect(capabilities).toContain('sign'); // Should have sign after learning
      });
    });
  });

  describe('Cross-Algorithm Testing', () => {
    const keyTypes: KeyType[] = ['ed25519', 'rsa', 'secp256k1'];

    keyTypes.forEach(keyType => {
      describe(`${keyType} algorithm`, () => {
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

        it('should sign and verify correctly', async () => {
          const data = 'Cross-algorithm test data';
          const signature = await key.sign(data);
          const isValid = await key.verify(data, signature);
          
          expect(isValid).toBe(true);
        });

        it('should have correct key type', () => {
          expect(key.type).toBe(keyType);
        });

        it('should have same public key as signer', () => {
          expect(key.getPublicKey()).toBe(signer.getPublicKey());
        });

        it('should learn from compatible signer', () => {
          const publicOnlyKey = Key.createPublic(signer.getPublicKey(), keyType);
          if (!publicOnlyKey) throw new Error('Failed to create public-only key');
          
          const result = publicOnlyKey.useSigner(signer);
          expect(result).toBe(true);
        });
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid key type gracefully', () => {
      const key = Key.create({
        publicKeyPEM: 'invalid-key',
        keyType: 'invalid' as KeyType
      });
      expect(key).toBeNull();
    });

    it('should handle corrupted public key gracefully', () => {
      const key = Key.create({
        publicKeyPEM: 'corrupted-public-key',
        keyType: 'ed25519'
      });
      expect(key).toBeNull();
    });

    it('should handle learning from invalid signer gracefully', async () => {
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');
      
      const key = Key.createPublic(signer.getPublicKey(), 'ed25519');
      if (!key) throw new Error('Failed to create key');
      
      const invalidTeacher = {
        sign: async () => { throw new Error('Invalid teacher'); },
        getPublicKey: () => 'invalid-key'
      };
      
      const result = await key.learn([invalidTeacher]);
      expect(result).toBe(false);
    });
  });

  describe('Integration Tests', () => {
    it('should work with multiple signers and keys', async () => {
      // Create multiple signers
      const signer1 = Signer.generate('ed25519');
      const signer2 = Signer.generate('rsa');
      
      if (!signer1 || !signer2) throw new Error('Failed to generate signers');
      
      // Create keys from signers
      const key1 = Key.createFromSigner(signer1);
      const key2 = Key.createFromSigner(signer2);
      
      if (!key1 || !key2) throw new Error('Failed to create keys');
      
      // Test signing with both keys
      const data = 'Integration test data';
      const signature1 = await key1.sign(data);
      const signature2 = await key2.sign(data);
      
      // Verify signatures
      const isValid1 = await key1.verify(data, signature1);
      const isValid2 = await key2.verify(data, signature2);
      
      expect(isValid1).toBe(true);
      expect(isValid2).toBe(true);
      
      // Cross-verification should fail
      const crossValid1 = await key1.verify(data, signature2);
      const crossValid2 = await key2.verify(data, signature1);
      
      expect(crossValid1).toBe(false);
      expect(crossValid2).toBe(false);
    });

    it('should handle key learning workflow', async () => {
      // Create signer
      const signer = Signer.generate('ed25519');
      if (!signer) throw new Error('Failed to generate signer');
      
      // Create public-only key
      const publicKey = Key.createPublic(signer.getPublicKey(), 'ed25519');
      if (!publicKey) throw new Error('Failed to create public key');
      
      // Verify it can't sign initially
      expect(publicKey.canSign()).toBe(false);
      
      // Learn from signer
      const learned = publicKey.useSigner(signer);
      expect(learned).toBe(true);
      
      // Verify it can now sign
      expect(publicKey.canSign()).toBe(true);
      
      // Test signing
      const data = 'Learning workflow test';
      const signature = await publicKey.sign(data);
      const isValid = await publicKey.verify(data, signature);
      
      expect(isValid).toBe(true);
    });
  });
});
