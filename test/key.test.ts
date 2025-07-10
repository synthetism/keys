/**
 * Key Unit Tests - Refactored for 1.0.4 Architecture
 * [🔑] Tests the clean, public-facing Key unit
 * 
 * New Architecture:
 * - Key is a clean public key holder with getters only
 * - Key.create() for public keys only
 * - signer.createKey() to create Key with learned signing capabilities
 * - Key learns capabilities via teach/learn pattern
 * - No legacy methods (createFromSigner, useSigner, canSign, etc.)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Key } from '../src/key';
import { Signer } from '../src/signer';

describe('Key Unit - Refactored Architecture', () => {
  let signer: Signer;
  let publicKey: string;
  let keyType: 'ed25519';

  beforeEach(() => {
    const newSigner = Signer.generate('ed25519');
    if (!newSigner) throw new Error('Failed to generate test signer');
    signer = newSigner;
    publicKey = signer.getPublicKey();
    keyType = 'ed25519';
  });

  describe('Static Methods', () => {
    describe('create', () => {
      it('should create a public-only key', () => {
        const key = Key.create({
          publicKeyPEM: publicKey,
          keyType: keyType
        });
        
        expect(key).toBeDefined();
        expect(key?.publicKeyPEM).toBe(publicKey);
        expect(key?.keyType).toBe(keyType);
        expect(key?.keyId).toBeDefined();
        expect(typeof key?.keyId).toBe('string');
      });

      it('should accept metadata', () => {
        const meta = { name: 'test-key', purpose: 'testing' };
        const key = Key.create({
          publicKeyPEM: publicKey,
          keyType: keyType,
          meta
        });
        
        expect(key).toBeDefined();
        expect(key?.meta).toEqual(meta);
      });

      it('should return null for invalid public key', () => {

        expect(() => Key.create({
          publicKeyPEM: 'invalid-key',
          keyType: keyType
        })).toThrow('Invalid public key format for key type: ed25519');    
      });

    });

    describe('signer.createKey() integration', () => {
      it('should create key with learned signing capabilities', () => {
        const key = signer.createKey();
        
        expect(key).toBeDefined();
        expect(key?.publicKeyPEM).toBe(signer.getPublicKey());
        expect(key?.keyType).toBe(signer.getAlgorithm());
      });

      it('should inherit metadata from signer', () => {
        const metaSigner = Signer.generate('ed25519', { name: 'test-signer', purpose: 'testing' });
        if (!metaSigner) throw new Error('Failed to generate meta signer');
        
        const key = metaSigner.createKey();
        
        expect(key).toBeDefined();
        expect(key?.meta).toEqual({ name: 'test-signer', purpose: 'testing' });
      });
    });
  });

  describe('Instance Properties (Getters)', () => {
    let key: Key;

    beforeEach(() => {
      const newKey = Key.create({
        publicKeyPEM: publicKey,
        keyType: keyType,
        meta: { name: 'test-key' }
      });
      if (!newKey) throw new Error('Failed to create test key');
      key = newKey;
    });

    it('should expose publicKeyPEM getter', () => {
      expect(key.publicKeyPEM).toBe(publicKey);
      expect(typeof key.publicKeyPEM).toBe('string');
    });

    it('should expose keyType getter', () => {
      expect(key.keyType).toBe(keyType);
      expect(typeof key.keyType).toBe('string');
    });

    it('should expose keyId getter', () => {
      expect(key.keyId).toBeDefined();
      expect(typeof key.keyId).toBe('string');
      expect(key.keyId.length).toBeGreaterThan(0);
    });

    it('should expose meta getter', () => {
      expect(key.meta).toEqual({ name: 'test-key' });
      expect(typeof key.meta).toBe('object');
    });

    it('should return copies of meta to prevent mutation', () => {
      const meta1 = key.meta;
      const meta2 = key.meta;
      
      expect(meta1).toEqual(meta2);
      expect(meta1).not.toBe(meta2); // Different object references
    });
  });

  describe('Unit Interface', () => {
    let key: Key;

    beforeEach(() => {
      const newKey = Key.create({
        publicKeyPEM: publicKey,
        keyType: keyType
      });
      if (!newKey) throw new Error('Failed to create test key');
      key = newKey;
    });

    it('should have unit identity', () => {
      const identity = key.whoami();
      expect(identity).toContain('[🔑] Key Unit');
      expect(identity).toContain('ed25519');
    });

    it('should list capabilities', () => {
      const capabilities = key.capabilities();
      expect(Array.isArray(capabilities)).toBe(true);
      expect(capabilities.length).toBeGreaterThan(0);
    });

    it('should provide teaching contract', () => {
      const teaching = key.teach();
      expect(teaching).toBeDefined();
      expect(teaching.unitId).toBeDefined();
      expect(teaching.capabilities).toBeDefined();
      expect(typeof teaching.capabilities).toBe('object');
    });

    it('should support JSON serialization', () => {
      const json = key.toJSON();
      expect(json).toBeDefined();
      expect(json.unitId).toBe('key-unit');
      expect(json.keyId).toBe(key.keyId);
      expect(json.publicKeyPEM).toBe(key.publicKeyPEM);
      expect(json.keyType).toBe(key.keyType);
    });
  });

  describe('Teaching and Learning', () => {
    it('should demonstrate Key learning from Signer', async () => {
      // Create a public-only Key
      const publicKey = Key.create({
        publicKeyPEM: signer.getPublicKey(),
        keyType: signer.getAlgorithm() as 'ed25519'
      });
      if (!publicKey) throw new Error('Failed to create public key');

      // Get teaching from Signer
      const signerTeaching = signer.teach();
      expect(signerTeaching).toBeDefined();
      expect(signerTeaching.capabilities).toBeDefined();

      // Key can learn from Signer's teaching
      const learned = await publicKey.learn([signerTeaching]);
      expect(learned).toBe(true);
    });

    it('should demonstrate complete workflow', () => {
      // 1. Create Signer (primary cryptographic engine)
      const mySigner = Signer.generate('ed25519', { name: 'main-signer' });
      if (!mySigner) throw new Error('Failed to generate signer');

      // 2. Create Key from Signer (gets signing capabilities)
      const myKey = mySigner.createKey();
      if (!myKey) throw new Error('Failed to create key');

      // 3. Verify Key properties
      expect(myKey.publicKeyPEM).toBe(mySigner.getPublicKey());
      expect(myKey.keyType).toBe(mySigner.getAlgorithm());
      expect(myKey.meta).toEqual({ name: 'main-signer' });

      // 4. Both units can teach their capabilities
      const signerTeaching = mySigner.teach();
      const keyTeaching = myKey.teach();
      
      expect(signerTeaching.capabilities).toBeDefined();
      expect(keyTeaching.capabilities).toBeDefined();
    });
  });

  describe('Cross-Algorithm Testing', () => {
    const algorithms: Array<'ed25519' | 'rsa' | 'secp256k1'> = ['ed25519', 'rsa', 'secp256k1'];

    for (const algorithm of algorithms) {
      describe(`${algorithm} algorithm`, () => {
        let algorithmSigner: Signer;
        let algorithmKey: Key;

        beforeEach(() => {
          const newSigner = Signer.generate(algorithm);
          if (!newSigner) throw new Error(`Failed to generate ${algorithm} signer`);
          algorithmSigner = newSigner;
          
          const newKey = algorithmSigner.createKey();
          if (!newKey) throw new Error(`Failed to create ${algorithm} key`);
          algorithmKey = newKey;
        });

        it('should create key with correct properties', () => {
          expect(algorithmKey.publicKeyPEM).toBe(algorithmSigner.getPublicKey());
          expect(algorithmKey.keyType).toBe(algorithm);
          expect(algorithmKey.keyId).toBeDefined();
        });

        it('should support unit operations', () => {
          expect(algorithmKey.whoami()).toContain(algorithm);
          expect(algorithmKey.capabilities()).toBeInstanceOf(Array);
          expect(algorithmKey.teach()).toBeDefined();
        });
      });
    }
  });

  describe('Error Handling', () => {
    it('should handle invalid key type gracefully', () => {
      expect(() => Key.create({
        publicKeyPEM: publicKey,
        keyType: 'invalid' as unknown as 'ed25519'
      })).toThrow('Invalid key type: invalid');
    });

    it('should handle corrupted public key gracefully', () => {
      expect(() => Key.create({
        publicKeyPEM: 'not-a-valid-pem-key',
        keyType: keyType
      })).toThrow('Invalid public key format for key type: ed25519');

    });

    it('should handle missing required fields gracefully', () => {
      
      expect(() => Key.create({
        publicKeyPEM: '',
        keyType: keyType
      })).toThrow('Invalid parameters, publicKeyPEM and keyType are required');

      expect(() => Key.create({
        publicKeyPEM: publicKey,
        keyType: '' as unknown as 'ed25519'
      })).toThrow('Invalid parameters, publicKeyPEM and keyType are required');
      
   
    });
  });

  describe('Integration Tests', () => {
    it('should work with multiple signers and keys', () => {
      // Generate multiple signers
      const signer1 = Signer.generate('ed25519', { name: 'signer-1' });
      const signer2 = Signer.generate('ed25519', { name: 'signer-2' });
      
      if (!signer1 || !signer2) throw new Error('Failed to generate signers');

      // Create keys from signers
      const key1 = signer1.createKey();
      const key2 = signer2.createKey();
      
      if (!key1 || !key2) throw new Error('Failed to create keys');

      // Verify properties
      expect(key1.publicKeyPEM).toBe(signer1.getPublicKey());
      expect(key2.publicKeyPEM).toBe(signer2.getPublicKey());
      expect(key1.meta).toEqual({ name: 'signer-1' });
      expect(key2.meta).toEqual({ name: 'signer-2' });
      
      // Keys should have different IDs
      expect(key1.keyId).not.toBe(key2.keyId);
    });

    it('should handle key creation workflow', () => {
      // Step 1: Generate Signer
      const mySigner = Signer.generate('ed25519', { purpose: 'workflow-test' });
      if (!mySigner) throw new Error('Failed to generate signer');

      // Step 2: Create Key from Signer
      const myKey = mySigner.createKey();
      if (!myKey) throw new Error('Failed to create key from signer');

      // Step 3: Also create public-only key
      const publicOnlyKey = Key.create({
        publicKeyPEM: mySigner.getPublicKey(),
        keyType: mySigner.getAlgorithm() as 'ed25519',
        meta: { type: 'public-only' }
      });
      if (!publicOnlyKey) throw new Error('Failed to create public-only key');

      // Both keys should have same public material
      expect(myKey.publicKeyPEM).toBe(publicOnlyKey.publicKeyPEM);
      expect(myKey.keyType).toBe(publicOnlyKey.keyType);
      
      // But different metadata
      expect(myKey.meta).toEqual({ purpose: 'workflow-test' });
      expect(publicOnlyKey.meta).toEqual({ type: 'public-only' });
    });
  });
});
