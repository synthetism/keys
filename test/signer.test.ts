import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Signer } from '../src/signer';
import type { KeyType } from '../src/keys';

describe('Signer Unit', () => {
  describe('Static Methods', () => {
    describe('generate', () => {
      it('should generate a signer with ed25519 key type', () => {
        const signer = Signer.generate('ed25519', { name: 'test-signer' });
        
        expect(signer).toBeDefined();
        expect(signer).not.toBeNull();
        expect(signer!.getPublicKey()).toBeDefined();
        expect(signer!.type).toBe('ed25519');
      });
      
      it('should generate a signer with rsa key type', () => {
        const signer = Signer.generate('rsa', { name: 'test-signer' });
        
        expect(signer).toBeDefined();
        expect(signer).not.toBeNull();
        expect(signer!.getPublicKey()).toBeDefined();
        expect(signer!.type).toBe('rsa');
      });
      
      it('should generate a signer with secp256k1 key type', () => {
        const signer = Signer.generate('secp256k1', { name: 'test-signer' });
        
        expect(signer).toBeDefined();
        expect(signer).not.toBeNull();
        expect(signer!.getPublicKey()).toBeDefined();
        expect(signer!.type).toBe('secp256k1');
      });
      
      it('should accept metadata', () => {
        const meta = { name: 'test-signer', purpose: 'authentication' };
        const signer = Signer.generate('ed25519', meta);
        
        expect(signer).not.toBeNull();
        expect(signer!.metadata).toEqual(meta);
      });

      it('should throw on invalid key type', () => {
        expect(() => Signer.generate('invalid' as KeyType, {})).toThrow('Failed to generate key pair');
      });
    });
    
    describe('create', () => {
      it('should create signer from existing key pair', () => {
        const originalSigner = Signer.generate('ed25519');
        expect(originalSigner).not.toBeNull();
        
        const publicKey = originalSigner!.getPublicKey();
        const privateKey = (originalSigner as any).privateKeyPEM; // Access private for testing
        
        const signer = Signer.create(privateKey, publicKey, 'ed25519', { name: 'restored-signer' });
        
        expect(signer).toBeDefined();
        expect(signer).not.toBeNull();
        expect(signer!.getPublicKey()).toBe(publicKey);
        expect(signer!.metadata.name).toBe('restored-signer');
      });
      
      it('should create signer even with invalid key pair (validation is deferred)', () => {
        const signer = Signer.create('invalid-private', 'invalid-public', 'ed25519', {});
        
        // Creation succeeds but operations might fail later
        expect(signer).toBeDefined();
        expect(signer).not.toBeNull();
      });
    });
    
    describe('createFromKeyPair', () => {
      it('should create signer from key pair (alias for create)', () => {
        const originalSigner = Signer.generate('ed25519');
        expect(originalSigner).not.toBeNull();
        
        const publicKey = originalSigner!.getPublicKey();
        const privateKey = (originalSigner as any).privateKeyPEM; // Access private for testing
        
        const signer = Signer.createFromKeyPair(privateKey, publicKey, 'ed25519', { name: 'restored-signer' });
        
        expect(signer).toBeDefined();
        expect(signer).not.toBeNull();
        expect(signer!.getPublicKey()).toBe(publicKey);
      });
    });
  });
  
  describe('Instance Methods', () => {
    let signer: Signer;
    
    beforeEach(() => {
      const created = Signer.generate('ed25519', { name: 'test-signer' });
      expect(created).not.toBeNull();
      signer = created!;
    });
    
    describe('sign', () => {
      it('should sign string data', async () => {
        const data = 'test data';
        const signature = await signer.sign(data);
        
        expect(signature).toBeDefined();
        expect(typeof signature).toBe('string');
        expect(signature.length).toBeGreaterThan(0);
      });
      
      it('should produce consistent signatures for deterministic algorithms', async () => {
        const data = 'test data';
        const signature1 = await signer.sign(data);
        const signature2 = await signer.sign(data);
        
        // Ed25519 is deterministic
        expect(signature1).toBe(signature2);
      });
    });
    
    describe('verify', () => {
      it('should verify valid signatures', async () => {
        const data = 'test data';
        const signature = await signer.sign(data);
        
        const isValid = await signer.verify(data, signature);
        expect(isValid).toBe(true);
      });
      
      it('should reject invalid signatures', async () => {
        const data = 'test data';
        const invalidSignature = 'invalid-signature';
        
        const isValid = await signer.verify(data, invalidSignature);
        expect(isValid).toBe(false);
      });
      
      it('should reject signatures for different data', async () => {
        const data1 = 'test data 1';
        const data2 = 'test data 2';
        const signature = await signer.sign(data1);
        
        const isValid = await signer.verify(data2, signature);
        expect(isValid).toBe(false);
      });
    });
    
    describe('getPublicKey', () => {
      it('should return the public key', () => {
        const publicKey = signer.getPublicKey();
        expect(publicKey).toBeDefined();
        expect(typeof publicKey).toBe('string');
        expect(publicKey.length).toBeGreaterThan(0);
      });
      
      it('should return consistent public key', () => {
        const publicKey1 = signer.getPublicKey();
        const publicKey2 = signer.getPublicKey();
        expect(publicKey1).toBe(publicKey2);
      });
    });
    
    describe('getAlgorithm', () => {
      it('should return the algorithm type', () => {
        const algorithm = signer.getAlgorithm();
        expect(algorithm).toBe('ed25519');
      });
    });
    
    describe('type property', () => {
      it('should return the key type', () => {
        expect(signer.type).toBe('ed25519');
      });
    });
    
    describe('teach', () => {
      it('should teach capabilities to learner', () => {
        const teachingFunctions = signer.teach();
        
        console.log('Teaching Functions:', teachingFunctions);
        expect(teachingFunctions).toBeDefined();
        expect(typeof teachingFunctions).toBe('object');
        expect(teachingFunctions.capabilities.sign).toBeDefined();
        //expect(teachingFunctions.getPublicKey).toBeDefined();
        //expect(teachingFunctions.verify).toBeDefined();
        //expect(teachingFunctions.getAlgorithm).toBeDefined();
      });
    });
  });
  
  describe('Unit Interface', () => {
    let signer: Signer;
    
    beforeEach(() => {
      const created = Signer.generate('ed25519', { name: 'test-signer' });
      expect(created).not.toBeNull();
      signer = created!;
    });
    
    describe('execute', () => {
      it('should execute sign instruction', async () => {
        const data = 'test data';
        const signature = await signer.execute('sign', data);
        
        expect(signature).toBeDefined();
        expect(typeof signature).toBe('string');
      });
      
      it('should execute verify instruction', async () => {
        const data = 'test data';
        const signature = await signer.sign(data);
        
        const result = await signer.execute('verify', data, signature);
        expect(result).toBe(true);
      });
      
      it('should execute getPublicKey instruction', async () => {
        const publicKey = await signer.execute('getPublicKey');
        expect(publicKey).toBeDefined();
        expect(typeof publicKey).toBe('string');
      });
      
      it('should execute getAlgorithm instruction', async () => {
        const algorithm = await signer.execute('getAlgorithm');
        expect(algorithm).toBe('ed25519');
      });
      
      it('should throw for unknown instructions', async () => {
        await expect(signer.execute('unknown')).rejects.toThrow();
      });
    });
    
    describe('capabilities', () => {
      it('should return list of capabilities', () => {
        const capabilities = signer.capabilities();
        expect(capabilities).toContain('sign');
        expect(capabilities).toContain('verify');
        expect(capabilities).toContain('getPublicKey');
        expect(capabilities).toContain('getAlgorithm');
      });
    });
  });
  
  describe('Cross-Algorithm Testing', () => {
    const algorithms: KeyType[] = ['ed25519', 'rsa', 'secp256k1'];
    
    algorithms.forEach(algorithm => {
      describe(`${algorithm} algorithm`, () => {
        let signer: Signer;
        
        beforeEach(() => {
          const created = Signer.generate(algorithm, { name: `test-${algorithm}` });
          expect(created).not.toBeNull();
          signer = created!;
        });
        
        it('should sign and verify correctly', async () => {
          const data = 'test data';
          const signature = await signer.sign(data);
          const isValid = await signer.verify(data, signature);
          
          expect(isValid).toBe(true);
        });
        
        it('should have correct key type', () => {
          expect(signer.type).toBe(algorithm);
        });
        
        it('should have valid public key', () => {
          const publicKey = signer.getPublicKey();
          expect(publicKey).toBeDefined();
          expect(publicKey.length).toBeGreaterThan(0);
        });
      });
    });
  });
  
  describe('Error Handling', () => {
    it('should throw on invalid key type', () => {
      expect(() => Signer.generate('invalid' as KeyType, {})).toThrow('Failed to generate key pair');
    });
    
    it('should create signer even with corrupted key data (validation is deferred)', () => {
      const signer = Signer.create('corrupted-private-key', 'corrupted-public-key', 'ed25519', {});
      
      // Creation succeeds but operations might fail later
      expect(signer).toBeDefined();
      expect(signer).not.toBeNull();
    });
  });
  
  describe('Integration Tests', () => {
    it('should work with multiple signers', async () => {
      const signer1 = Signer.generate('ed25519');
      const signer2 = Signer.generate('rsa');
      const signer3 = Signer.generate('secp256k1');
      
      expect(signer1).not.toBeNull();
      expect(signer2).not.toBeNull();
      expect(signer3).not.toBeNull();
      
      const data = 'test data';
      
      // All should sign and verify correctly
      for (const signer of [signer1!, signer2!, signer3!]) {
        const signature = await signer.sign(data);
        const isValid = await signer.verify(data, signature);
        expect(isValid).toBe(true);
      }
    });
  });
});
