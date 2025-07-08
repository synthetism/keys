/**
 * Verification Functions Test Suite
 * Tests for the pure verification functions in verify.ts
 * 
 * This test suite focuses on the cryptographic verification functions
 * in isolation, ensuring they work correctly and securely.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { 
  isValidBase64, 
  verifyEd25519, 
  verifyRSA, 
  verifySecp256k1, 
  verifySignature 
} from '../src/verify';
import { Signer } from '../src/signer';

describe('Verification Functions', () => {
  describe('isValidBase64', () => {
    it('should validate correct base64 strings', () => {
      expect(isValidBase64('SGVsbG8gV29ybGQ=')).toBe(true);
      expect(isValidBase64('dGVzdA==')).toBe(true);
      expect(isValidBase64('YWJjZGVmZ2hpams=')).toBe(true);
    });

    it('should reject invalid base64 strings', () => {
      expect(isValidBase64('SGVsbG8gV29ybGQ= + corrupted')).toBe(false);
      expect(isValidBase64('not-base64!')).toBe(false);
      expect(isValidBase64('SGVsbG8gV29ybGQ=====')).toBe(false); // Too many padding chars
      expect(isValidBase64('')).toBe(false);
    });

    it('should reject strings with invalid characters', () => {
      expect(isValidBase64('SGVsbG8@V29ybGQ=')).toBe(false);
      expect(isValidBase64('SGVsbG8 V29ybGQ=')).toBe(false);
      expect(isValidBase64('SGVsbG8\nV29ybGQ=')).toBe(false);
    });
  });

  describe('verifyEd25519', () => {
    let signer: Signer;
    let publicKey: string;
    let testData: string;
    let validSignature: string;

    beforeEach(async () => {
      signer = Signer.generate('ed25519')!;
      publicKey = signer.getPublicKey();
      testData = 'test data for ed25519';
      validSignature = await signer.sign(testData);
    });

    it('should verify valid Ed25519 signatures', () => {
      expect(verifyEd25519(testData, validSignature, publicKey)).toBe(true);
    });

    it('should reject invalid Ed25519 signatures', () => {
      expect(verifyEd25519(testData, 'invalid-signature', publicKey)).toBe(false);
      expect(verifyEd25519(testData, validSignature + 'corrupted', publicKey)).toBe(false);
    });

    it('should reject signatures for different data', () => {
      expect(verifyEd25519('different data', validSignature, publicKey)).toBe(false);
    });

    it('should reject signatures with invalid base64', () => {
      const corruptedSignature = validSignature + ' + corrupted';
      expect(verifyEd25519(testData, corruptedSignature, publicKey)).toBe(false);
    });

    it('should handle empty or null inputs', () => {
      expect(verifyEd25519('', validSignature, publicKey)).toBe(false);
      expect(verifyEd25519(testData, '', publicKey)).toBe(false);
      expect(verifyEd25519(testData, validSignature, '')).toBe(false);
    });
  });

  describe('verifyRSA', () => {
    let signer: Signer;
    let publicKey: string;
    let testData: string;
    let validSignature: string;

    beforeEach(async () => {
      signer = Signer.generate('rsa')!;
      publicKey = signer.getPublicKey();
      testData = 'test data for rsa';
      validSignature = await signer.sign(testData);
    });

    it('should verify valid RSA signatures', () => {
      expect(verifyRSA(testData, validSignature, publicKey)).toBe(true);
    });

    it('should reject invalid RSA signatures', () => {
      expect(verifyRSA(testData, 'invalid-signature', publicKey)).toBe(false);
      expect(verifyRSA(testData, validSignature + 'corrupted', publicKey)).toBe(false);
    });

    it('should reject signatures for different data', () => {
      expect(verifyRSA('different data', validSignature, publicKey)).toBe(false);
    });

    it('should reject signatures with invalid base64', () => {
      const corruptedSignature = validSignature + ' + corrupted';
      expect(verifyRSA(testData, corruptedSignature, publicKey)).toBe(false);
    });

    it('should handle empty or null inputs', () => {
      expect(verifyRSA('', validSignature, publicKey)).toBe(false);
      expect(verifyRSA(testData, '', publicKey)).toBe(false);
      expect(verifyRSA(testData, validSignature, '')).toBe(false);
    });
  });

  describe('verifySecp256k1', () => {
    let signer: Signer;
    let publicKey: string;
    let testData: string;
    let validSignature: string;

    beforeEach(async () => {
      signer = Signer.generate('secp256k1')!;
      publicKey = signer.getPublicKey();
      testData = 'test data for secp256k1';
      validSignature = await signer.sign(testData);
    });

    it('should verify valid secp256k1 signatures', () => {
      expect(verifySecp256k1(testData, validSignature, publicKey)).toBe(true);
    });

    it('should reject invalid secp256k1 signatures', () => {
      expect(verifySecp256k1(testData, 'invalid-signature', publicKey)).toBe(false);
      expect(verifySecp256k1(testData, validSignature + 'corrupted', publicKey)).toBe(false);
    });

    it('should reject signatures for different data', () => {
      expect(verifySecp256k1('different data', validSignature, publicKey)).toBe(false);
    });

    it('should reject signatures with invalid base64', () => {
      const corruptedSignature = validSignature + ' + corrupted';
      expect(verifySecp256k1(testData, corruptedSignature, publicKey)).toBe(false);
    });

    it('should handle empty or null inputs', () => {
      expect(verifySecp256k1('', validSignature, publicKey)).toBe(false);
      expect(verifySecp256k1(testData, '', publicKey)).toBe(false);
      expect(verifySecp256k1(testData, validSignature, '')).toBe(false);
    });
  });

  describe('verifySignature (generic)', () => {
    const algorithms = ['ed25519', 'rsa', 'secp256k1'] as const;
    
    algorithms.forEach(algorithm => {
      describe(`with ${algorithm}`, () => {
        let signer: Signer;
        let publicKey: string;
        let testData: string;
        let validSignature: string;

        beforeEach(async () => {
          signer = Signer.generate(algorithm)!;
          publicKey = signer.getPublicKey();
          testData = `test data for ${algorithm}`;
          validSignature = await signer.sign(testData);
        });

        it(`should verify valid ${algorithm} signatures`, () => {
          expect(verifySignature(testData, validSignature, publicKey, algorithm)).toBe(true);
        });

        it(`should reject invalid ${algorithm} signatures`, () => {
          expect(verifySignature(testData, 'invalid-signature', publicKey, algorithm)).toBe(false);
          expect(verifySignature(testData, validSignature + 'corrupted', publicKey, algorithm)).toBe(false);
        });

        it(`should reject ${algorithm} signatures for different data`, () => {
          expect(verifySignature('different data', validSignature, publicKey, algorithm)).toBe(false);
        });
      });
    });

    it('should return false for unsupported algorithms', () => {
      expect(verifySignature('data', 'signature', 'key', 'x25519')).toBe(false);
      expect(verifySignature('data', 'signature', 'key', 'wireguard')).toBe(false);
    });
  });

  describe('Security Tests', () => {
    it('should prevent signature reuse across different algorithms', async () => {
      const data = 'test data';
      
      // Generate signers for different algorithms
      const ed25519Signer = Signer.generate('ed25519')!;
      const rsaSigner = Signer.generate('rsa')!;
      
      // Sign with ed25519
      const ed25519Signature = await ed25519Signer.sign(data);
      
      // Should not verify with RSA public key
      expect(verifyRSA(data, ed25519Signature, rsaSigner.getPublicKey())).toBe(false);
      expect(verifySignature(data, ed25519Signature, rsaSigner.getPublicKey(), 'rsa')).toBe(false);
    });

    it('should prevent signature reuse across different keys of same algorithm', async () => {
      const data = 'test data';
      
      // Generate two different ed25519 signers
      const signer1 = Signer.generate('ed25519')!;
      const signer2 = Signer.generate('ed25519')!;
      
      // Sign with first signer
      const signature = await signer1.sign(data);
      
      // Should not verify with second signer's public key
      expect(verifyEd25519(data, signature, signer2.getPublicKey())).toBe(false);
    });

    it('should handle malformed signatures gracefully', () => {
      const data = 'test data';
      const publicKey = Signer.generate('ed25519')!.getPublicKey();
      
      const malformedSignatures = [
        'not-base64-at-all',
        'SGVsbG8gV29ybGQ=', // Valid base64 but wrong length
        'YWJjZGVmZ2hpams=', // Valid base64 but not a signature
        '',
        'null',
        'undefined'
      ];
      
      malformedSignatures.forEach(malformedSig => {
        expect(verifyEd25519(data, malformedSig, publicKey)).toBe(false);
        expect(verifySignature(data, malformedSig, publicKey, 'ed25519')).toBe(false);
      });
    });
  });
});
