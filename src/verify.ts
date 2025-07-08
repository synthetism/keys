/**
 * Cryptographic verification functions
 * Pure functions for signature verification across different algorithms
 * 
 * These functions are designed to be:
 * - Pure (no side effects)
 * - Testable in isolation
 * - Reusable across different units
 * - Well-validated with proper error handling
 * 
 * @author Synet Team
 */

import * as crypto from 'node:crypto';

/**
 * Validate base64 format
 * Ensures the signature is properly formatted base64 before crypto operations
 */
export function isValidBase64(str: string): boolean {
  try {
    // Empty strings are not valid base64
    if (!str || str === '') {
      return false;
    }
    
    // Check if string contains only valid base64 characters
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(str)) {
      return false;
    }
    
    // Check if the decoded and re-encoded string matches the original
    const decoded = Buffer.from(str, 'base64');
    const reencoded = decoded.toString('base64');
    return reencoded === str;
  } catch {
    return false;
  }
}

/**
 * Verify Ed25519 signature
 * @param data The original data that was signed
 * @param signature The signature in base64 format
 * @param publicKey The public key in PEM format
 * @returns true if signature is valid, false otherwise
 */
export function verifyEd25519(data: string, signature: string, publicKey: string): boolean {
  try {
    // Validate inputs
    if (!data || !signature || !publicKey) {
      return false;
    }
    
    // Validate base64 format first
    if (!isValidBase64(signature)) {
      return false;
    }
    
    return crypto.verify(
      null,
      Buffer.from(data),
      {
        key: publicKey,
        format: 'pem',
      },
      Buffer.from(signature, 'base64')
    );
  } catch {
    return false;
  }
}

/**
 * Verify RSA signature
 * @param data The original data that was signed
 * @param signature The signature in base64 format
 * @param publicKey The public key in PEM format
 * @returns true if signature is valid, false otherwise
 */
export function verifyRSA(data: string, signature: string, publicKey: string): boolean {
  try {
    // Validate inputs
    if (!data || !signature || !publicKey) {
      return false;
    }
    
    // Validate base64 format first
    if (!isValidBase64(signature)) {
      return false;
    }
    
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, 'base64');
  } catch {
    return false;
  }
}

/**
 * Verify secp256k1 signature
 * @param data The original data that was signed
 * @param signature The signature in base64 format
 * @param publicKey The public key in PEM format
 * @returns true if signature is valid, false otherwise
 */
export function verifySecp256k1(data: string, signature: string, publicKey: string): boolean {
  try {
    // Validate inputs
    if (!data || !signature || !publicKey) {
      return false;
    }
    
    // Validate base64 format first
    if (!isValidBase64(signature)) {
      return false;
    }
    
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, 'base64');
  } catch {
    return false;
  }
}

/**
 * Generic verification function that dispatches to specific algorithms
 * @param data The original data that was signed
 * @param signature The signature in base64 format
 * @param publicKey The public key in PEM format
 * @param keyType The key type/algorithm
 * @returns true if signature is valid, false otherwise
 */
export function verifySignature(
  data: string, 
  signature: string, 
  publicKey: string, 
  keyType: 'ed25519' | 'rsa' | 'secp256k1' | 'x25519' | 'wireguard'
): boolean {
  switch (keyType) {
    case 'ed25519':
      return verifyEd25519(data, signature, publicKey);
    case 'rsa':
      return verifyRSA(data, signature, publicKey);
    case 'secp256k1':
      return verifySecp256k1(data, signature, publicKey);
    case 'x25519':
    case 'wireguard':
      return false; // These are not for signing
    default:
      return false;
  }
}
