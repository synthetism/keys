/**
 * Signer Unit - Primary cryptographic signing unit
 * [🔐] Self-contained cryptographic engine that knows how to sign
 * 
 * Design principles:
 * - Signer is the primary unit (holds private key securely)
 * - Full Unit architecture with execute, teach, capabilities
 * - Self-contained cryptographic operations (no external dependencies)
 * - Can teach capabilities to Key units
 * 
 * @author Synet Team
 */

import { BaseUnit, createUnitSchema } from '@synet/unit';
import { generateKeyPair, type KeyType } from './keys';
import { createId } from './utils';
import * as crypto from 'node:crypto';

/**
 * ISigner interface for all signing implementations
 */
export interface ISigner {
  sign(data: string): Promise<string>;
  getPublicKey(): string;
  getAlgorithm?(): string;
}

/**
 * Signer Unit - Primary unit for key generation and signing
 * [🔐] The source of truth for cryptographic operations
 */
export class Signer extends BaseUnit implements ISigner {
  private privateKeyPEM: string;
  private publicKeyPEM: string;
  private keyType: KeyType;
  private keyId: string;
  private meta: Record<string, unknown>;

  private constructor(
    privateKeyPEM: string,
    publicKeyPEM: string,
    keyType: KeyType,
    meta: Record<string, unknown> = {}
  ) {
    super(createUnitSchema({
      name: 'signer-unit',
      version: '1.0.0'
    }));
    
    this.privateKeyPEM = privateKeyPEM;
    this.publicKeyPEM = publicKeyPEM;
    this.keyType = keyType;
    this.keyId = createId();
    this.meta = { ...meta };

    // Register capabilities
    this._addCapability('sign', (...args: unknown[]) => {
      // Handle both direct string and object with data property
      const data = typeof args[0] === 'string' ? args[0] : (args[0] as { data: string })?.data;
      return this.sign(data);
    });
    this._addCapability('getPublicKey', () => this.getPublicKey());
    this._addCapability('verify', (...args: unknown[]) => {
      // Handle both direct strings and object with data/signature properties
      if (typeof args[0] === 'string' && typeof args[1] === 'string') {
        return this.verify(args[0], args[1]);
      }
      const obj = args[0] as { data: string; signature: string };
      return this.verify(obj.data, obj.signature);
    });
    this._addCapability('getAlgorithm', () => this.getAlgorithm());
    this._addCapability('createKey', (...args: unknown[]) => 
      this.createKey(args[0] as Record<string, unknown>));
    this._addCapability('toJSON', () => this.toJSON());
  }

  /**
   * Generate new signer with fresh key pair
   */
  static generate(keyType: KeyType, meta?: Record<string, unknown>): Signer | null {
    try {
      const keyPair = generateKeyPair(keyType);
      if (!keyPair || !keyPair.privateKey || !keyPair.publicKey) {
        return null;
      }
      return new Signer(keyPair.privateKey, keyPair.publicKey, keyType, meta);
    } catch (error) {
      console.error('[🔐] Failed to generate signer:', error);
      return null;
    }
  }

  /**
   * Create signer from existing key pair
   */
  static create(
    privateKeyPEM: string,
    publicKeyPEM: string,
    keyType: KeyType,
    meta?: Record<string, unknown>
  ): Signer | null {
    try {
      if (!privateKeyPEM || !publicKeyPEM || !keyType) {
        return null;
      }
      return new Signer(privateKeyPEM, publicKeyPEM, keyType, meta);
    } catch (error) {
      console.error('[🔐] Failed to create signer:', error);
      return null;
    }
  }

  /**
   * Create signer from existing key pair (compatibility method)
   */
  static createFromKeyPair(
    privateKeyPEM: string,
    publicKeyPEM: string,
    keyType: KeyType,
    meta?: Record<string, unknown>
  ): Signer | null {
    return Signer.create(privateKeyPEM, publicKeyPEM, keyType, meta);
  }

  // Unit implementation
  whoami(): string {
    return `[🔐] Signer Unit - Secure ${this.keyType} cryptographic engine (${this.keyId.slice(0, 8)})`;
  }

  capabilities(): string[] {
    return this._getAllCapabilities();
  }

  help(): void {
    console.log(`
[🔐] Signer Unit - Self-Contained Cryptographic Engine

Identity: ${this.whoami()}
Algorithm: ${this.keyType}

Core Capabilities:
- sign(data): Sign data with private key
- getPublicKey(): Get public key for sharing  
- verify(data, signature): Verify signatures
- getAlgorithm(): Get signing algorithm
- createKey(): Create associated Key unit
- toJSON(): Export metadata (no private key)

Unit Operations:
- execute(capability, ...args): Execute any capability
- teach(): Share all capabilities with other units
- capabilities(): List all available capabilities
- learn(capabilities): Absorb capabilities from other units

Security Contract:
- Private key never exposed outside unit
- Implements ISigner interface for external compatibility
- Can be used directly or through learned capabilities

Try me:
  const signer = Signer.generate('ed25519', { name: 'my-signer' });
  await signer.execute('sign', 'hello world');
  const key = await signer.execute('createKey', { name: 'my-key' });
  const publicKey = await signer.execute('getPublicKey');
    `);
  }

  teach(): Record<string, (...args: unknown[]) => unknown> {
    return {
      sign: (...args: unknown[]) => this.sign(args[0] as string),
      getPublicKey: () => this.getPublicKey(),
      verify: (...args: unknown[]) => this.verify(args[0] as string, args[1] as string),
      getAlgorithm: () => this.getAlgorithm(),
      createKey: (...args: unknown[]) => this.createKey(args[0] as Record<string, unknown>),
      toJSON: () => this.toJSON()
    };
  }

  // ISigner implementation
  async sign(data: string): Promise<string> {
    try {
      return this.performSigning(data, this.privateKeyPEM, this.keyType);
    } catch (error) {
      throw new Error(`[🔐] Signing failed: ${error}`);
    }
  }

  getPublicKey(): string {
    return this.publicKeyPEM;
  }

  getAlgorithm(): string {
    return this.keyType;
  }

  // Additional capabilities
  async verify(data: string, signature: string): Promise<boolean> {
    try {
      return this.performVerification(data, signature, this.publicKeyPEM, this.keyType);
    } catch {
      return false;
    }
  }

  /**
   * Create associated Key unit that learns from this Signer
   */
  createKey(meta?: Record<string, unknown>): any {
    // Import Key dynamically to avoid circular dependency
    const { Key } = require('./key');
    return Key.createFromSigner(this, meta);
  }

  /**
   * Export signer metadata (excludes private key for security)
   */
  toJSON(): Record<string, unknown> {
    return {
      id: this.keyId,
      publicKeyPEM: this.publicKeyPEM,
      type: this.keyType,
      meta: this.meta,
      canSign: true,
      algorithm: this.keyType
    };
  }

  // Getters for internal access
  get id(): string {
    return this.keyId;
  }

  get type(): KeyType {
    return this.keyType;
  }

  get metadata(): Record<string, unknown> {
    return { ...this.meta };
  }

  /**
   * Convert key to PEM format for cryptographic operations
   */
  private convertToPEMFormat(keyData: string, keyType: KeyType, isPublic = false): string {
    // Our keys are generated in PEM format by default, so they should already be PEM
    if (keyData.includes('-----BEGIN')) {
      return keyData;
    }
    
    // If we have a hex format key, we need to convert it
    throw new Error(`Key format conversion needed for ${keyType} key. Expected PEM format but got hex.`);
  }

  /**
   * Perform cryptographic signing based on key type
   */
  private performSigning(data: string, privateKey: string, keyType: KeyType): string {
    if (!data || !privateKey) {
      throw new Error('Invalid input: data and privateKey are required');
    }

    try {
      switch (keyType) {
        case 'ed25519':
          return this.signEd25519(data, privateKey);
        case 'rsa':
          return this.signRSA(data, privateKey);
        case 'secp256k1':
          return this.signSecp256k1(data, privateKey);
        case 'x25519':
          throw new Error('X25519 is for key exchange, not signing');
        case 'wireguard':
          throw new Error('WireGuard keys are for VPN, not signing');
        default:
          throw new Error(`Unsupported key type for signing: ${keyType}`);
      }
    } catch (error) {
      throw new Error(`Signing failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Perform cryptographic verification based on key type
   */
  private performVerification(data: string, signature: string, publicKey: string, keyType: KeyType): boolean {
    if (!data || !signature || !publicKey) {
      return false;
    }

    try {
      switch (keyType) {
        case 'ed25519':
          return this.verifyEd25519(data, signature, publicKey);
        case 'rsa':
          return this.verifyRSA(data, signature, publicKey);
        case 'secp256k1':
          return this.verifySecp256k1(data, signature, publicKey);
        case 'x25519':
        case 'wireguard':
          return false; // These are not for signing
        default:
          return false;
      }
    } catch {
      return false;
    }
  }

  /**
   * Sign data with Ed25519 key
   */
  private signEd25519(data: string, privateKey: string): string {
    const signature = crypto.sign(null, Buffer.from(data), {
      key: privateKey,
      format: 'pem',
    });
    return signature.toString('base64');
  }

  /**
   * Verify Ed25519 signature
   */
  private verifyEd25519(data: string, signature: string, publicKey: string): boolean {
    return crypto.verify(
      null,
      Buffer.from(data),
      {
        key: publicKey,
        format: 'pem',
      },
      Buffer.from(signature, 'base64')
    );
  }

  /**
   * Sign data with RSA key
   */
  private signRSA(data: string, privateKey: string): string {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'base64');
  }

  /**
   * Verify RSA signature
   */
  private verifyRSA(data: string, signature: string, publicKey: string): boolean {
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, 'base64');
  }

  /**
   * Sign data with secp256k1 key
   */
  private signSecp256k1(data: string, privateKey: string): string {
    // For secp256k1, we use ECDSA with SHA256
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'base64');
  }

  /**
   * Verify secp256k1 signature
   */
  private verifySecp256k1(data: string, signature: string, publicKey: string): boolean {
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, 'base64');
  }
}
