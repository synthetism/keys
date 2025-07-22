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

import { Unit, createUnitSchema, type TeachingContract, type UnitProps } from '@synet/unit';
import { generateKeyPair, detectKeyFormat, pemToHex, pemPrivateKeyToHex, type KeyType } from './keys';
import { verifySignature } from './verify';
import { createId, base64ToBase64Url } from './utils';
import * as crypto from 'node:crypto';
import { Key } from './key';

/**
 * ISigner interface for external signing implementations
 * Simplified to core signing functionality only
 */
export interface ISigner {
  sign(data: string): Promise<string>;
}

/**
 * Configuration for creating a Signer unit
 */
export interface SignerConfig {
  privateKeyPEM: string;
  publicKeyPEM: string;
  keyType: KeyType;
  secure?: boolean; // Whether to use secure signing methods
  metadata?: Record<string, unknown>;
  isigner?: ISigner; // External signer for edge cases
}

/**
 * Props interface for Signer unit - follows Unit Architecture Doctrine
 */
export interface SignerProps extends UnitProps {
  privateKeyPEM: string;
  publicKeyPEM: string;
  keyType: KeyType;
  keyId: string;
  metadata: Record<string, unknown>;
  secure: boolean; // Whether to use secure signing methods
  isigner?: ISigner;
}

  interface SignerGenerateParams {
    secure?: boolean;
    metadata?: Record<string, unknown>;
  }

/**
 * Signer Unit - Primary unit for key generation and signing
 * The source of truth for cryptographic operations
 */
export class Signer extends Unit<SignerProps> implements ISigner {

  protected constructor(props: SignerProps) {
    super(props);

    // Register capabilities
    this._addCapability('sign', (...args: unknown[]) => {
      // Handle both direct string and object with data property
      const data = typeof args[0] === 'string' ? args[0] : (args[0] as { data: string })?.data;
      return this.sign(data);
    });
    this._addCapability('getPublicKey', () => this.getPublicKey());
    this._addCapability('getPublicKeyHex', () => this.getPublicKeyHex());
    this._addCapability('getPrivateKeyHex', () => this.getPrivateKeyHex());
    this._addCapability('verify', (...args: unknown[]) => {
      // Handle both direct strings and object with data/signature properties
      if (typeof args[0] === 'string' && typeof args[1] === 'string') {
        return this.verify(args[0], args[1]);
      }
      const obj = args[0] as { data: string; signature: string };
      return this.verify(obj.data, obj.signature);
    });
    this._addCapability('getAlgorithm', () => this.getAlgorithm());
    this._addCapability('getKey', (...args: unknown[]) => 
      this.getKey(args[0] as Record<string, unknown>));
    this._addCapability('toJSON', () => this.toJSON());
  }

 


  /**
   * Generate new signer with fresh key pair
   */
  static generate(
    keyType: KeyType, 
    params: SignerGenerateParams = {}
  ): Signer
  {

    try {
      const keyPair = generateKeyPair(keyType);
      if (!keyPair || !keyPair.privateKey || !keyPair.publicKey) {
        throw new Error('Failed to generate key pair');
      }
      
      const props: SignerProps = {
        dna: createUnitSchema({
          id: 'signer',
          version: '1.0.0'
        }),
        privateKeyPEM: keyPair.privateKey,
        publicKeyPEM: keyPair.publicKey,
        keyType,
        keyId: createId(),
        metadata: params?.metadata || {},
        created: new Date(),
        secure: params?.secure !== undefined ? params.secure : false,
      };
      
      console.log(`[🔐] Generated new Signer with key type: ${keyType}, secure: ${props.secure} metadata: ${JSON.stringify(props.metadata)}`);
      return new Signer(props);
    } catch (error) {
      console.error('[🔐] Failed to generate signer:', error);
      throw new Error('Failed to generate key pair');
    }
  }

  /**
   * Create signer from existing key pair
   */
  static create(config: SignerConfig): Signer {
    try {
  
      if (!config.privateKeyPEM || !config.publicKeyPEM || !config.keyType) {
        throw new Error('Invalid parameters, privateKeyPEM, publicKeyPEM, and keyType are required');
      }
      
      const props: SignerProps = {
        dna: createUnitSchema({
          id: 'signer',
          version: '1.0.0'
        }),
        privateKeyPEM: config.privateKeyPEM,
        publicKeyPEM: config.publicKeyPEM,
        keyType: config.keyType,
        keyId: createId(),
        metadata: config.metadata || {},
        created: new Date(),
        secure: config.secure || true, // Use secure signing methods if specified
      };
      
      return new Signer(props);
    } catch (error) {
      console.error('[🔐] Failed to create signer:', error);
      throw error;
    }
  }

  /**
   * Create signer from existing key pair (compatibility method)
   */
  static createFromKeyPair(
    privateKeyPEM: string,
    publicKeyPEM: string,
    keyType: KeyType,
    metadata?: Record<string, unknown>
  ): Signer | null {
    return Signer.create({
      privateKeyPEM,
      publicKeyPEM,
      keyType,
      metadata
    });
  }

  /**
   * Create signer with external ISigner (edge case)
   * For cases where signing logic is handled externally
   */
  static createWithSigner(params: {
    signer: ISigner;
    keyType?: KeyType;
    publicKeyPEM?: string;
    metadata?: Record<string, unknown>;
  }): Signer | null {
    try {
      // Create a Signer with external signing capability
      // Note: Public key should be provided in metadata if needed
      const publicKeyPEM = params.publicKeyPEM as string || '';

      const keyType = params.keyType || 'ed25519';
      const props: SignerProps = {
        dna: createUnitSchema({
          id: 'signer',
          version: '1.0.0'
        }),
        privateKeyPEM: '', // External signer handles signing
        publicKeyPEM,
        keyType,
        keyId: createId(),
        metadata: params.metadata || {},
        isigner: params.signer,
        created: new Date(),
        secure: true,
      };
      
      return new Signer(props);
    } catch (error) {
      console.error('[🔐] Failed to create signer with external ISigner:', error);
      return null;
    }
  }

  // Unit implementation
  whoami(): string {
    return `[🔐] Signer Unit - Secure ${this.props.keyType} cryptographic engine (${this.props.keyId.slice(0, 8)})`;
  }

  capabilities(): string[] {
    return this._getAllCapabilities();
  }

  help(): void {
    console.log(`
[🔐] Signer Unit - Self-Contained Cryptographic Engine

Identity: ${this.whoami()}
Algorithm: ${this.props.keyType}

Core Capabilities:
- sign(data): Sign data with private key
- getPublicKey(): Get public key for sharing  
- getPublicKeyHex(): Get public key in hex format
- getPrivateKeyHex(): Get private key in hex format (secure mode dependent)
- verify(data, signature): Verify signatures
- getAlgorithm(): Get signing algorithm
- getKey(): Get data needed to create associated Key unit
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
  const keyData = await signer.execute('getKey', { name: 'my-key' });
  // Then use Key.createFromSigner(signer, keyData.meta) separately
  const publicKey = await signer.execute('getPublicKey');
    `);
  }

  teach(): TeachingContract {
    return {
      unitId: this.dna.id,
      capabilities: {
        sign: (...args: unknown[]) => this.sign(args[0] as string),
        getPublicKey: () => this.getPublicKey(),
        getPublicKeyHex: () => this.getPublicKeyHex(),
        getPrivateKeyHex: () => this.getPrivateKeyHex(),
        verify: (...args: unknown[]) => this.verify(args[0] as string, args[1] as string),
        getAlgorithm: () => this.getAlgorithm(),
        toJSON: () => this.toJSON(),
        getKeyType: () => this.props.keyType,
      }
    };
  }

  // ISigner implementation
  async sign(data: string): Promise<string> {
    try {
      // Use external signer if available, otherwise use native signing
      if (this.props.isigner) {
        return this.props.isigner.sign(data);
      }
      return this.performSigning(data, this.props.privateKeyPEM, this.props.keyType);
    } catch (error) {
      throw new Error(`[🔐] Signing failed: ${error}`);
    }
  }

  getPublicKey(): string {
    return this.props.publicKeyPEM;
  }

  getAlgorithm(): string {
    return this.props.keyType;
  }

  /**
   * Create a Key unit from this Signer's key material
   * The Key will learn signing capabilities from this Signer
   */
  createKey() {
    try {
      const key = Key.create({
        publicKeyPEM: this.props.publicKeyPEM,
        keyType: this.props.keyType,
        meta: { ...this.props.metadata }
      });
      
      if (key) {
        // Teach the key our signing capabilities
        const teaching = this.teach();
        key.learn([teaching]);
      }
      
      return key;
    } catch (error) {
      console.error('[🔐] Failed to create key:', error);
      return null;
    }
  }

  // Additional capabilities
  async verify(data: string, signature: string): Promise<boolean> {
    try {
      return this.performVerification(data, signature, this.props.publicKeyPEM, this.props.keyType);
    } catch {
      return false;
    }
  }

  /**
   * Get data needed to create associated Key unit
   * Returns the data needed for Key.createFromSigner() to avoid circular dependency
   */
  getKey(meta?: Record<string, unknown>): {
    publicKeyPEM: string;
    keyType: KeyType;
    meta: Record<string, unknown>;
    signer: ISigner;
  } {
    return {
      publicKeyPEM: this.props.publicKeyPEM,
      keyType: this.props.keyType,
      meta: { ...meta },
      signer: this as ISigner
    };
  }

  /**
   * Export signer metadata (excludes private key for security)
   */
  toJSON(): Record<string, unknown> {
    return {
      id: this.props.keyId,
      publicKeyPEM: this.props.publicKeyPEM,
      type: this.props.keyType,
      meta: this.props.meta,
      canSign: true,
      algorithm: this.props.keyType
    };
  }

  // Getters for internal access
  get id(): string {
    return this.props.keyId;
  }

  get type(): KeyType {
    return this.props.keyType;
  }

  get metadata(): Record<string, unknown> {
    return { ...this.props.metadata };
  }

  get privateKeyPEM(): string {
    return this.props.secure ? '' : this.props.privateKeyPEM;
  }

  get publicKeyPEM(): string {
    return this.props.publicKeyPEM;
  }

  get keyType(): string {
    return this.props.keyType;
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
   * Uses tested verification functions from verify.ts
   */
  private performVerification(data: string, signature: string, publicKey: string, keyType: KeyType): boolean {
    return verifySignature(data, signature, publicKey, keyType);
  }

  /**
   * Sign data with Ed25519 key
   */
  private signEd25519(data: string, privateKey: string): string {
    const signature = crypto.sign(null, Buffer.from(data), {
      key: privateKey,
      format: 'pem',
    });
    const base64Signature = signature.toString('base64');
    return base64ToBase64Url(base64Signature);
  }

  /**
   * Sign data with RSA key
   */
  private signRSA(data: string, privateKey: string): string {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    const base64Signature = sign.sign(privateKey, 'base64');
    return base64ToBase64Url(base64Signature);
  }

  /**
   * Sign data with secp256k1 key
   */
  private signSecp256k1(data: string, privateKey: string): string {
    // For secp256k1, we use ECDSA with SHA256
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    const base64Signature = sign.sign(privateKey, 'base64');
    return base64ToBase64Url(base64Signature);
  }

  /**
   * Get public key in hex format for DID generation
   * This allows DID generation to work immediately with hex format
   */
  getPublicKeyHex(): string | null {
    try {
      // Use the pemToHex utility from keys.ts
      return pemToHex(this.props.publicKeyPEM);
    } catch (error) {
      console.error('[🔐] Failed to convert public key to hex:', error);
      return null;
    }
  }

  /**
   * Get private key in hex format (respects security flag)
   * Only returns private key if secure flag is false
   */
  getPrivateKeyHex(): string | null {
    if (this.props.secure) {
      console.warn('[🔐] Private key access denied - secure mode enabled');
      return null;
    }
    
    try {
      return pemPrivateKeyToHex(this.props.privateKeyPEM);
    } catch (error) {
      console.error('[🔐] Failed to convert private key to hex:', error);
      return null;
    }
  }



}
