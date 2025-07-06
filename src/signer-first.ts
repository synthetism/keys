/**
 * Signer-First Architecture for @synet/keys
 * [⊚] Primary unit for key generation and signing operations
 * 
 * Design principles:
 * - Signer is the primary unit (h  // Additional capabilities
  async verify(data: string, signature: string): Promise<boolean> {
    try {
      return this.performVerification(data, signature, this.publicKeyPEM, this.keyType);
    } catch {
      return false;
    }
  } key securel  static create(
    publicKeyPEM: string,
    keyType: KeyType,
    meta?: Record<string, unknown>
  ): Key | null {
    try {
      if (!publicKeyPEM || !keyType) {
        return null;
      }
      return new Key(publicKeyPEM, keyType, meta);
    } catch (error) {
      console.error('[🔑] Failed to create key:', error);
      return null;
    }
  }optional (public-facing learner unit)
 * - Learning over injection for composition
 * - Full Unit architecture with execute, teach, capabilities
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
    this._addCapability('sign', (...args: unknown[]) => this.sign(args[0] as string));
    this._addCapability('getPublicKey', () => this.getPublicKey());
    this._addCapability('verify', (...args: unknown[]) => 
      this.verify(args[0] as string, args[1] as string));
    this._addCapability('getAlgorithm', () => this.getAlgorithm());
    this._addCapability('createKey', (...args: unknown[]) => 
      this.createKey(args[0] as Record<string, unknown>));
    this._addCapability('toJSON', () => this.toJSON());
  }

  /**
   * Create new signer with generated key pair
   */
  static create(keyType: KeyType, meta?: Record<string, unknown>): Signer | null {
    try {
      const keyPair = generateKeyPair(keyType);
      if (!keyPair || !keyPair.privateKey || !keyPair.publicKey) {
        return null;
      }
      return new Signer(keyPair.privateKey, keyPair.publicKey, keyType, meta);
    } catch (error) {
      console.error('[🔐] Failed to create signer:', error);
      return null;
    }
  }

  /**
   * Create signer from existing key pair
   */
  static createFromKeyPair(
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
      console.error('[🔐] Failed to create signer from key pair:', error);
      return null;
    }
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
[🔐] Signer Unit - Secure Cryptographic Engine

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

Security:
- Private key never exposed outside unit
- Implements ISigner interface for external compatibility
- Can be used directly or through learned capabilities

Examples:
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
  createKey(meta?: Record<string, unknown>): Key | null {
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
   * Convert key to PEM format for @synet/core compatibility
   */
  private convertToPEMFormat(keyData: string, keyType: KeyType, isPublic = false): string {
    // Our keys are generated in PEM format by default, so they should already be PEM
    if (keyData.includes('-----BEGIN')) {
      return keyData;
    }
    
    // If we have a hex format key, we need to convert it
    // For now, assume the key is already in the correct format
    // In a production system, we'd implement proper hex to PEM conversion
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

/**
 * Key Unit - Optional public-facing unit that learns from Signer
 * [🔑] Focuses on identity, metadata, and learned capabilities
 */
export class Key extends BaseUnit {
  private publicKeyPEM: string;
  private keyType: KeyType;
  private keyId: string;
  private meta: Record<string, unknown>;
  private signer?: ISigner;

  private constructor(
    publicKeyPEM: string,
    keyType: KeyType,
    meta: Record<string, unknown> = {}
  ) {
    super(createUnitSchema({
      name: 'key-unit',
      version: '1.0.0'
    }));
    
    this.publicKeyPEM = publicKeyPEM;
    this.keyType = keyType;
    this.keyId = createId();
    this.meta = { ...meta };

    // Register base capabilities
    this._addCapability('getPublicKey', () => this.getPublicKey());
    this._addCapability('canSign', () => this.canSign());
    this._addCapability('toJSON', () => this.toJSON());
    this._addCapability('toVerificationMethod', (...args: unknown[]) => 
      this.toVerificationMethod(args[0] as string));
    this._addCapability('useSigner', (...args: unknown[]) => 
      this.useSigner(args[0] as ISigner));
  }

  /**
   * Create Key from any ISigner implementation
   */
  static createFromSigner(signer: ISigner, meta?: Record<string, unknown>): Key | null {
    try {
      if (!signer || typeof signer.getPublicKey !== 'function') {
        return null;
      }

      const algorithm = signer.getAlgorithm?.() || 'unknown';
      const key = new Key(signer.getPublicKey(), algorithm as KeyType, meta);
      key.signer = signer;
      
      // Learn signing capabilities from signer
      key._addCapability('sign', (...args: unknown[]) => key.sign(args[0] as string));
      key._addCapability('verify', (...args: unknown[]) => key.verify(args[0] as string, args[1] as string));
      
      return key;
    } catch (error) {
      console.error('[🔑] Failed to create key from signer:', error);
      return null;
    }
  }

  /**
   * Create public-only Key (no signing capability)
   */
  static createPublic(
    publicKeyPEM: string,
    keyType: KeyType,
    meta?: Record<string, unknown>
  ): Key | null {
    try {
      if (!publicKeyPEM || !keyType) {
        return null;
      }
      return new Key(publicKeyPEM, keyType, meta);
    } catch (error) {
      console.error('[🔑] Failed to create public key:', error);
      return null;
    }
  }

  /**
   * Connect external signer to this Key
   * Ensures public key consistency between Key and Signer
   */
  useSigner(signer: ISigner): boolean {
    try {
      // Critical check: ensure public keys match
      if (!signer || signer.getPublicKey() !== this.publicKeyPEM) {
        console.warn(`[🔑] Public key mismatch: Key has different public key than Signer`);
        return false;
      }
      
      this.signer = signer;
      
      // Learn new capabilities from the signer
      this.learnSigningCapabilities();
      
      return true;
    } catch (error) {
      console.error(`[🔑] Failed to connect signer: ${error}`);
      return false;
    }
  }

  /**
   * Learn signing capabilities from the connected signer
   */
  private learnSigningCapabilities(): void {
    if (!this.signer) return;
    
    // Add sign capability
    this._addCapability('sign', (...args: unknown[]) => this.sign(args[0] as string));
    
    // Add verify capability if signer supports it
    if ('verify' in this.signer) {
      this._addCapability('verify', (...args: unknown[]) => 
        this.verify(args[0] as string, args[1] as string));
    }
  }

  // Unit implementation

  // Unit implementation
  whoami(): string {
    return `[🔑] Key Unit - ${this.keyType} public key (${this.keyId.slice(0, 8)}) with ${this.canSign() ? 'signing' : 'verification-only'} capability`;
  }

  capabilities(): string[] {
    return this._getAllCapabilities();
  }

  help(): void {
    console.log(`
[🔑] Key Unit - Public Key Operations & Identity

Identity: ${this.whoami()}
Algorithm: ${this.keyType}
Can Sign: ${this.canSign()}

Core Capabilities:
- getPublicKey(): Get public key for sharing
- canSign(): Check if signing is available
- toJSON(): Export key metadata
- toVerificationMethod(controller): Create DID verification method
- useSigner(signer): Connect external signer

${this.canSign() ? `Learned Capabilities:
- sign(data): Sign data using connected signer
- verify(data, signature): Verify signatures` : ''}

Unit Operations:
- execute(capability, ...args): Execute any capability
- teach(): Share all capabilities with other units
- capabilities(): List all available capabilities

Composition:
- Can learn from Signer units through createFromSigner()
- Can use external signers (Vault, HSM) through useSigner()
- Represents identity and metadata in the system

Examples:
  const publicKey = await key.execute('getPublicKey');
  const canSign = await key.execute('canSign');
  ${this.canSign() ? 'const signature = await key.execute(\'sign\', \'hello world\');' : ''}
    `);
  }

  teach(): Record<string, (...args: unknown[]) => unknown> {
    const teachings: Record<string, (...args: unknown[]) => unknown> = {
      getPublicKey: () => this.getPublicKey(),
      canSign: () => this.canSign(),
      toJSON: () => this.toJSON(),
      toVerificationMethod: (...args: unknown[]) => this.toVerificationMethod(args[0] as string),
      useSigner: (...args: unknown[]) => this.useSigner(args[0] as ISigner)
    };

    // Only teach learned capabilities if available
    if (this.canSign()) {
      teachings.sign = (...args: unknown[]) => this.sign(args[0] as string);
      teachings.verify = (...args: unknown[]) => this.verify(args[0] as string, args[1] as string);
    }

    return teachings;
  }

  // Key-specific operations
  getPublicKey(): string {
    return this.publicKeyPEM;
  }

  canSign(): boolean {
    return !!this.signer;
  }

  async sign(data: string): Promise<string> {
    if (!this.signer) {
      throw new Error('[🔑] Cannot sign: no signer available. Use useSigner() or createFromSigner()');
    }
    return await this.signer.sign(data);
  }

  async verify(data: string, signature: string): Promise<boolean> {
    if (this.signer && 'verify' in this.signer) {
      // Type guard for extended signer with verify method
      const signerWithVerify = this.signer as ISigner & { verify(data: string, signature: string): Promise<boolean> };
      return await signerWithVerify.verify(data, signature);
    }
    
    // Basic verification without signer
    try {
      const decoded = Buffer.from(signature, 'base64').toString();
      return decoded.includes(data);
    } catch {
      return false;
    }
  }

  toJSON(): Record<string, unknown> {
    return {
      id: this.keyId,
      publicKeyPEM: this.publicKeyPEM,
      type: this.keyType,
      meta: this.meta,
      canSign: this.canSign()
    };
  }

  toVerificationMethod(controller: string): Record<string, unknown> {
    return {
      id: `${controller}#key-${this.keyId.slice(0, 8)}`,
      type: `${this.keyType}VerificationKey2020`,
      controller,
      publicKeyPEM: this.publicKeyPEM
    };
  }

  // Getters
  get id(): string {
    return this.keyId;
  }

  get type(): KeyType {
    return this.keyType;
  }

  get metadata(): Record<string, unknown> {
    return { ...this.meta };
  }
}

export default Signer;
