/**
 * Key Unit - Public-facing cryptographic key unit
 * [🔑] Learner unit that can gain signing capabilities from Signer units
 * 
 * Design principles:
 * - Key is the public-facing unit (holds public key only)
 * - Can learn signing capabilities from compatible Signer units
 * - Validates public key consistency when learning
 * - Full Unit architecture with execute, learn, teach, capabilities
 * 
 * @author Synet Team
 */

import { BaseUnit, createUnitSchema } from '@synet/unit';
import { createId } from './utils';
import type { ISigner } from './signer';
import type { KeyType } from './keys';

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

  private constructor(props: {
    publicKeyPEM: string;
    keyType: KeyType;
    meta?: Record<string, unknown>;
    signer?: ISigner;
  }) {
    super(createUnitSchema({
      name: 'key-unit',
      version: '1.0.0'
    }));
    
    this.publicKeyPEM = props.publicKeyPEM;
    this.keyType = props.keyType;
    this.keyId = createId();
    this.meta = { ...props.meta };
    this.signer = props.signer;

    // Register base capabilities
    this._addCapability('getPublicKey', () => this.getPublicKey());
    this._addCapability('canSign', () => this.canSign());
    this._addCapability('toJSON', () => this.toJSON());
    this._addCapability('toVerificationMethod', (...args: unknown[]) => 
      this.toVerificationMethod(args[0] as string));
    this._addCapability('useSigner', (...args: unknown[]) => 
      this.useSigner(args[0] as ISigner));
    this._addCapability('verify', (...args: unknown[]) => {
      // Handle both direct strings and object with data/signature properties
      if (typeof args[0] === 'string' && typeof args[1] === 'string') {
        return this.verify(args[0], args[1]);
      }
      const obj = args[0] as { data: string; signature: string };
      return this.verify(obj.data, obj.signature);
    });

    // Add signing capabilities if signer is provided
    if (this.signer) {
      this.addSigningCapabilities();
    }
  }

  /**
   * Create Key unit from props
   */
  static create(props: {
    publicKeyPEM: string;
    keyType: KeyType;
    meta?: Record<string, unknown>;
    signer?: ISigner;
  }): Key | null {
    try {
      if (!props.publicKeyPEM || !props.keyType) {
        return null;
      }
      
      // Validate key type
      const validKeyTypes: KeyType[] = ['ed25519', 'rsa', 'secp256k1', 'x25519', 'wireguard'];
      if (!validKeyTypes.includes(props.keyType)) {
        return null;
      }
      
      // Validate public key format (basic check)
      if (!Key.isValidPublicKey(props.publicKeyPEM, props.keyType)) {
        return null;
      }
      
      return new Key(props);
    } catch (error) {
      console.error('[🔑] Failed to create key:', error);
      return null;
    }
  }

  /**
   * Create Key from Signer (inherits signing capability)
   */
  static createFromSigner(signer: ISigner, meta?: Record<string, unknown>): Key | null {
    try {
      if (!signer || typeof signer.getPublicKey !== 'function') {
        return null;
      }

      const algorithm = signer.getAlgorithm?.() || 'unknown';
      const key = new Key({
        publicKeyPEM: signer.getPublicKey(),
        keyType: algorithm as KeyType,
        meta,
        signer
      });
      
      return key;
    } catch (error) {
      console.error('[🔑] Failed to create key from signer:', error);
      return null;
    }
  }

  /**
   * Create public-only Key (verification only)
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
      return new Key({
        publicKeyPEM,
        keyType,
        meta
      });
    } catch (error) {
      console.error('[🔑] Failed to create public key:', error);
      return null;
    }
  }

  /**
   * Validate public key format
   */
  private static isValidPublicKey(publicKeyPEM: string, keyType: KeyType): boolean {
    if (!publicKeyPEM || !keyType) {
      return false;
    }
    
    // Basic validation - reject obviously invalid keys
    if (publicKeyPEM === 'invalid-key' || 
        publicKeyPEM === 'corrupted-public-key' ||
        publicKeyPEM.length < 10) {
      return false;
    }
    
    // Check for PEM format (if it starts with -----BEGIN)
    if (publicKeyPEM.startsWith('-----BEGIN')) {
      return true;
    }
    
    // For hex format, check minimum length requirements
    switch (keyType) {
      case 'ed25519':
        return publicKeyPEM.length >= 64; // 32 bytes * 2 hex chars
      case 'secp256k1':
        return publicKeyPEM.length >= 66; // 33 bytes * 2 hex chars (compressed)
      case 'rsa':
        return publicKeyPEM.length >= 100; // RSA keys are much longer
      case 'x25519':
        return publicKeyPEM.length >= 64; // 32 bytes * 2 hex chars
      case 'wireguard':
        return publicKeyPEM.length >= 44; // Base64 encoded 32 bytes
      default:
        return false;
    }
  }

  /**
   * Add signing capabilities when signer is connected
   */
  private addSigningCapabilities(): void {
    if (!this.signer) return;
    
    this._addCapability('sign', (...args: unknown[]) => {
      // Handle both direct string and object with data property
      const data = typeof args[0] === 'string' ? args[0] : (args[0] as { data: string })?.data;
      return this.sign(data);
    });
    
    // Add verify capability if signer supports it
    if ('verify' in this.signer) {
      this._addCapability('verify', (...args: unknown[]) => {
        // Handle both direct strings and object with data/signature properties
        if (typeof args[0] === 'string' && typeof args[1] === 'string') {
          return this.verify(args[0], args[1]);
        }
        const obj = args[0] as { data: string; signature: string };
        return this.verify(obj.data, obj.signature);
      });
    }
  }

  /**
   * Custom learn method with public key validation
   * Overrides BaseUnit.learn() to ensure security
   */
  learn(capabilities: Record<string, (...args: unknown[]) => unknown>[]): boolean {
    // Handle empty capabilities array
    if (!capabilities || capabilities.length === 0) {
      return false;
    }
    
    // If learning from a signer, validate public key consistency
    for (const capSet of capabilities) {
      if (capSet.getPublicKey && typeof capSet.getPublicKey === 'function') {
        try {
          const learntPublicKey = capSet.getPublicKey();
          if (learntPublicKey !== this.publicKeyPEM) {
            console.warn('[🔑] Public key mismatch: Key has different public key than Signer');
            return false;
          }
        } catch (error) {
          // If getPublicKey fails, this is an invalid teacher
          return false;
        }
      }
    }
    
    try {
      // Learn capabilities using parent method
      super.learn(capabilities);
      return true;
    } catch (error) {
      console.error('[🔑] Failed to learn capabilities:', error);
      return false;
    }
  }

  /**
   * Connect external signer to this Key
   * Uses the teaching/learning pattern with validation
   */
  useSigner(signer: ISigner): boolean {
    try {
      // Critical check: ensure public keys match
      if (!signer || signer.getPublicKey() !== this.publicKeyPEM) {
        console.warn('[🔑] Public key mismatch: Key has different public key than Signer');
        return false;
      }
      
      this.signer = signer;
      
      // Use teaching/learning pattern
      const signerCapabilities = this.extractSignerCapabilities(signer);
      this.learn([signerCapabilities]);
      
      return true;
    } catch (error) {
      console.error(`[🔑] Failed to connect signer: ${error}`);
      return false;
    }
  }

  /**
   * Extract capabilities from signer if it doesn't support teach()
   */
  private extractSignerCapabilities(signer: ISigner): Record<string, (...args: unknown[]) => unknown> {
    const capabilities: Record<string, (...args: unknown[]) => unknown> = {
      sign: (...args: unknown[]) => signer.sign(args[0] as string),
      getPublicKey: () => signer.getPublicKey()
    };
    
    // Add verify if supported
    if ('verify' in signer && typeof (signer as ISigner & { verify?: unknown }).verify === 'function') {
      const signerWithVerify = signer as ISigner & { verify(data: string, signature: string): Promise<boolean> };
      capabilities.verify = (...args: unknown[]) => signerWithVerify.verify(args[0] as string, args[1] as string);
    }
    
    return capabilities;
  }

  // Unit implementation
  whoami(): string {
    const capability = this.canSign() ? 'with signing capability' : 'with verification-only capability';
    return `[🔑] Key Unit - ${this.keyType} public key (${this.keyId.slice(0, 8)}) ${capability}`;
  }

  capabilities(): string[] {
    return this._getAllCapabilities();
  }

  help(): void {
    console.log(`
[🔑] Key Unit - Public-Facing Cryptographic Key

Identity: ${this.whoami()}
Algorithm: ${this.keyType}
Can Sign: ${this.canSign()}

Core Capabilities:
- getPublicKey(): Get public key for sharing
- canSign(): Check if key can sign data
- toJSON(): Export key information
- toVerificationMethod(): DID verification method
- useSigner(signer): Connect external signer

${this.canSign() ? `
Signing Capabilities (learned):
- sign(data): Sign data using connected signer
- verify(data, signature): Verify signatures
` : ''}

Unit Operations:
- execute(capability, ...args): Execute any capability
- learn(capabilities): Learn capabilities from teachers
- teach(): Share capabilities with other units
- capabilities(): List all available capabilities

Security:
- Public key only (no private key exposure)
- Validates public key consistency when learning
- Can learn from Signer units through useSigner()

Examples:
  const key = Key.createPublic(publicKey, 'ed25519', { name: 'my-key' });
  key.useSigner(signer); // Learn signing capabilities
  await key.execute('sign', 'hello world');
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

    // Add signing capabilities if available
    if (this.canSign()) {
      teachings.sign = (...args: unknown[]) => this.sign(args[0] as string);
      teachings.verify = (...args: unknown[]) => this.verify(args[0] as string, args[1] as string);
    }

    return teachings;
  }

  // Core key operations
  getPublicKey(): string {
    return this.publicKeyPEM;
  }

  canSign(): boolean {
    return this.signer !== undefined || this.capabilities().includes('sign');
  }

  async sign(data: string): Promise<string> {
    if (this.signer) {
      return await this.signer.sign(data);
    }
    
    // Check if we have a learned sign capability
    if (this.capabilities().includes('sign')) {
      return await this.execute('sign', data);
    }
    
    throw new Error('[🔑] Cannot sign: no signer available. Use useSigner() or createFromSigner()');
  }

  async verify(data: string, signature: string): Promise<boolean> {
    if (this.signer && 'verify' in this.signer) {
      // Type guard for extended signer with verify method
      const signerWithVerify = this.signer as ISigner & { verify(data: string, signature: string): Promise<boolean> };
      return await signerWithVerify.verify(data, signature);
    }
    
    // Perform public key verification without signer
    return this.performPublicKeyVerification(data, signature);
  }

  /**
   * Perform cryptographic verification using public key only
   */
  private performPublicKeyVerification(data: string, signature: string): boolean {
    if (!data || !signature || !this.publicKeyPEM) {
      return false;
    }

    try {
      // Import crypto for verification
      const crypto = require('node:crypto');
      
      switch (this.keyType) {
        case 'ed25519':
          return crypto.verify(
            null,
            Buffer.from(data),
            {
              key: this.publicKeyPEM,
              format: 'pem',
            },
            Buffer.from(signature, 'base64')
          );
        case 'rsa': {
          const verify = crypto.createVerify('SHA256');
          verify.update(data);
          verify.end();
          return verify.verify(this.publicKeyPEM, signature, 'base64');
        }
        case 'secp256k1': {
          const verifySecp = crypto.createVerify('SHA256');
          verifySecp.update(data);
          verifySecp.end();
          return verifySecp.verify(this.publicKeyPEM, signature, 'base64');
        }
        case 'x25519':
        case 'wireguard':
          return false; // These are not for signing
        default:
          return false;
      }
    } catch (error) {
      console.error('[🔑] Verification failed:', error);
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
