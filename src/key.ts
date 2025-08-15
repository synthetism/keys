/**
 * Key Unit - Public-facing cryptographic key unit
 *  Clean unit that holds public key material and can learn signing capabilities
 * 
 * Design principles:
 * - Key is the public-facing unit (holds public key only)
 * - Can learn signing capabilities from Signer units via teach/learn pattern
 * - Simple getters for public properties (no complex methods)
 * - Full Unit architecture with execute, learn, teach, capabilities
 * 
 * @author Synet Team
 */

import { Unit, createUnitSchema, type TeachingContract, type UnitProps } from '@synet/unit';
import { createId } from './utils';
import type { KeyType } from './keys';
import * as crypto from 'node:crypto';

/**
 * Configuration for creating a Key unit
 */
export interface KeyConfig {
  publicKeyPEM: string;
  keyType: KeyType;
  meta?: Record<string, unknown>;
}

/**
 * Props interface for Key unit - follows Unit Architecture Doctrine
 */
export interface KeyProps extends UnitProps {
  publicKeyPEM: string;
  keyType: KeyType;
  keyId: string;
  meta: Record<string, unknown>;
}

export class Key extends Unit<KeyProps> {

  protected constructor(props: KeyProps) {
    super(props);

    // Register capabilities
    // Note: 'sign' and 'verify' capabilities are added dynamically when learned from Signer
    this._addCapability('getPublicKey', () => this.getPublicKey());
    this._addCapability('canSign', () => this.canSign());
    this._addCapability('toJSON', () => this.toJSON());
  }

  // Public property getters (props-based access)
  get publicKeyPEM(): string {
    return this.props.publicKeyPEM;
  }

  get keyType(): KeyType {
    return this.props.keyType;
  }

  get keyId(): string {
    return this.props.keyId;
  }

  get meta(): Record<string, unknown> {
    return { ...this.props.meta };
  }

  /**
   * Create Key unit from config
   */
  static create(config: KeyConfig): Key {
    try {
      if (!config.publicKeyPEM || !config.keyType) {
        throw new Error('Invalid parameters, publicKeyPEM and keyType are required');
      }
      
      // Validate key type
      const validKeyTypes: KeyType[] = ['ed25519', 'rsa', 'secp256k1', 'x25519', 'wireguard'];
      if (!validKeyTypes.includes(config.keyType)) {
        throw new Error(`Invalid key type: ${config.keyType}`);
      }
      
      // Validate public key format (basic check)
      if (!Key.isValidPublicKey(config.publicKeyPEM, config.keyType)) {
        throw new Error(`Invalid public key format for key type: ${config.keyType}`);
      }
      
      const props: KeyProps = {
        dna: createUnitSchema({
          id: 'key-unit',
          version: '1.0.7'
        }),
        publicKeyPEM: config.publicKeyPEM,
        keyType: config.keyType,
        keyId: createId(),
        meta: config.meta || {},
        created: new Date()
      };
      
      return new Key(props);
    } catch (error) {
      console.error('[🔑] Failed to create key:', error);
      throw error;
    }
  }

  private static isValidPublicKey(publicKeyPEM: string, keyType: KeyType): boolean {
    try {
      // Basic validation - check for PEM format
      if (!publicKeyPEM.includes('-----BEGIN') || !publicKeyPEM.includes('-----END')) {
        return false;
      }
      
      // Key type specific validation
      switch (keyType) {
        case 'ed25519':
          return publicKeyPEM.includes('PUBLIC KEY');
        case 'rsa':
          return publicKeyPEM.includes('PUBLIC KEY') || publicKeyPEM.includes('RSA PUBLIC KEY');
        case 'secp256k1':
        case 'x25519':
        case 'wireguard':
          return publicKeyPEM.includes('PUBLIC KEY');
        default:
          return false;
      }
    } catch {
      return false;
    }
  }

  // Unit implementation
  whoami(): string {
    return `[🔑] Key Unit - ${this.props.keyType} public key (${this.props.keyId.slice(0, 8)})`;
  }

  capabilities(): string[] {
    return this._getAllCapabilities();
  }

  help(): void {
    console.log(`
[🔑] Key Unit - Clean Public Key Carrier

Identity: ${this.whoami()}
Key Type: ${this.props.keyType}
Key ID: ${this.props.keyId}

Public Properties:
  - publicKeyPEM: ${this.props.publicKeyPEM.substring(0, 50)}...
  - keyType: ${this.props.keyType}
  - keyId: ${this.props.keyId}

Capabilities: ${this.capabilities().join(', ')}

The Key unit holds public key material and can learn signing capabilities
from Signer units through the teach/learn pattern.
    `);
  }

  teach(): TeachingContract {
    return {
      unitId: this.dna.id,
      capabilities: {
        getPublicKey: () => this.props.publicKeyPEM,
        getKeyType: () => this.props.keyType,
        getKeyId: () => this.props.keyId,
        toJSON: () => this.toJSON(),
        sign: (...args: unknown[]) => this.sign(args[0] as string),
        verify: (...args: unknown[]) => this.verify(args[0] as string, args[1] as string),
      }
    };
  }

  /**
   * Verify signature using public key
   * Must learn verification capability from Signer to use this method
   */
  async verify(data: string, signature: string): Promise<boolean> {
    try {
      // Use learned verification capability (preferred and secure)
      if (this.capabilities().includes('verify')) {
        return this.execute('verify', data, signature);
      }
      
      // No fallback - Keys must learn verification from Signer
      throw new Error('[🔑] Cannot verify without learning verification capability from Signer. Use signer.createKey() or key.learn([signerTeaching])');
    } catch (error) {
      if (error instanceof Error && error.message.includes('Cannot verify without learning')) {
        throw error;
      }
      return false;
    }
  }

  /**
   * Sign data - uses learned signing capability if available
   */
  async sign(data: string): Promise<string> {
    if (this.canSign()) {
      return this.execute('sign', data);
    }
    throw new Error('[🔑] Cannot sign with public-only key. Use signer.createKey() or key.learn([signerTeaching]) to enable signing.');
  }

  /**
   * Check if this key can sign
   * Returns true if signing capabilities have been learned
   */
  canSign(): boolean {
    return this.capabilities().includes('sign');
  }

  /**
   * Get public key (compatibility method)
   */
  getPublicKey(): string {
    return this.props.publicKeyPEM;
  }

  toJSON(): Record<string, unknown> {
    return {
      unitId: this.dna.id,
      keyId: this.props.keyId,
      publicKeyPEM: this.props.publicKeyPEM,
      keyType: this.props.keyType,
      meta: this.props.meta,
      created: this.props.created,
      capabilities: this.capabilities()
    };
  }

  /**
   * Override learn method to handle Signer teachings
   */
  async learn(teachings: TeachingContract[]): Promise<boolean> {
    try {
      for (const teaching of teachings) {
        if (teaching.capabilities?.sign) {
          // Add both signing and verification capabilities dynamically
          this._addCapability('sign', teaching.capabilities.sign);
          //console.debug(`Key learned signing capability from ${teaching.unitId}`);
        }
        if (teaching.capabilities?.verify) {
          // Learn robust verification from Signer
          this._addCapability('verify', teaching.capabilities.verify);
          //console.debug(`Key learned verification capability from ${teaching.unitId}`);
        }
        if (teaching.capabilities?.sign || teaching.capabilities?.verify) {
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error('Failed to learn capabilities:', error);
      return false;
    }
  }
}
