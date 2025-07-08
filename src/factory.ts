/**
 * Factory functions to avoid circular dependencies
 */

import { Key } from './key';
import { Signer } from './signer';
import type { KeyType } from './keys';

/**
 * Create a Key from a Signer and teach it signing capabilities
 */
export function createKeyFromSigner(signer: Signer) {
  try {
    const key = Key.create({
      publicKeyPEM: signer.getPublicKey(),
      keyType: signer.getAlgorithm() as KeyType,
      meta: signer.metadata
    });
    
    if (key) {
      // Teach the key our signing capabilities
      const teaching = signer.teach();
      key.learn([teaching]);
    }
    
    return key;
  } catch (error) {
    console.error('[🔐] Failed to create key from signer:', error);
    return null;
  }
}
