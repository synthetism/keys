// Key generation functions
export { 
  generateKeyPair, 
  derivePublicKey, 
  getShortId, 
  getFingerprint,
  // Key format conversion utilities
  pemToHex,
  hexToPem,
  base64ToHex,
  hexToBase64,
  detectKeyFormat,
  toHex
} from "./keys";
export type { KeyPair, KeyType, KeyFormat } from "./keys";

// Verification functions
export {
  isValidBase64,
  verifyEd25519,
  verifyRSA,
  verifySecp256k1,
  verifySignature
} from "./verify";

// Unit architecture - Signer and Key units
export { Signer, type ISigner } from "./signer";
export { Key } from "./key";
