// Key generation functions
export { generateKeyPair, derivePublicKey, getShortId, getFingerprint } from "./keys";
export type { KeyPair, KeyType, KeyFormat } from "./keys";

// Unit architecture - Signer and Key units
export { Signer, type ISigner } from "./signer";
export { Key } from "./key";

// Legacy compatibility (deprecated)
export { Key as LegacyKey } from "./key-old";
export type { UnitSchema, UnitCapabilities, CredentialKey } from "./key-old";
