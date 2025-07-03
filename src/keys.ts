import * as crypto from "node:crypto";

/**
 * Supported cryptographic key types
 */
export type KeyType = "rsa" | "ed25519" | "x25519" | "secp256k1" | "wireguard";

/**
 * Key pair interface for all cryptographic key types
 */
export interface KeyPair {
  privateKey: string;
  publicKey: string;
  type: KeyType;
}

/**
 * Key encoding formats
 */
export type KeyFormat = "pem" | "raw" | "base64";

/**
 * Generate a cryptographic key pair
 * @param type The type of key to generate
 * @param options Optional configuration for key generation
 * @returns A key pair object containing the private and public keys
 * @throws Error if the key type is unsupported
 */
export function generateKeyPair(type: KeyType, options?: { format?: KeyFormat }): KeyPair {
  const format = options?.format || "pem";
  
  try {
    switch (type) {
      case "rsa":
        return generateRsaKeyPair(format);
      case "ed25519":
        return generateEd25519KeyPair(format);
      case "x25519":
        return generateX25519KeyPair(format);
      case "secp256k1":
        return generateSecp256k1KeyPair(format);
      case "wireguard":
        return generateWireguardKeyPair();
      default:
        throw new Error(`Unsupported key type: ${type}`);
    }
  } catch (error) {
    throw new Error(`Failed to generate ${type} key pair: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Generate RSA key pair (2048-bit)
 */
function generateRsaKeyPair(format: KeyFormat): KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { 
    publicKey: publicKey.toString(), 
    privateKey: privateKey.toString(), 
    type: "rsa" 
  };
}

/**
 * Generate Ed25519 key pair (digital signatures)
 */
function generateEd25519KeyPair(format: KeyFormat): KeyPair {
  if (format === "raw" || format === "base64") {
    // For raw format, we'll use PEM generation and extract the raw bytes
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "der" },
    });
    
    // Extract raw 32-byte keys from DER format
    const privateKeyRaw = Buffer.from(privateKey).subarray(-32); // Last 32 bytes
    const publicKeyRaw = Buffer.from(publicKey).subarray(-32); // Last 32 bytes
    
    return {
      privateKey: format === "base64" ? privateKeyRaw.toString("base64") : privateKeyRaw.toString("hex"),
      publicKey: format === "base64" ? publicKeyRaw.toString("base64") : publicKeyRaw.toString("hex"),
      type: "ed25519"
    };
  }
  
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { 
    publicKey: publicKey.toString(), 
    privateKey: privateKey.toString(), 
    type: "ed25519" 
  };
}

/**
 * Generate X25519 key pair (key exchange, used by WireGuard)
 */
function generateX25519KeyPair(format: KeyFormat): KeyPair {
  if (format === "raw" || format === "base64") {
    // For raw format, we'll use PEM generation and extract the raw bytes
    const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519", {
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "der" },
    });
    
    // Extract raw 32-byte keys from DER format
    const privateKeyRaw = Buffer.from(privateKey).subarray(-32); // Last 32 bytes
    const publicKeyRaw = Buffer.from(publicKey).subarray(-32); // Last 32 bytes
    
    return {
      privateKey: format === "base64" ? privateKeyRaw.toString("base64") : privateKeyRaw.toString("hex"),
      publicKey: format === "base64" ? publicKeyRaw.toString("base64") : publicKeyRaw.toString("hex"),
      type: "x25519"
    };
  }
  
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { 
    publicKey: publicKey.toString(), 
    privateKey: privateKey.toString(), 
    type: "x25519" 
  };
}

/**
 * Generate secp256k1 key pair (Bitcoin/Ethereum style)
 */
function generateSecp256k1KeyPair(format: KeyFormat): KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "secp256k1",
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { 
    publicKey: publicKey.toString(), 
    privateKey: privateKey.toString(), 
    type: "secp256k1" 
  };
}

/**
 * Generate WireGuard-compatible key pair (X25519 with base64 encoding)
 */
function generateWireguardKeyPair(): KeyPair {
  // WireGuard uses X25519 keys in base64 format
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
  
  // Extract raw 32-byte keys from DER format for WireGuard compatibility
  const privateKeyRaw = Buffer.from(privateKey).subarray(-32); // Last 32 bytes
  const publicKeyRaw = Buffer.from(publicKey).subarray(-32); // Last 32 bytes
  
  return {
    privateKey: privateKeyRaw.toString("base64"),
    publicKey: publicKeyRaw.toString("base64"),
    type: "wireguard"
  };
}
/** 
 * Extract the public key from a private key
 * @param privateKey The private key in PEM format
 * @returns The corresponding public key in PEM format, or null if extraction fails
 */
export function derivePublicKey(privateKey: string): string | null {
  try {
    if (
      !privateKey ||
      !privateKey.includes("-----BEGIN") ||
      !privateKey.includes("-----END")
    ) {
      return null;
    }
    // Create a KeyObject from the private key PEM
    const privateKeyObj = crypto.createPrivateKey({
      key: privateKey,
      format: "pem",
    });

    // Derive the public key from the private key
    const publicKey = crypto.createPublicKey(privateKeyObj).export({
      type: "spki",
      format: "pem",
    });

    return publicKey.toString();
  } catch (error) {
    console.error("Failed to derive public key:", error);
    return null;
  }
}

/**
 * Compute a short identifier from a public key
 * @param publicKey The public key in PEM format
 * @returns A 16-character hexadecimal identifier
 */
export function getShortId(publicKey: string): string {
  const hash = crypto.createHash("sha256").update(publicKey).digest("hex");
  return hash.substring(0, 16);
}

/**
 * Compute a fingerprint from a public key
 * @param publicKey The public key in PEM format
 * @returns A 64-character hexadecimal fingerprint
 */
export function getFingerprint(publicKey: string): string {
  return crypto.createHash("sha256").update(publicKey).digest("hex");
}