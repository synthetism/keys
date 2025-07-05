/**
 * Test file for Key unit in @synet/keys
 */

import { describe, it, expect, vi } from 'vitest';
import { Key } from '../src/key';

describe('Key Unit', () => {
  it('should show help', () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    
    Key.help();
    
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it('should generate a new key pair', () => {
    const key = Key.generate('ed25519', { name: 'test-key' });
    
    expect(key).toBeDefined();
    expect(key.id).toBeDefined();
    expect(key.type).toBe('ed25519');
    expect(key.publicKeyHex).toBeDefined();
    expect(key.canSign()).toBe(true);
    expect(key.meta.name).toBe('test-key');
  });

  it('should create key from existing key pair', () => {
    const existingPublicKey = 'existing-public-key-hex';
    const existingPrivateKey = 'existing-private-key-hex';
    
    const key = Key.fromKeyPair('ed25519', existingPublicKey, existingPrivateKey, { name: 'migrated-key' });
    
    expect(key.publicKeyHex).toBe(existingPublicKey);
    expect(key.canSign()).toBe(true);
    expect(key.meta.name).toBe('migrated-key');
  });

  it('should generate different key types', () => {
    const ed25519Key = Key.generate('ed25519');
    const rsaKey = Key.generate('rsa');
    const x25519Key = Key.generate('x25519');
    
    expect(ed25519Key.type).toBe('ed25519');
    expect(rsaKey.type).toBe('rsa');
    expect(x25519Key.type).toBe('x25519');
    
    expect(ed25519Key.publicKeyHex).toBeDefined();
    expect(rsaKey.publicKeyHex).toBeDefined();
    expect(x25519Key.publicKeyHex).toBeDefined();
  });

  it('should create public-only key', () => {
    const originalKey = Key.generate('ed25519');
    const publicKey = Key.createPublic('ed25519', originalKey.publicKeyHex);
    
    expect(publicKey.publicKeyHex).toBe(originalKey.publicKeyHex);
    expect(publicKey.canSign()).toBe(false);
  });

  it('should sign and verify data', async () => {
    const key = Key.generate('ed25519');
    const data = 'test data to sign';
    
    const signature = await key.sign(data);
    expect(signature).toBeDefined();
    
    const isValid = await key.verify(data, signature);
    expect(isValid).toBe(true);
    
    const isInvalid = await key.verify('different data', signature);
    expect(isInvalid).toBe(false);
  });

  it('should create public key copy', () => {
    const originalKey = Key.generate('ed25519');
    const publicKey = originalKey.toPublicKey();
    
    expect(publicKey.publicKeyHex).toBe(originalKey.publicKeyHex);
    expect(publicKey.canSign()).toBe(false);
    expect(originalKey.canSign()).toBe(true);
  });

  it('should export to JSON', () => {
    const key = Key.generate('ed25519', { name: 'test-key' });
    const json = key.toJSON();
    
    expect(json.id).toBe(key.id);
    expect(json.publicKeyHex).toBe(key.publicKeyHex);
    expect(json.type).toBe('ed25519');
    expect(json.meta.name).toBe('test-key');
    expect(json.canSign).toBe(true);
  });

  it('should create verification method', () => {
    const key = Key.generate('ed25519');
    const controller = 'did:example:123';
    
    const vm = key.toVerificationMethod(controller);
    
    expect(vm.id).toBe(`${controller}#${key.id}`);
    expect(vm.type).toBe('ed25519VerificationKey2020');
    expect(vm.controller).toBe(controller);
    expect(vm.publicKeyHex).toBe(key.publicKeyHex);
  });

  it('should have unit DNA and capabilities', () => {
    const key = Key.generate('ed25519');
    
    expect(key.dna).toBeDefined();
    expect(key.dna.name).toBe('Key Unit');
    expect(key.dna.version).toBe('1.0.0');
    expect(key.dna.capabilities).toContain('sign');
    expect(key.dna.capabilities).toContain('getPublicKey');
    expect(key.dna.capabilities).toContain('verify');
    
    expect(key.whoami).toBe('Key Unit v1.0.0');
  });

  it('should work with external signer', () => {
    // Mock signer
    const mockSigner = {
      sign: vi.fn().mockResolvedValue('mock-signature'),
      getPublicKey: vi.fn().mockReturnValue('mock-public-key'),
      getAlgorithm: vi.fn().mockReturnValue('Ed25519')
    };
    
    const key = Key.createWithSigner('ed25519', 'mock-public-key', mockSigner);
    
    expect(key.canSign()).toBe(true);
    expect(key.publicKeyHex).toBe('mock-public-key');
  });

  it('should handle public key that cannot sign', async () => {
    const publicKey = Key.createPublic('ed25519', 'some-public-key');
    
    expect(publicKey.canSign()).toBe(false);
    await expect(publicKey.sign('data')).rejects.toThrow('Key cannot sign');
  });

  it('should demonstrate unit pattern benefits', () => {
    console.log('\n=== Key Unit Demo ===');
    
    // Show help
    Key.help();
    
    // Generate key
    const key = Key.generate('ed25519', { name: 'demo-key' });
    console.log('\n✅ Generated key:', {
      id: key.id,
      type: key.type,
      canSign: key.canSign(),
      publicKey: key.publicKeyHex.slice(0, 20) + '...'
    });
    
    // Show capabilities
    console.log('\n🛠️ Key capabilities:', key.dna.capabilities);
    
    // Show DNA
    console.log('\n🧬 Unit DNA:', key.dna.name, key.dna.version);
    
    console.log('\n💡 This demonstrates:');
    console.log('• Self-documenting with help()');
    console.log('• Secure key generation');
    console.log('• No private key exposure');
    console.log('• Type-safe operations');
    console.log('• Unit pattern benefits');
  });
});
