const crypto = require('crypto');

console.log('Investigating Node.js crypto capabilities...');

// Test X25519 for WireGuard
try {
  const keyPair = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
  
  console.log('✓ X25519 works - can replace tweetnacl for WireGuard!');
  console.log('Public key length:', keyPair.publicKey.length, 'bytes');
  console.log('Private key length:', keyPair.privateKey.length, 'bytes');
  
  // Extract raw 32-byte keys (WireGuard format)
  const pubKeyRaw = keyPair.publicKey.slice(-32);
  const privKeyRaw = keyPair.privateKey.slice(-32);
  
  console.log('Raw public key (base64):', pubKeyRaw.toString('base64'));
  console.log('Raw private key (base64):', privKeyRaw.toString('base64'));
  
} catch (e) {
  console.log('✗ X25519 failed:', e.message);
}

// Test other key types
const tests = [
  { name: 'ed25519', params: 'ed25519', options: {} },
  { name: 'secp256k1', params: 'ec', options: { namedCurve: 'secp256k1' } },
  { name: 'rsa', params: 'rsa', options: { modulusLength: 2048 } }
];

for (const test of tests) {
  try {
    const keyPair = crypto.generateKeyPairSync(test.params, test.options);
    console.log(`✓ ${test.name} supported`);
  } catch (e) {
    console.log(`✗ ${test.name} not supported:`, e.message);
  }
}
