/**
 * Test the core Signer.createKey() functionality
 */

const { Signer } = require('./dist/signer');

async function testSignerCreateKey() {
  console.log('\n=== Testing Signer.createKey() ===');
  
  // Step 1: Create Signer
  const signer = Signer.generate('ed25519', { name: 'test-signer' });
  if (!signer) {
    console.error('❌ Failed to create Signer');
    return;
  }
  console.log('✅ Signer created:', signer.whoami());
  
  // Step 2: Create Key from Signer
  const key = signer.createKey();
  if (!key) {
    console.error('❌ Failed to create Key from Signer');
    return;
  }
  console.log('✅ Key created:', key.whoami());
  
  // Step 3: Verify Key properties
  console.log('🔍 Key properties:');
  console.log('  - publicKeyPEM matches:', key.publicKeyPEM === signer.getPublicKey());
  console.log('  - keyType matches:', key.keyType === signer.getAlgorithm());
  console.log('  - can sign:', key.canSign());
  
  // Step 4: Test signing
  try {
    const testData = 'Hello, world!';
    const signature = await key.sign(testData);
    console.log(`✅ Key can sign! Signature: ${signature.substring(0, 20)}...`);
    
    // Step 5: Test verification
    const isValid = await key.verify(testData, signature);
    console.log('✅ Signature verification:', isValid);
    
    // Step 6: Test execute interface
    const executeSignature = await key.execute('sign', testData);
    console.log('✅ Execute interface works:', typeof executeSignature === 'string');
    
  } catch (error) {
    console.error('❌ Signing failed:', error);
  }
}

async function testPublicOnlyKey() {
  console.log('\n=== Testing Public-Only Key ===');
  
  // Step 1: Create Signer for public key material
  const signer = Signer.generate('ed25519');
  if (!signer) {
    console.error('❌ Failed to create Signer');
    return;
  }
  
  // Step 2: Create public-only Key
  const { Key } = require('./dist/key');
  const publicKey = Key.create({
    publicKeyPEM: signer.getPublicKey(),
    keyType: signer.getAlgorithm(),
    meta: { type: 'public-only' }
  });
  
  if (!publicKey) {
    console.error('❌ Failed to create public-only Key');
    return;
  }
  
  console.log('✅ Public-only Key created:', publicKey.whoami());
  console.log('  - can sign (before learning):', publicKey.canSign());
  
  // Step 3: Try to sign (should fail)
  try {
    await publicKey.sign('test');
    console.error('❌ Public-only key should not be able to sign!');
  } catch (error) {
    console.log('✅ Public-only key correctly refuses to sign');
  }
  
  // Step 4: Teach the key to sign
  const teaching = signer.teach();
  const learned = await publicKey.learn([teaching]);
  console.log('✅ Learning result:', learned);
  console.log('  - can sign (after learning):', publicKey.canSign());
  
  // Step 5: Now try to sign
  try {
    const signature = await publicKey.sign('test data');
    console.log('✅ Key can now sign after learning!');
    
    const isValid = await publicKey.verify('test data', signature);
    console.log('✅ Signature verification:', isValid);
  } catch (error) {
    console.error('❌ Signing failed after learning:', error);
  }
}

// Run tests
testSignerCreateKey()
  .then(() => testPublicOnlyKey())
  .then(() => console.log('\n=== Tests Complete ==='))
  .catch(console.error);
