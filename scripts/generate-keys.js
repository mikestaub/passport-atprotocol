const crypto = require('crypto');
const fs = require('fs');

function generateECKey(kid) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });

  const publicKeyJwk = publicKey.export({ format: 'jwk' });
  const privateKeyJwk = privateKey.export({ format: 'jwk' });

  // Create a JWK representation of the key
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    use: 'sig',
    kid: kid,
    x: publicKeyJwk.x,
    y: publicKeyJwk.y,
    d: privateKeyJwk.d,
  };

  return JSON.stringify(jwk);
}

// Generate 3 keys
const privateKeys = {
  PRIVATE_KEY_1: generateECKey('key-1'),
  PRIVATE_KEY_2: generateECKey('key-2'),
  PRIVATE_KEY_3: generateECKey('key-3'),
};

// Save the keys to a .env file
const envContent = Object.entries(privateKeys)
  .map(([key, value]) => `${key}='${value}'`)
  .join('\n');

fs.writeFileSync('.env', envContent);

console.log('Private keys generated and saved to .env file');
