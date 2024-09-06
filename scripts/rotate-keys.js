const fs = require('fs');
const crypto = require('crypto');
const dotenv = require('dotenv');

function generateECKey(kid) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });

  const publicKeyJwk = publicKey.export({ format: 'jwk' });
  const privateKeyJwk = privateKey.export({ format: 'jwk' });

  return {
    kty: 'EC',
    crv: 'P-256',
    use: 'sig',
    kid: kid,
    x: publicKeyJwk.x,
    y: publicKeyJwk.y,
    d: privateKeyJwk.d,
  };
}

function rotateKeys() {
  // Load existing keys from .env file
  dotenv.config();
  const existingKeys = {
    PRIVATE_KEY_1: JSON.parse(process.env.PRIVATE_KEY_1),
    PRIVATE_KEY_2: JSON.parse(process.env.PRIVATE_KEY_2),
    PRIVATE_KEY_3: JSON.parse(process.env.PRIVATE_KEY_3),
  };

  // Generate a new key
  const newKey = generateECKey(`key-${Date.now()}`);

  // Rotate keys
  const rotatedKeys = {
    PRIVATE_KEY_1: existingKeys.PRIVATE_KEY_2,
    PRIVATE_KEY_2: existingKeys.PRIVATE_KEY_3,
    PRIVATE_KEY_3: newKey,
  };

  // Save the rotated keys to .env file
  const envContent = Object.entries(rotatedKeys)
    .map(([key, value]) => `${key}='${JSON.stringify(value)}'`)
    .join('\n');

  fs.writeFileSync('.env', envContent);

  console.log('Keys rotated and saved to .env file');
}

rotateKeys();
