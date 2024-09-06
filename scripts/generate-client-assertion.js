const jose = require('node-jose');
const crypto = require('crypto');

require('dotenv').config();

async function generateClientAssertion(privateKeyJwk, clientId, audience) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: clientId,
    sub: clientId,
    aud: audience,
    jti: crypto.randomBytes(16).toString('hex'),
    iat: now,
    exp: now + 300,
  };

  const header = {
    alg: 'ES256',
    kid: privateKeyJwk.kid,
  };

  console.log('Signing JWK:', JSON.stringify(privateKeyJwk, null, 2));

  const keystore = jose.JWK.createKeyStore();
  await keystore.add(privateKeyJwk);
  const key = keystore.get(privateKeyJwk.kid);

  const signed = await jose.JWS.createSign({ format: 'compact', fields: header }, key)
    .update(JSON.stringify(payload))
    .final();

  return signed;
}

async function main() {
  try {
    const privateKeyJwk = JSON.parse(process.env.PRIVATE_KEY_1);
    console.log('Parsed Private Key:', JSON.stringify(privateKeyJwk, null, 2));

    const clientId =
      'https://b6f0-2601-18f-27f-b590-2c31-b649-112a-116d.ngrok-free.app/static/client-metadata.json';
    const audience = 'https://bsky.social';

    const clientAssertion = await generateClientAssertion(privateKeyJwk, clientId, audience);
    console.log('Client Assertion:', clientAssertion);

    // Verify the assertion
    const publicKeyJwk = { ...privateKeyJwk };
    delete publicKeyJwk.d; // Remove the private key component
    console.log('Public Key for Verification:', JSON.stringify(publicKeyJwk, null, 2));

    const keystore = jose.JWK.createKeyStore();
    await keystore.add(publicKeyJwk);

    const verified = await jose.JWS.createVerify(keystore).verify(clientAssertion);
    console.log('Verified Payload:', JSON.parse(verified.payload.toString()));
  } catch (error) {
    console.error('Error:', error);
  }
}

main();
