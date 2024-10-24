import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const unisign = require('./build/unisign.node');
const { SchnorrSigner } = unisign;

function stringToByteArray(str) {
  const buffer = Buffer.from(str, 'utf-8');
  return Array.from(buffer);
}

const signingKeyBytes = SchnorrSigner.random();
const signer = new SchnorrSigner(signingKeyBytes);
const verifyingKey = signer.verifyingKey();

const messageBytes = stringToByteArray("example message to sign");
const signature = signer.sign(messageBytes);

// console.log("signingKeyBytes", signingKeyBytes)
// console.log("verifyingKey", verifyingKey);
// console.log("signature", signature);

console.assert(signingKeyBytes.length === 32);
console.assert(verifyingKey.length === 32);
console.assert(signature.length === 64);

let verified = false;

try {
  signer.verify(messageBytes, signature);
  verified = true;
  console.log("signature verified");
} catch (e) {
  console.error("verification failed", e);
}

console.assert(verified);
