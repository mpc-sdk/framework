import init, { SchnorrSigner } from '@schnorr-bindings';

await init();

console.log("webassembly initialized...");

function stringToUint8Array(str) {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

const signingKeyBytes = SchnorrSigner.random();
const signer = new SchnorrSigner(signingKeyBytes);
const verifyingKey = signer.verifyingKey();
const messageBytes = stringToUint8Array("example message to sign");
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
