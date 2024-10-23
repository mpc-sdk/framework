import init, { EddsaSigner } from '@eddsa-bindings';

await init();

console.log("webassembly initialized...");

function stringToUint8Array(str) {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

let signingKeyBytes = EddsaSigner.random();
let signer = new EddsaSigner(signingKeyBytes);
let messageBytes = stringToUint8Array("example message to sign");
let signature = signer.sign(messageBytes);

console.log("signingKeyBytes", signingKeyBytes)
console.log("verifyingKey", signer.verifyingKey());
console.log("signature", signature);

let verified = false;

try {
  signer.verify(messageBytes, signature);
  verified = true;
  console.log("signature verified");
} catch (e) {
  console.error("verification failed", e);
}

console.assert(verified);
