import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const unisign = require('./unisign.node');
const { EcdsaSigner } = unisign;

function stringToByteArray(str) {
  const buffer = Buffer.from(str, 'utf-8');
  return Array.from(buffer);
}

function arraysEqual(arr1, arr2) {
  if (arr1.length !== arr2.length) {
    return false;
  }

  for (let i = 0; i < arr1.length; i++) {
    if (arr1[i] !== arr2[i]) {
      return false;
    }
  }

  return true;
}

function signVerify() {
  console.log("signVerify");

  const signingKeyBytes = EcdsaSigner.random();
  const signer = new EcdsaSigner(signingKeyBytes);

  const messageBytes = stringToByteArray("example message to sign");
  const signature = signer.sign(messageBytes);
  const verifyingKey = signer.verifyingKey();

  // console.log("signingKeyBytes", signingKeyBytes)
  // console.log("verifyingKey", verifyingKey);
  // console.log("signature", signature);

  console.assert(signingKeyBytes.length === 32);
  console.assert(verifyingKey.length === 33); // SEC1 encoded bytes
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
}

// NOTE: EcdsaSigner.recover() assumes the Keccak256 hash so 
// NOTE: we must use signEth() to ensure the message
// NOTE: is hashed with Keccak256.
function signEthRecover() {
  console.log("signEthRecover");

  const signingKeyBytes = EcdsaSigner.random();
  const signer = new EcdsaSigner(signingKeyBytes);
  const verifyingKey = signer.verifyingKey();
  const messageBytes = stringToByteArray("example message to sign");
  const hashBytes = EcdsaSigner.keccak256(messageBytes);
  const signature = signer.signEth(messageBytes);

  // console.log("signingKeyBytes", signingKeyBytes)
  // console.log("verifyingKey", verifyingKey);
  // console.log("signature", signature);

  console.assert(signingKeyBytes.length === 32);
  console.assert(verifyingKey.length === 33); // SEC1 encoded bytes
  console.assert(signature.bytes.length === 64);
  console.assert(typeof(signature.recoveryId) === "number");
  console.assert(signature.recoveryId === 0 || signature.recoveryId === 1);

  let verified = false;
  
  try {
    signer.verifyPrehash(hashBytes, signature.bytes);
    verified = true;
    console.log("signature verified");
  } catch (e) {
    console.error("verification failed", e);
  }
  
  console.assert(verified);
  
  try {
    const publicKey = EcdsaSigner.recover(messageBytes, signature);
    console.assert(arraysEqual(verifyingKey, publicKey));
  } catch(e) {
    console.error("public key recovery failed", e);
  }

}

signVerify();
signEthRecover();
