import init, { EddsaSigner } from '@eddsa-bindings';

function stringToUint8Array(str) {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

init().then((module) => {
  console.log("webassembly initialized...");
  let signingKeyBytes = EddsaSigner.random();
  console.log("signingKeyBytes", signingKeyBytes)
  let signer = new EddsaSigner(signingKeyBytes);
  console.log("verifyingKey", signer.verifyingKey());

  let message = "example message to sign";
  let messageBytes = stringToUint8Array(message);

  let signature = signer.sign(messageBytes);
  console.log("signature", signature);
  
  try {
    signer.verify(messageBytes, signature);
    console.log("signature verified");
  } catch (e) {
    console.error("verification failed", e);
  }

})
