import { Wallet, Signature } from "ethers";

const privateKey =
  "0xf64abc91d673bcf100c3cf2bc42507df566d36a18189ae41c377c55ee26a44fd";
const wallet = new Wallet(privateKey);
const message = "example message";
const signature = await wallet.signMessage(message);
const sig = Signature.from(signature);

function stripPrefix(s) {
  return s.replace(/^0x/, '');
}

const vectors = {
  signedMessage: {
    privateKey: stripPrefix(privateKey),
    message,
    signature: {
      r: stripPrefix(sig.r),
      s: stripPrefix(sig.s),
      v: sig.v,
    },
  },
}

console.log(JSON.stringify(vectors, undefined, 2));

// console.log(sig.r);
// console.log(sig.s);
// console.log(sig.v);

