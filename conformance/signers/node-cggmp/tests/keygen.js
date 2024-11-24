import {
  parentPort,
  workerData,
} from 'node:worker_threads';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const polysig = require('../build/polysig.node');
const { partyIndex, server, parameters, sessionIdSeed } = workerData;
const partyKeys = require("./ecdsa.json").slice(0, parameters.parties);

const { CggmpProtocol } = polysig;

const publicKey = partyKeys[partyIndex].encrypt.public;

const participants = partyKeys.map((key) => {
  return key.encrypt.public;
});

const verifiers = partyKeys.map((key) => {
  return { bytes: key.sign.public };
});

const signer = partyKeys[partyIndex].sign.private;
const options = {
  keypair: partyKeys[partyIndex].encrypt,
  server,
  parameters
};

const party = {
  publicKey,
  participants,
  isInitiator: partyIndex == 0,
  verifiers,
  partyIndex,
};

const keyShare = await CggmpProtocol.dkg(
  options,
  party,
  sessionIdSeed,
  signer,
);

await parentPort.postMessage({partyIndex, keyShare});

// console.log("cggmp", CggmpProtocol);

/*
// Convert from a hex-encoded string.
function fromHexString(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

const publicKey = Array.from(fromHexString("f228c0826177e911648a67568ca516b4949c511d7f94fdd96321ea521689c01c"));
const partyIndex = 0;
const message = "a3e6e406aeb475f43aa762bb752a8f9d57b7fa327a2a53c7ae00b13f8d116b38";
const participants = [[242,40,192,130,97,119,233,17,100,138,103,86,140,165,22,180,148,156,81,29,127,148,253,217,99,33,234,82,22,137,192,28],[30,24,115,66,232,8,226,69,197,50,171,83,204,31,12,67,253,168,129,129,103,73,224,139,203,232,221,92,66,219,88,122],[116,105,160,109,121,54,36,96,50,227,208,32,122,218,113,23,106,211,98,20,153,110,243,240,153,6,200,198,243,126,29,63]];
const keygenSessionIdSeed = "ee507039fb7b14bf8190f300c66732110b401a68ba8e0d3fa464809972d33489";
const signSessionIdSeed = "289e497ac7c2640adda5bf9bf0e9a05833f1807d1c4dce3f73e3483513bfa25e";
const signer = "7ffe002c836dead5df9bf9c6a1a08bab7c7e8f05d0d856b3b4ebaffc02939d9e";
const verifiers = ["020193382c068e26337453213b192538dafecf1d9a28743109b7d924df855c460a","02258988dafbf0f83080cf3669ab3591f5566c4c2ea3a1cb28a76f3fa071467986","03dc7ec659f54f71b85e97b85ef4a90423ef8df15427648db5918dae880d895c61"].map((v) => {
  return {bytes: Array.from(fromHexString(v))};
});
const options = {
  protocol: "cggmp",
  keypair: {pem: `-----BEGIN NOISE PATTERN-----
Tm9pc2VfTk5fMjU1MTlfQ2hhQ2hhUG9seV9CTEFLRTJz
-----END NOISE PATTERN-----

-----BEGIN NOISE PUBLIC KEY-----
8ijAgmF36RFkimdWjKUWtJScUR1/lP3ZYyHqUhaJwBw=
-----END NOISE PUBLIC KEY-----

-----BEGIN NOISE PRIVATE KEY-----
KBTGv5plD8tTd5vzlf4bCrhiP+096R06W4ZnTuEom1w=
-----END NOISE PRIVATE KEY-----
`},
  server: {
    serverUrl: "ws://127.0.0.1:8008",
    serverPublicKey: Array.from(fromHexString("745522c5231a7a3c1a4226d3cb0367ce23649d45d7c8e5411d2fa5c3399a4f6d")),
  },
  parameters: {
    parties: 3,
    threshold: 2,
  },
};
const party = {
  publicKey,
  participants,
  isInitiator: partyIndex == 0,
  verifiers,
  partyIndex,
};
const signParty = {
  publicKey,
  participants: [participants[0], participants[2]],
  isInitiator: partyIndex == 0,
  verifiers: [verifiers[0], verifiers[2]],
  partyIndex,
};

try {

  // Start key generation
  const keyShare = await CggmpProtocol.dkg(
    options,
    party,
    Array.from(fromHexString(keygenSessionIdSeed)),
    Array.from(fromHexString(signer)),
  );

  console.log("keygen completed", keyShare);

  const protocol = new CggmpProtocol(options, keyShare);
  const verifyingKey = protocol.verifyingKey();
  const address = protocol.address();

  console.log("verifyingKey", verifyingKey);
  console.log("address", address);

  console.assert(verifyingKey.length === 33); // SEC1 encoded

  // First and third parties perform signing
  if (partyIndex == 0 || partyIndex == 2) {
    const result = await protocol.sign(
      signParty,
      Array.from(fromHexString(signSessionIdSeed)),
      Array.from(fromHexString(signer)),
      message,
    );

    console.log("signature", result);
    console.log("signing completed");
  }
} catch (e) {
  console.error(e);
}

*/
