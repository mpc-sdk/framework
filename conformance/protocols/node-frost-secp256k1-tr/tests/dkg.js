import {
  parentPort,
  workerData,
} from 'node:worker_threads';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const polysig = require('../build/polysig.node');
const { partyIndex, server, parameters } = workerData;
const partyKeys = require("./schnorr.json").slice(0, parameters.parties);

const { FrostSecp256K1TrProtocol: FrostProtocol } = polysig;

const publicKey = partyKeys[partyIndex].encrypt.public;

const participants = partyKeys.map((key) => {
  return key.encrypt.public;
});

const verifiers = partyKeys.map((key) => {
  return { publicKey: key.sign.public };
});

const signer = { bytes: partyKeys[partyIndex].sign.private };
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

const keyShare = await FrostProtocol.dkg(
  options,
  party,
  signer,
);

await parentPort.postMessage({partyIndex, keyShare});
