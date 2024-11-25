import {
  Worker, isMainThread, parentPort, workerData,
} from 'node:worker_threads';
import fs from 'fs';

const dkgScript = './tests/dkg.js';
const signScript = './tests/sign.js';

// Convert from a hex-encoded string.
function fromHexString(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

const serverKey = fs.readFileSync(
  "../../../crates/integration_tests/tests/server_public_key.txt", "utf8");

const server = {
  serverUrl: "ws://127.0.0.1:8008",
  serverPublicKey: Array.from(fromHexString(serverKey)),
};
const parameters = {
  parties: 3,
  threshold: 2,
};

console.log("FROST Ed25519, begin dkg...");

let tasks = [];

const identifiers = Array.apply(null, Array(parameters.parties)).map((_, i) => {
  return {id: i + 1};
});

for (let i = 0;i < parameters.parties;i++) {
  tasks.push(new Promise((resolve, reject) => {
    const worker = new Worker(dkgScript, {
      workerData: {
        partyIndex: i,
        server,
        parameters,
        identifiers,
      }
    });

    worker.on('message', resolve);
    worker.on('error', reject);
    worker.on('exit', (code) => {
      if (code !== 0)
        throw new Error(`Worker stopped with exit code ${code}`);
    });
  }));
}

const keyShares = await Promise.all(tasks);

console.assert(keyShares.length === parameters.parties);

console.log("FROST Ed25519, dkg complete, begin signing...");

const message = "a3e6e406aeb475f43aa762bb752a8f9d57b7fa327a2a53c7ae00b13f8d116b38";

// Pick the signing parties
tasks = [];
const indices = [0, 2];
const signers = [
  keyShares[0].keyShare,
  keyShares[2].keyShare,
];

signers.forEach((keyShare, index) => {
  const partyIndex = indices[index];
    
  tasks.push(new Promise((resolve, reject) => {
    const worker = new Worker(signScript, {
      workerData: {
        partyIndex,
        indices,
        server,
        identifiers: indices.map((i) => identifiers[i]),
        parameters,
        keyShare,
        message,
      }
    });

    worker.on('message', resolve);
    worker.on('error', reject);
    worker.on('exit', (code) => {
      if (code !== 0)
        throw new Error(`Worker stopped with exit code ${code}`);
    });
  }));
});

const signatures = await Promise.all(tasks);
console.assert(signatures.length === parameters.threshold);
console.log("FROST Ed25519, signing complete, done.");
