const module = await import("/pkg/mpc_webassembly_bindings.js");

// Initialize the webassembly
await module.default();

// Convert from a hex-encoded string.
function fromHexString(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

const publicKey = ${PUBLIC_KEY};
const partyIndex = ${INDEX};
const message = "${MESSAGE}";
const participants = ${PARTICIPANTS};
const keygenSessionIdSeed = ${KEYGEN_SESSION_ID_SEED};
const signSessionIdSeed = ${SIGN_SESSION_ID_SEED};
const signer = ${SIGNER};
const verifiers = ${VERIFIERS};
const options = {
  protocol: "cggmp",
  keypair: `${KEYPAIR}`,
  server: {
    serverUrl: "${SERVER_URL}",
    serverPublicKey: "${SERVER_PUBLIC_KEY}",
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

const protocol = new module.CggmpProtocol();

try {

  // Start key generation
  const keyShare = await protocol.keygen(
    options,
    party,
    fromHexString(keygenSessionIdSeed),
    fromHexString(signer),
  );

  console.log("keygen completed");

  const keyShareElement = document.getElementById("key-share");
  keyShareElement.innerHTML = `<p class="address">Address: ${keyShare.address}</p>`;

  // First and third parties perform signing
  if (partyIndex == 0 || partyIndex == 2) {
    const result = await protocol.sign(
      options,
      signParty,
      fromHexString(signSessionIdSeed),
      fromHexString(signer),
      keyShare.privateKey,
      message,
    );

    console.log("signature: ", result);

    const signatureElement = document.getElementById("signature");
    signatureElement.innerHTML = `
      <p class="signature">Signature: ${result.cggmp}</p>`;

    console.log("signing completed");
  }
} catch (e) {
  console.error(e);
}
