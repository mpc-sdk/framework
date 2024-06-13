const module = await import("/pkg/mpc_bindings.js");

// Initialize the webassembly
await module.default();

const partyIndex = ${INDEX};
const message = "${MESSAGE}";
const participants = ${PARTICIPANTS};
const signingParticipants = ${SIGNING_PARTICIPANTS};
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

// Start key generation
try {
  // Get the promise for key generation
  const keyShare = await module.keygen(options, participants);

  console.log("keygen completed");

  const keyShareElement = document.getElementById("key-share");
  keyShareElement.innerHTML = `
    <p class="address">Address: ${keyShare.address}</p>
    <p class="party-number">Party number: ${keyShare.privateKey.cggmp.i}</p>`;
  // First and third parties perform signing
  if (partyIndex == 0 || partyIndex == 2) {

    const result = await module.sign(
      options,
      signingParticipants,
      keyShare.privateKey,
      message);

    console.log("signature: ", result);

    const signatureElement = document.getElementById("signature");
    signatureElement.innerHTML = `
      <p class="signature-address">Address: ${result.cggmp.address}</p>
      <p>${JSON.stringify(result.cggmp.signature)}</p>`;

    console.log("signing completed");
  }
} catch (e) {
  console.error(e);
}
