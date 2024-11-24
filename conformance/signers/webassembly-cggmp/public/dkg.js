const module = await import("/pkg/polysig_webassembly_bindings.js");

// Initialize the webassembly
await module.default();

const { CggmpProtocol } = module;

const params = new URLSearchParams(document.location.search);
const pageData = JSON.parse(params.get('data'));
const { partyIndex, server, parameters, sessionIdSeed } = pageData;
const partyKeys = JSON.parse(params.get('keys'));

const publicKey = partyKeys[partyIndex].encrypt.public;

const participants = partyKeys.map((key) => {
  return key.encrypt.public;
});

const verifiers = partyKeys.map((key) => {
  return key.sign.public;
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

function replacer(key, value) {
  if(value instanceof Map) {
    return {
      dataType: 'Map',
      value: Array.from(value.entries()),
    };
  } else {
    return value;
  }
}


console.log(keyShare);
// console.log(JSON.stringify(keyShare, replacer));

const el = document.getElementById("key-share");
el.innerHTML = `<p class="key-share">${JSON.stringify({partyIndex, keyShare}, replacer)}</p>`;

/*
// Convert from a hex-encoded string.
function fromHexString(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

const publicKey = "f228c0826177e911648a67568ca516b4949c511d7f94fdd96321ea521689c01c";
const partyIndex = 0;
const message = "a3e6e406aeb475f43aa762bb752a8f9d57b7fa327a2a53c7ae00b13f8d116b38";
const participants = [[242,40,192,130,97,119,233,17,100,138,103,86,140,165,22,180,148,156,81,29,127,148,253,217,99,33,234,82,22,137,192,28],[30,24,115,66,232,8,226,69,197,50,171,83,204,31,12,67,253,168,129,129,103,73,224,139,203,232,221,92,66,219,88,122],[116,105,160,109,121,54,36,96,50,227,208,32,122,218,113,23,106,211,98,20,153,110,243,240,153,6,200,198,243,126,29,63]];
const keygenSessionIdSeed = "5fba144ee5e0fb88ccb1508ae5a5a29bf54e6e76c60c00435ed06a8c616c40d4";
const signSessionIdSeed = "a1599b74d9dec62784120b142f0a5fc497ae24e7fa6fe8bd9e8dec2fa91f94bd";
const signer = "989e2c1fe387fcafed28ed8ce9755e391dbab6058a07e8f6359feb7c8e1b29d2";
const verifiers = ["3056301006072A8648CE3D020106052B8104000A03420004F2EA2A223CCE657A50BEF0681A95BE3A05EC5C770C61FAA8A9B9A5CE18267625530217F6110E37F1903328049F4ABB3F5374ABF3823A9C0C37F66D5B6E00D55B","3056301006072A8648CE3D020106052B8104000A03420004F094C98315B5313A102A18308AEDB882CA67795EC478550217670FC4237079CA6173740BB60277F314581537E9D91504B002339B4FAD278C25ED1FDB80A7D186","3056301006072A8648CE3D020106052B8104000A034200044AE034E89465603A86AF51ACD09F387F1F703A95FDD9AC54E8A07FE174B2EA3D56F183B9172D562886E9D6AD39210FEC58A631F9430EAD8A11BEDE990312745D"];
const options = {
  protocol: "cggmp",
  keypair: `-----BEGIN NOISE PATTERN-----
Tm9pc2VfTk5fMjU1MTlfQ2hhQ2hhUG9seV9CTEFLRTJz
-----END NOISE PATTERN-----

-----BEGIN NOISE PUBLIC KEY-----
8ijAgmF36RFkimdWjKUWtJScUR1/lP3ZYyHqUhaJwBw=
-----END NOISE PUBLIC KEY-----

-----BEGIN NOISE PRIVATE KEY-----
KBTGv5plD8tTd5vzlf4bCrhiP+096R06W4ZnTuEom1w=
-----END NOISE PRIVATE KEY-----
`,
  server: {
    serverUrl: "ws://127.0.0.1:8008",
    serverPublicKey: "745522c5231a7a3c1a4226d3cb0367ce23649d45d7c8e5411d2fa5c3399a4f6d",
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
    fromHexString(keygenSessionIdSeed),
    fromHexString(signer),
  );

  console.log("keygen completed", keyShare);


  const keyShareElement = document.getElementById("key-share");
  keyShareElement.innerHTML = `<p class="key-share">${JSON.stringify(keyShare)}</p>`;
  
  const protocol = new CggmpProtocol(options, keyShare);
  const verifyingKey = protocol.verifyingKey();
  const address = protocol.address();

  console.log("verifyingKey", verifyingKey);
  console.log("address", address);

  console.assert(verifyingKey.length === 33); // SEC1 encoded

  const keyShareElement = document.getElementById("key-share");
  keyShareElement.innerHTML = `<p class="address">Address: ${address}</p>`;

  // First and third parties perform signing
  if (partyIndex == 0 || partyIndex == 2) {
    const result = await protocol.sign(
      // options,
      signParty,
      fromHexString(signSessionIdSeed),
      fromHexString(signer),
      // keyShare,
      message,
    );

    console.log("signature", result);

    const signatureElement = document.getElementById("signature");
    signatureElement.innerHTML = `
      <p class="signature">Signature: ${result}</p>`;

    console.log("signing completed");
  }
} catch (e) {
  console.error(e);
}

*/
