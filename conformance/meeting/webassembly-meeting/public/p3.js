const module = await import("/pkg/polysig_webassembly_bindings.js");

// Initialize the webassembly
await module.default();

const { joinMeeting } = module;
const serverUrl = "ws://localhost:8008/";
const index = 3;
const userId = Array.from(new Uint8Array(32));
userId[0] = index;

const publicKey = new Uint8Array(32);
publicKey[0] = index;
const verifyingKey = new Uint8Array(32);
verifyingKey[0] = index;
const userData = {
  publicKey: Array.from(publicKey),
  verifyingKey: Array.from(verifyingKey),
  associatedData: null,
};

const { search } = document.location;
const params = new URLSearchParams(search);
const meetingId = params.get("meetingId");

console.log("jooining meeting...", meetingId);

const participants = await joinMeeting(
  serverUrl, meetingId, userId, userData);

const el = document.getElementById("participants");
el.innerHTML = `
  <p class="participants">${JSON.stringify(participants)}</p>`;
