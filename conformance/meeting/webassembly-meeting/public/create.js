const module = await import("/pkg/polysig_webassembly_bindings.js");

// Initialize the webassembly
await module.default();

const { createMeeting } = module;
const serverUrl = "ws://localhost:8008/";
const ids = [1, 2, 3];
const userIds = ids.map((id) => {
  const userId = Array.from(new Uint8Array(32));
  userId[0] = id;
  return userId;
});

try {
  const meetingId = await createMeeting(serverUrl, userIds, userIds[0]);
  const el = document.getElementById("meeting-id");
  el.innerHTML = `
    <p class="meeting-id">${meetingId}</p>`;

} catch (e) {
  console.error(e);
}
