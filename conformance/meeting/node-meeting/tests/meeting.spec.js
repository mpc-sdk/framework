import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const polysig = require('../build/polysig.node');
const { createMeeting, joinMeeting } = polysig;

const serverUrl = "ws://localhost:8008/";
const numParticipants = 5;

const indices = Array.apply(null, Array(numParticipants));
const userIds = indices.map((_, index) => {
  let id = new Uint8Array(32);
  id[0] = index + 1;
  return { id: Array.from(id) };
});

const userData = indices.map((_, index) => {
  return {
    publicKey: [index + 1],
    verifyingKey: [index + 1],
    associatedData: null,
  };
});

const meetingId = await createMeeting(
  serverUrl, userIds, userIds[0]);

const otherIds = userIds.slice(0);
const others = [];
otherIds.forEach((id, index) => {
  const data = userData[index];
  others.push([id, data]);
});

const participants = [];

for (const item of others) {
  const [id, data] = item;
  participants.push(new Promise(async (resolve, reject) => {
    try {
      const results = await joinMeeting(
        serverUrl, meetingId, id, data);
      resolve(results);
    } catch (e) {
      reject(e);
    }
  }))
}

const results = await Promise.all(participants);
console.assert(results.length === numParticipants)
console.log(results);
