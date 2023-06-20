import init from '/pkg/mpc_bindings.js';

const bindings = await init();
const parameters = {
  parties: 3,
  threshold: 1,
};

const server = {
  serverUrl: "http://127.0.0.1:8008",
  serverPublicKey: "3d7f4b9500995ba88b5b42a6e520d7e8ba278939a9ace68aa4f2b18d17582f2f",
};

const options = {
  protocol: "gg20",
  sessionId: "67e55044-10b1-426f-9247-bb680e5fe0c8",
  server,
  parameters,
};

console.log(bindings);
console.log(options);
