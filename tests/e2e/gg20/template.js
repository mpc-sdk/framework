import("/pkg/mpc_bindings.js").then(async (module) => {
  // Initialize the webassembly
  await module.default();

  const participants = ${PARTICIPANTS};
  const options = {
    protocol: "gg20",
    keypair: `${KEYPAIR}`,
    //sessionId: "${SESSION_ID}",
    sessionId: null,
    server: {
      serverUrl: "${SERVER_URL}",
      serverPublicKey: "${SERVER_PUBLIC_KEY}",
    },
    parameters: {
      parties: 3,
      threshold: 1,
    },
  };

  // Start key generation
  try {
    // Get the promise for key generation
    const keygen = module.keygen(options, participants);

    keygen
      .then((keyShare) => {
        console.log("key share generated: ", keyShare);
      })
      .catch((err) => {
        console.error(err);
      });
  } catch (e) {
    console.error(e);
  }

});
