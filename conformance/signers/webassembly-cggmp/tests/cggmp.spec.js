// @ts-check
import { test, expect } from '@playwright/test';
import fs from 'fs';

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const partyKeys = require('./ecdsa.json');

const URL = process.env.TEST_URL || "http://localhost:5173";

function reviver(key, value) {
  if(typeof value === 'object' && value !== null) {
    if (value.dataType === 'Map') {
      return new Map(value.value);
    }
  }
  return value;
}

// Convert from a hex-encoded string.
function fromHexString(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

const dkgSessionIdSeed = "ee507039fb7b14bf8190f300c66732110b401a68ba8e0d3fa464809972d33489";
const signSessionIdSeed = "289e497ac7c2640adda5bf9bf0e9a05833f1807d1c4dce3f73e3483513bfa25e";
const serverKey = fs.readFileSync(
  "../../../integration_tests/tests/server_public_key.txt", "utf8");
const message = "a3e6e406aeb475f43aa762bb752a8f9d57b7fa327a2a53c7ae00b13f8d116b38";

const server = {
  serverUrl: "ws://127.0.0.1:8008",
  serverPublicKey: Array.from(fromHexString(serverKey)),
};
const parameters = {
  parties: 3,
  threshold: 2,
};

function proxyConsoleError(id, page) {
  // Proxy browser console.error()
  page.on("console", (message) => {
    if (message.type() === "error") {
      console.error("console.error: ", id, message.text());
    } else if (message.type() === "warn") {
      console.warn("console.warn: ", id, message.text());
    } else if (message.type() === "info") {
      console.info("console.info: ", id, message.text());
    } else if (message.type() === "log") {
      console.log("console.log: ", id, message.text());
    }
  });

  // Unhandled error
  page.on("pageerror", (err) => {
    console.error("unhandled error:", id, err);
  });
}

test("CGGMP: keygen and sign message", async ({ context, page }) => {
  // The default timeout is 90 seconds which fails on Firefox
  // (Chromium and Webkit are ok) so we increase the timeout here.
  //
  // SEE: https://playwright.dev/docs/test-timeouts#test-timeout
  //
  // Firefox can be up to 5x slower, here is an example
  // from a successful test run:
  //
  // Slow test file: [firefox] › cggmp.spec.js (10.6m)
  // Slow test file: [webkit] › cggmp.spec.js (2.3m)
  // Slow test file: [chromium] › cggmp.spec.js (1.2m)
  //
  test.setTimeout(60 * 1000 * 15);
  
  // DKG
  let pages = [];
  let selectors = [];

  for (let i = 0;i < parameters.parties;i++) {
    const pageData = {
      partyIndex: i,
      server,
      parameters,
      sessionIdSeed: Array.from(fromHexString(dkgSessionIdSeed)),
    };
    const url = `${URL}/dkg.html?data=${encodeURIComponent(JSON.stringify(pageData))}&keys=${encodeURIComponent(JSON.stringify(partyKeys.slice(0, parameters.parties)))}`;

    const page = await context.newPage();
    proxyConsoleError(`p${i + 1}`, page);
    await page.goto(url);
    await page.bringToFront();
    
    pages.push(page);
    selectors.push(".key-share");
  }

  await Promise.all(selectors);

  const keyShares = [];
  for (const page of pages) {
      const keyShare = JSON.parse(await page.textContent(".key-share"), reviver);
      keyShares.push(keyShare);

    console.log(keyShare);
  }
  
  // Sign
  pages = [];
  selectors = [];

  const indices = [0, 2];
  const signers = [
    keyShares[0].keyShare,
    keyShares[2].keyShare,
  ];
  
  let index = 0;
  for (const keyShare of signers) {
    const partyIndex = indices[index];

    // Hack for serde not handling a phantom property
    // on ThresholdKeyShare as expected
    keyShare.phantom = null;

    const pageData = {
      partyIndex,
      indices,
      server,
      parameters,
      sessionIdSeed: Array.from(fromHexString(signSessionIdSeed)),
      keyShare,
      message,
    };

    // console.log(pageData)
    
    const url = `${URL}/sign.html?data=${encodeURIComponent(JSON.stringify(pageData))}&keys=${encodeURIComponent(JSON.stringify(partyKeys.slice(0, parameters.parties)))}`;

    const page = await context.newPage();
    proxyConsoleError(`p${index + 1}`, page);
    await page.goto(url);
    await page.bringToFront();
    
    pages.push(page);
    selectors.push(".signature");

    index++;

  }
  
  await Promise.all(selectors);
});
