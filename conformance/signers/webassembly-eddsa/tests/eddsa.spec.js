// @ts-check
const { test, expect } = require('@playwright/test');

const URL = process.env.TEST_URL || "http://localhost:9009/cggmp";

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
    console.error("unhandled error:", id, err.stack);
  });
}

test("EdDSA: keygen and sign message", async ({ context, page }) => {
});
