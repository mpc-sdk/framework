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

  const p1 = `${URL}/p1.html`;
  const p2 = `${URL}/p2.html`;
  const p3 = `${URL}/p3.html`;

  proxyConsoleError("p1", page);
  await page.goto(p1);
  await page.bringToFront();

  const page2 = await context.newPage();
  proxyConsoleError("p2", page2);
  await page2.goto(p2);
  await page2.bringToFront();

  const page3 = await context.newPage();
  proxyConsoleError("p3", page3);
  await page3.goto(p3);
  await page3.bringToFront();

  const pages = context.pages();

  const selectors = [
    page.waitForSelector(".address"),
    page2.waitForSelector(".address"),
    page3.waitForSelector(".address"),
  ];
  
  /*
  const selectors = [
    page.waitForSelector(".signature-address"),
    page2.waitForSelector(".party-number"),
    page3.waitForSelector(".signature-address"),
  ];
  */

  await Promise.all(selectors);
});
