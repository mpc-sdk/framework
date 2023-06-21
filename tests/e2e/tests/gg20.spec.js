// @ts-check
const { test, expect } = require('@playwright/test');

const GG20_URL = process.env.TEST_URL || "http://localhost:9009/gg20";

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

test("GG20: keygen and sign message", async ({ context, page }) => {
  const p1 = `${GG20_URL}/p1.html`;
  const p2 = `${GG20_URL}/p2.html`;
  const p3 = `${GG20_URL}/p3.html`;

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

  await Promise.all(
    pages.map((page) => {
      return page.waitForSelector(".party-number");
    })
  );

});
