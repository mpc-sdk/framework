// @ts-check
const { test, expect } = require('@playwright/test');

const URL = process.env.TEST_URL || "http://localhost:5173";

test("EdDSA: keygen and sign message", async ({ context, page }) => {
  await page.goto(URL);
});
