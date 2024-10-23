// @ts-check
import { test, expect } from '@playwright/test';

const URL = process.env.TEST_URL || "http://localhost:5173";

test("ECDSA: keygen and sign message", async ({ context, page }) => {
  await page.goto(URL);
});
