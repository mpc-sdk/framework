// @ts-check
import { test, expect } from '@playwright/test';

const URL = process.env.TEST_URL || "http://localhost:5173";

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

test("Meeting: create and join room", async ({ context, page }) => {
  // Create the meeting and retrieve the meeting id
  const create = `${URL}/create.html`;
  proxyConsoleError("create", page);
  await page.goto(create);
  await page.bringToFront();

  await page.waitForSelector(".meeting-id");
  const meetingId = await page.textContent(".meeting-id");

  // Everyone joins the meeting room
  const p1 = `${URL}/join.html?meetingId=${meetingId}&index=1`;
  const p2 = `${URL}/join.html?meetingId=${meetingId}&index=2`;
  const p3 = `${URL}/join.html?meetingId=${meetingId}&index=3`;

  const page1 = await context.newPage();
  proxyConsoleError("p1", page1);
  await page1.goto(p1);
  await page1.bringToFront();
  
  const page2 = await context.newPage();
  proxyConsoleError("p2", page2);
  await page2.goto(p2);
  await page2.bringToFront();

  const page3 = await context.newPage();
  proxyConsoleError("p3", page3);
  await page3.goto(p3);
  await page3.bringToFront();

  // const pages = context.pages();
  
  const selectors = [
    page1.waitForSelector(".participants"),
    page2.waitForSelector(".participants"),
    page3.waitForSelector(".participants"),
  ];

  await Promise.all(selectors);
    
  const pages = [page1, page2, page3];
  const results = [];
  for (const page of pages) {
    const text = await page.textContent(".participants");
    // Should be valid JSON but for assertion it's easier
    // to compare the string values
    JSON.parse(text);
    results.push(text);
  }

  const allEqual = results => results.every( v => v === results[0] )
  console.assert(allEqual);
});
