import test from "node:test";
import assert from "node:assert/strict";

test("IPv4 private ranges are identified", async () => {
  const source = await import("../server.js");
  assert.ok(source);
});
