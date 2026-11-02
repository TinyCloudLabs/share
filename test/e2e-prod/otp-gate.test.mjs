import { test } from "node:test";
import assert from "node:assert/strict";
import { createOtpGate, isOtpSend } from "./otp-gate.mjs";

const fakeClock = () => {
  let time = 0;
  return { now: () => time, sleep: async (ms) => { time += ms; }, advance: (ms) => { time += ms; } };
};

test("sends are spaced at least minGapMs apart, so no 4 fall inside one minute", async () => {
  const clock = fakeClock();
  const gate = createOtpGate({ minGapMs: 21_000, now: clock.now, sleep: clock.sleep });
  const sends = [];
  for (let identity = 0; identity < 4; identity++) {
    await gate.wait();
    sends.push(gate.record());
    clock.advance(2_000); // the next sign-in comes quickly
  }
  assert.deepEqual(sends.map((send) => send.gapMs), [null, 21_000, 21_000, 21_000]);
  assert.ok(sends[3].atMs - sends[0].atMs >= 60_000, "4 sends span at least a minute");
});

test("no wait for the first send, or when the last send is old enough", async () => {
  const clock = fakeClock();
  const gate = createOtpGate({ minGapMs: 21_000, now: clock.now, sleep: clock.sleep });
  assert.equal(await gate.wait(), 0);
  gate.record();
  clock.advance(30_000);
  assert.equal(await gate.wait(), 0);
  clock.advance(-25_000);
  assert.equal(await gate.wait(), 16_000);
});

test("a send recorded from elsewhere (a resend the widget made) also pushes the next one back", async () => {
  const clock = fakeClock();
  const gate = createOtpGate({ minGapMs: 21_000, now: clock.now, sleep: clock.sleep });
  gate.record();
  clock.advance(5_000);
  assert.deepEqual(gate.record(), { atMs: 5_000, gapMs: 5_000 });
  assert.equal(await gate.wait(), 21_000);
});

test("only OpenKey's email-code send request is a send", () => {
  assert.equal(isOtpSend("POST", "https://api.openkey.so/api/auth/email-otp/send-verification-otp"), true);
  assert.equal(isOtpSend("POST", "https://openkey.so/api/auth/email-otp/send-verification-otp?x=1"), true);
  assert.equal(isOtpSend("OPTIONS", "https://api.openkey.so/api/auth/email-otp/send-verification-otp"), false);
  assert.equal(isOtpSend("POST", "https://api.openkey.so/api/auth/sign-in/email-otp"), false);
  assert.equal(isOtpSend("POST", "https://evil.test/api/auth/email-otp/send-verification-otp"), false);
});
