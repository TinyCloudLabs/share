import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_REQUIRED_SLICES, GATE_SLICES, SLICE_STATUS, gateSummary, gateVerdict, parseRequiredSlices, summarizeSlices } from "./gate-slices.mjs";

const allFlows = GATE_SLICES.flatMap((slice) => slice.flows);
const flowResults = (passing) => Object.fromEntries(allFlows.map((flow) => [flow, passing.includes(flow)]));
const everyName = GATE_SLICES.map((slice) => slice.name);

test("the slices cover every gated flow exactly once", () => {
  assert.deepEqual([...new Set(allFlows)].sort(), allFlows.slice().sort());
  assert.deepEqual(allFlows.slice().sort(), ["bearer", "denialMatrix", "domain", "editConflict", "exactEmail", "folder", "notification", "senderLibrary"]);
});

test("the slice order follows the blueprint: bearer first, then addressed, then policy", () => {
  assert.deepEqual(everyName, ["bearer", "addressed", "policy", "denial"]);
});

test("the exit code defaults to the bearer slice alone", () => {
  assert.deepEqual(parseRequiredSlices(undefined), ["bearer"]);
  assert.deepEqual(parseRequiredSlices(""), ["bearer"]);
  assert.deepEqual(parseRequiredSlices("   "), ["bearer"]);
  assert.deepEqual(DEFAULT_REQUIRED_SLICES, ["bearer"]);
});

test("`all` restores the previous all-at-once demand", () => {
  assert.deepEqual(parseRequiredSlices("all"), everyName);
});

test("an explicit list is honoured and de-duplicated", () => {
  assert.deepEqual(parseRequiredSlices("bearer, policy ,bearer"), ["bearer", "policy"]);
});

test("an unknown slice name is an error, never a gate on nothing", () => {
  assert.throws(() => parseRequiredSlices("bearer,typo"), /unknown slice\(s\) typo/);
  assert.throws(() => parseRequiredSlices(","), /named no slice/);
});

test("a slice whose every flow passed is proven", () => {
  const report = summarizeSlices({ flowResults: flowResults(["bearer", "senderLibrary"]), attempted: ["bearer"] });
  const bearer = report.find((slice) => slice.name === "bearer");
  assert.equal(bearer.status, SLICE_STATUS.passed);
  assert.deepEqual(bearer.unprovenFlows, []);
});

test("a slice that was never entered is not-attempted, not failed", () => {
  const report = summarizeSlices({ flowResults: flowResults([]), attempted: [] });
  for (const slice of report) {
    assert.equal(slice.status, SLICE_STATUS.notAttempted, `${slice.name} must not read as failed`);
    assert.match(slice.detail, /ended before this slice was reached/);
  }
});

test("a slice blocked by its prerequisite says which slice caused it", () => {
  const report = summarizeSlices({ flowResults: flowResults(["bearer", "senderLibrary"]), attempted: ["bearer", "addressed"], failures: { addressed: "boom" }, blockedBy: { policy: "addressed" } });
  const policy = report.find((slice) => slice.name === "policy");
  assert.equal(policy.status, SLICE_STATUS.notAttempted);
  assert.match(policy.detail, /not attempted because addressed did not pass/);
});

test("a slice that threw reports the error that ended it", () => {
  const report = summarizeSlices({ flowResults: flowResults([]), attempted: ["denial"], failures: { denial: "agent-browser wait timed out" } });
  const denial = report.find((slice) => slice.name === "denial");
  assert.equal(denial.status, SLICE_STATUS.failed);
  assert.equal(denial.detail, "agent-browser wait timed out");
});

test("a slice that ran to completion without setting a flow names that flow", () => {
  const report = summarizeSlices({ flowResults: flowResults(["exactEmail", "notification"]), attempted: ["addressed"] });
  const addressed = report.find((slice) => slice.name === "addressed");
  assert.equal(addressed.status, SLICE_STATUS.failed);
  assert.deepEqual(addressed.unprovenFlows, ["editConflict"]);
  assert.match(addressed.detail, /without proving editConflict/);
});

test("one broken slice cannot hide the slices that passed", () => {
  // The 2026-07-25 shape: everything green except the policy slice.
  const report = summarizeSlices({
    flowResults: flowResults(["bearer", "senderLibrary", "exactEmail", "notification", "editConflict", "denialMatrix", "folder"]),
    attempted: ["bearer", "addressed", "policy", "denial"],
  });
  const verdict = gateVerdict(report, parseRequiredSlices(undefined));
  assert.deepEqual(verdict.provenSlices, ["bearer", "addressed", "denial"]);
  assert.deepEqual(verdict.unprovenSlices, ["policy"]);
  assert.equal(verdict.requiredSlicesPassed, true);
  assert.equal(verdict.allSlicesPassed, false);
});

test("partial success never reads as readiness", () => {
  const report = summarizeSlices({ flowResults: flowResults(["bearer", "senderLibrary"]), attempted: ["bearer"] });
  const verdict = gateVerdict(report, ["bearer"]);
  assert.equal(verdict.requiredSlicesPassed, true);
  assert.equal(verdict.allSlicesPassed, false);
  const summary = gateSummary(verdict);
  assert.match(summary, /still unproven: addressed, policy, denial/);
  assert.match(summary, /This is not release readiness\./);
});

test("a failed required slice is named in the verdict", () => {
  const report = summarizeSlices({ flowResults: flowResults([]), attempted: ["bearer"], failures: { bearer: "no link" } });
  const verdict = gateVerdict(report, ["bearer"]);
  assert.equal(verdict.requiredSlicesPassed, false);
  assert.deepEqual(verdict.failedRequiredSlices, ["bearer"]);
  assert.match(gateSummary(verdict), /required slice\(s\) bearer did not pass/);
});

test("only an all-slice run may be summarized as fully proven", () => {
  const report = summarizeSlices({ flowResults: flowResults(allFlows), attempted: everyName });
  const verdict = gateVerdict(report, ["bearer"]);
  assert.equal(verdict.allSlicesPassed, true);
  assert.match(gateSummary(verdict), /proved every slice/);
  assert.doesNotMatch(gateSummary(verdict), /not release readiness/);
});

test("summarizeSlices refuses to guess when given no flow results", () => {
  assert.throws(() => summarizeSlices({}), /requires flowResults/);
});
