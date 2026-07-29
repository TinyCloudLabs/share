/*
 * TC-307. Independently provable, independently reportable slices.
 *
 * The gate used to demand exactEmail, domain, bearer, editConflict, folder,
 * notification and denialMatrix simultaneously, and every flow ran in one
 * unguarded straight line inside browserGate(). The first failure threw out of
 * the whole function, so every later flow was never attempted yet reported
 * `false` — indistinguishable in the artifact from "attempted and failed". On
 * 2026-07-25 five flows were green and only `domain` failed; the harness was
 * rebuilt and all seven went red together, and nothing recorded could tell
 * those two situations apart.
 *
 * The blueprint (docs/site/sharing/index.html, c66e647) prescribes proving the
 * bearer slice alone first, then recipient-addressed, then policy, then the
 * agent device flow. This module is the machinery for that: the slice
 * definitions, the required-slice selection that scopes the exit code, and the
 * status computation that keeps "not attempted" distinct from "failed".
 *
 * Everything here is pure so the reporting can be tested without running a
 * browser — the part that previously had no coverage at all.
 */

/**
 * Ordered per the blueprint. `flows` are the gateResults keys the slice must
 * set; `requires` names slices whose success this slice genuinely depends on
 * (a dependency is a fact about the run, not a preference about ordering).
 */
export const GATE_SLICES = Object.freeze([
  Object.freeze({
    name: "bearer",
    flows: Object.freeze(["bearer", "senderLibrary"]),
    requires: Object.freeze([]),
    summary: "link-only bearer shares and the persisted sender library",
  }),
  Object.freeze({
    name: "addressed",
    flows: Object.freeze(["exactEmail", "notification", "editConflict"]),
    requires: Object.freeze([]),
    summary: "recipient-addressed shares, notification delivery, and stale-write recovery",
  }),
  Object.freeze({
    name: "policy",
    // The policy slice shares objects out of the sender's own library, and the
    // only thing that puts objects there is a completed addressed share. That
    // is a real dependency: running it after a failed `addressed` slice would
    // report a library failure caused two slices earlier.
    flows: Object.freeze(["folder", "domain"]),
    requires: Object.freeze(["addressed"]),
    summary: "Node-enforced folder and domain policy shares",
  }),
  Object.freeze({
    name: "denial",
    flows: Object.freeze(["denialMatrix"]),
    requires: Object.freeze([]),
    summary: "the enforcing-boundary denial matrix",
  }),
]);

export const DEFAULT_REQUIRED_SLICES = Object.freeze(["bearer"]);
export const SLICE_STATUS = Object.freeze({ passed: "passed", failed: "failed", notAttempted: "not-attempted" });

/**
 * Which slices the exit code is gated on. Defaults to the blueprint's first
 * slice; `all` restores the previous all-at-once demand. An unknown name is an
 * error rather than a silent no-op — a typo that quietly gates on nothing is
 * exactly the false green this issue exists to remove.
 */
export function parseRequiredSlices(value, slices = GATE_SLICES) {
  const known = slices.map((slice) => slice.name);
  if (value === undefined || value === null || String(value).trim().length === 0) return [...DEFAULT_REQUIRED_SLICES];
  const text = String(value).trim();
  if (text === "all") return known;
  const names = text.split(",").map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  if (names.length === 0) throw new Error("SHARING_E2E_REQUIRED_SLICES named no slice");
  const unknown = names.filter((name) => !known.includes(name));
  if (unknown.length > 0) throw new Error(`SHARING_E2E_REQUIRED_SLICES named unknown slice(s) ${unknown.join(", ")}; known slices are ${known.join(", ")}`);
  return [...new Set(names)];
}

/**
 * The verdict for every slice. `attempted` is the set of slices the run
 * actually entered, `failures` maps a slice to the error that ended it, and
 * `flowResults` is the harness's gateResults object.
 *
 * A slice that was never entered is "not-attempted", never "failed": the
 * distinction is the whole point. A slice that was entered and threw is
 * "failed" with that error. A slice that ran to completion but left a flow
 * flag unset is also "failed", and says which flow it never proved.
 */
export function summarizeSlices({ slices = GATE_SLICES, flowResults, attempted, failures = {}, blockedBy = {} } = {}) {
  if (typeof flowResults !== "object" || flowResults === null) throw new TypeError("summarizeSlices requires flowResults");
  const attemptedSet = new Set(attempted ?? []);
  return slices.map((slice) => {
    const flows = Object.fromEntries(slice.flows.map((flow) => [flow, flowResults[flow] === true]));
    const unproven = slice.flows.filter((flow) => flowResults[flow] !== true);
    if (!attemptedSet.has(slice.name)) {
      const reason = blockedBy[slice.name];
      return {
        name: slice.name,
        status: SLICE_STATUS.notAttempted,
        summary: slice.summary,
        flows,
        unprovenFlows: slice.flows.slice(),
        detail: reason === undefined
          ? "the run ended before this slice was reached"
          : `not attempted because ${reason} did not pass; a failure here would report a cause from another slice`,
      };
    }
    const failure = failures[slice.name];
    if (failure !== undefined) return { name: slice.name, status: SLICE_STATUS.failed, summary: slice.summary, flows, unprovenFlows: unproven, detail: failure };
    if (unproven.length > 0) return { name: slice.name, status: SLICE_STATUS.failed, summary: slice.summary, flows, unprovenFlows: unproven, detail: `slice completed without proving ${unproven.join(", ")}` };
    return { name: slice.name, status: SLICE_STATUS.passed, summary: slice.summary, flows, unprovenFlows: [], detail: "every flow in this slice was proven" };
  });
}

/**
 * The honest headline. `requiredSlicesPassed` scopes the exit code;
 * `allSlicesPassed` is the only thing that may be described as readiness, so
 * a run that proves one slice can never read as a run that proved them all.
 */
export function gateVerdict(sliceReport, requiredSlices) {
  const required = new Set(requiredSlices);
  const proven = sliceReport.filter((slice) => slice.status === SLICE_STATUS.passed).map((slice) => slice.name);
  const unproven = sliceReport.filter((slice) => slice.status !== SLICE_STATUS.passed).map((slice) => slice.name);
  const failedRequired = sliceReport.filter((slice) => required.has(slice.name) && slice.status !== SLICE_STATUS.passed);
  return {
    requiredSlices: [...requiredSlices],
    provenSlices: proven,
    unprovenSlices: unproven,
    failedRequiredSlices: failedRequired.map((slice) => slice.name),
    requiredSlicesPassed: failedRequired.length === 0,
    allSlicesPassed: unproven.length === 0,
  };
}

/** One sentence that can never overstate what was proven. */
export function gateSummary(verdict) {
  if (verdict.allSlicesPassed) return `Hermetic production-shaped sharing gate proved every slice: ${verdict.provenSlices.join(", ")}.`;
  const provenText = verdict.provenSlices.length === 0 ? "no slice was proven" : `proven slices: ${verdict.provenSlices.join(", ")}`;
  const requiredText = verdict.requiredSlicesPassed
    ? `required slice(s) ${verdict.requiredSlices.join(", ")} passed`
    : `required slice(s) ${verdict.failedRequiredSlices.join(", ")} did not pass`;
  return `Hermetic gate is scoped to ${verdict.requiredSlices.join(", ")}: ${requiredText}. ${provenText}; still unproven: ${verdict.unprovenSlices.join(", ")}. This is not release readiness.`;
}
