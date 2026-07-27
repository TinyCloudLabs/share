export function parsePsLines(psOutput) {
  return psOutput
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [pid, pgid, ...commandParts] = line.split(/\s+/);
      return { pid: Number(pid), pgid: Number(pgid), command: commandParts.join(" ") };
    });
}

export function findSurvivingOwnedProcesses(psLines, ownedPgids, excludePid) {
  return psLines.filter((entry) => ownedPgids.has(entry.pgid) && entry.pid !== excludePid);
}
