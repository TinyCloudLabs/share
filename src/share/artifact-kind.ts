/**
 * What the viewer renders as a page rather than a document: a single-file
 * HTML page or a React component (JSX/TSX). The viewer's own classifier
 * (`classifyContent`) decides from the saved media type or the file name; this
 * reads the file name only, so the sender sees the label before anything is
 * uploaded.
 */
export type ArtifactKind = "html" | "jsx" | "tsx";

export function artifactKindOf(filename: string): ArtifactKind | undefined {
  const match = /\.(html?|jsx|tsx)$/i.exec(filename);
  if (match === null) return undefined;
  const extension = match[1]!.toLowerCase();
  return extension === "jsx" ? "jsx" : extension === "tsx" ? "tsx" : "html";
}

export const ARTIFACT_KIND_LABEL: Readonly<Record<ArtifactKind, string>> = {
  html: "Artifact · HTML",
  jsx: "Artifact · JSX",
  tsx: "Artifact · TSX",
};

/** Said next to a chosen file: what a recipient gets depends on who can open it. */
export const ARTIFACT_NOTE_LINK = "Opens as a page for anyone with the link.";
export const ARTIFACT_NOTE_ADDRESSED = "Named recipients get a download for now. Choose “Anyone with the link” to open it as a page.";
