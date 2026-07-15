import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  parseAllowedNodeOrigins,
  parseOpenKeyOrigin,
  parseRegistryOrigin,
  replaceViewerDeploymentCspSources,
} from "../src/viewer/deployment-config.js";

const SOURCES = {
  registryOrigin: "https://registry.tinycloud.xyz",
  nodeOrigins: [
    "https://node.tinycloud.xyz",
    "https://backup.tinycloud.xyz",
  ],
  openKeyOrigin: "https://openkey.so",
} as const;

function directive(text: string, name: string): string {
  const match = text.match(new RegExp(`${name}\\s+'self'[^;\"\\n]*`));
  if (match === null) throw new Error(`missing ${name}`);
  return match[0];
}

describe("viewer deployment origin policy", () => {
  it("reuses the frozen multi-label DNS/default-HTTPS grammar", () => {
    expect(parseAllowedNodeOrigins(SOURCES.nodeOrigins.join(","))).toEqual(
      SOURCES.nodeOrigins,
    );
    expect(parseOpenKeyOrigin(SOURCES.openKeyOrigin)).toBe(
      SOURCES.openKeyOrigin,
    );
    expect(parseRegistryOrigin(SOURCES.registryOrigin, true)).toBe(
      SOURCES.registryOrigin,
    );

    for (const origin of [
      "https://127.0.0.1",
      "https://localhost",
      "https://node.tinycloud.xyz:8443",
      "https://NODE.tinycloud.xyz",
      "https://node.tinycloud.xyz/path",
    ]) {
      expect(() => parseAllowedNodeOrigins(origin), origin).toThrow();
      expect(() => parseRegistryOrigin(origin, true), origin).toThrow();
    }
  });

  it("allows only an explicit canonical loopback registry during development", () => {
    expect(parseRegistryOrigin(undefined, false)).toBe(
      "http://127.0.0.1:8787",
    );
    expect(parseRegistryOrigin("http://localhost:9999", false)).toBe(
      "http://localhost:9999",
    );
    expect(() => parseRegistryOrigin(undefined, true)).toThrow(/required/);
    expect(() => parseRegistryOrigin("http://registry.example", false)).toThrow();
  });

  it("produces matching meta and _headers build-output CSP from one source set", () => {
    const viewerTemplate = readFileSync(
      resolve(process.cwd(), "viewer.html"),
      "utf8",
    );
    const headersTemplate = readFileSync(
      resolve(process.cwd(), "public/_headers"),
      "utf8",
    );
    const viewerOutput = replaceViewerDeploymentCspSources(
      viewerTemplate,
      SOURCES,
    );
    const headersOutput = replaceViewerDeploymentCspSources(
      headersTemplate,
      SOURCES,
    );

    for (const output of [viewerOutput, headersOutput]) {
      expect(output).not.toContain("__TINYCLOUD_");
      expect(output).not.toContain("127.0.0.1");
      expect(output).not.toContain("localhost");
      expect(directive(output, "connect-src")).toBe(
        "connect-src 'self' https://registry.tinycloud.xyz https://node.tinycloud.xyz https://backup.tinycloud.xyz",
      );
      expect(directive(output, "frame-src")).toBe(
        "frame-src 'self' https://openkey.so",
      );
    }
  });
});
