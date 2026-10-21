import { describe, expect, it } from "vitest";
import type { Manifest } from "@tinycloud/sdk-core";

import { assertManifestInScope, ManifestRejectedError } from "../src/share/manifest-policy.ts";
import {
  APPROVALS_PREFIX, COURIER_MANIFEST_SCOPE, COURIER_PREFIX, COURIER_SPACE, ORDERS_PREFIX,
  assertCourierPermissions, courierManifest, CourierManifestError,
} from "../src/courier/scope.ts";

type Permission = NonNullable<Manifest["permissions"]>[number];
const base = (): Permission[] => [...(courierManifest().permissions ?? [])];
const withPermissions = (permissions: Permission[]): Manifest => ({ ...courierManifest(), permissions });
const kv = (path: string, actions: string[], space: string = COURIER_SPACE): Permission => ({ service: "tinycloud.kv", space, path, actions, skipPrefix: true });

describe("the courier session's requested authority", () => {
  it("is exactly: get+list on the courier prefix, put on approvals/ and put on orders/", () => {
    expect(() => assertCourierPermissions(courierManifest())).not.toThrow();
    // and it satisfies the generic scope the shared sign-in helper applies before OpenKey opens
    expect(() => assertManifestInScope(courierManifest(), COURIER_MANIFEST_SCOPE, "0x0000000000000000000000000000000000000001")).not.toThrow();
    expect(courierManifest().defaults).toBe(false);
    expect(courierManifest().includePublicSpace).toBe(false);
  });

  // Each of these must be refused by the second check, which states "put only under two prefixes".
  const refused: [string, Permission[]][] = [
    ["a put under me/", [...base(), kv(`${COURIER_PREFIX}me/`, ["put"])]],
    ["a put on the whole courier prefix", [kv(COURIER_PREFIX, ["get", "list", "put"]), ...base().slice(1)]],
    ["a put on me/approvals without the trailing slash", [...base().slice(0, 1), kv(APPROVALS_PREFIX.slice(0, -1), ["put"]), base()[2]!]],
    ["a put under me/approvals/../x", [...base(), kv(`${APPROVALS_PREFIX}../x`, ["put"])]],
    ["a put on to/ (a peer's mailbox files)", [...base(), kv(`${COURIER_PREFIX}to/`, ["put"])]],
    ["a put on me/requests/", [...base(), kv(`${COURIER_PREFIX}me/requests/`, ["put"])]],
    ["a del on approvals", [...base().slice(0, 1), kv(APPROVALS_PREFIX, ["put", "del"]), base()[2]!]],
    ["a del on the courier prefix", [kv(COURIER_PREFIX, ["get", "list", "del"]), ...base().slice(1)]],
    ["metadata on the courier prefix", [kv(COURIER_PREFIX, ["get", "list", "metadata"]), ...base().slice(1)]],
    ["a delegation ability", [...base(), { service: "tinycloud.delegation", space: COURIER_SPACE, path: COURIER_PREFIX, actions: ["delegate"], skipPrefix: true }]],
    ["a wildcard action", [...base(), kv(COURIER_PREFIX, ["*"])]],
    ["another space", [...base(), kv(COURIER_PREFIX, ["get"], "applications")]],
    ["the vault", [...base(), { service: "tinycloud.vault", space: COURIER_SPACE, path: COURIER_PREFIX, actions: ["get"], skipPrefix: true }]],
    ["a read of the whole space", [...base(), kv("", ["get", "list"])]],
    ["a missing approvals grant", [base()[0]!, base()[2]!]],
    ["a missing orders grant", [base()[0]!, base()[1]!]],
    ["a missing read", [base()[1]!, base()[2]!]],
  ];
  for (const [name, permissions] of refused) {
    it(`refuses ${name}`, () => {
      expect(() => assertCourierPermissions(withPermissions(permissions))).toThrow(CourierManifestError);
    });
  }

  it("refuses the public space and a secrets grant", () => {
    expect(() => assertCourierPermissions({ ...courierManifest(), includePublicSpace: true })).toThrow(CourierManifestError);
    expect(() => assertCourierPermissions({ ...courierManifest(), secrets: { TOKEN: ["read"] } } as unknown as Manifest)).toThrow(CourierManifestError);
  });

  it("is also refused by the shared helper's scope for a broader manifest (belt and braces)", () => {
    const broad = withPermissions([...base(), kv("other/", ["get"])]);
    expect(() => assertManifestInScope(broad, COURIER_MANIFEST_SCOPE, "0x0000000000000000000000000000000000000001")).toThrow(ManifestRejectedError);
  });

  it("keeps the two write prefixes distinct from the read prefix", () => {
    expect(APPROVALS_PREFIX).toBe("xyz.tinycloud.courier/me/approvals/");
    expect(ORDERS_PREFIX).toBe("xyz.tinycloud.courier/me/orders/");
  });
});
