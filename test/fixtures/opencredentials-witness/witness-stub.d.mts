export interface WitnessStub {
  readonly fetch: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
  readonly reqs: Map<string, unknown>;
  readonly code: string;
  readonly issuerKeys: readonly unknown[];
}
export function makeWitness(options?: { readonly code?: string; readonly maxAttempts?: number; readonly subjectDid?: string }): WitnessStub;
export function generateHolderKey(): unknown;
