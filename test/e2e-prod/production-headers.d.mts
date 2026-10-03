export interface ProductionHeaderRule {
  readonly pattern: string;
  readonly headers: Record<string, string>;
  readonly detach: string[];
}

export function parseProductionHeaders(source: string): ProductionHeaderRule[];

export function productionHeadersForPath(
  rules: readonly ProductionHeaderRule[],
  pathname: string,
): Record<string, string>;
