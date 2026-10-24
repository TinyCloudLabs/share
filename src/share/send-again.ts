import type { SenderShareRecord } from "@tinycloud/share-sdk";
import { EXPIRY_CHOICES, type ExpiryChoice, type RecipientSelection } from "./composer-model.js";

/**
 * What the composer is opened with for "Send the link again". Only what the sender's saved share
 * already holds: who it was for, who it was emailed to, how long it lasted, and the file's name.
 * The file itself, its key and the sealed envelope are not carried; the sender attaches the file again.
 */
export interface ComposerPrefill {
  readonly recipient: RecipientSelection;
  /** Mailboxes the earlier link was emailed to. */
  readonly deliveryEmails: readonly string[];
  readonly expiry: ExpiryChoice;
  readonly filename?: string;
}

const CHOICE_MS: Readonly<Record<ExpiryChoice, number>> = { "24h": 86_400_000, "7d": 7 * 86_400_000, "30d": 30 * 86_400_000 };

/** The expiry choice closest to how long the share lasted. */
export function expiryChoiceFor(registeredAt: string, expiresAt: string): ExpiryChoice {
  const lasted = Date.parse(expiresAt) - Date.parse(registeredAt);
  let best: ExpiryChoice = EXPIRY_CHOICES[0]![0];
  for (const [choice] of EXPIRY_CHOICES) if (!(Math.abs(CHOICE_MS[choice] - lasted) >= Math.abs(CHOICE_MS[best] - lasted))) best = choice;
  return best;
}

/** True for shares the composer can make again. A share for one OpenKey device cannot be made from the composer yet. */
export function canSendAgain(record: Pick<SenderShareRecord, "recipientMatcher">): boolean {
  return record.recipientMatcher.kind !== "recipientDid";
}

export function prefillFromRecord(record: SenderShareRecord): ComposerPrefill {
  const matcher = record.recipientMatcher;
  const recipient: RecipientSelection = matcher.kind === "bearer" || matcher.kind === "recipientDid" ? { kind: "bearer" } : { kind: matcher.kind, value: matcher.value };
  return {
    recipient,
    deliveryEmails: record.deliveredRecipients ?? [],
    expiry: expiryChoiceFor(record.registeredAt, record.expiresAt),
    ...(record.filename === undefined ? {} : { filename: record.filename }),
  };
}
