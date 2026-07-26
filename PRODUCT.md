# Product

## Register

product

## Users

An OpenKey-authenticated sender can upload or author text and binary resources, choose bearer or addressed policies, read/list/edit permissions, compact or inline formats, and optional delivery. After a share reaches its canonical state, one sender-private encrypted history entry is written in the authenticated `share` space. The sender home lists those entries with cursor pagination and can decrypt the exact link on demand to copy or open it. A recipient opening that link from a clean browser still receives the established fragment protocol and completes the addressed claim flow when required.

## Product Purpose

TinyCloud Sharing encrypts selected content in the sender's browser, stores CID-addressed encrypted bytes, and returns compact or inline links whose fragment holds the bearer or envelope material. The sender library stores the complete link and sender-facing metadata only inside a network-encrypted Vault value; public keys, metadata, bindings, logs, analytics, and unauthenticated responses contain no link fragment, claim secret, exact-email policy, or private authority material. Success means the sender can later recover the identical link in a fresh browser signed into the same OpenKey account. Links created before sender history was introduced are not backfilled and are recoverable only when the sender still possesses the complete URL and explicitly imports it.

## Brand Personality

Quietly technical, trustworthy, humane. The experience should feel like a careful security tool made legible for people: explicit about boundaries, calm during waiting, and warm without pretending that cryptography is magic.

## Anti-references

Avoid generic SaaS dashboards, fake success celebrations, unverifiable delivery claims, opaque security jargon, decorative gradients, and any design that makes a destructive or irreversible action look like a casual link click.

## Design Principles

- Tell the truth about each boundary: a possession link is the authority, and creating one does not send an email.
- Make the safe path obvious: one primary action, scoped facts, and recovery guidance beside every failure.
- Keep secrets and protocol mechanics out of view code; render only derived, user-safe summaries.
- Give exact scope a human shape: show the selected file, read-only possession semantics, and expiry before creation.
- Treat accessibility and low-connectivity behavior as part of the security model, not polish after the fact.

## Accessibility & Inclusion

Target WCAG 2.2 AA. Use semantic labels, keyboard-first controls, visible focus, status announcements, text alternatives for diagrams, high-contrast state colors, and reduced-motion behavior. Never rely on color alone. Support narrow mobile layouts and browser capability failures without trapping the user.
