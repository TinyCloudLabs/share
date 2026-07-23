# Product

## Register

product

## Users

Two people use this surface: a sender who wants to share one read-only Markdown resource with an exact email address, and a recipient opening that invitation from a clean browser. They need to understand what has been verified, what has not, and what action is safe next.

## Product Purpose

TinyCloud Sharing turns an exact, pre-authorized KV or named-SQL Markdown resource into an end-to-end verifiable invitation. Success means the sender sees truthful delivery state and the recipient can safely claim a holder-bound credential, authorize one read, and recover from ordinary failure without exposing URL secrets.

## Brand Personality

Quietly technical, trustworthy, humane. The experience should feel like a careful security tool made legible for people: explicit about boundaries, calm during waiting, and warm without pretending that cryptography is magic.

## Anti-references

Avoid generic SaaS dashboards, fake success celebrations, unverifiable delivery claims, opaque security jargon, decorative gradients, and any design that makes a destructive or irreversible action look like a casual link click.

## Design Principles

- Tell the truth about each boundary: requested is not sent, and verified is not authorized until the service says so.
- Make the safe path obvious: one primary action, scoped facts, and recovery guidance beside every failure.
- Keep secrets and protocol mechanics out of view code; render only derived, user-safe summaries.
- Give exact scope a human shape: show the resource, method, source kind, and expiry before confirmation.
- Treat accessibility and low-connectivity behavior as part of the security model, not polish after the fact.

## Accessibility & Inclusion

Target WCAG 2.2 AA. Use semantic labels, keyboard-first controls, visible focus, status announcements, text alternatives for diagrams, high-contrast state colors, and reduced-motion behavior. Never rely on color alone. Support narrow mobile layouts and browser capability failures without trapping the user.
