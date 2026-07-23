# Product

## Register

product

## Users

Two people use this surface: an OpenKey-authenticated sender who wants to share one read-only text or Markdown file through a private possession-based link, and a recipient opening that link from a clean browser. They need to understand that the complete link is the authority, that email notification is not enabled, and what action is safe next.

## Product Purpose

TinyCloud Sharing encrypts one selected file in the sender's browser, stores only CID-addressed encrypted bytes, and returns a link whose fragment holds the decryption material. Success means the sender can reliably copy that link without an email capability, and a recipient can recover the original file in a clean browser while the fragment remains client-only. Exact-email policy sharing remains a separate, fail-closed capability.

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
